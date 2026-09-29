"""SAML response validation.

Takes a captured SAML response (raw XML, base64, or the URL-encoded form body
"SAMLResponse=...") and checks it against what the app expects: issuer,
destination, audience, recipient, NameID format, attributes, signatures (verified
cryptographically against the expected signing certificate - never against the
certificate inside the response), algorithm and validity window. Optionally
compares NameID and attribute values with an Okta baseline for the same test user.

Pure functions: no database, no network.
"""
from __future__ import annotations

import base64
import hashlib
import re
import zlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from urllib.parse import parse_qs, unquote_plus

from lxml import etree

NS = {"samlp": "urn:oasis:names:tc:SAML:2.0:protocol", "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
      "ds": "http://www.w3.org/2000/09/xmldsig#", "xenc": "http://www.w3.org/2001/04/xmlenc#"}
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
PASS, WARN, FAIL, INFO = "PASS", "WARN", "FAIL", "INFO"
UNSPECIFIED = {"", None, "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"}
_PARSER = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, dtd_validation=False,
                          huge_tree=False, remove_comments=True)


class SamlInputError(ValueError):
    pass


@dataclass
class Check:
    key: str
    label: str
    expected: str
    actual: str
    status: str
    note: str = ""


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    response_sha256: str = ""

    @property
    def verdict(self) -> str:
        st = {c.status for c in self.checks}
        return "FAIL" if FAIL in st else ("PASS_WITH_WARNINGS" if WARN in st else "PASS")

    def as_dict(self) -> dict:
        return {"checks": [asdict(c) for c in self.checks], "summary": self.summary}


# --- input ---------------------------------------------------------------------
def decode(text: str | bytes) -> bytes:
    """Accept raw XML, base64 (POST binding), deflated base64 (Redirect), or a form body."""
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    t = text.strip()
    if not t:
        raise SamlInputError("Paste a SAML response")
    if "SAMLResponse=" in t and not t.lstrip().startswith("<"):
        vals = parse_qs(t.split("?", 1)[-1], keep_blank_values=True).get("SAMLResponse")
        if not vals:
            raise SamlInputError("No SAMLResponse value in the form body")
        t = vals[0]
    if t.startswith("<"):
        xml = t.encode()
    else:
        raw = re.sub(r"\s+", "", t)
        if "%" in raw:
            raw = unquote_plus(raw)
        try:
            data = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=False)
        except Exception as exc:
            raise SamlInputError("Not XML and not valid base64") from exc
        if not data.lstrip().startswith(b"<"):
            try:
                data = zlib.decompress(data, -15)
            except zlib.error as exc:
                raise SamlInputError("Decoded value is not XML") from exc
        xml = data
    if b"<!DOCTYPE" in xml.upper() or b"<!ENTITY" in xml.upper():
        raise SamlInputError("DOCTYPE / ENTITY declarations are not allowed in a SAML response")
    if len(xml) > 2_000_000:
        raise SamlInputError("Response is too large")
    return xml


def _parse(xml: bytes):
    try:
        root = etree.fromstring(xml, parser=_PARSER)
    except etree.XMLSyntaxError as exc:
        raise SamlInputError(f"Not well-formed XML: {exc}") from exc
    if etree.QName(root).localname != "Response" or etree.QName(root).namespace != NS["samlp"]:
        raise SamlInputError("The XML is not a SAML 2.0 <samlp:Response>")
    return root


def _t(el, path) -> str | None:
    x = el.find(path, NS) if el is not None else None
    return x.text.strip() if x is not None and x.text else None


def _dt(v: str | None) -> datetime | None:
    if not v:
        return None
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00")).astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        return None


def pem_of(cert: str | None) -> str | None:
    """Normalise a PEM or bare base64 (x5c) certificate to PEM."""
    if not cert:
        return None
    c = cert.strip()
    if "BEGIN CERTIFICATE" in c:
        return c
    body = re.sub(r"\s+", "", c)
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(body[i:i + 64] for i in range(0, len(body), 64)) + \
        "\n-----END CERTIFICATE-----\n"


def cert_sha256(pem: str | None) -> str | None:
    if not pem:
        return None
    from cryptography import x509
    try:
        c = x509.load_pem_x509_certificate(pem.encode())
    except ValueError:
        return None
    from cryptography.hazmat.primitives import hashes
    return c.fingerprint(hashes.SHA256()).hex(":").upper()


def _verify(el, pem: str) -> tuple[bool, str]:
    """Verify the enveloped signature on `el` (Response or Assertion) with the expected cert."""
    from signxml import XMLVerifier
    from signxml.exceptions import InvalidInput, InvalidSignature
    try:
        res = XMLVerifier().verify(etree.tostring(el), x509_cert=pem, ignore_ambiguous_key_info=True)
        res = res[0] if isinstance(res, list) else res
        # The signature must cover this element itself (defends against signature wrapping).
        if res.signed_xml is None or res.signed_xml.get("ID") != el.get("ID"):
            return False, "The signature does not reference this element"
        return True, ""
    except (InvalidSignature, InvalidInput) as exc:
        return False, str(exc)[:300]
    except Exception as exc:  # malformed signature, unsupported algorithm
        return False, f"{type(exc).__name__}: {str(exc)[:300]}"


# --- parse into a summary --------------------------------------------------------
def summarise(xml: bytes) -> tuple[dict, object]:
    root = _parse(xml)
    a = root.find("saml:Assertion", NS)
    enc = root.find("saml:EncryptedAssertion", NS)
    subj = a.find("saml:Subject", NS) if a is not None else None
    nameid = subj.find("saml:NameID", NS) if subj is not None else None
    scd = subj.find("saml:SubjectConfirmation/saml:SubjectConfirmationData", NS) if subj is not None else None
    cond = a.find("saml:Conditions", NS) if a is not None else None
    attrs: dict[str, list[str]] = {}
    if a is not None:
        for at in a.findall("saml:AttributeStatement/saml:Attribute", NS):
            attrs.setdefault(at.get("Name"), []).extend(
                (v.text or "").strip() for v in at.findall("saml:AttributeValue", NS))
    sig_r = root.find("ds:Signature", NS)
    sig_a = a.find("ds:Signature", NS) if a is not None else None

    def sig_info(sig):
        if sig is None:
            return None
        return {"algorithm": (sig.find("ds:SignedInfo/ds:SignatureMethod", NS).get("Algorithm")
                              if sig.find("ds:SignedInfo/ds:SignatureMethod", NS) is not None else None),
                "digest": (sig.find(".//ds:DigestMethod", NS).get("Algorithm")
                           if sig.find(".//ds:DigestMethod", NS) is not None else None),
                "embedded_cert_sha256": cert_sha256(pem_of(_t(sig, "ds:KeyInfo/ds:X509Data/ds:X509Certificate")))}
    summary = {
        "response_id": root.get("ID"), "in_response_to": root.get("InResponseTo"),
        "issue_instant": root.get("IssueInstant"), "destination": root.get("Destination"),
        "status": (root.find("samlp:Status/samlp:StatusCode", NS).get("Value")
                   if root.find("samlp:Status/samlp:StatusCode", NS) is not None else None),
        "status_message": _t(root, "samlp:Status/samlp:StatusMessage"),
        "issuer": _t(root, "saml:Issuer") or _t(a, "saml:Issuer"),
        "response_issuer": _t(root, "saml:Issuer"),
        "assertion_issuer": _t(a, "saml:Issuer"),
        "encrypted": enc is not None and a is None,
        "name_id": nameid.text.strip() if nameid is not None and nameid.text else None,
        "name_id_format": nameid.get("Format") if nameid is not None else None,
        "recipient": scd.get("Recipient") if scd is not None else None,
        "scd_not_on_or_after": scd.get("NotOnOrAfter") if scd is not None else None,
        "not_before": cond.get("NotBefore") if cond is not None else None,
        "not_on_or_after": cond.get("NotOnOrAfter") if cond is not None else None,
        "audiences": [x.text.strip() for x in cond.findall("saml:AudienceRestriction/saml:Audience", NS) if x.text]
        if cond is not None else [],
        "authn_context": _t(a, "saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef"),
        "attributes": attrs,
        "response_signature": sig_info(sig_r), "assertion_signature": sig_info(sig_a),
    }
    return summary, (root, a)


# --- validate --------------------------------------------------------------------
def _j(v) -> str:
    if v is None or v == "" or v == []:
        return "—"
    return ", ".join(v) if isinstance(v, (list, tuple, set)) else str(v)


def validate(response: str | bytes, expected: dict, baseline: dict | None = None, now: datetime | None = None,
             signing_cert_pem: str | None = None, captured: bool = True, skew_seconds: int = 180,
             strict: bool = False) -> Report:
    """strict=True is used for the gating stages (pre/post cutover): a signature that could not be
    verified, or an encrypted assertion that could not be inspected, is a FAIL instead of a warning.

    expected keys: issuer, audience, acs_urls, name_id_format, attributes, group_attributes,
    sign_assertion, signature_algorithm ('rsa-sha256'), authn_context, cert_pem (optional).
    baseline: a previous summary (e.g. Okta's response for the same test user)."""
    xml = decode(response)
    rep = Report(response_sha256=hashlib.sha256(xml).hexdigest())
    summary, (root, assertion) = summarise(xml)
    rep.summary = summary
    add = lambda *a, **k: rep.checks.append(Check(*a, **k))  # noqa: E731
    now = now or datetime.utcnow()

    st = summary["status"]
    add("status", "Status", "Success", (st or "—").rsplit(":", 1)[-1] + (f" ({summary['status_message']})" if summary["status_message"] else ""),
        PASS if st == SUCCESS else FAIL, "" if st == SUCCESS else "The IdP returned an error, not an assertion")
    if st != SUCCESS:
        return rep

    if len(root.findall("saml:Assertion", NS)) + len(root.findall("saml:EncryptedAssertion", NS)) > 1:
        add("assertions", "Assertions", "exactly one", "more than one", FAIL, "Multiple assertions are not expected")
    exp_iss = expected.get("issuer")
    add("issuer", "Issuer", _j(exp_iss), _j(summary["issuer"]),
        PASS if summary["issuer"] == exp_iss else FAIL,
        "" if summary["issuer"] == exp_iss else "The SP checks the issuer; a different value is rejected")

    acs = set(expected.get("acs_urls") or [])
    dest = summary["destination"]
    if dest is None:
        add("destination", "Destination", _j(sorted(acs)), "—", WARN, "No Destination attribute (some SPs require it)")
    elif acs:
        add("destination", "Destination", _j(sorted(acs)), dest, PASS if dest in acs else FAIL)

    if summary["encrypted"]:
        add("encrypted", "Assertion", "Readable", "Encrypted", FAIL if strict else WARN,
            "The assertion is encrypted; NameID, audience and attributes cannot be checked here. "
            "Capture it with encryption off in the test environment, or at the SP.")
    else:
        aud = expected.get("audience")
        if aud:
            ok = aud in summary["audiences"]
            add("audience", "Audience", aud, _j(summary["audiences"]), PASS if ok else FAIL,
                "" if ok else "The SP rejects assertions for another audience")
        if acs:
            rec = summary["recipient"]
            add("recipient", "Recipient", _j(sorted(acs)), _j(rec), PASS if rec in acs else FAIL)
        exp_fmt = expected.get("name_id_format")
        got_fmt = summary["name_id_format"]
        if exp_fmt in UNSPECIFIED:
            add("name_id_format", "NameID format", _j(exp_fmt) if exp_fmt else "unspecified", _j(got_fmt), INFO)
        else:
            add("name_id_format", "NameID format", exp_fmt, _j(got_fmt), PASS if got_fmt == exp_fmt else FAIL)
        add("name_id", "NameID present", "a value", _j(summary["name_id"]), PASS if summary["name_id"] else FAIL)

        got = summary["attributes"]
        groups = set(expected.get("group_attributes") or [])
        for name in expected.get("attributes") or []:
            if name in got:
                vals = [v for v in got[name] if v]
                add(f"attr:{name}", f"Attribute '{name}'", "present", _j(vals) if vals else "(empty)",
                    PASS if vals or name in groups else WARN, "" if vals else "Present but empty")
            else:
                add(f"attr:{name}", f"Attribute '{name}'", "present", "missing",
                    WARN if name in groups else FAIL,
                    "A group attribute is left out when the user has no matching groups" if name in groups
                    else "The SP expects this attribute")
        extra = sorted(set(got) - set(expected.get("attributes") or []))
        if extra:
            add("attr_extra", "Extra attributes", "—", _j(extra), INFO, "Sent now but not by Okta; usually harmless")

        if baseline:
            b_nid = baseline.get("name_id")
            add("baseline:name_id", "NameID vs Okta", _j(b_nid), _j(summary["name_id"]),
                PASS if b_nid == summary["name_id"] else (WARN if b_nid and summary["name_id"] and
                                                           b_nid.lower() == summary["name_id"].lower() else FAIL),
                "" if b_nid == summary["name_id"] else
                "A different NameID usually means the SP creates a new account or finds none")
            bat = baseline.get("attributes") or {}
            for name in sorted(set(bat) | set(got)):
                if name not in bat:
                    continue
                bv, gv = [v for v in bat[name] if v], [v for v in got.get(name, []) if v]
                same = (set(bv) == set(gv)) if name in groups else (bv == gv)
                ci = [v.lower() for v in bv] == [v.lower() for v in gv]
                add(f"baseline:{name}", f"'{name}' vs Okta", _j(bv), _j(gv),
                    PASS if same else (WARN if ci else FAIL),
                    "" if same else ("Differs only in upper/lower case" if ci else
                                     ("Group lists differ" if name in groups else "Value differs from Okta")))

        nb, noa = _dt(summary["not_before"]), _dt(summary["not_on_or_after"])
        if noa and now > noa + _skew(skew_seconds):
            add("validity", "Validity window", "not expired", f"expired {summary['not_on_or_after']}",
                INFO if captured else FAIL, "Expected for a response captured earlier" if captured else "")
        elif nb and now + _skew(skew_seconds) < nb:
            add("validity", "Validity window", "already valid", f"not before {summary['not_before']}", WARN,
                "Clock difference between the IdP and this machine")
        elif noa:
            add("validity", "Validity window", "valid now", f"until {summary['not_on_or_after']}", PASS)
        if nb and noa and (noa - nb).total_seconds() > 3600:
            add("lifetime", "Assertion lifetime", "≤ 60 min", f"{int((noa - nb).total_seconds() // 60)} min", WARN,
                "A long lifetime widens the replay window")
        exp_ctx = expected.get("authn_context")
        if exp_ctx:
            add("authn_context", "AuthnContextClassRef", exp_ctx, _j(summary["authn_context"]),
                PASS if summary["authn_context"] == exp_ctx else WARN)

    # signatures
    rs, asg = summary["response_signature"], summary["assertion_signature"]
    if expected.get("sign_assertion") and not summary["encrypted"]:
        add("assertion_signed", "Assertion signed", "Yes", "Yes" if asg else "No", PASS if asg else FAIL)
    if not rs and not asg:
        add("signed", "Signature", "Response or assertion signed", "Unsigned", FAIL, "An unsigned response must be rejected")
    exp_alg = expected.get("signature_algorithm") or "rsa-sha256"
    for label, sig in (("Response", rs), ("Assertion", asg)):
        if sig:
            alg = (sig["algorithm"] or "").rsplit("#", 1)[-1]
            add(f"alg:{label.lower()}", f"{label} signature algorithm", exp_alg, alg or "—",
                PASS if alg == exp_alg else WARN, "" if alg == exp_alg else "Confirm the SP accepts it")
    pem = pem_of(signing_cert_pem or expected.get("cert_pem"))
    if not pem:
        add("signature_valid", "Signature verified", "valid with the expected certificate", "not checked",
            FAIL if strict else WARN,
            "No signing certificate configured (PF_SIGNING_CERT_FILE), so the signature could not be verified")
    else:
        fp = cert_sha256(pem)
        if fp is None:
            add("signature_valid", "Signature verified", "a valid certificate", "certificate unreadable", FAIL)
        else:
            for label, el, sig in (("Response", root, rs), ("Assertion", assertion, asg)):
                if sig is None or el is None:
                    continue
                ok, err = _verify(el, pem)
                add(f"sig:{label.lower()}", f"{label} signature verified", f"valid with {fp[:23]}…",
                    "valid" if ok else "INVALID", PASS if ok else FAIL, err)
                emb = sig.get("embedded_cert_sha256")
                if emb and emb != fp:
                    add(f"cert:{label.lower()}", f"{label} certificate in KeyInfo", fp[:23] + "…", emb[:23] + "…", WARN,
                        "The response carries a different certificate than expected")
    return rep


def _skew(seconds: int):
    from datetime import timedelta
    return timedelta(seconds=seconds)
