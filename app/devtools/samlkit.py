"""DEMO / TEST ONLY: build signed SAML responses with a throw-away key.

Used by the tests, the sample data and the local mock IdP. Never used by the
migration flow itself.
"""
from __future__ import annotations

import base64
import uuid
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from xml.sax.saxutils import escape, quoteattr


def make_keypair(cn: str = "demo-idp-signing") -> tuple[str, str]:
    """(private key PEM, certificate PEM) - self-signed, 2048-bit, 2 years."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=730)).sign(key, hashes.SHA256()))
    return (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()).decode(),
            cert.public_bytes(serialization.Encoding.PEM).decode())


def _iso(d: datetime) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_response(issuer: str, audience: str, acs: str, name_id: str, attributes: dict[str, list[str]],
                   name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                   key_pem: str | None = None, cert_pem: str | None = None, sign: str = "assertion",
                   now: datetime | None = None, lifetime_minutes: int = 5,
                   authn_context: str = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
                   status: str = "urn:oasis:names:tc:SAML:2.0:status:Success") -> str:
    """Return the base64 SAMLResponse. sign: 'assertion' | 'response' | 'both' | 'none'."""
    now = now or datetime.utcnow()
    rid, aid = "_" + uuid.uuid4().hex, "_" + uuid.uuid4().hex
    attrs = "".join(
        f'<saml:Attribute Name={quoteattr(n)} NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">'
        + "".join(f"<saml:AttributeValue>{escape(v)}</saml:AttributeValue>" for v in vs) + "</saml:Attribute>"
        for n, vs in attributes.items())
    xml = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{rid}" Version="2.0" IssueInstant="{_iso(now)}" Destination={quoteattr(acs)}><saml:Issuer>{escape(issuer)}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{status}"/></samlp:Status><saml:Assertion ID="{aid}" Version="2.0" IssueInstant="{_iso(now)}"><saml:Issuer>{escape(issuer)}</saml:Issuer><saml:Subject><saml:NameID Format="{name_id_format}">{escape(name_id)}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{_iso(now + timedelta(minutes=lifetime_minutes))}" Recipient={quoteattr(acs)}/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{_iso(now - timedelta(minutes=1))}" NotOnOrAfter="{_iso(now + timedelta(minutes=lifetime_minutes))}"><saml:AudienceRestriction><saml:Audience>{escape(audience)}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="{_iso(now)}"><saml:AuthnContext><saml:AuthnContextClassRef>{authn_context}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement>{attrs}</saml:AttributeStatement></saml:Assertion></samlp:Response>"""
    root = etree.fromstring(xml.encode())
    if sign != "none":
        from signxml import XMLSigner, methods
        signer = XMLSigner(method=methods.enveloped, signature_algorithm="rsa-sha256", digest_algorithm="sha256",
                           c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
        signer.namespaces = {"ds": "http://www.w3.org/2000/09/xmldsig#"}
        ns = {"saml": "urn:oasis:names:tc:SAML:2.0:assertion"}
        if sign in ("assertion", "both"):
            a = root.find("saml:Assertion", ns)
            signed_a = signer.sign(a, key=key_pem, cert=cert_pem, reference_uri=aid)
            _place_after_issuer(signed_a)
            root.replace(a, signed_a)
        if sign in ("response", "both"):
            root = signer.sign(root, key=key_pem, cert=cert_pem, reference_uri=rid)
            _place_after_issuer(root)
    return base64.b64encode(etree.tostring(root)).decode()


def _place_after_issuer(el) -> None:
    """SAML schema wants <ds:Signature> right after <saml:Issuer>. Moving it does not
    break the enveloped signature (it is excluded from the digest)."""
    sig = el.find("{http://www.w3.org/2000/09/xmldsig#}Signature")
    iss = el.find("{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
    if sig is not None and iss is not None:
        el.remove(sig)
        iss.addnext(sig)
