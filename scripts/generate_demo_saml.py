"""DEMO ONLY: create throw-away signing keys and sample SAML responses for one app,
so you can try SAML validation without a real PingFederate.

Run discovery first (flask discover), then:
    python scripts/generate_demo_saml.py [--app-id 0oa3engwiki00000003]

Writes to data/demo/:
    pf-signing-demo.crt            "PingFederate" signing certificate (paste it, or set PF_SIGNING_CERT_FILE)
    okta-signing-demo.crt          "Okta" signing certificate for the baseline
    <app>-okta-baseline.txt        Okta response for the test user        -> stage: Okta baseline
    <app>-pingfederate-ok.txt      PingFederate response, matches          -> stage: Pre-cutover (PASS)
    <app>-pingfederate-broken.txt  wrong NameID + missing attribute        -> FAIL
The private keys are not kept. Never use these files with a real SP.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_settings  # noqa: E402
from app.devtools.samlkit import build_response, make_keypair  # noqa: E402
from app.models.db import Application, SessionLocal, init_engine  # noqa: E402
from app.services import cutover  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--app-id", default="0oa3engwiki00000003")
    ap.add_argument("--user", default="jane.doe@northwind.example")
    args = ap.parse_args()
    s = get_settings()
    init_engine(s.database_url)
    db = SessionLocal()
    app = db.get(Application, args.app_id)
    if app is None or not app.is_saml:
        sys.exit(f"SAML app {args.app_id} not found - run 'flask discover' first")
    out = Path(__file__).resolve().parent.parent / "data" / "demo"
    out.mkdir(parents=True, exist_ok=True)
    (pk, pc), (ok_, oc) = make_keypair("demo-pingfederate-signing"), make_keypair("demo-okta-signing")
    (out / "pf-signing-demo.crt").write_text(pc)
    (out / "okta-signing-demo.crt").write_text(oc)
    exp = cutover.expected_values(app, s)
    fmt = exp["name_id_format"] or "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
    values = {n: (["Engineering", "Wiki-Editors"] if n in exp["group_attributes"] else [f"{n}-value"])
              for n in exp["attributes"]}
    slug = app.label.split(" ")[0].lower()
    okta = build_response(cutover.okta_issuer(app), exp["audience"], exp["acs_urls"][0], args.user, values,
                          name_id_format=fmt, key_pem=ok_, cert_pem=oc)
    good = build_response(exp["issuer"], exp["audience"], exp["acs_urls"][0], args.user, values,
                          name_id_format=fmt, key_pem=pk, cert_pem=pc)
    broken_vals = dict(list(values.items())[1:])
    broken = build_response(exp["issuer"], exp["audience"], exp["acs_urls"][0], "jdoe", broken_vals,
                            name_id_format=fmt, key_pem=pk, cert_pem=pc)
    for name, body in ((f"{slug}-okta-baseline.txt", okta), (f"{slug}-pingfederate-ok.txt", good),
                       (f"{slug}-pingfederate-broken.txt", broken)):
        (out / name).write_text(body)
    print(f"Demo files for {app.label} written to {out}")
    print("For the go/no-go gate, set PF_SIGNING_CERT_FILE=data/demo/pf-signing-demo.crt in .env and restart.")
    print("The Okta baseline: paste okta-signing-demo.crt as the certificate (the demo key is not Okta's).")


if __name__ == "__main__":
    main()
