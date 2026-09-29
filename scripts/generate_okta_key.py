"""Generate an RSA key pair for the Okta API Services app (private_key_jwt).

The private key is written to secrets/okta_service_app.pem and never leaves this machine.
The PUBLIC key is printed as a JWK: paste it into Okta (API Services app -> General ->
Public keys -> Add key -> paste). Then put the printed KID in .env as OKTA_PRIVATE_KEY_KID.

Usage:  python scripts/generate_okta_key.py [--force | --show]
        --show re-prints the public key and KID of the existing key without changing it.
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

OUT = Path(__file__).resolve().parent.parent / "secrets" / "okta_service_app.pem"


def b64u(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def main() -> None:
    if "--show" in sys.argv:
        # Re-print the public key and KID of the existing private key; nothing is written.
        if not OUT.exists():
            sys.exit(f"{OUT} does not exist. Run without --show to generate it.")
        key = serialization.load_pem_private_key(OUT.read_bytes(), password=None)
        print(f"Existing private key: {OUT}\n")
    else:
        if OUT.exists() and "--force" not in sys.argv:
            sys.exit(f"{OUT} already exists. Re-run with --force to replace it (the old key stops working "
                     "in Okta), or with --show to print its public key and KID.")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        OUT.parent.mkdir(exist_ok=True)
        OUT.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
        print(f"Private key saved to {OUT} (keep it secret; it is git-ignored).\n")
    pub = key.public_key().public_numbers()
    jwk = {"e": b64u(pub.e), "kty": "RSA", "n": b64u(pub.n)}
    # RFC 7638 thumbprint as the key ID
    kid = base64.urlsafe_b64encode(hashlib.sha256(
        json.dumps(jwk, separators=(",", ":"), sort_keys=True).encode()).digest()).rstrip(b"=").decode()
    jwk = {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "e": jwk["e"], "n": jwk["n"]}
    print("1) Paste this PUBLIC key into Okta (API Services app -> General -> Public keys -> Add key):\n")
    print(json.dumps(jwk, indent=2))
    print(f"\n2) Put this in .env:\nOKTA_PRIVATE_KEY_KID={kid}")


if __name__ == "__main__":
    main()
