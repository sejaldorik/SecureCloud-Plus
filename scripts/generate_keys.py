"""
Development-only ECC key pair generation utility script.
Generates a fresh client-side SECP256R1 (NIST P-256) ECC key pair.

Note: The generated private key must be kept securely by the test client and is never
stored on the server, in metadata sidecars, or on the blockchain.
"""

import sys
from pathlib import Path

# Add project root directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.ecc import (
    generate_ecc_key_pair,
    serialize_public_key,
    serialize_private_key
)


def main() -> None:
    """
    Generates and prints a client-side ECC public/private key pair.
    """
    private_key, public_key = generate_ecc_key_pair()

    public_pem = serialize_public_key(public_key)
    private_pem = serialize_private_key(private_key)

    print("=" * 60)
    print("DEVELOPMENT CLIENT-SIDE ECC KEY PAIR GENERATED")
    print("=" * 60)
    print("\n--- PUBLIC KEY PEM (Pass to POST /files/upload) ---")
    print(public_pem)
    print("--- PRIVATE KEY PEM (Pass to GET /files/{file_id}/download) ---")
    print(private_pem)
    print("=" * 60)
    print("SECURITY NOTICE: The private key is client-side only and must be kept securely.")
    print("=" * 60)


if __name__ == "__main__":
    main()
