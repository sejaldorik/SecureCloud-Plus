import os
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

HKDF_INFO = b"SecureCloud+ ECC-AES-GCM KEK"
KEK_SIZE_BYTES = 32
KEK_NONCE_SIZE_BYTES = 12


class ECCError(Exception):
    """Custom exception for ECC cryptographic operations."""
    pass


def generate_ecc_key_pair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """
    Generates a new ECC key pair using the SECP256R1 (NIST P-256) curve.

    Returns:
        Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]: (private_key, public_key)
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key: ec.EllipticCurvePublicKey) -> str:
    """
    Serializes an ECC public key to a PEM formatted string.
    """
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_bytes.decode('utf-8')


def sanitize_pem(pem_str: str) -> str:
    """
    Normalize PEM strings received through HTTP query/form inputs.
    """
    if not pem_str:
        return pem_str

    # Normalize newlines
    pem_str = pem_str.replace("\\n", "\n").replace("\r\n", "\n")

    raw_lines = [
        line
        for line in pem_str.splitlines()
        if line.strip()
    ]

    if (
        len(raw_lines) >= 2
        and raw_lines[0].strip().startswith("-----BEGIN")
        and raw_lines[-1].strip().startswith("-----END")
    ):
        header = raw_lines[0].strip()
        footer = raw_lines[-1].strip()

        # Restore spaces converted from '+' inside Base64 body
        body_lines = [line.replace(" ", "+").strip() for line in raw_lines[1:-1]]

        return "\n".join([header] + body_lines + [footer]) + "\n"

    return pem_str


def deserialize_public_key(pem_str: str) -> ec.EllipticCurvePublicKey:
    """
    Deserializes a PEM formatted string into an ECC public key object.
    """
    try:
        clean_pem = sanitize_pem(pem_str)
        public_key = serialization.load_pem_public_key(clean_pem.encode('utf-8'))
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ECCError("Loaded key is not a valid ECC public key.")
        return public_key
    except Exception as e:
        raise ECCError(f"Invalid public key PEM: {str(e)}") from e


def serialize_private_key(private_key: ec.EllipticCurvePrivateKey) -> str:
    """
    Serializes an ECC private key to a PEM formatted string (unencrypted PKCS8).
    """
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem_bytes.decode('utf-8')


def deserialize_private_key(pem_str: str) -> ec.EllipticCurvePrivateKey:
    """
    Deserializes a PEM formatted string into an ECC private key object.
    """
    try:
        clean_pem = sanitize_pem(pem_str)
        private_key = serialization.load_pem_private_key(clean_pem.encode('utf-8'), password=None)
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ECCError("Loaded key is not a valid ECC private key.")
        return private_key
    except Exception as e:
        raise ECCError(f"Invalid private key PEM: {str(e)}") from e


def derive_kek(private_key: ec.EllipticCurvePrivateKey, peer_public_key: ec.EllipticCurvePublicKey) -> bytes:
    """
    Derives a 256-bit Key Encryption Key (KEK) using ECDH shared secret + HKDF-SHA256.

    Args:
        private_key: Local ECC private key.
        peer_public_key: Peer/remote ECC public key.

    Returns:
        bytes: 32-byte (256-bit) KEK.
    """
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEK_SIZE_BYTES,
        salt=None,
        info=HKDF_INFO,
    )
    kek = hkdf.derive(shared_secret)
    return kek


def wrap_aes_key(file_aes_key: bytes, recipient_public_key: ec.EllipticCurvePublicKey) -> Dict[str, str]:
    """
    Wraps a dynamic file AES-256 key using ECC (ECDH + HKDF-SHA256 + AES-256-GCM key wrapping).

    Args:
        file_aes_key (bytes): 32-byte AES key used for file encryption.
        recipient_public_key (ec.EllipticCurvePublicKey): Recipient's ECC public key.

    Returns:
        Dict[str, str]: Protected key metadata dictionary:
            - ephemeral_public_key_pem: Serialized ephemeral ECC public key
            - kek_nonce: Hex-encoded 12-byte nonce used with KEK
            - wrapped_aes_key: Hex-encoded encrypted file AES key + tag
    """
    try:
        # 1. Generate fresh ephemeral ECC key pair
        ephemeral_private_key, ephemeral_public_key = generate_ecc_key_pair()

        # 2. Perform ECDH to derive shared secret and HKDF-SHA256 to derive KEK
        kek = derive_kek(ephemeral_private_key, recipient_public_key)

        # 3. Generate random 12-byte KEK nonce and encrypt file AES key with AES-GCM
        kek_nonce = os.urandom(KEK_NONCE_SIZE_BYTES)
        aesgcm_kek = AESGCM(kek)
        wrapped_payload = aesgcm_kek.encrypt(kek_nonce, file_aes_key, None)

        return {
            "ephemeral_public_key_pem": serialize_public_key(ephemeral_public_key),
            "kek_nonce": kek_nonce.hex(),
            "wrapped_aes_key": wrapped_payload.hex()
        }
    except Exception as e:
        raise ECCError(f"Failed to wrap AES key: {str(e)}") from e


def unwrap_aes_key(wrapped_bundle: Dict[str, str], recipient_private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """
    Unwraps a protected file AES-256 key using the recipient's ECC private key.

    Args:
        wrapped_bundle (Dict[str, str]): Dictionary containing ephemeral_public_key_pem, kek_nonce, wrapped_aes_key.
        recipient_private_key (ec.EllipticCurvePrivateKey): Authorized recipient ECC private key.

    Returns:
        bytes: Recovered original 32-byte file AES key.

    Raises:
        ECCError: If key recovery fails or authentication fails (wrong key or tampered data).
    """
    try:
        ephemeral_pub_pem = wrapped_bundle["ephemeral_public_key_pem"]
        kek_nonce = bytes.fromhex(wrapped_bundle["kek_nonce"])
        wrapped_payload = bytes.fromhex(wrapped_bundle["wrapped_aes_key"])

        ephemeral_public_key = deserialize_public_key(ephemeral_pub_pem)

        # Re-derive KEK using recipient private key + ephemeral public key
        kek = derive_kek(recipient_private_key, ephemeral_public_key)

        # Decrypt file AES key using KEK
        aesgcm_kek = AESGCM(kek)
        file_aes_key = aesgcm_kek.decrypt(kek_nonce, wrapped_payload, None)
        return file_aes_key
    except InvalidTag as e:
        raise ECCError("Key unwrap failed: Authentication tag invalid. Wrong private key or tampered key bundle.") from e
    except Exception as e:
        if isinstance(e, ECCError):
            raise
        raise ECCError(f"Key unwrap failed: {str(e)}") from e
