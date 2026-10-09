import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import ec

from app.main import app
from app.services.encryption import generate_key, encrypt_bytes, decrypt_bytes
from app.services.ecc import (
    generate_ecc_key_pair,
    serialize_public_key,
    deserialize_public_key,
    serialize_private_key,
    deserialize_private_key,
    wrap_aes_key,
    unwrap_aes_key,
    ECCError
)


def test_ecc_key_generation():
    """
    Verifies that ECC key pair generation, serialization, and deserialization work correctly.
    """
    private_key, public_key = generate_ecc_key_pair()

    assert isinstance(private_key, ec.EllipticCurvePrivateKey)
    assert isinstance(public_key, ec.EllipticCurvePublicKey)

    pub_pem = serialize_public_key(public_key)
    priv_pem = serialize_private_key(private_key)

    assert "BEGIN PUBLIC KEY" in pub_pem
    assert "BEGIN PRIVATE KEY" in priv_pem

    reloaded_pub = deserialize_public_key(pub_pem)
    reloaded_priv = deserialize_private_key(priv_pem)

    assert isinstance(reloaded_pub, ec.EllipticCurvePublicKey)
    assert isinstance(reloaded_priv, ec.EllipticCurvePrivateKey)


def test_two_operations_produce_different_protected_keys():
    """
    Verifies that wrapping the exact same AES key twice produces distinct protected key bundles
    due to fresh ephemeral ECC key pairs and fresh KEK nonces.
    """
    file_aes_key = generate_key()
    _, recipient_pub = generate_ecc_key_pair()

    bundle1 = wrap_aes_key(file_aes_key, recipient_pub)
    bundle2 = wrap_aes_key(file_aes_key, recipient_pub)

    assert bundle1["ephemeral_public_key_pem"] != bundle2["ephemeral_public_key_pem"]
    assert bundle1["kek_nonce"] != bundle2["kek_nonce"]
    assert bundle1["wrapped_aes_key"] != bundle2["wrapped_aes_key"]


def test_protected_aes_key_recovery_with_correct_private_key():
    """
    Verifies that the protected AES key can be successfully unwrapped with the correct recipient private key,
    and that the recovered AES key decrypts the file payload cleanly.
    """
    original_plaintext = b"Payload protected with dynamic AES-256 and ECC ECDH key wrapping"
    
    # 1. Encrypt file with dynamic AES key
    payload, original_file_aes_key, _nonce = encrypt_bytes(original_plaintext)

    # 2. Wrap AES key for recipient
    recipient_priv, recipient_pub = generate_ecc_key_pair()
    wrapped_bundle = wrap_aes_key(original_file_aes_key, recipient_pub)

    # 3. Recover AES key using recipient private key
    recovered_file_aes_key = unwrap_aes_key(wrapped_bundle, recipient_priv)

    assert recovered_file_aes_key == original_file_aes_key

    # 4. Decrypt original payload with recovered AES key
    decrypted_content = decrypt_bytes(payload, recovered_file_aes_key)
    assert decrypted_content == original_plaintext


def test_recovery_fails_with_incorrect_private_key():
    """
    Verifies that attempting to unwrap a protected AES key using an unauthorized private key raises an ECCError.
    """
    file_aes_key = generate_key()
    _, recipient_pub = generate_ecc_key_pair()
    wrong_priv, _ = generate_ecc_key_pair()

    wrapped_bundle = wrap_aes_key(file_aes_key, recipient_pub)

    with pytest.raises(ECCError) as exc_info:
        unwrap_aes_key(wrapped_bundle, wrong_priv)

    assert "Key unwrap failed" in str(exc_info.value)


def test_api_does_not_expose_plaintext_aes_or_private_ecc_keys():
    """
    Verifies that POST /files/upload returns protected key metadata (ephemeral pub key, nonce, wrapped key)
    WITHOUT exposing the plaintext file AES key or any ECC private key.
    """
    client = TestClient(app)
    file_content = b"Confidential file payload for Phase 3 API test"
    filename = "ecc_protected.txt"

    _, recipient_pub = generate_ecc_key_pair()
    recipient_pub_pem = serialize_public_key(recipient_pub)

    response = client.post(
        "/files/upload",
        data={"recipient_public_key_pem": recipient_pub_pem},
        files={"file": (filename, file_content)}
    )

    assert response.status_code == 201
    data = response.json()

    assert "ecc_protected" in data["status"]
    assert "protected_key" in data

    protected_key = data["protected_key"]
    assert "ephemeral_public_key_pem" in protected_key
    assert "kek_nonce" in protected_key
    assert "wrapped_aes_key" in protected_key

    # CRITICAL: Verify PLAINTEXT AES key and PRIVATE ECC key are NEVER returned
    response_text = response.text
    assert "PRIVATE KEY" not in response_text
    assert "file_aes_key" not in data
    assert "plaintext_key" not in data
    assert "aes_key" not in data


def test_pem_sanitization_normal_and_query_corrupted():
    """
    Verifies that sanitize_pem handles normal PEM, literal \\n, CRLF, and spaces replacing '+' in Base64 body.
    """
    priv, pub = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub)
    priv_pem = serialize_private_key(priv)

    # 1. Normal PEM remains valid
    pub_deserialized = deserialize_public_key(pub_pem)
    priv_deserialized = deserialize_private_key(priv_pem)
    assert isinstance(pub_deserialized, ec.EllipticCurvePublicKey)
    assert isinstance(priv_deserialized, ec.EllipticCurvePrivateKey)

    # 2. Literal \\n and CRLF formatting
    pub_pem_literal = pub_pem.replace("\n", "\\n")
    priv_pem_crlf = priv_pem.replace("\n", "\r\n")

    assert isinstance(deserialize_public_key(pub_pem_literal), ec.EllipticCurvePublicKey)
    assert isinstance(deserialize_private_key(priv_pem_crlf), ec.EllipticCurvePrivateKey)

    # 3. Spaces replacing '+' in Base64 body (URL query unescaping simulation)
    priv_pem_spaces = priv_pem.replace("+", " ")
    pub_pem_spaces = pub_pem.replace("+", " ")

    clean_priv = deserialize_private_key(priv_pem_spaces)
    clean_pub = deserialize_public_key(pub_pem_spaces)

    assert isinstance(clean_priv, ec.EllipticCurvePrivateKey)
    assert isinstance(clean_pub, ec.EllipticCurvePublicKey)

    # 4. Functional wrap and unwrap using sanitized keys
    aes_key = generate_key()
    bundle = wrap_aes_key(aes_key, clean_pub)
    unwrapped = unwrap_aes_key(bundle, clean_priv)

    assert unwrapped == aes_key

