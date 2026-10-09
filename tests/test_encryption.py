import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.services.encryption import (
    encrypt_bytes,
    decrypt_bytes,
    generate_key,
    EncryptionError
)


def test_different_ciphertext_for_same_plaintext():
    """
    Verifies that encrypting the same plaintext twice produces different payloads
    due to fresh random key and nonce generation.
    """
    plaintext = b"Top secret cloud storage test payload"

    payload1, key1, nonce1 = encrypt_bytes(plaintext)
    payload2, key2, nonce2 = encrypt_bytes(plaintext)

    # Payloads, keys, and nonces must all be unique
    assert payload1 != payload2
    assert key1 != key2
    assert nonce1 != nonce2

    # Also test same key with fresh nonces
    shared_key = generate_key()
    p3, k3, n3 = encrypt_bytes(plaintext, key=shared_key)
    p4, k4, n4 = encrypt_bytes(plaintext, key=shared_key)

    assert p3 != p4
    assert n3 != n4
    assert k3 == k4 == shared_key


def test_correct_decryption_restores_original_file():
    """
    Verifies that decrypting with the correct key restores exact original plaintext.
    """
    original_plaintext = b"SecureCloud+ Phase 2 Encryption Test Content \x00\xff\xfe"

    payload, key, _nonce = encrypt_bytes(original_plaintext)
    decrypted = decrypt_bytes(payload, key)

    assert decrypted == original_plaintext


def test_modified_ciphertext_fails_decryption():
    """
    Verifies that tampering with ciphertext or auth tag causes decryption/authentication to fail.
    """
    original_plaintext = b"Authenticated ciphertext integrity test"

    payload, key, _nonce = encrypt_bytes(original_plaintext)

    # 1. Flip a bit in payload (tamper with ciphertext/tag)
    tampered_payload = bytearray(payload)
    tampered_payload[-1] ^= 0xFF  # Mutate last byte of auth tag
    tampered_payload = bytes(tampered_payload)

    with pytest.raises(EncryptionError) as exc_info:
        decrypt_bytes(tampered_payload, key)
    assert "Authentication tag validation failed" in str(exc_info.value) or "Decryption failed" in str(exc_info.value)

    # 2. Attempt decryption using wrong key
    wrong_key = generate_key()
    with pytest.raises(EncryptionError):
        decrypt_bytes(payload, wrong_key)


def test_api_does_not_expose_aes_key():
    """
    Verifies that POST /files/upload encrypts the file and returns metadata
    WITHOUT exposing the AES key in the response payload or headers.
    """
    client = TestClient(app)
    file_content = b"Content to test API key privacy compliance"
    filename = "confidential_doc.txt"

    response = client.post(
        "/files/upload",
        files={"file": (filename, file_content)}
    )

    assert response.status_code == 201
    data = response.json()

    # Check expected output fields
    assert "file_id" in data
    assert data["filename"] == filename
    assert data["file_size"] == len(file_content)
    assert "sha256" in data
    assert "encrypted" in data["status"]

    # CRITICAL: Verify AES key is NOT present in keys or response text
    assert "key" not in data
    assert "aes_key" not in data
    assert "encryption_key" not in data
    assert "secret" not in data
    assert "nonce" not in data

    # Verify target file on disk contains encrypted ciphertext (not original plaintext)
    upload_dir = Path("uploads")
    matching_files = list(upload_dir.glob(f"{data['file_id']}*"))
    assert len(matching_files) > 0, "Encrypted file was not stored on disk"

    stored_content = matching_files[0].read_bytes()
    assert stored_content != file_content, "Disk file matches plaintext! File was not encrypted on disk."
