import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.services.hashing import calculate_sha256_bytes
from app.services.ecc import generate_ecc_key_pair, serialize_public_key, serialize_private_key
from app.services.blockchain import blockchain_service
from app.storage.file_storage import storage_manager

client = TestClient(app)


def test_1_upload_file_successfully():
    """
    TEST 1: Upload a file successfully via POST /files/upload and obtain response metadata.
    """
    file_content = b"Phase 5 Complete Integration Test Payload - Confidential Data 2026"
    filename = "phase5_test_doc.txt"

    response = client.post(
        "/files/upload",
        files={"file": (filename, file_content)}
    )

    assert response.status_code == 201
    data = response.json()

    assert "file_id" in data
    assert data["filename"] == filename
    assert data["file_size"] == len(file_content)
    assert data["sha256"] == calculate_sha256_bytes(file_content)
    assert "status" in data
    assert "protected_key" in data
    assert "blockchain_tx_hash" in data
    assert data["blockchain_tx_hash"] is not None


def test_2_verify_encrypted_file_exists_on_disk():
    """
    TEST 2: Upload a file and verify that the encrypted payload file exists on disk inside uploads/.
    """
    file_content = b"Disk storage verification binary data payload"
    filename = "disk_check.bin"

    response = client.post("/files/upload", files={"file": (filename, file_content)})
    assert response.status_code == 201
    data = response.json()
    file_id = data["file_id"]

    encrypted_path = storage_manager.get_encrypted_file_path(file_id)
    assert encrypted_path is not None
    assert encrypted_path.exists()
    assert encrypted_path.stat().st_size > 0

    # Ensure the content stored on disk is encrypted ciphertext, NOT plaintext
    stored_bytes = encrypted_path.read_bytes()
    assert stored_bytes != file_content


def test_3_verify_blockchain_metadata_exists():
    """
    TEST 3: Verify that on-chain metadata record exists in the FileKeyManager smart contract.
    """
    file_content = b"Blockchain record verification string"
    filename = "onchain_verify.txt"

    response = client.post("/files/upload", files={"file": (filename, file_content)})
    assert response.status_code == 201
    data = response.json()
    file_id = data["file_id"]

    # Query smart contract via blockchain_service
    onchain_record = blockchain_service.get_file_from_chain(file_id)

    assert onchain_record["file_id"] == file_id
    assert onchain_record["file_hash"] == calculate_sha256_bytes(file_content)
    assert "ephemeral_public_key_pem" in onchain_record
    assert "kek_nonce" in onchain_record
    assert "wrapped_aes_key" in onchain_record
    assert onchain_record["owner"].startswith("0x")


def test_4_download_and_decrypt_file_successfully():
    """
    TEST 4: Download and decrypt the file successfully via GET /files/{file_id}/download.
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    file_content = b"End-to-end encryption and decryption test payload"
    filename = "download_test.txt"

    # Upload with explicit recipient public key
    upload_res = client.post(
        "/files/upload",
        data={"recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    assert upload_res.status_code == 201
    file_id = upload_res.json()["file_id"]

    # Download passing recipient private key
    download_res = client.get(
        f"/files/{file_id}/download",
        params={"recipient_private_key_pem": priv_pem}
    )

    assert download_res.status_code == 200
    assert download_res.content == file_content


def test_5_verify_decrypted_file_is_identical_to_original():
    """
    TEST 5: Verify decrypted file payload matches original plaintext byte-for-byte.
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    file_content = bytes(range(256))  # Test full binary byte range 0x00-0xFF
    filename = "binary_exact_match.dat"

    upload_res = client.post(
        "/files/upload",
        data={"recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    assert upload_res.status_code == 201
    data = upload_res.json()
    file_id = data["file_id"]

    download_res = client.get(
        f"/files/{file_id}/download",
        params={"recipient_private_key_pem": priv_pem}
    )

    assert download_res.status_code == 200
    assert download_res.content == file_content
    assert len(download_res.content) == len(file_content)


def test_6_verify_sha256_integrity_check_passes():
    """
    TEST 6: Verify that recalculating SHA-256 on decrypted file matches stored hash.
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    file_content = b"Integrity check payload string for SHA-256 verification"
    filename = "sha256_check.txt"

    original_sha256 = calculate_sha256_bytes(file_content)

    upload_res = client.post(
        "/files/upload",
        data={"recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    assert upload_res.status_code == 201
    data = upload_res.json()
    assert data["sha256"] == original_sha256

    file_id = data["file_id"]

    download_res = client.get(
        f"/files/{file_id}/download",
        params={"recipient_private_key_pem": priv_pem}
    )

    assert download_res.status_code == 200
    decrypted_content = download_res.content
    recalculated_sha256 = calculate_sha256_bytes(decrypted_content)

    assert recalculated_sha256 == original_sha256
    assert download_res.headers.get("X-SHA256-Checksum") == original_sha256


def test_7_modified_encrypted_file_fails_decryption():
    """
    TEST 7: Modify the encrypted file on disk and verify that AES-GCM decryption/authentication fails.
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    file_content = b"File content to be tampered on disk"
    filename = "tamper_target.txt"

    upload_res = client.post(
        "/files/upload",
        data={"recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    assert upload_res.status_code == 201
    data = upload_res.json()
    file_id = data["file_id"]

    # Locate encrypted file path and tamper with bytes
    enc_path = storage_manager.get_encrypted_file_path(file_id)
    assert enc_path is not None and enc_path.exists()

    original_enc_bytes = bytearray(enc_path.read_bytes())
    original_enc_bytes[-1] ^= 0xFF  # Corrupt auth tag byte
    enc_path.write_bytes(bytes(original_enc_bytes))

    # Attempt download -> must fail with HTTP 400 Bad Request
    download_res = client.get(
        f"/files/{file_id}/download",
        params={"recipient_private_key_pem": priv_pem}
    )

    assert download_res.status_code == 400
    assert "Decryption or authentication failed" in download_res.json()["detail"]


def test_8_verify_plaintext_keys_not_exposed_in_api_or_logs():
    """
    TEST 8: Verify that plaintext AES keys and ECC private keys are NOT exposed in API responses.
    """
    file_content = b"Privacy compliance audit payload"
    filename = "privacy_audit.txt"

    upload_res = client.post("/files/upload", files={"file": (filename, file_content)})
    assert upload_res.status_code == 201

    data = upload_res.json()
    response_text = upload_res.text

    # Verify standard output format
    assert "file_id" in data
    assert "protected_key" in data

    # Verify recipient_private_key_pem is absent
    assert "recipient_private_key_pem" not in data
    assert "auto_recipient_private_key_pem" not in data

    # Verify PLAINTEXT file AES key is absent
    assert "file_aes_key" not in data
    assert "plaintext_key" not in data
    assert "aes_key" not in data

    # Verify ECC private key is NOT in protected_key structure or response
    protected_key = data["protected_key"]
    assert "private_key" not in protected_key
    assert "PRIVATE KEY" not in response_text


def test_9_upload_same_plaintext_twice_produces_different_ciphertext():
    """
    TEST 9: Upload the exact same plaintext file twice and verify that encryption outputs
    (file_ids, nonces, wrapped keys, ciphertexts) are different because fresh dynamic keys/nonces are used.
    """
    file_content = b"Identical plaintext content uploaded twice for randomness verification"
    filename = "duplicate_content.txt"

    res1 = client.post("/files/upload", files={"file": (filename, file_content)})
    res2 = client.post("/files/upload", files={"file": (filename, file_content)})

    assert res1.status_code == 201
    assert res2.status_code == 201

    data1 = res1.json()
    data2 = res2.json()

    # Same original SHA-256 digest and file size
    assert data1["sha256"] == data2["sha256"]
    assert data1["file_size"] == data2["file_size"]

    # File IDs and transaction hashes must be unique
    assert data1["file_id"] != data2["file_id"]
    assert data1["blockchain_tx_hash"] != data2["blockchain_tx_hash"]

    # Protected key bundles must be unique (fresh ephemeral key + fresh KEK nonce)
    pk1 = data1["protected_key"]
    pk2 = data2["protected_key"]

    assert pk1["ephemeral_public_key_pem"] != pk2["ephemeral_public_key_pem"]
    assert pk1["kek_nonce"] != pk2["kek_nonce"]
    assert pk1["wrapped_aes_key"] != pk2["wrapped_aes_key"]

    # On-disk stored encrypted binary ciphertexts must be unique
    path1 = storage_manager.get_encrypted_file_path(data1["file_id"])
    path2 = storage_manager.get_encrypted_file_path(data2["file_id"])

    assert path1.read_bytes() != path2.read_bytes()


def test_10_verify_ecc_private_key_never_exposed_or_stored(caplog):
    """
    TEST 10: Verify security requirements:
    - upload response does NOT contain recipient_private_key_pem
    - file metadata does NOT contain auto_recipient_private_key_pem
    - blockchain does NOT contain ECC private key
    - logs do NOT expose ECC private key
    """
    import json
    file_content = b"Security audit payload for ECC private key non-exposure"
    filename = "security_audit.txt"

    response = client.post("/files/upload", files={"file": (filename, file_content)})
    assert response.status_code == 201

    data = response.json()
    response_text = response.text

    # 1. Upload response does NOT contain recipient_private_key_pem
    assert "recipient_private_key_pem" not in data
    assert "auto_recipient_private_key_pem" not in data
    assert "PRIVATE KEY" not in response_text

    # 2. File metadata sidecar does NOT contain auto_recipient_private_key_pem
    file_id = data["file_id"]
    meta = storage_manager.read_file_metadata(file_id) or {}
    assert "auto_recipient_private_key_pem" not in meta
    assert "auto_recipient_private_key_pem" not in meta.get("protected_key", {})
    assert "PRIVATE KEY" not in json.dumps(meta)

    # 3. Blockchain does NOT contain ECC private key
    onchain_record = blockchain_service.get_file_from_chain(file_id)
    assert "PRIVATE KEY" not in str(onchain_record)

    # 4. Logs do NOT expose ECC private key
    assert "PRIVATE KEY" not in caplog.text

