import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.services.hashing import calculate_sha256_bytes
from app.services.ecc import generate_ecc_key_pair, serialize_public_key, serialize_private_key
from app.services.blockchain import blockchain_service
from app.storage.file_storage import storage_manager

client = TestClient(app)


def test_1_user_with_download_permission_can_download_before_revocation():
    """
    TEST 1: Verify that a user granted DOWNLOAD permission can download and decrypt the file BEFORE revocation.
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    owner_id = "alice_owner_8"
    target_user_id = "bob_grantee_8"
    file_content = b"Content shared with Bob before key revocation"
    filename = "shared_pre_revocation.txt"

    # Upload as Alice
    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id, "recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    assert upload_res.status_code == 201
    file_id = upload_res.json()["file_id"]

    # Alice grants DOWNLOAD permission to Bob
    client.post(
        f"/files/{file_id}/access",
        json={"target_user_id": target_user_id, "permission": "DOWNLOAD", "requesting_user_id": owner_id}
    )

    # Bob downloads file successfully
    download_res = client.get(
        f"/files/{file_id}/download",
        params={"user_id": target_user_id, "recipient_private_key_pem": priv_pem}
    )
    assert download_res.status_code == 200
    assert download_res.content == file_content


def test_2_owner_successfully_revokes_user():
    """
    TEST 2: Verify that file owner successfully revokes user access via POST /files/{file_id}/revoke/{user_id} using owner's ECC private key.
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    owner_id = "alice_owner_8"
    target_user_id = "bob_grantee_8"
    file_content = b"Content for revocation execution test"
    filename = "revoke_test.txt"

    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id, "recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    file_id = upload_res.json()["file_id"]

    client.post(
        f"/files/{file_id}/access",
        json={"target_user_id": target_user_id, "permission": "DOWNLOAD", "requesting_user_id": owner_id}
    )

    # Alice revokes Bob using owner_private_key_pem
    revoke_res = client.post(
        f"/files/{file_id}/revoke/{target_user_id}",
        data={"requesting_user_id": owner_id, "owner_private_key_pem": priv_pem}
    )

    assert revoke_res.status_code == 200
    data = revoke_res.json()

    assert data["file_id"] == file_id
    assert data["revoked_user_id"] == target_user_id
    assert data["new_version"] == 2
    assert data["status"] == "revoked"
    assert "transaction_hash" in data
    assert data["transaction_hash"] is not None


def test_3_revoked_user_receives_http_403():
    """
    TEST 3: Verify that after revocation, the revoked user receives HTTP 403 Forbidden on download attempts.
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    owner_id = "alice_owner_8"
    target_user_id = "bob_grantee_8"
    file_content = b"Content for 403 rejection test"
    filename = "rejection_test.txt"

    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id, "recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    file_id = upload_res.json()["file_id"]

    client.post(f"/files/{file_id}/access", json={"target_user_id": target_user_id, "permission": "DOWNLOAD", "requesting_user_id": owner_id})
    client.post(f"/files/{file_id}/revoke/{target_user_id}", data={"requesting_user_id": owner_id, "owner_private_key_pem": priv_pem})

    # Bob attempts download post-revocation
    res = client.get(f"/files/{file_id}/download", params={"user_id": target_user_id, "recipient_private_key_pem": priv_pem})

    assert res.status_code == 403
    assert "Access Denied" in res.json()["detail"]


def test_4_revoked_user_cannot_reach_key_recovery_or_decryption():
    """
    TEST 4: Verify that a revoked user is blocked at the pre-decryption hook before unwrap_aes_key or decrypt_bytes.
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    owner_id = "alice_owner_8"
    target_user_id = "bob_grantee_8"
    file_content = b"Pre-decryption isolation test post-revocation"
    filename = "isolation_post_revoke.txt"

    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id, "recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    file_id = upload_res.json()["file_id"]

    client.post(f"/files/{file_id}/access", json={"target_user_id": target_user_id, "permission": "DOWNLOAD", "requesting_user_id": owner_id})
    client.post(f"/files/{file_id}/revoke/{target_user_id}", data={"requesting_user_id": owner_id, "owner_private_key_pem": priv_pem})

    with patch("app.routes.files.unwrap_aes_key") as mock_unwrap, \
         patch("app.routes.files.decrypt_bytes") as mock_decrypt:

        mock_unwrap.side_effect = AssertionError("unwrap_aes_key must NOT be called for revoked users!")
        mock_decrypt.side_effect = AssertionError("decrypt_bytes must NOT be called for revoked users!")

        download_res = client.get(f"/files/{file_id}/download", params={"user_id": target_user_id, "recipient_private_key_pem": priv_pem})

        assert download_res.status_code == 403
        mock_unwrap.assert_not_called()
        mock_decrypt.assert_not_called()


def test_5_aes_key_changes_after_rotation():
    """
    TEST 5: Verify that the stored ciphertext on disk is re-encrypted with a fresh dynamic AES key upon rotation.
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    owner_id = "alice_owner_8"
    target_user_id = "bob_grantee_8"
    file_content = b"Payload to check dynamic ciphertext mutation upon rotation"
    filename = "key_change_test.txt"

    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id, "recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    file_id = upload_res.json()["file_id"]

    client.post(f"/files/{file_id}/access", json={"target_user_id": target_user_id, "permission": "DOWNLOAD", "requesting_user_id": owner_id})

    # Record stored ciphertext before rotation
    path_v1 = storage_manager.get_encrypted_file_path(file_id)
    ciphertext_v1 = path_v1.read_bytes()

    # Execute key rotation via revocation
    client.post(f"/files/{file_id}/revoke/{target_user_id}", data={"requesting_user_id": owner_id, "owner_private_key_pem": priv_pem})

    # Record stored ciphertext after rotation
    path_v2 = storage_manager.get_encrypted_file_path(file_id)
    ciphertext_v2 = path_v2.read_bytes()

    # Ciphertexts MUST be different due to fresh AES-256 key & fresh nonce
    assert ciphertext_v1 != ciphertext_v2


def test_6_file_version_changes_from_1_to_2():
    """
    TEST 6: Verify that file version increments from 1 (initial upload) to 2 (after key rotation).
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    owner_id = "alice_owner_8"
    target_user_id = "bob_grantee_8"
    file_content = b"Version incrementing test payload"
    filename = "version_test.txt"

    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id, "recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    assert upload_res.json()["version"] == 1
    file_id = upload_res.json()["file_id"]

    client.post(f"/files/{file_id}/access", json={"target_user_id": target_user_id, "permission": "DOWNLOAD", "requesting_user_id": owner_id})

    revoke_res = client.post(f"/files/{file_id}/revoke/{target_user_id}", data={"requesting_user_id": owner_id, "owner_private_key_pem": priv_pem})
    assert revoke_res.status_code == 200
    assert revoke_res.json()["new_version"] == 2

    meta = storage_manager.read_file_metadata(file_id)
    assert meta["version"] == 2


def test_7_owner_can_still_download_after_rotation():
    """
    TEST 7: Verify that the file owner can download and decrypt the re-encrypted cloud file after key rotation.
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    owner_id = "alice_owner_8"
    target_user_id = "bob_grantee_8"
    file_content = b"Owner post-rotation file recovery verification string"
    filename = "owner_post_rotate.txt"

    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id, "recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    file_id = upload_res.json()["file_id"]

    client.post(f"/files/{file_id}/access", json={"target_user_id": target_user_id, "permission": "DOWNLOAD", "requesting_user_id": owner_id})
    client.post(f"/files/{file_id}/revoke/{target_user_id}", data={"requesting_user_id": owner_id, "owner_private_key_pem": priv_pem})

    # Owner Alice downloads post-rotation
    download_res = client.get(f"/files/{file_id}/download", params={"user_id": owner_id, "recipient_private_key_pem": priv_pem})

    assert download_res.status_code == 200
    assert download_res.content == file_content
    assert download_res.headers.get("X-File-Version") == "2"


def test_8_remaining_authorized_user_can_still_download_after_rotation():
    """
    TEST 8: Verify that remaining authorized users (e.g. Carol) can still download after Bob is revoked.
    """
    alice_priv, alice_pub = generate_ecc_key_pair()
    alice_pub_pem = serialize_public_key(alice_pub)
    alice_priv_pem = serialize_private_key(alice_priv)

    carol_priv, carol_pub = generate_ecc_key_pair()
    carol_pub_pem = serialize_public_key(carol_pub)
    carol_priv_pem = serialize_private_key(carol_priv)

    bob_priv, bob_pub = generate_ecc_key_pair()
    bob_priv_pem = serialize_private_key(bob_priv)

    owner_id = "alice_owner_8"
    revoked_user_id = "bob_revoked"
    active_grantee_id = "carol_active"
    file_content = b"Multi-grantee rotation payload for Carol"
    filename = "multi_grantee.txt"

    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id, "recipient_public_key_pem": alice_pub_pem},
        files={"file": (filename, file_content)}
    )
    file_id = upload_res.json()["file_id"]

    # Grant access to Bob and Carol (passing Carol's public key)
    client.post(f"/files/{file_id}/access", json={"target_user_id": revoked_user_id, "permission": "DOWNLOAD", "requesting_user_id": owner_id})
    client.post(f"/files/{file_id}/access", json={"target_user_id": active_grantee_id, "permission": "DOWNLOAD", "requesting_user_id": owner_id, "public_key_pem": carol_pub_pem})

    # Revoke Bob using Alice's private key
    client.post(f"/files/{file_id}/revoke/{revoked_user_id}", data={"requesting_user_id": owner_id, "owner_private_key_pem": alice_priv_pem})

    # Carol can still download post-rotation using her private key
    carol_res = client.get(f"/files/{file_id}/download", params={"user_id": active_grantee_id, "recipient_private_key_pem": carol_priv_pem})
    assert carol_res.status_code == 200
    assert carol_res.content == file_content

    # Bob receives 403 Forbidden
    bob_res = client.get(f"/files/{file_id}/download", params={"user_id": revoked_user_id, "recipient_private_key_pem": bob_priv_pem})
    assert bob_res.status_code == 403


def test_9_blockchain_contains_access_revoked_event():
    """
    TEST 9: Verify that on-chain smart contract state records the AccessRevoked transaction and version update.
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    owner_id = "alice_owner_8"
    revoked_user_id = "bob_revoked"
    file_content = b"Blockchain AccessRevoked transaction audit string"
    filename = "bc_revoke_audit.txt"

    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id, "recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    file_id = upload_res.json()["file_id"]

    client.post(f"/files/{file_id}/access", json={"target_user_id": revoked_user_id, "permission": "DOWNLOAD", "requesting_user_id": owner_id})

    revoke_res = client.post(f"/files/{file_id}/revoke/{revoked_user_id}", data={"requesting_user_id": owner_id, "owner_private_key_pem": priv_pem})
    tx_hash = revoke_res.json()["transaction_hash"]

    assert tx_hash is not None
    assert len(tx_hash) > 0

    # Query contract state
    onchain_record = blockchain_service.get_file_from_chain(file_id)
    assert onchain_record["version"] == 2


def test_10_tampering_with_newly_encrypted_file_causes_integrity_failure():
    """
    TEST 10: Verify that modifying the newly rotated ciphertext on disk causes AES-GCM authentication/decryption to fail.
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    owner_id = "alice_owner_8"
    revoked_user_id = "bob_revoked"
    file_content = b"Content to test tamper detection on rotated ciphertext"
    filename = "tamper_rotated.txt"

    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id, "recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    file_id = upload_res.json()["file_id"]

    client.post(f"/files/{file_id}/access", json={"target_user_id": revoked_user_id, "permission": "DOWNLOAD", "requesting_user_id": owner_id})
    client.post(f"/files/{file_id}/revoke/{revoked_user_id}", data={"requesting_user_id": owner_id, "owner_private_key_pem": priv_pem})

    # Tamper with rotated ciphertext file on disk
    enc_path = storage_manager.get_encrypted_file_path(file_id)
    raw = bytearray(enc_path.read_bytes())
    raw[-1] ^= 0xFF
    enc_path.write_bytes(bytes(raw))

    # Owner attempt download -> fails with 400 Bad Request
    res = client.get(f"/files/{file_id}/download", params={"user_id": owner_id, "recipient_private_key_pem": priv_pem})
    assert res.status_code == 400
    assert "Decryption or authentication failed" in res.json()["detail"]


def test_11_plaintext_aes_and_ecc_private_keys_never_exposed():
    """
    TEST 11: Verify that plaintext AES keys and ECC private keys are NOT exposed in revoke API output or sidecars.
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    owner_id = "alice_owner_8"
    revoked_user_id = "bob_revoked"
    file_content = b"Privacy audit for Phase 8 revocation output"
    filename = "privacy_phase8.txt"

    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id, "recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    file_id = upload_res.json()["file_id"]

    client.post(f"/files/{file_id}/access", json={"target_user_id": revoked_user_id, "permission": "DOWNLOAD", "requesting_user_id": owner_id})

    revoke_res = client.post(f"/files/{file_id}/revoke/{revoked_user_id}", data={"requesting_user_id": owner_id, "owner_private_key_pem": priv_pem})
    assert revoke_res.status_code == 200

    data = revoke_res.json()
    text = revoke_res.text

    assert "file_id" in data
    assert "new_version" in data
    assert "transaction_hash" in data

    # Verify key secrecy
    assert "file_aes_key" not in data
    assert "plaintext_key" not in data
    assert "PRIVATE KEY" not in text


def test_12_wrong_owner_private_key_fails():
    """
    TEST 12: Verify that providing an invalid/wrong owner private key during revocation returns HTTP 400 Bad Request.
    """
    alice_priv, alice_pub = generate_ecc_key_pair()
    alice_pub_pem = serialize_public_key(alice_pub)
    
    wrong_priv, _ = generate_ecc_key_pair()
    wrong_priv_pem = serialize_private_key(wrong_priv)

    owner_id = "alice_owner_8"
    target_user_id = "bob_grantee_8"

    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id, "recipient_public_key_pem": alice_pub_pem},
        files={"file": ("wrong_key_test.txt", b"Wrong key test content")}
    )
    file_id = upload_res.json()["file_id"]

    client.post(f"/files/{file_id}/access", json={"target_user_id": target_user_id, "permission": "DOWNLOAD", "requesting_user_id": owner_id})

    revoke_res = client.post(
        f"/files/{file_id}/revoke/{target_user_id}",
        data={"requesting_user_id": owner_id, "owner_private_key_pem": wrong_priv_pem}
    )

    assert revoke_res.status_code == 400
    assert "Invalid or incorrect owner private key" in revoke_res.json()["detail"]


def test_13_unauthorized_user_cannot_perform_revocation():
    """
    TEST 13: Verify that a non-owner user attempting revocation receives HTTP 403 Forbidden.
    """
    alice_priv, alice_pub = generate_ecc_key_pair()
    alice_pub_pem = serialize_public_key(alice_pub)
    alice_priv_pem = serialize_private_key(alice_priv)

    owner_id = "alice_owner_8"
    target_user_id = "bob_grantee_8"
    unauth_user_id = "eve_hacker"

    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id, "recipient_public_key_pem": alice_pub_pem},
        files={"file": ("unauth_test.txt", b"Unauthorized revocation test content")}
    )
    file_id = upload_res.json()["file_id"]

    client.post(f"/files/{file_id}/access", json={"target_user_id": target_user_id, "permission": "DOWNLOAD", "requesting_user_id": owner_id})

    revoke_res = client.post(
        f"/files/{file_id}/revoke/{target_user_id}",
        data={"requesting_user_id": unauth_user_id, "owner_private_key_pem": alice_priv_pem}
    )

    assert revoke_res.status_code == 403
    assert "not authorized to revoke access" in revoke_res.json()["detail"]

