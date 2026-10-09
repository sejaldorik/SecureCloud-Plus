import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.services.hashing import calculate_sha256_bytes
from app.services.ecc import generate_ecc_key_pair, serialize_public_key, serialize_private_key
from app.services.access_control import access_control_service, PermissionType

client = TestClient(app)


def test_1_owner_can_access_their_own_file():
    """
    TEST 1: Verify that the file owner can download and decrypt their own file.
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    owner_id = "alice_owner"
    file_content = b"Confidential document owned by Alice"
    filename = "alice_doc.txt"

    # Upload file as owner Alice
    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id, "recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    assert upload_res.status_code == 201
    data = upload_res.json()
    file_id = data["file_id"]

    # Download file as owner Alice
    download_res = client.get(
        f"/files/{file_id}/download",
        params={"user_id": owner_id, "recipient_private_key_pem": priv_pem}
    )

    assert download_res.status_code == 200
    assert download_res.content == file_content


def test_2_user_with_download_permission_can_download_file():
    """
    TEST 2: Verify that a user explicitly granted DOWNLOAD permission can download the file.
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    owner_id = "bob_owner"
    granted_user_id = "carol_user"
    file_content = b"Shared document for Carol to download"
    filename = "shared_doc.txt"

    # Upload as Bob
    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id, "recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    assert upload_res.status_code == 201
    data = upload_res.json()
    file_id = data["file_id"]

    # Bob grants DOWNLOAD permission to Carol
    access_res = client.post(
        f"/files/{file_id}/access",
        json={
            "target_user_id": granted_user_id,
            "permission": "DOWNLOAD",
            "requesting_user_id": owner_id
        }
    )
    assert access_res.status_code == 200
    assert access_res.json()["permission"] == "DOWNLOAD"

    # Carol downloads file successfully
    download_res = client.get(
        f"/files/{file_id}/download",
        params={"user_id": granted_user_id, "recipient_private_key_pem": priv_pem}
    )
    assert download_res.status_code == 200
    assert download_res.content == file_content


def test_3_user_without_permission_receives_access_denied():
    """
    TEST 3: Verify that a user without permission receives HTTP 403 Access Denied.
    """
    owner_id = "dave_owner"
    unauthorized_user_id = "eve_intruder"
    file_content = b"Top secret data for Dave only"
    filename = "secret_dave.txt"

    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id},
        files={"file": (filename, file_content)}
    )
    assert upload_res.status_code == 201
    file_id = upload_res.json()["file_id"]

    # Eve attempts to download -> Rejected with 403 Forbidden
    download_res = client.get(
        f"/files/{file_id}/download",
        params={"user_id": unauthorized_user_id}
    )

    assert download_res.status_code == 403
    assert "Access Denied" in download_res.json()["detail"]


def test_4_changing_user_to_denied_prevents_further_access():
    """
    TEST 4: Verify that changing a user's permission to DENIED prevents further access attempts.
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    owner_id = "frank_owner"
    target_user_id = "grace_user"
    file_content = b"Temporarily shared document for Grace"
    filename = "temp_shared.txt"

    # Upload & Grant DOWNLOAD permission to Grace
    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id, "recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    file_id = upload_res.json()["file_id"]

    client.post(
        f"/files/{file_id}/access",
        json={
            "target_user_id": target_user_id,
            "permission": "DOWNLOAD",
            "requesting_user_id": owner_id
        }
    )

    # Initial download by Grace succeeds
    res1 = client.get(
        f"/files/{file_id}/download",
        params={"user_id": target_user_id, "recipient_private_key_pem": priv_pem}
    )
    assert res1.status_code == 200

    # Frank revokes/denies access for Grace via DELETE /files/{file_id}/access/{user_id}
    deny_res = client.delete(
        f"/files/{file_id}/access/{target_user_id}",
        params={"requesting_user_id": owner_id}
    )
    assert deny_res.status_code == 200
    assert deny_res.json()["permission"] == "DENIED"

    # Subsequent download attempt by Grace fails with 403 Forbidden
    res2 = client.get(
        f"/files/{file_id}/download",
        params={"user_id": target_user_id, "recipient_private_key_pem": priv_pem}
    )
    assert res2.status_code == 403
    assert "Access Denied" in res2.json()["detail"]


def test_5_unauthorized_user_cannot_reach_key_recovery_or_decryption_step():
    """
    TEST 5: Verify that unauthorized users are stopped at the pre-decryption access check
    BEFORE key recovery (unwrap_aes_key) or AES decryption (decrypt_bytes) is attempted.
    """
    owner_id = "helen_owner"
    unauthorized_user_id = "mallory_attacker"
    file_content = b"Pre-decryption isolation test content"
    filename = "isolation_test.txt"

    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id},
        files={"file": (filename, file_content)}
    )
    file_id = upload_res.json()["file_id"]

    # Patch unwrap_aes_key to throw an error if ever invoked
    with patch("app.routes.files.unwrap_aes_key") as mock_unwrap, \
         patch("app.routes.files.decrypt_bytes") as mock_decrypt:

        mock_unwrap.side_effect = AssertionError("unwrap_aes_key should NOT be called for unauthorized users!")
        mock_decrypt.side_effect = AssertionError("decrypt_bytes should NOT be called for unauthorized users!")

        download_res = client.get(
            f"/files/{file_id}/download",
            params={"user_id": unauthorized_user_id}
        )

        assert download_res.status_code == 403
        assert "Access Denied" in download_res.json()["detail"]
        
        # Verify cryptographic methods were NEVER called
        mock_unwrap.assert_not_called()
        mock_decrypt.assert_not_called()


def test_6_existing_authorized_download_and_integrity_verification_still_work():
    """
    TEST 6: Verify that authorized download, AES-256-GCM decryption, and SHA-256 integrity verification
    continue working seamlessly after adding fine-grained access control.
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    owner_id = "ian_owner"
    reader_user_id = "jack_reader"
    file_content = b"Integrity check content with access control enabled"
    filename = "integrity_ac.txt"

    expected_sha256 = calculate_sha256_bytes(file_content)

    # 1. Upload file as Ian with explicitly provided recipient public key
    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id, "recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    assert upload_res.status_code == 201
    file_id = upload_res.json()["file_id"]

    # 2. Ian grants READ access to Jack
    client.post(
        f"/files/{file_id}/access",
        json={
            "target_user_id": reader_user_id,
            "permission": "READ",
            "requesting_user_id": owner_id
        }
    )

    # 3. Jack downloads file and verifies SHA-256 integrity digest header
    download_res = client.get(
        f"/files/{file_id}/download",
        params={"user_id": reader_user_id, "recipient_private_key_pem": priv_pem}
    )

    assert download_res.status_code == 200
    assert download_res.content == file_content
    assert download_res.headers.get("X-SHA256-Checksum") == expected_sha256


def test_7_owner_cannot_be_denied():
    """
    TEST 7: Verify that attempt to set owner's permission to DENIED is rejected and owner retains access.
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    owner_id = "owner_protected_user"
    file_content = b"Owner protection test content"
    filename = "owner_protection.txt"

    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id, "recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    assert upload_res.status_code == 201
    file_id = upload_res.json()["file_id"]

    # Attempt to deny owner via DELETE /files/{file_id}/access/{user_id}
    deny_res = client.delete(
        f"/files/{file_id}/access/{owner_id}",
        params={"requesting_user_id": owner_id}
    )
    assert deny_res.status_code == 403
    assert "Cannot deny or revoke access for file owner" in deny_res.json()["detail"]

    # Verify owner can still download
    download_res = client.get(
        f"/files/{file_id}/download",
        params={"user_id": owner_id, "recipient_private_key_pem": priv_pem}
    )
    assert download_res.status_code == 200
    assert download_res.content == file_content


def test_8_owner_cannot_revoke_themselves():
    """
    TEST 8: Verify that attempt by file owner to revoke themselves is rejected.
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    owner_id = "self_revoke_owner"
    file_content = b"Self revocation protection payload"
    filename = "self_revoke.txt"

    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id, "recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    assert upload_res.status_code == 201
    file_id = upload_res.json()["file_id"]

    # Attempt self-revocation
    revoke_res = client.post(
        f"/files/{file_id}/revoke/{owner_id}",
        data={"requesting_user_id": owner_id, "recipient_private_key_pem": priv_pem}
    )
    assert revoke_res.status_code == 403
    assert "cannot revoke their own access" in revoke_res.json()["detail"]

    # Verify owner can still download
    download_res = client.get(
        f"/files/{file_id}/download",
        params={"user_id": owner_id, "recipient_private_key_pem": priv_pem}
    )
    assert download_res.status_code == 200
    assert download_res.content == file_content


def test_9_normal_non_owner_user_can_still_be_denied_and_owner_can_download():
    """
    TEST 9: Verify that non-owner user can be denied while file owner retains download access.
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    owner_id = "main_owner_user"
    target_user_id = "revoked_grantee_user"
    file_content = b"Non-owner revocation validation content"
    filename = "non_owner_revoke.txt"

    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id, "recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    assert upload_res.status_code == 201
    file_id = upload_res.json()["file_id"]

    # Grant download permission to target
    client.post(
        f"/files/{file_id}/access",
        json={"target_user_id": target_user_id, "permission": "DOWNLOAD", "requesting_user_id": owner_id}
    )

    # Deny non-owner
    deny_res = client.delete(
        f"/files/{file_id}/access/{target_user_id}",
        params={"requesting_user_id": owner_id}
    )
    assert deny_res.status_code == 200
    assert deny_res.json()["permission"] == "DENIED"

    # Non-owner gets 403
    target_download = client.get(
        f"/files/{file_id}/download",
        params={"user_id": target_user_id, "recipient_private_key_pem": priv_pem}
    )
    assert target_download.status_code == 403

    # Owner can still download successfully
    owner_download = client.get(
        f"/files/{file_id}/download",
        params={"user_id": owner_id, "recipient_private_key_pem": priv_pem}
    )
    assert owner_download.status_code == 200
    assert owner_download.content == file_content


def test_10_owner_permission_survives_service_reload():
    """
    TEST 10: Verify that owner permission survives server/service reload (cleared in-memory records).
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    owner_id = "reload_test_owner"
    file_content = b"Content to test permission persistence across server reloads"
    filename = "reload_test.txt"

    # Upload file
    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id, "recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    assert upload_res.status_code == 201
    file_id = upload_res.json()["file_id"]

    # Clear in-memory access control records to simulate server reload/restart
    access_control_service._records.clear()
    assert (file_id, owner_id) not in access_control_service._records

    # Owner attempts download post-reload -> succeeds via lazy recovery from disk metadata
    download_res = client.get(
        f"/files/{file_id}/download",
        params={"user_id": owner_id, "recipient_private_key_pem": priv_pem}
    )
    assert download_res.status_code == 200
    assert download_res.content == file_content


def test_11_non_owner_without_permission_receives_403_after_reload():
    """
    TEST 11: Verify that a non-owner without permission still receives HTTP 403 Forbidden after service reload.
    """
    owner_id = "reload_owner_11"
    unauthorized_id = "unauthorized_user_11"
    file_content = b"Confidential content after server reload"
    filename = "reload_unauth.txt"

    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id},
        files={"file": (filename, file_content)}
    )
    file_id = upload_res.json()["file_id"]

    # Clear in-memory records to simulate server reload
    access_control_service._records.clear()

    # Unauthorized user attempts download -> rejected with 403 Forbidden
    download_res = client.get(
        f"/files/{file_id}/download",
        params={"user_id": unauthorized_id}
    )
    assert download_res.status_code == 403
    assert "no registered permissions" in download_res.json()["detail"]


def test_12_denied_revoked_users_remain_denied():
    """
    TEST 12: Verify that explicitly denied/revoked users remain denied.
    """
    priv_key, pub_key = generate_ecc_key_pair()
    pub_pem = serialize_public_key(pub_key)
    priv_pem = serialize_private_key(priv_key)

    owner_id = "reload_owner_12"
    target_user_id = "denied_user_12"
    file_content = b"Content for denied status retention test"
    filename = "denied_retention.txt"

    upload_res = client.post(
        "/files/upload",
        data={"owner_id": owner_id, "recipient_public_key_pem": pub_pem},
        files={"file": (filename, file_content)}
    )
    file_id = upload_res.json()["file_id"]

    # Grant & Deny target user
    client.post(
        f"/files/{file_id}/access",
        json={"target_user_id": target_user_id, "permission": "DOWNLOAD", "requesting_user_id": owner_id}
    )
    client.delete(
        f"/files/{file_id}/access/{target_user_id}",
        params={"requesting_user_id": owner_id}
    )

    # Denied user download attempt -> 403 Forbidden
    res = client.get(
        f"/files/{file_id}/download",
        params={"user_id": target_user_id, "recipient_private_key_pem": priv_pem}
    )
    assert res.status_code == 403
    assert "DENIED" in res.json()["detail"]


