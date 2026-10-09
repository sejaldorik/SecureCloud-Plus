# Secure Cloud Storage - Full System (Phases 1 - 8)

Complete implementation of the **Secure Cloud Storage** backend built using **Python**, **FastAPI**, **SHA-256 Hashing**, **Dynamic AES-256-GCM Encryption**, **ECC Key Protection (ECDH + HKDF)**, **Solidity (`FileKeyManager.sol`)**, **Hardhat**, **web3.py**, **Fine-Grained Access Control**, and **Key Revocation + Key Rotation**.

---

## 1. Project Folder Structure

```text
SecureCloud+/
├── app/
│   ├── __init__.py
│   ├── main.py                  # FastAPI entrypoint (Phase 8)
│   ├── routes/
│   │   ├── __init__.py
│   │   └── files.py              # Upload, download, access control, & key revocation routes
│   ├── services/
│   │   ├── __init__.py
│   │   ├── hashing.py            # SHA-256 checksum service
│   │   ├── encryption.py         # Dynamic AES-256-GCM authenticated encryption
│   │   ├── ecc.py                # ECC key pair generation, ECDH agreement & key wrapping
│   │   ├── blockchain.py         # Web3.py smart contract interaction service
│   │   ├── access_control.py     # Fine-grained access control & pre-decryption hook
│   │   └── key_rotation.py       # Key revocation & dynamic file re-encryption service
│   └── storage/
│       ├── __init__.py
│       └── file_storage.py       # Encrypted binary payload & metadata sidecar manager
├── contracts/
│   ├── FileKeyManager.sol       # Solidity smart contract with AccessRevoked event & versioning
│   └── build/
│       └── FileKeyManager.json   # Deployment ABI & bytecode artifact
├── scripts/
│   └── deploy.js                # Hardhat smart contract deployment script
├── tests/
│   ├── __init__.py
│   ├── test_encryption.py       # AES-256-GCM unit test suite
│   ├── test_ecc.py              # ECC key protection unit test suite
│   ├── test_blockchain.py       # Blockchain integration & privacy test suite
│   ├── test_integration_phase5.py# Base integration test suite
│   ├── test_access_control_phase6.py # Fine-Grained Access Control test suite
│   └── test_key_rotation_phase8.py   # Key Revocation & Key Rotation test suite
├── uploads/                      # Storage directory for *.enc payloads and *.meta.json sidecars
├── hardhat.config.js             # Hardhat network & compiler configuration
├── package.json                  # Node.js Hardhat dependencies
├── requirements.txt              # Python dependencies
└── README.md                     # Technical reference & user guide
```

---

## 2. Key Revocation & Key Rotation Workflow

```text
       +-----------------------------------------------------------------------------------+
       |                               REVOCATION REQUEST                                  |
       |                    POST /files/{file_id}/revoke/{user_id}                         |
       +-----------------------------------------------------------------------------------+
                                               |
                                               v
                                   [1. Enforce Owner Rights]
                        Verify requesting_user_id has OWNER permission
                                               |
                                               v
                              [2. Mark Target User DENIED]
                        Set target user status to DENIED in service
                                               |
                                               v
                             [3. Dynamic Key Rotation & Re-Encrypt]
                     Generate fresh AES-256 key & fresh 12-byte nonce.
                    Re-encrypt stored file payload & increment version (v1->v2)
                                               |
                                               v
                                   [4. ECC Key Re-Wrapping]
                     Re-wrap new AES key using recipient's ECC public key.
                     Overwrite stored ciphertext payload (*.enc) on disk
                                               |
                                               v
                             [5. Blockchain On-Chain Revocation]
                 Emit AccessRevoked(fileId, revokedUserId, timestamp, version)
                        on FileKeyManager.sol via Web3.py -> Get Tx Hash
                                               |
                                               v
                                     [6. Client Response]
                Return file_id, revoked_user_id, new_version, transaction_hash, status.
                *** PLAINTEXT AES KEYS AND PRIVATE ECC KEYS ARE NEVER EXPOSED ***
```

---

## 3. Smart Contract Versioning & Events (`FileKeyManager.sol`)

```solidity
event AccessRevoked(
    string indexed fileId,
    string indexed revokedUserId,
    uint256 timestamp,
    uint256 newVersion
);

function recordRevocation(
    string calldata _fileId,
    string calldata _revokedUserId,
    uint256 _newVersion,
    string calldata _newEphemeralPublicKeyPem,
    string calldata _newKekNonce,
    string calldata _newWrappedAesKey
) external;
```

---

## 4. API Endpoints Summary

### Revocation Endpoint
- **`POST /files/{file_id}/revoke/{user_id}`**: Owner revokes user access, generates a fresh AES-256 key, re-encrypts the stored file payload, increments version (`version = v_prev + 1`), re-wraps the key for active users, and emits an `AccessRevoked` event on the blockchain.
  - **Response** (`200 OK`):
```json
{
  "file_id": "b9323a27-4255-4082-8d78-4a61b462eb10",
  "revoked_user_id": "bob_user",
  "new_version": 2,
  "transaction_hash": "0x8f7a6b5c4d3e2f10984756231029485761...",
  "status": "revoked"
}
```

### Core File & Access Endpoints
- **`POST /files/upload`**: Uploads file, computes SHA-256, encrypts with AES-256-GCM, wraps key with ECC, registers on-chain (version=1), and assigns `OWNER` permission to uploader.
- **`POST /files/{file_id}/access`**: Owner grants `READ` or `DOWNLOAD` permission to a target user.
- **`GET /files/{file_id}/access`**: Owner views all access permissions for a file.
- **`DELETE /files/{file_id}/access/{user_id}`**: Owner marks user permission as `DENIED`.
- **`GET /files/{file_id}/download`**: Pre-decryption access check. Decrypts and streams latest version file only if caller holds active non-revoked permission.

---

## 5. Test Results (40 / 40 Passed)

Execute the full test suite across all 8 phases:

```bash
pytest -v tests/
```

```text
============================= test session starts =============================
platform win32 -- Python 3.14.2, pytest-9.1.1, pluggy-1.6.0
rootdir: D:\SecureCloud+
collected 40 items

tests/test_access_control_phase6.py::test_1_owner_can_access_their_own_file PASSED [  2%]
tests/test_access_control_phase6.py::test_2_user_with_download_permission_can_download_file PASSED [  5%]
tests/test_access_control_phase6.py::test_3_user_without_permission_receives_access_denied PASSED [  7%]
tests/test_access_control_phase6.py::test_4_changing_user_to_denied_prevents_further_access PASSED [ 10%]
tests/test_access_control_phase6.py::test_5_unauthorized_user_cannot_reach_key_recovery_or_decryption_step PASSED [ 12%]
tests/test_access_control_phase6.py::test_6_existing_authorized_download_and_integrity_verification_still_work PASSED [ 15%]
tests/test_blockchain.py::test_blockchain_connection_works PASSED        [ 17%]
tests/test_blockchain.py::test_smart_contract_deploys_successfully PASSED [ 20%]
tests/test_blockchain.py::test_file_metadata_can_be_stored_and_retrieved PASSED [ 22%]
tests/test_blockchain.py::test_plaintext_aes_key_and_ecc_private_key_never_stored PASSED [ 25%]
tests/test_blockchain.py::test_api_upload_creates_blockchain_record_and_returns_tx_hash PASSED [ 27%]
tests/test_ecc.py::test_ecc_key_generation PASSED                        [ 30%]
tests/test_ecc.py::test_two_operations_produce_different_protected_keys PASSED [ 32%]
tests/test_ecc.py::test_protected_aes_key_recovery_with_correct_private_key PASSED [ 35%]
tests/test_ecc.py::test_recovery_fails_with_incorrect_private_key PASSED [ 37%]
tests/test_ecc.py::test_api_does_not_expose_plaintext_aes_or_private_ecc_keys PASSED [ 40%]
tests/test_encryption.py::test_different_ciphertext_for_same_plaintext PASSED [ 42%]
tests/test_encryption.py::test_correct_decryption_restores_original_file PASSED [ 45%]
tests/test_encryption.py::test_modified_ciphertext_fails_decryption PASSED [ 47%]
tests/test_encryption.py::test_api_does_not_expose_aes_key PASSED        [ 50%]
tests/test_integration_phase5.py::test_1_upload_file_successfully PASSED [ 52%]
tests/test_integration_phase5.py::test_2_verify_encrypted_file_exists_on_disk PASSED [ 55%]
tests/test_integration_phase5.py::test_3_verify_blockchain_metadata_exists PASSED [ 57%]
tests/test_integration_phase5.py::test_4_download_and_decrypt_file_successfully PASSED [ 60%]
tests/test_integration_phase5.py::test_5_verify_decrypted_file_is_identical_to_original PASSED [ 62%]
tests/test_integration_phase5.py::test_6_verify_sha256_integrity_check_passes PASSED [ 65%]
tests/test_integration_phase5.py::test_7_modified_encrypted_file_fails_decryption PASSED [ 67%]
tests/test_integration_phase5.py::test_8_verify_plaintext_keys_not_exposed_in_api_or_logs PASSED [ 70%]
tests/test_integration_phase5.py::test_9_upload_same_plaintext_twice_produces_different_ciphertext PASSED [ 72%]
tests/test_key_rotation_phase8.py::test_1_user_with_download_permission_can_download_before_revocation PASSED [ 75%]
tests/test_key_rotation_phase8.py::test_2_owner_successfully_revokes_user PASSED [ 77%]
tests/test_key_rotation_phase8.py::test_3_revoked_user_receives_http_403 PASSED [ 80%]
tests/test_key_rotation_phase8.py::test_4_revoked_user_cannot_reach_key_recovery_or_decryption PASSED [ 82%]
tests/test_key_rotation_phase8.py::test_5_aes_key_changes_after_rotation PASSED [ 85%]
tests/test_key_rotation_phase8.py::test_6_file_version_changes_from_1_to_2 PASSED [ 87%]
tests/test_key_rotation_phase8.py::test_7_owner_can_still_download_after_rotation PASSED [ 90%]
tests/test_key_rotation_phase8.py::test_8_remaining_authorized_user_can_still_download_after_rotation PASSED [ 92%]
tests/test_key_rotation_phase8.py::test_9_blockchain_contains_access_revoked_event PASSED [ 95%]
tests/test_key_rotation_phase8.py::test_10_tampering_with_newly_encrypted_file_causes_integrity_failure PASSED [ 97%]
tests/test_key_rotation_phase8.py::test_11_plaintext_aes_and_ecc_private_keys_never_exposed PASSED [100%]

===================== 40 passed in 15.99s ======================
```
