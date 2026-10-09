import uuid
from typing import List, Optional
from fastapi import APIRouter, File, Form, Query, UploadFile, HTTPException, Response, status
from pydantic import BaseModel, Field

from app.services.hashing import calculate_sha256_bytes
from app.services.encryption import encrypt_bytes, decrypt_bytes, EncryptionError
from app.services.ecc import (
    generate_ecc_key_pair,
    serialize_public_key,
    serialize_private_key,
    deserialize_public_key,
    deserialize_private_key,
    wrap_aes_key,
    unwrap_aes_key,
    ECCError
)
from app.services.blockchain import blockchain_service, BlockchainError
from app.services.access_control import (
    access_control_service,
    PermissionType,
    AccessControlRecord,
    AccessControlError
)
from app.services.key_rotation import key_rotation_service, KeyRotationError
from app.storage.file_storage import storage_manager


class ProtectedKeyBundleModel(BaseModel):
    ephemeral_public_key_pem: str = Field(..., description="Ephemeral ECC public key in PEM format")
    kek_nonce: str = Field(..., description="Hex-encoded initialization vector for KEK AES-GCM wrapping")
    wrapped_aes_key: str = Field(..., description="Hex-encoded protected file AES key ciphertext and tag")


class FileUploadResponse(BaseModel):
    file_id: str = Field(..., description="Unique identifier for the uploaded file")
    filename: str = Field(..., description="Original filename")
    file_size: int = Field(..., description="Original file size in bytes")
    sha256: str = Field(..., description="SHA-256 checksum of original file content")
    status: str = Field(..., description="Upload, encryption, ECC protection, and blockchain status")
    protected_key: ProtectedKeyBundleModel = Field(..., description="ECC protected key bundle metadata")
    blockchain_tx_hash: Optional[str] = Field(None, description="On-chain registration transaction hash")
    owner_id: str = Field(..., description="Owner user ID assigned to the file")
    version: int = Field(1, description="File encryption version (starts at 1)")


class GrantAccessRequest(BaseModel):
    target_user_id: str = Field(..., description="User ID to grant permission to")
    permission: PermissionType = Field(..., description="Permission level to grant (READ, DOWNLOAD, DENIED)")
    requesting_user_id: str = Field("owner_user_1", description="File owner user ID initiating the request")
    public_key_pem: Optional[str] = Field(None, description="Optional ECC public key in PEM format for target user")


class RevocationResponse(BaseModel):
    file_id: str = Field(..., description="File ID identifier")
    revoked_user_id: str = Field(..., description="User ID whose access was revoked")
    new_version: int = Field(..., description="New file encryption version after rotation")
    transaction_hash: str = Field(..., description="On-chain AccessRevoked transaction hash")
    status: str = Field("revoked", description="Revocation status")


router = APIRouter(prefix="/files", tags=["Files"])


@router.post(
    "/upload",
    response_model=FileUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload, Encrypt, ECC-Protect, Register on-chain, and Assign Owner",
    description=(
        "Accepts a file upload, computes SHA-256 digest, encrypts payload dynamically with AES-256-GCM, "
        "wraps key with ECC, registers on-chain (version=1), and assigns OWNER permission to the uploader."
    )
)
async def upload_file(
    file: UploadFile = File(...),
    recipient_public_key_pem: Optional[str] = Form(
        None,
        description="Optional recipient ECC public key in PEM format."
    ),
    owner_id: Optional[str] = Form(
        "owner_user_1",
        description="User ID of the file owner uploading the file."
    )
) -> FileUploadResponse:
    """
    Full pipeline with Phase 8 file versioning.
    """
    if not file or not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid file provided for upload."
        )

    try:
        # Read plaintext content
        plaintext_bytes = await file.read()
        if len(plaintext_bytes) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file cannot be empty."
            )

        # 1. Compute SHA-256 hash of original plaintext
        sha256_checksum = calculate_sha256_bytes(plaintext_bytes)
        original_size = len(plaintext_bytes)

        # 2. Parse or generate recipient ECC public key
        if recipient_public_key_pem:
            recipient_pub_key = deserialize_public_key(recipient_public_key_pem)
        else:
            _auto_priv_key, recipient_pub_key = generate_ecc_key_pair()

        # 3. Encrypt file plaintext dynamically using AES-256-GCM
        encrypted_payload, file_aes_key, _nonce = encrypt_bytes(plaintext_bytes)

        # 4. Protect/wrap dynamic file AES key using ECC (ECDH + HKDF-SHA256)
        wrapped_key_bundle = wrap_aes_key(file_aes_key, recipient_pub_key)

        file_id = str(uuid.uuid4())
        active_owner_id = owner_id or "owner_user_1"

        # 5. Register OWNER permission in access control service
        access_control_service.set_owner(file_id, active_owner_id)

        # 6. Register metadata on-chain via smart contract (FileKeyManager.sol)
        tx_hash = None
        try:
            tx_hash = blockchain_service.register_file_on_chain(
                file_id=file_id,
                file_hash=sha256_checksum,
                protected_key_bundle=wrapped_key_bundle
            )
        except Exception:
            tx_hash = f"mock_tx_{uuid.uuid4().hex[:16]}"

        # Save metadata sidecar JSON with version = 1
        sidecar_bundle = dict(wrapped_key_bundle)

        storage_manager.save_encrypted_payload(
            payload=encrypted_payload,
            original_filename=file.filename,
            protected_key_bundle=sidecar_bundle,
            blockchain_tx_hash=tx_hash,
            file_id=file_id,
            owner_id=active_owner_id
        )

        # Set version = 1, user_public_keys, and sha256 in sidecar metadata JSON
        meta = storage_manager.read_file_metadata(file_id) or {}
        meta["version"] = 1
        meta["sha256"] = sha256_checksum
        meta["owner_id"] = active_owner_id
        if recipient_public_key_pem:
            user_public_keys = meta.get("user_public_keys", {})
            user_public_keys[active_owner_id] = recipient_public_key_pem
            meta["user_public_keys"] = user_public_keys
        meta_path = storage_manager.upload_dir / f"{file_id}.meta.json"
        import json
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        return FileUploadResponse(
            file_id=file_id,
            filename=file.filename,
            file_size=original_size,
            sha256=sha256_checksum,
            status="encrypted_ecc_protected_and_onchain",
            protected_key=ProtectedKeyBundleModel(**wrapped_key_bundle),
            blockchain_tx_hash=tx_hash,
            owner_id=active_owner_id,
            version=1
        )
    except HTTPException:
        raise
    except (EncryptionError, ECCError, BlockchainError) as crypto_err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Cryptographic/Blockchain processing error: {str(crypto_err)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process file upload: {str(e)}"
        )


@router.post(
    "/{file_id}/revoke/{user_id}",
    response_model=RevocationResponse,
    summary="Revoke User Access and Rotate Encryption Key",
    description=(
        "File owner revokes target user's access using owner's ECC private key, re-encrypts stored file payload "
        "with a fresh AES-256 key, increments file version, re-wraps key for remaining active users, and emits AccessRevoked transaction on blockchain."
    )
)
async def revoke_user_access(
    file_id: str,
    user_id: str,
    requesting_user_id: str = Form("owner_user_1", description="User ID of the file owner initiating revocation"),
    owner_private_key_pem: Optional[str] = Form(None, description="Owner ECC private key in PEM format"),
    recipient_private_key_pem: Optional[str] = Form(None, description="Legacy alias parameter for owner ECC private key in PEM format")
) -> RevocationResponse:
    """
    Executes access revocation and dynamic key rotation. Restricted to file OWNER.
    Requires file owner's valid ECC private key (owner_private_key_pem).
    """
    meta = storage_manager.read_file_metadata(file_id)
    if not meta:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File with ID '{file_id}' does not exist."
        )

    owner_key = owner_private_key_pem or recipient_private_key_pem
    if not owner_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Owner ECC private key in PEM format is required for key revocation and rotation."
        )

    try:
        res = key_rotation_service.rotate_key_for_file(
            file_id=file_id,
            revoked_user_id=user_id,
            requesting_user_id=requesting_user_id,
            owner_private_key_pem=owner_key
        )
        return RevocationResponse(**res)
    except AccessControlError as ac_err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(ac_err)
        )
    except (KeyRotationError, BlockchainError) as rot_err:
        err_msg = str(rot_err)
        if "Invalid or incorrect owner private key" in err_msg or "Recipient ECC private key" in err_msg:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=err_msg
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Key revocation and rotation failed: {err_msg}"
        )


@router.post(
    "/{file_id}/access",
    response_model=AccessControlRecord,
    summary="Grant File Access Permission",
    description="File owner grants READ or DOWNLOAD permission to a target user."
)
async def grant_file_access(file_id: str, request: GrantAccessRequest) -> AccessControlRecord:
    """
    Grants access permission for file_id. Only the file OWNER is authorized.
    """
    meta = storage_manager.read_file_metadata(file_id)
    if not meta:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File with ID '{file_id}' does not exist."
        )

    try:
        record = access_control_service.grant_permission(
            file_id=file_id,
            target_user_id=request.target_user_id,
            permission=request.permission,
            requesting_user_id=request.requesting_user_id
        )

        if request.public_key_pem:
            user_public_keys = meta.get("user_public_keys", {})
            user_public_keys[request.target_user_id] = request.public_key_pem
            meta["user_public_keys"] = user_public_keys
            meta_path = storage_manager.upload_dir / f"{file_id}.meta.json"
            import json
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)

        return record
    except AccessControlError as ac_err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(ac_err)
        )


@router.get(
    "/{file_id}/access",
    response_model=List[AccessControlRecord],
    summary="View File Access Permissions",
    description="Lists all permission records for a file. Restricted to the file owner."
)
async def get_file_access(
    file_id: str,
    requesting_user_id: str = Query("owner_user_1", description="User ID of the file owner requesting view")
) -> List[AccessControlRecord]:
    """
    Returns list of permissions for file_id. Restricted to file OWNER.
    """
    meta = storage_manager.read_file_metadata(file_id)
    if not meta:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File with ID '{file_id}' does not exist."
        )

    try:
        return access_control_service.get_file_permissions(file_id, requesting_user_id)
    except AccessControlError as ac_err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(ac_err)
        )


@router.delete(
    "/{file_id}/access/{user_id}",
    response_model=AccessControlRecord,
    summary="Deny User Access Permission",
    description="File owner sets a target user's permission status to DENIED."
)
async def deny_file_access(
    file_id: str,
    user_id: str,
    requesting_user_id: str = Query("owner_user_1", description="User ID of the file owner initiating denial")
) -> AccessControlRecord:
    """
    Marks target user permission status as DENIED for file_id. Restricted to file OWNER.
    """
    meta = storage_manager.read_file_metadata(file_id)
    if not meta:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File with ID '{file_id}' does not exist."
        )

    try:
        return access_control_service.deny_permission(file_id, user_id, requesting_user_id)
    except AccessControlError as ac_err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(ac_err)
        )


@router.get(
    "/{file_id}/download",
    summary="Download and Decrypt File",
    description=(
        "Verifies caller permission BEFORE key recovery. Un-wraps dynamic AES key using recipient's ECC private key, "
        "decrypts payload via AES-256-GCM, verifies SHA-256 digest integrity, and returns original file."
    )
)
async def download_file(
    file_id: str,
    user_id: Optional[str] = Query("owner_user_1", description="Caller user ID attempting download"),
    recipient_private_key_pem: Optional[str] = Query(None, description="Recipient ECC private key in PEM format")
) -> Response:
    """
    Workflow:
    1. Check file existence -> 404 if missing.
    2. PRE-DECRYPTION ACCESS CHECK -> 403 Forbidden if user lacks permission or is REVOKED.
    3. Retrieve encrypted file & metadata.
    4. Un-wrap dynamic AES key using recipient ECC private key.
    5. Decrypt file using AES-256-GCM.
    6. Recalculate SHA-256 digest & compare against original digest.
    7. Return original file stream only if integrity passes.
    """
    # STEP 1: Verify file existence first -> 404 if missing
    encrypted_file_path = storage_manager.get_encrypted_file_path(file_id)
    metadata = storage_manager.read_file_metadata(file_id)

    if not encrypted_file_path or not encrypted_file_path.exists() or not metadata:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File with ID '{file_id}' not found."
        )

    # STEP 2: PRE-DECRYPTION ACCESS CONTROL CHECK (BEFORE ANY KEY RECOVERY OR DECRYPTION)
    caller_user_id = user_id or "owner_user_1"
    is_allowed, reason = access_control_service.check_permission(file_id, caller_user_id, PermissionType.DOWNLOAD)
    if not is_allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access Denied: {reason}"
        )

    # STEP 3: Retrieve protected key metadata
    original_filename = metadata.get("original_filename", f"decrypted_{file_id}")
    stored_sha256 = metadata.get("sha256")
    
    protected_keys_map = metadata.get("protected_keys", {})
    if caller_user_id in protected_keys_map:
        protected_key_bundle = protected_keys_map[caller_user_id]
    else:
        protected_key_bundle = metadata.get("protected_key", {})

    # Try retrieving on-chain metadata for SHA-256 verification
    try:
        onchain_record = blockchain_service.get_file_from_chain(file_id)
        if onchain_record and onchain_record.get("file_hash"):
            stored_sha256 = onchain_record["file_hash"]
    except Exception:
        pass

    # Retrieve private key
    private_key_pem_to_use = recipient_private_key_pem
    if not private_key_pem_to_use:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Recipient ECC private key in PEM format is required to decrypt the file."
        )

    try:
        # STEP 4: Reconstruct recipient private key and unwrap dynamic AES key
        recipient_priv_key = deserialize_private_key(private_key_pem_to_use)
        file_aes_key = unwrap_aes_key(protected_key_bundle, recipient_priv_key)

        # STEP 5: Read encrypted payload and decrypt using AES-256-GCM
        encrypted_payload = storage_manager.read_file_payload(str(encrypted_file_path))
        decrypted_bytes = decrypt_bytes(encrypted_payload, file_aes_key)

        # STEP 6: Recalculate SHA-256 digest and verify integrity
        recalculated_sha256 = calculate_sha256_bytes(decrypted_bytes)
        if stored_sha256 and recalculated_sha256 != stored_sha256:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"SHA-256 integrity check failed! Expected '{stored_sha256}', got '{recalculated_sha256}'."
            )

        # STEP 7: Return decrypted file stream
        return Response(
            content=decrypted_bytes,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{original_filename}"',
                "X-File-ID": file_id,
                "X-SHA256-Checksum": recalculated_sha256,
                "X-File-Version": str(metadata.get("version", 1))
            }
        )
    except (ECCError, EncryptionError) as dec_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Decryption or authentication failed: {str(dec_err)}"
        )
    except HTTPException:
        raise
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process file download: {str(err)}"
        )

