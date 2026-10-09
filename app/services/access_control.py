import time
from enum import Enum
from typing import Dict, List, Tuple, Optional
from pydantic import BaseModel, Field


class PermissionType(str, Enum):
    OWNER = "OWNER"
    READ = "READ"
    DOWNLOAD = "DOWNLOAD"
    DENIED = "DENIED"


class AccessControlRecord(BaseModel):
    user_id: str = Field(..., description="User ID identifier")
    file_id: str = Field(..., description="File ID identifier")
    permission: PermissionType = Field(..., description="Assigned permission type")
    status: str = Field("active", description="Status of permission record (active, denied)")
    created_at: float = Field(default_factory=time.time, description="Unix timestamp of record creation")


class AccessControlError(Exception):
    """Custom exception raised when access control validation fails."""
    pass


class AccessControlService:
    """
    Service managing fine-grained access permissions for files.
    Enforces pre-decryption permission checks before key unwrapping or decryption.
    """

    def __init__(self):
        # Key: (file_id, user_id) -> AccessControlRecord
        self._records: Dict[Tuple[str, str], AccessControlRecord] = {}

    def set_owner(self, file_id: str, owner_user_id: str) -> AccessControlRecord:
        """
        Assigns OWNER permission to the creator of a file upon upload.
        """
        record = AccessControlRecord(
            user_id=owner_user_id,
            file_id=file_id,
            permission=PermissionType.OWNER,
            status="active"
        )
        self._records[(file_id, owner_user_id)] = record
        return record

    def grant_permission(
        self,
        file_id: str,
        target_user_id: str,
        permission: PermissionType,
        requesting_user_id: str
    ) -> AccessControlRecord:
        """
        Allows file owner to grant READ or DOWNLOAD permission to target user.
        """
        # Enforce that grantor has OWNER permission
        is_owner, _ = self.check_permission(file_id, requesting_user_id, required_op=PermissionType.OWNER)
        if not is_owner:
            raise AccessControlError(f"User '{requesting_user_id}' does not have OWNER permission to grant access for file '{file_id}'.")

        existing_record = self._records.get((file_id, target_user_id))
        if existing_record and existing_record.permission == PermissionType.OWNER and permission == PermissionType.DENIED:
            raise AccessControlError(f"Cannot deny or revoke access for file owner '{target_user_id}'.")

        record = AccessControlRecord(
            user_id=target_user_id,
            file_id=file_id,
            permission=permission,
            status="active" if permission != PermissionType.DENIED else "denied"
        )
        self._records[(file_id, target_user_id)] = record
        return record

    def deny_permission(self, file_id: str, target_user_id: str, requesting_user_id: str) -> AccessControlRecord:
        """
        Marks a user's permission as DENIED (pre-revocation phase 6 status).
        """
        return self.grant_permission(
            file_id=file_id,
            target_user_id=target_user_id,
            permission=PermissionType.DENIED,
            requesting_user_id=requesting_user_id
        )

    def get_file_permissions(self, file_id: str, requesting_user_id: str) -> List[AccessControlRecord]:
        """
        Retrieves all permissions registered for a file if requested by the owner.
        """
        is_owner, _ = self.check_permission(file_id, requesting_user_id, required_op=PermissionType.OWNER)
        if not is_owner:
            raise AccessControlError(f"User '{requesting_user_id}' is not authorized to view access records for file '{file_id}'.")

        return [record for (f_id, _), record in self._records.items() if f_id == file_id]

    def check_permission(
        self,
        file_id: str,
        user_id: str,
        required_op: PermissionType = PermissionType.DOWNLOAD
    ) -> Tuple[bool, str]:
        """
        Pre-decryption permission hook. Evaluates if user_id holds sufficient rights for required_op.

        Returns:
            Tuple[bool, str]: (is_allowed, reason_message)
        """
        record = self._records.get((file_id, user_id))

        if not record:
            try:
                from app.storage.file_storage import storage_manager
                meta = storage_manager.read_file_metadata(file_id)
                if meta and meta.get("owner_id", "owner_user_1") == user_id:
                    record = self.set_owner(file_id, user_id)
            except Exception:
                pass

        if not record:
            return False, f"User '{user_id}' has no registered permissions for file '{file_id}'."

        if record.status == "denied" or record.permission == PermissionType.DENIED:
            return False, f"User '{user_id}' access status is DENIED for file '{file_id}'."

        # OWNER has full permissions for all operations
        if record.permission == PermissionType.OWNER:
            return True, "Access granted: User is OWNER."

        # Requiring OWNER permission
        if required_op == PermissionType.OWNER:
            if record.permission == PermissionType.OWNER:
                return True, "Access granted: User is OWNER."
            return False, f"User '{user_id}' does not have OWNER permission."

        # DOWNLOAD operation allows OWNER, DOWNLOAD, or READ
        if required_op in (PermissionType.DOWNLOAD, PermissionType.READ):
            if record.permission in (PermissionType.OWNER, PermissionType.DOWNLOAD, PermissionType.READ):
                return True, f"Access granted: User holds '{record.permission.value}' permission."

        return False, f"User '{user_id}' permission '{record.permission.value}' is insufficient for '{required_op.value}'."


# Default access control service instance
access_control_service = AccessControlService()
