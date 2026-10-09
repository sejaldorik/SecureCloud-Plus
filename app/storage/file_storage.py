import json
import uuid
from pathlib import Path
from typing import Dict, Any, Tuple, Optional


class FileStorageManager:
    """
    Handles saving encrypted files and protected key metadata sidecars to local disk storage.
    """

    def __init__(self, upload_dir: str = "uploads"):
        self.upload_dir = Path(upload_dir)
        self.ensure_upload_dir()

    def ensure_upload_dir(self) -> None:
        """
        Ensure the uploads directory exists on disk.
        """
        self.upload_dir.mkdir(parents=True, exist_ok=True)

    def save_encrypted_payload(
        self,
        payload: bytes,
        original_filename: str,
        protected_key_bundle: Optional[Dict[str, Any]] = None,
        blockchain_tx_hash: Optional[str] = None,
        file_id: Optional[str] = None,
        owner_id: Optional[str] = None
    ) -> Tuple[str, str, int]:
        """
        Saves an encrypted binary payload (nonce + ciphertext + auth tag) to the uploads directory.
        Plaintext files are never saved to disk. Metadata and blockchain transaction hash
        are saved alongside in a JSON sidecar file.

        Args:
            payload (bytes): Encrypted binary data to persist.
            original_filename (str): Original filename provided by the user.
            protected_key_bundle (Optional[Dict[str, Any]]): ECC protected key metadata.
            blockchain_tx_hash (Optional[str]): On-chain registration transaction hash.
            file_id (Optional[str]): Optional custom file ID. Generated if omitted.
            owner_id (Optional[str]): Optional owner user ID assigned to the file.

        Returns:
            Tuple[str, str, int]: (file_id, stored_file_path, encrypted_file_size)
        """
        self.ensure_upload_dir()

        file_id = file_id or str(uuid.uuid4())
        extension = Path(original_filename).suffix
        stored_filename = f"{file_id}{extension}.enc" if extension else f"{file_id}.enc"
        file_path = self.upload_dir / stored_filename

        # Write encrypted binary content directly to disk
        with open(file_path, "wb") as destination:
            destination.write(payload)

        # Save metadata sidecar JSON
        meta_path = self.upload_dir / f"{file_id}.meta.json"
        meta_content = {
            "file_id": file_id,
            "original_filename": original_filename,
            "protected_key": protected_key_bundle,
            "blockchain_tx_hash": blockchain_tx_hash,
            "owner_id": owner_id
        }
        with open(meta_path, "w", encoding="utf-8") as meta_file:
            json.dump(meta_content, meta_file, indent=2)

        encrypted_file_size = file_path.stat().st_size
        return file_id, str(file_path), encrypted_file_size

    def get_encrypted_file_path(self, file_id: str) -> Optional[Path]:
        """
        Locates encrypted file path on disk matching file_id.
        """
        self.ensure_upload_dir()
        matches = list(self.upload_dir.glob(f"{file_id}*.enc"))
        if matches:
            return matches[0]
        return None

    def read_file_payload(self, file_path: str) -> bytes:
        """
        Reads binary content of a stored file from disk.
        """
        with open(file_path, "rb") as source:
            return source.read()

    def read_file_metadata(self, file_id: str) -> Optional[Dict[str, Any]]:
        """
        Reads metadata JSON for a stored file if present.
        """
        meta_path = self.upload_dir / f"{file_id}.meta.json"
        if not meta_path.exists():
            return None
        with open(meta_path, "r", encoding="utf-8") as meta_file:
            return json.load(meta_file)


# Default storage instance
storage_manager = FileStorageManager()
