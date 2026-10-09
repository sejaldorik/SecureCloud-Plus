import hashlib
from typing import BinaryIO


def calculate_sha256(file_obj: BinaryIO, chunk_size: int = 65536) -> str:
    """
    Calculate the SHA-256 digest of a binary file stream in chunks.

    Args:
        file_obj (BinaryIO): File-like binary object supporting .read() and .seek().
        chunk_size (int): Size of memory chunks to read (default 64KB).

    Returns:
        str: Hexadecimal string representing SHA-256 checksum.
    """
    sha256_hash = hashlib.sha256()
    file_obj.seek(0)
    while chunk := file_obj.read(chunk_size):
        sha256_hash.update(chunk)
    file_obj.seek(0)  # Reset stream pointer back to beginning
    return sha256_hash.hexdigest()


def calculate_sha256_bytes(data: bytes) -> str:
    """
    Calculate SHA-256 digest of raw bytes.

    Args:
        data (bytes): Byte content.

    Returns:
        str: Hexadecimal string representing SHA-256 checksum.
    """
    return hashlib.sha256(data).hexdigest()
