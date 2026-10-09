import os
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

KEY_SIZE_BYTES = 32     # 256 bits
NONCE_SIZE_BYTES = 12   # 96 bits for AES-GCM


class EncryptionError(Exception):
    """Custom exception raised when encryption or decryption operations fail."""
    pass


def generate_key() -> bytes:
    """
    Generates a cryptographically secure random 256-bit (32-byte) AES key.

    Returns:
        bytes: 32 random bytes.
    """
    return AESGCM.generate_key(bit_length=256)


def generate_nonce() -> bytes:
    """
    Generates a cryptographically secure random 96-bit (12-byte) initialization vector/nonce.

    Returns:
        bytes: 12 random bytes.
    """
    return os.urandom(NONCE_SIZE_BYTES)


def encrypt_bytes(data: bytes, key: bytes = None) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypts plaintext bytes using AES-256-GCM authenticated encryption.

    Args:
        data (bytes): Plaintext bytes to encrypt.
        key (bytes, optional): 32-byte AES key. If None, a new random key is generated.

    Returns:
        Tuple[bytes, bytes, bytes]: (payload, key, nonce)
            - payload: Binary structure containing nonce (12 bytes) prepended to (ciphertext + 16-byte tag)
            - key: 32-byte AES key used for encryption
            - nonce: 12-byte nonce used for encryption
    """
    try:
        if key is None:
            key = generate_key()
        elif len(key) != KEY_SIZE_BYTES:
            raise ValueError(f"AES key must be exactly {KEY_SIZE_BYTES} bytes long.")

        nonce = generate_nonce()
        aesgcm = AESGCM(key)

        # AESGCM encrypts data and appends 16-byte GCM authentication tag
        ciphertext_and_tag = aesgcm.encrypt(nonce, data, None)

        # Combine nonce and ciphertext+tag into a single payload for storage
        encrypted_payload = nonce + ciphertext_and_tag
        return encrypted_payload, key, nonce
    except Exception as e:
        if isinstance(e, ValueError):
            raise
        raise EncryptionError(f"Encryption failed: {str(e)}") from e


def decrypt_bytes(payload: bytes, key: bytes) -> bytes:
    """
    Decrypts an AES-256-GCM encrypted payload and verifies authenticity.

    Args:
        payload (bytes): Encrypted binary payload (nonce + ciphertext + tag)
        key (bytes): 32-byte AES key used during encryption.

    Returns:
        bytes: Decrypted original plaintext bytes.

    Raises:
        EncryptionError: If payload is invalid, corrupted, or tampered with.
    """
    try:
        if len(key) != KEY_SIZE_BYTES:
            raise ValueError(f"AES key must be exactly {KEY_SIZE_BYTES} bytes long.")
        if len(payload) < NONCE_SIZE_BYTES + 16:
            raise EncryptionError("Payload too short: Missing required nonce or GCM authentication tag.")

        nonce = payload[:NONCE_SIZE_BYTES]
        ciphertext_and_tag = payload[NONCE_SIZE_BYTES:]

        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, None)
        return plaintext
    except InvalidTag as e:
        raise EncryptionError("Decryption failed: Authentication tag validation failed (data tampered or wrong key).") from e
    except Exception as e:
        if isinstance(e, (ValueError, EncryptionError)):
            raise
        raise EncryptionError(f"Decryption failed: {str(e)}") from e
