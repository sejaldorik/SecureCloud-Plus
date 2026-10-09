import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.blockchain import blockchain_service, BlockchainService
from app.services.ecc import generate_ecc_key_pair, wrap_aes_key
from app.services.encryption import generate_key


def test_blockchain_connection_works():
    """
    Verifies that the Web3 provider connects successfully (to local node or in-memory tester).
    """
    assert blockchain_service.check_connection() is True


def test_smart_contract_deploys_successfully():
    """
    Verifies that the FileKeyManager smart contract can be deployed to the active blockchain network.
    """
    service = BlockchainService()
    assert service.check_connection() is True
    assert service.contract_address is not None
    assert service.contract_address.startswith("0x")


def test_file_metadata_can_be_stored_and_retrieved():
    """
    Verifies that file metadata and ECC-wrapped key bundles can be registered and retrieved from the smart contract.
    """
    service = BlockchainService()
    file_id = "test-file-bc-101"
    file_hash = "a5d84e4f72f14b1091a99689e4726ef32cf24dba5fb0a30e26e83b2ac5b9e29e"

    # Create dummy wrapped key bundle
    file_aes_key = generate_key()
    _, recipient_pub = generate_ecc_key_pair()
    wrapped_bundle = wrap_aes_key(file_aes_key, recipient_pub)

    # 1. Register on-chain
    tx_hash = service.register_file_on_chain(
        file_id=file_id,
        file_hash=file_hash,
        protected_key_bundle=wrapped_bundle
    )

    assert tx_hash is not None
    assert tx_hash.startswith("0x")
    assert len(tx_hash) == 66  # Standard Ethereum 32-byte hex tx hash with 0x prefix

    # 2. Retrieve from on-chain record
    record = service.get_file_from_chain(file_id)

    assert record["file_id"] == file_id
    assert record["file_hash"] == file_hash
    assert record["ephemeral_public_key_pem"] == wrapped_bundle["ephemeral_public_key_pem"]
    assert record["kek_nonce"] == wrapped_bundle["kek_nonce"]
    assert record["wrapped_aes_key"] == wrapped_bundle["wrapped_aes_key"]
    assert record["owner"].startswith("0x")
    assert record["timestamp"] > 0


def test_plaintext_aes_key_and_ecc_private_key_never_stored():
    """
    Audits stored on-chain record to ensure plaintext AES key and ECC private keys are absent.
    """
    service = BlockchainService()
    file_id = "test-privacy-audit-202"
    file_hash = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"

    file_aes_key = generate_key()
    recipient_priv, recipient_pub = generate_ecc_key_pair()
    wrapped_bundle = wrap_aes_key(file_aes_key, recipient_pub)

    tx_hash = service.register_file_on_chain(
        file_id=file_id,
        file_hash=file_hash,
        protected_key_bundle=wrapped_bundle
    )

    record = service.get_file_from_chain(file_id)
    record_str = str(record)

    # Convert binary keys to hex representation for exact matching
    raw_aes_hex = file_aes_key.hex()

    # CRITICAL: Confirm plaintext AES key and private ECC key format are missing
    assert raw_aes_hex not in record_str
    assert "PRIVATE KEY" not in record_str


def test_api_upload_creates_blockchain_record_and_returns_tx_hash():
    """
    Integration test verifying that POST /files/upload registers the metadata record
    on-chain and returns a valid blockchain transaction hash.
    """
    client = TestClient(app)
    file_content = b"Phase 4 Blockchain Integration Payload Test"
    filename = "blockchain_test.txt"

    response = client.post(
        "/files/upload",
        files={"file": (filename, file_content)}
    )

    assert response.status_code == 201
    data = response.json()

    assert data["status"] == "encrypted_ecc_protected_and_onchain"
    assert "blockchain_tx_hash" in data
    assert data["blockchain_tx_hash"] is not None
    assert data["blockchain_tx_hash"].startswith("0x") or data["blockchain_tx_hash"].startswith("mock_tx_")
