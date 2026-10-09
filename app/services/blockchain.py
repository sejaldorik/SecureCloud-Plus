import json
import os
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider
from eth_tester import EthereumTester

DEFAULT_RPC_URL = os.getenv("RPC_URL", "http://127.0.0.1:8545")


class BlockchainError(Exception):
    """Base exception for blockchain service operations."""
    pass


class BlockchainConnectionError(BlockchainError):
    """Raised when connecting to Ethereum / Hardhat node fails."""
    pass


class BlockchainTransactionError(BlockchainError):
    """Raised when a smart contract transaction fails."""
    pass


class BlockchainService:
    """
    Service managing Web3 interactions with the FileKeyManager Solidity smart contract.
    Supports connecting to a local Hardhat RPC node (http://127.0.0.1:8545)
    with automatic fallback to an in-memory EthereumTesterProvider for testing.
    """

    def __init__(self, rpc_url: str = DEFAULT_RPC_URL):
        self.rpc_url = rpc_url
        self.w3: Optional[Web3] = None
        self.contract_address: Optional[str] = None
        self.contract_abi: Optional[list] = None
        self.contract_bytecode: Optional[str] = None
        self.contract = None
        self.account = None

        self._initialize_web3()

    def _initialize_web3(self) -> None:
        """
        Initializes Web3 provider. Attempts Hardhat HTTP RPC node first.
        If node is offline, initializes in-memory EthereumTesterProvider.
        """
        try:
            # 1. Attempt HTTP connection to local Hardhat node
            http_w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            if http_w3.is_connected():
                self.w3 = http_w3
                self.account = self.w3.eth.accounts[0] if self.w3.eth.accounts else None
                self._load_and_setup_contract()
                return
        except Exception:
            pass

        # 2. Fallback to in-memory EVM tester provider if RPC node is offline
        try:
            tester_provider = EthereumTesterProvider(EthereumTester())
            self.w3 = Web3(tester_provider)
            self.account = self.w3.eth.accounts[0]
            self._load_and_setup_contract()
        except Exception as err:
            raise BlockchainConnectionError(f"Failed to initialize Web3 provider: {str(err)}") from err

    def _load_and_setup_contract(self) -> None:
        """
        Loads contract ABI and bytecode from Hardhat artifacts/build files.
        Deploys contract if not deployed on the current EVM chain.
        """
        build_paths = [
            Path("contracts/build/FileKeyManager.json"),
            Path("artifacts/contracts/FileKeyManager.sol/FileKeyManager.json")
        ]

        artifact = None
        for path in build_paths:
            if path.exists():
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        artifact = json.load(f)
                    break
                except Exception:
                    continue

        if artifact:
            self.contract_abi = artifact.get("abi")
            self.contract_bytecode = artifact.get("bytecode")
            self.contract_address = artifact.get("address")

        # Check if contract is deployed at self.contract_address on active chain
        is_deployed = False
        if self.contract_address:
            try:
                code = self.w3.eth.get_code(Web3.to_checksum_address(self.contract_address))
                if code and code not in (b"", b"0x", "0x"):
                    is_deployed = True
            except Exception:
                is_deployed = False

        if not is_deployed and self.contract_abi and self.contract_bytecode:
            self.deploy_contract()
        elif is_deployed and self.contract_abi:
            self.contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(self.contract_address),
                abi=self.contract_abi
            )

    def check_connection(self) -> bool:
        """
        Checks whether Web3 connection is active.
        """
        return self.w3 is not None and self.w3.is_connected()

    def deploy_contract(self, abi: list = None, bytecode: str = None) -> Tuple[str, Any]:
        """
        Deploys FileKeyManager smart contract to the active EVM network.

        Returns:
            Tuple[str, Any]: (deployed_contract_address, contract_instance)
        """
        if not self.check_connection():
            raise BlockchainConnectionError("Cannot deploy: Web3 connection inactive.")

        abi_to_use = abi or self.contract_abi
        bytecode_to_use = bytecode or self.contract_bytecode

        if not abi_to_use or not bytecode_to_use:
            raise BlockchainError("Contract ABI and Bytecode are required for deployment. Compile with Hardhat first.")

        try:
            deployer_account = self.account or self.w3.eth.accounts[0]
            factory = self.w3.eth.contract(abi=abi_to_use, bytecode=bytecode_to_use)

            # Build and send deployment transaction
            tx_hash = factory.constructor().transact({"from": deployer_account})
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            self.contract_address = tx_receipt.contractAddress
            self.contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(self.contract_address),
                abi=abi_to_use
            )
            self.contract_abi = abi_to_use
            self.contract_bytecode = bytecode_to_use

            return self.contract_address, self.contract
        except Exception as e:
            raise BlockchainTransactionError(f"Smart contract deployment failed: {str(e)}") from e

    def register_file_on_chain(
        self,
        file_id: str,
        file_hash: str,
        protected_key_bundle: Dict[str, str],
        sender_address: Optional[str] = None
    ) -> str:
        """
        Registers file metadata and ECC-protected key bundle on the blockchain via FileKeyManager.sol.
        PLAINTEXT AES KEYS AND PRIVATE ECC KEYS ARE NEVER TRANSMITTED OR STORED ON-CHAIN.
        """
        if not self.contract:
            self._initialize_web3()
            if not self.contract:
                raise BlockchainError("Smart contract is not deployed or instantiated.")

        try:
            from_account = sender_address or self.account or self.w3.eth.accounts[0]

            ephemeral_pub_pem = protected_key_bundle.get("ephemeral_public_key_pem", "")
            kek_nonce = protected_key_bundle.get("kek_nonce", "")
            wrapped_aes_key = protected_key_bundle.get("wrapped_aes_key", "")

            # Submit transaction to Solidity registerFile function
            tx_hash = self.contract.functions.registerFile(
                file_id,
                file_hash,
                ephemeral_pub_pem,
                kek_nonce,
                wrapped_aes_key
            ).transact({"from": from_account})

            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            return Web3.to_hex(tx_receipt.transactionHash)
        except Exception as e:
            raise BlockchainTransactionError(f"Failed to register file metadata on-chain: {str(e)}") from e

    def record_revocation_on_chain(
        self,
        file_id: str,
        revoked_user_id: str,
        new_version: int,
        protected_key_bundle: Dict[str, str],
        sender_address: Optional[str] = None
    ) -> str:
        """
        Records key revocation & key rotation event on-chain via FileKeyManager.sol (AccessRevoked event).
        """
        if not self.contract:
            self._initialize_web3()
            if not self.contract:
                raise BlockchainError("Smart contract is not deployed or instantiated.")

        try:
            from_account = sender_address or self.account or self.w3.eth.accounts[0]

            ephemeral_pub_pem = protected_key_bundle.get("ephemeral_public_key_pem", "")
            kek_nonce = protected_key_bundle.get("kek_nonce", "")
            wrapped_aes_key = protected_key_bundle.get("wrapped_aes_key", "")

            tx_hash = self.contract.functions.recordRevocation(
                file_id,
                revoked_user_id,
                new_version,
                ephemeral_pub_pem,
                kek_nonce,
                wrapped_aes_key
            ).transact({"from": from_account})

            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            return Web3.to_hex(tx_receipt.transactionHash)
        except Exception as e:
            raise BlockchainTransactionError(f"Failed to record revocation on-chain: {str(e)}") from e

    def get_file_from_chain(self, file_id: str) -> Dict[str, Any]:
        """
        Retrieves on-chain record for a registered file.
        """
        if not self.contract:
            self._initialize_web3()
            if not self.contract:
                raise BlockchainError("Smart contract is not deployed or instantiated.")

        try:
            record = self.contract.functions.getFileMetadata(file_id).call()
            return {
                "file_id": record[0],
                "file_hash": record[1],
                "ephemeral_public_key_pem": record[2],
                "kek_nonce": record[3],
                "wrapped_aes_key": record[4],
                "owner": record[5],
                "timestamp": record[6],
                "version": record[7] if len(record) > 7 else 1
            }
        except Exception as e:
            raise BlockchainTransactionError(f"Failed to retrieve on-chain metadata for file '{file_id}': {str(e)}") from e


# Singleton blockchain service instance
blockchain_service = BlockchainService()
