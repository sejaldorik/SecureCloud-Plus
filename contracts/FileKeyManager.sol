// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FileKeyManager
 * @dev Manages registration, retrieval, and key revocation/rotation events for encrypted file key metadata on-chain.
 * Plaintext AES keys and ECC private keys are NEVER stored on-chain.
 */
contract FileKeyManager {

    struct FileRecord {
        string fileId;
        string fileHash;
        string ephemeralPublicKeyPem;
        string kekNonce;
        string wrappedAesKey;
        address owner;
        uint256 timestamp;
        uint256 version;
    }

    // Mapping from fileId to FileRecord
    mapping(string => FileRecord) private files;
    
    // Array of all registered file IDs
    string[] private fileIds;

    // Events
    event FileRegistered(
        string indexed fileId,
        string fileHash,
        address indexed owner,
        uint256 timestamp,
        uint256 version
    );

    event AccessRevoked(
        string indexed fileId,
        string indexed revokedUserId,
        uint256 timestamp,
        uint256 newVersion
    );

    /**
     * @dev Registers file metadata and ECC-wrapped AES key bundle on-chain.
     */
    function registerFile(
        string calldata _fileId,
        string calldata _fileHash,
        string calldata _ephemeralPublicKeyPem,
        string calldata _kekNonce,
        string calldata _wrappedAesKey
    ) external {
        require(bytes(_fileId).length > 0, "File ID cannot be empty");
        require(bytes(files[_fileId].fileId).length == 0, "File ID already registered");
        require(bytes(_fileHash).length > 0, "File hash cannot be empty");
        require(bytes(_wrappedAesKey).length > 0, "Wrapped AES key cannot be empty");

        files[_fileId] = FileRecord({
            fileId: _fileId,
            fileHash: _fileHash,
            ephemeralPublicKeyPem: _ephemeralPublicKeyPem,
            kekNonce: _kekNonce,
            wrappedAesKey: _wrappedAesKey,
            owner: msg.sender,
            timestamp: block.timestamp,
            version: 1
        });

        fileIds.push(_fileId);

        emit FileRegistered(_fileId, _fileHash, msg.sender, block.timestamp, 1);
    }

    /**
     * @dev Records key revocation and key rotation event on-chain.
     */
    function recordRevocation(
        string calldata _fileId,
        string calldata _revokedUserId,
        uint256 _newVersion,
        string calldata _newEphemeralPublicKeyPem,
        string calldata _newKekNonce,
        string calldata _newWrappedAesKey
    ) external {
        require(bytes(files[_fileId].fileId).length > 0, "File ID not registered");
        require(bytes(_revokedUserId).length > 0, "Revoked user ID cannot be empty");
        require(_newVersion > files[_fileId].version, "New version must be greater than current version");

        FileRecord storage record = files[_fileId];
        record.version = _newVersion;
        record.ephemeralPublicKeyPem = _newEphemeralPublicKeyPem;
        record.kekNonce = _newKekNonce;
        record.wrappedAesKey = _newWrappedAesKey;
        record.timestamp = block.timestamp;

        emit AccessRevoked(_fileId, _revokedUserId, block.timestamp, _newVersion);
    }

    /**
     * @dev Retrieves stored metadata and ECC-protected key bundle for a registered file.
     */
    function getFileMetadata(string calldata _fileId)
        external
        view
        returns (
            string memory fileId,
            string memory fileHash,
            string memory ephemeralPublicKeyPem,
            string memory kekNonce,
            string memory wrappedAesKey,
            address owner,
            uint256 timestamp,
            uint256 version
        )
    {
        require(bytes(files[_fileId].fileId).length > 0, "File metadata not found");
        FileRecord memory record = files[_fileId];
        return (
            record.fileId,
            record.fileHash,
            record.ephemeralPublicKeyPem,
            record.kekNonce,
            record.wrappedAesKey,
            record.owner,
            record.timestamp,
            record.version
        );
    }

    /**
     * @dev Returns total number of registered files.
     */
    function getFileCount() external view returns (uint256) {
        return fileIds.length;
    }
}
