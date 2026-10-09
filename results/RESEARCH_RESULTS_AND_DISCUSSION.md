# Research Results and Discussion: SecureCloud+

## 1. Experimental Setup

The **SecureCloud+** architecture is a hybrid cryptographic cloud storage system designed to deliver confidentiality, data integrity, fine-grained access control, and dynamic key revocation backed by smart contract event logging.

The system implementation incorporates the following core security and architectural primitives:
- **Symmetric Payload Encryption**: AES-256 in Galois/Counter Mode (AES-256-GCM), providing authenticated encryption with a fresh 96-bit (12-byte) initialization vector/nonce for every encryption operation.
- **Asymmetric Key Wrapping**: Elliptic Curve Cryptography (ECC) based on the SECP256R1 (NIST P-256) curve. Key Encryption Keys (KEKs) are derived using Elliptic Curve Diffie-Hellman (ECDH) shared secret exchange paired with HKDF-SHA256, protecting dynamic file AES keys during storage and distribution.
- **Decentralized Metadata & Event Ledger**: Web3-connected Solidity smart contract (`FileKeyManager.sol`) deployed on an Ethereum Virtual Machine (EVM) environment, recording file hashes, public key PEMs, wrapped AES key payloads, and emitting immutable `AccessRevoked` events.
- **Access Control & Policy Enforcement**: An active route guard mechanism managing authorization states (`OWNER`, `DOWNLOAD`, `DENIED`, `REVOKED`) to intercept and validate user requests prior to initiating any cryptographic unwrapping or payload decryption operations.
- **Key Revocation & Dynamic Rotation**: An automated re-encryption mechanism that invalidates access for revoked users by generating a fresh AES-256 key, incrementing the file version number ($v1 \rightarrow v2$), re-encrypting the stored payload, re-wrapping keys for remaining authorized users, and logging transaction events on-chain.

### Experimental Methodology
Performance and security benchmarks were evaluated across five discrete file size categories:
1. **10 KB** ($10,240\text{ bytes}$)
2. **100 KB** ($102,400\text{ bytes}$)
3. **500 KB** ($512,000\text{ bytes}$)
4. **1 MB** ($1,048,576\text{ bytes}$)
5. **5 MB** ($5,242,880\text{ bytes}$)

To eliminate transient environment spikes and ensure statistical consistency, **five independent test iterations** were executed for each file size. All recorded execution timings represent exact arithmetic averages measured in milliseconds ($\text{ms}$) using high-precision performance counters.

---

## 2. Performance Evaluation

The measured empirical performance data for cryptographic operations, file upload/download pipelines, blockchain transactions, and key rotation workflows across all five file sizes are detailed in Table I.

### Table I: Measured Performance Metrics Across File Sizes (Averaged Over 5 Iterations)

| File Size | File Size (Bytes) | Encryption Time (ms) | Decryption Time (ms) | Upload Time (ms) | Download Time (ms) | Blockchain TX Time (ms) | Key Rotation Time (ms) |
|---|---|---|---|---|---|---|---|
| **10 KB** | 10,240 | 0.0698 | 0.0156 | 144.3505 | 35.2627 | 96.7482 | 111.8534 |
| **100 KB** | 102,400 | 0.0811 | 0.0496 | 142.7935 | 37.7851 | 98.8717 | 108.7612 |
| **500 KB** | 512,000 | 0.3188 | 0.1844 | 147.5064 | 44.4139 | 108.0759 | 115.5996 |
| **1 MB** | 1,048,576 | 0.8837 | 0.8044 | 143.4226 | 33.5068 | 106.5641 | 116.0155 |
| **5 MB** | 5,242,880 | 5.6952 | 4.6281 | 184.5729 | 48.5584 | 99.9096 | 140.5244 |

---

## 3. Performance Discussion

Analysis of the empirical timing data yields several insights regarding the operational efficiency and scaling behavior of the SecureCloud+ architecture:

### A. Symmetric Encryption and Decryption Scaling
AES-256-GCM operation times exhibit a direct linear scaling relationship with payload size:
- For small files ($10\text{ KB}$ and $100\text{ KB}$), symmetric encryption completes in **$0.0698\text{ ms}$** and **$0.0811\text{ ms}$**, while decryption completes in **$0.0156\text{ ms}$** and **$0.0496\text{ ms}$**, demonstrating sub-millisecond cryptographic performance.
- As the file payload increases to $5\text{ MB}$, encryption time scales to **$5.6952\text{ ms}$** and decryption time scales to **$4.6281\text{ ms}$**.
- The low overhead of AES-256-GCM hardware/primitive acceleration ensures that core encryption and decryption remain highly performant even as file sizes grow by two orders of magnitude.

### B. End-to-End API Upload and Download Overhead
- **Upload Overhead**: Total API Upload latency remains relatively stable (~$142.79\text{ ms}$ to ~$147.51\text{ ms}$) across files up to $1\text{ MB}$, and increases moderately to **$184.57\text{ ms}$** for a $5\text{ MB}$ file. This latency incorporates HTTP multipart parsing, SHA-256 hashing, AES encryption, ECC key wrapping, disk I/O write operations, and EVM contract transaction submission.
- **Download Overhead**: API Download operations range from **$33.51\text{ ms}$** to **$48.56\text{ ms}$**. The reduced processing time compared to upload stems from avoiding smart contract state modification transactions during read-only retrieval.

### C. Blockchain Transaction Latency
Smart contract transaction execution times range between **$96.75\text{ ms}$** and **$108.08\text{ ms}$** across all tested payload sizes. Because the contract only processes fixed-size metadata string fields (file identifier, SHA-256 checksum hash, public key PEM, KEK nonce, and hex-encoded wrapped key bundle), blockchain transaction latency remains invariant to the underlying file size.

### D. Key Rotation Overhead
Key rotation timing measures the complete revocation lifecycle: payload decryption, fresh AES-256 key generation, re-encryption, version bump ($v1 \rightarrow v2$), ECC key re-wrapping, disk update, and EVM transaction broadcast. The measured rotation overhead ranges from **$108.76\text{ ms}$** ($100\text{ KB}$) to **$140.52\text{ ms}$** ($5\text{ MB}$).

---

## 4. Security Evaluation

The system was evaluated against eight formal security experiments covering cryptographic randomness, tamper resistance, key management isolation, access control, and privacy guarantees. The results are summarized in Table II.

### Table II: Security Evaluation Matrix

| Experiment | Expected Result | Observed Result | Status |
|---|---|---|---|
| **A. Same Plaintext Encrypted Twice** | Different ciphertext produced | Ciphertexts distinct (Length: 60 bytes, Payload Match: False) | **PASSED** |
| **B. Ciphertext Modification** | AES-GCM authentication/decryption failure | `EncryptionError` raised on GCM tag validation failure | **PASSED** |
| **C. Wrong ECC Private Key** | AES key recovery failure | `ECCError` raised: wrong private key failed KEK derivation/unwrap | **PASSED** |
| **D. Unauthorized User Access** | HTTP 403 before AES key recovery/decryption | `HTTP 403 Access Denied` (User has no registered permissions) | **PASSED** |
| **E. Revoked User Access** | HTTP 403 before AES key recovery/decryption | `HTTP 403 Access Denied` (User access status is `DENIED`) | **PASSED** |
| **F. Key Rotation Version Change** | AES key/file version changes after revocation (v1 -> v2) | Version incremented to `v2`, revocation status logged | **PASSED** |
| **G. Authorized User Access After Rotation** | Download/decryption succeeds for remaining authorized user | `HTTP 200 OK`, file content restored successfully | **PASSED** |
| **H. Blockchain Protection** | Plaintext AES key and ECC private key are NOT stored on chain | On-chain record contains only ephemeral pub key PEM, nonce, wrapped ciphertext | **PASSED** |

### Security Discussion

1. **Dynamic Encryption & Nonce Freshness**: Encrypting identical plaintext payloads twice yields completely distinct ciphertexts. Generating unique 256-bit AES keys and fresh 96-bit nonces per call prevents replay attacks and pattern leakage.
2. **AES-GCM Authenticated Tamper Detection**: Bit-flipping experiments on stored `.enc` files verify that AES-GCM authentication tag checking raises an explicit `EncryptionError` and rejects decryption attempt, preventing modified or corrupted ciphertexts from being returned.
3. **ECC Key Protection**: Attempting to unwrap protected AES key bundles using an unassociated ECC private key fails at the ECDH/HKDF step, raising an `ECCError` and confirming asymmetric key isolation.
4. **Pre-Cryptographic Access Control Enforcement**: Requests from unauthorized or revoked users trigger an `HTTP 403` exception at the route guard level **before** storage access, key unwrapping, or AES decryption occur, eliminating unauthorized compute consumption.
5. **On-Chain Zero Key Exposure**: Verification of smart contract state mappings confirms that plaintext AES keys and private ECC keys are **never** committed to the blockchain, eliminating zero-knowledge credential leaks on public ledgers.

---

## 5. Key Revocation Evaluation

To validate key revocation completeness, an 11-step sequential revocation experiment was executed. Table III details the observed result at each step of the sequence.

### Table III: 11-Step Key Revocation Execution Flow

| Step | Action / Scenario | Observed Result |
|:---:|---|---|
| **01** | User B receives `DOWNLOAD` permission | `HTTP 200` — Permission registered in access control service |
| **02** | User B successfully downloads the file | `HTTP 200` — Content downloaded and verified (51 bytes matched) |
| **03** | Owner revokes User B | `HTTP 200` — Revocation request processed by owner `alice_owner_seq` |
| **04** | New AES key is generated | Fresh 256-bit AES key sampled via `AESGCM.generate_key()` |
| **05** | File encryption version increases | Version incremented from `v1` to `v2` |
| **06** | File is re-encrypted | Payload re-encrypted with new AES key & IV, persisted to `file_id.enc` |
| **07** | Blockchain records `AccessRevoked` | Event `AccessRevoked` emitted, TX Hash: `0xf313f5f2ef6e95e15eda14ad8eff4099507aa05810a043726f76ba4fdf32f821` |
| **08** | User B attempts download post-revocation | `GET /files/{file_id}/download?user_id=bob_grantee_seq` submitted |
| **09** | User B receives `HTTP 403` | `HTTP 403 Forbidden` — Access denied prior to decryption attempt |
| **10** | Owner downloads successfully | `HTTP 200` — Owner unwraps v2 key bundle and decrypts latest file version |
| **11** | Remaining authorized user (User C) downloads successfully | `HTTP 200` — User C unwraps v2 key bundle and decrypts latest file version |

### Sequence Breakdown
The sequence confirms that when an owner revokes User B:
$$\text{Permission Granted} \rightarrow \text{Successful Access} \rightarrow \text{Owner Revocation} \rightarrow \text{Fresh AES Key Sampled}$$
$$\rightarrow \text{Version Increment } (v1 \rightarrow v2) \rightarrow \text{Payload Re-encrypted} \rightarrow \text{On-Chain Event Emitted}$$
$$\rightarrow \text{Revoked User Blocked (HTTP 403)} \rightarrow \text{Owner & Remaining Authorized Users Retain Access}$$

---

## 6. Research Findings

Based strictly on empirical test observations, the primary research findings are:

1. **Complete Security Compliance**: All **8 out of 8** security validation experiments passed without failure.
2. **Deterministic Key Revocation Flow**: All **11 out of 11** steps in the key revocation workflow executed successfully.
3. **Automated Key Rotation & Versioning**: Revoking a user automatically triggers file version incrementation ($v1 \rightarrow v2$), re-encrypting stored data with a fresh AES-256 key.
4. **Early Access Rejection**: Access control policies block revoked users at the access guard boundary (`HTTP 403`), preventing unauthorized key recovery or decryption attempts.
5. **Selective Access Preservation**: Access revocation for a targeted user does not disrupt access for file owners or remaining authorized grantees.
6. **Verifiable Audit Logging**: The smart contract records `AccessRevoked` events on-chain with valid, unique EVM transaction hashes.

---

## 7. Limitations

The findings of this evaluation are bound by the following experimental scope limitations:

1. **Environment Dependence**: Experiments were conducted on a single local environment utilizing an in-memory EVM test provider and local disk storage.
2. **Payload Size Boundary**: Empirical performance conclusions are strictly established for file sizes between **10 KB** and **5 MB**.
3. **Network Latency Variability**: Blockchain transaction latency is subject to EVM network congestion, RPC provider configuration, and gas fee dynamics in public network deployments.
4. **Client-Side Data Retention Boundary**: Key revocation invalidates future file version access on the server; however, local plaintext copies previously downloaded to a revoked client's device prior to revocation cannot be remotely erased.
