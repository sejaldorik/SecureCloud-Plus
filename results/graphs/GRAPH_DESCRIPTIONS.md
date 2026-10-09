# SecureCloud+ Graph Descriptions & Research Interpretations

This document provides formal descriptions, data sources, and IEEE-style research interpretations for all figures generated from the SecureCloud+ experimental evaluation.

---

## Figure 1: Encryption Time vs. File Size

- **Figure Number**: Figure 1
- **File Name**: `01_encryption_time.png`
- **Figure Title**: AES-256-GCM Encryption Time vs. File Size
- **What the Graph Represents**: The relationship between symmetric payload size ($10\text{ KB}$ to $5\text{ MB}$) and AES-256-GCM authenticated encryption processing time.
- **Exact Data Source**: `results/performance_results.csv` (Column: `Encryption Time (ms)`)
- **Research Interpretation**:
  AES-256-GCM encryption processing latency scales directly in a linear fashion with payload size, ranging from $0.0698\text{ ms}$ for a $10\text{ KB}$ file to $5.6952\text{ ms}$ for a $5\text{ MB}$ file. Sub-millisecond performance is maintained for payloads up to $1\text{ MB}$ ($0.8837\text{ ms}$), demonstrating minimal computational overhead for low-to-medium file sizes. The low scaling constant confirms that symmetric authenticated encryption introduces minimal latency into the file upload workflow.

---

## Figure 2: Decryption Time vs. File Size

- **Figure Number**: Figure 2
- **File Name**: `02_decryption_time.png`
- **Figure Title**: AES-256-GCM Decryption Time vs. File Size
- **What the Graph Represents**: The processing time required for AES-256-GCM decryption and GCM authentication tag verification across payload sizes ($10\text{ KB}$ to $5\text{ MB}$).
- **Exact Data Source**: `results/performance_results.csv` (Column: `Decryption Time (ms)`)
- **Research Interpretation**:
  Decryption latency displays near-linear growth, increasing from $0.0156\text{ ms}$ at $10\text{ KB}$ to $4.6281\text{ ms}$ at $5\text{ MB}$. Symmetric decryption executes faster than encryption across all evaluated payload sizes due to optimized single-pass AES-GCM authentication checking. The sub-5 ms decryption speed at $5\text{ MB}$ guarantees near-instantaneous content retrieval following key unwrapping.

---

## Figure 3: Total API Upload Time vs. File Size

- **Figure Number**: Figure 3
- **File Name**: `03_upload_time.png`
- **Figure Title**: Total API Upload Time vs. File Size
- **What the Graph Represents**: Total end-to-end API upload request duration, incorporating multipart HTTP parsing, SHA-256 hashing, AES encryption, ECC key wrapping, disk I/O write operations, and EVM contract metadata registration.
- **Exact Data Source**: `results/performance_results.csv` (Column: `Upload Time (ms)`)
- **Research Interpretation**:
  Total upload latency remains constrained between $142.79\text{ ms}$ and $147.51\text{ ms}$ for file payloads up to $1\text{ MB}$, and experiences a moderate increase to $184.57\text{ ms}$ for a $5\text{ MB}$ payload. The baseline latency (~$140\text{ ms}$) is predominantly driven by disk persistence and EVM smart contract transaction processing rather than symmetric encryption. Overall upload performance confirms that the system handles multi-megabyte uploads with sub-200 ms total turnaround time.

---

## Figure 4: Total API Download Time vs. File Size

- **Figure Number**: Figure 4
- **File Name**: `04_download_time.png`
- **Figure Title**: Total API Download Time vs. File Size
- **What the Graph Represents**: The total duration for end-to-end file retrieval via the download API endpoint, including route guard authorization, ECC key unwrapping, disk payload read, and AES-GCM decryption.
- **Exact Data Source**: `results/performance_results.csv` (Column: `Download Time (ms)`)
- **Research Interpretation**:
  Download API latency spans from $33.51\text{ ms}$ ($1\text{ MB}$) to $48.56\text{ ms}$ ($5\text{ MB}$), demonstrating low operational overhead across all tested payload sizes. Because file downloads execute read-only queries that bypass smart contract state modifications, download latencies are significantly lower than upload latencies. The low overhead ensures rapid file access for authorized users.

---

## Figure 5: Blockchain Transaction Time vs. File Size

- **Figure Number**: Figure 5
- **File Name**: `05_blockchain_transaction_time.png`
- **Figure Title**: Blockchain Metadata Transaction Time vs. File Size
- **What the Graph Represents**: Execution time for registering file metadata (file identifier, SHA-256 hash, public key PEM, KEK nonce, and wrapped key bundle) on the EVM smart contract (`FileKeyManager.sol`).
- **Exact Data Source**: `results/performance_results.csv` (Column: `Blockchain TX Time (ms)`)
- **Research Interpretation**:
  Blockchain transaction execution times remain bounded between $96.75\text{ ms}$ and $108.08\text{ ms}$ across all payload sizes. Because the smart contract method processes fixed-size string metadata rather than raw file byte streams, transaction execution latency is independent of the file size. This property ensures consistent, predictable on-chain metadata registration overhead regardless of file volume.

---

## Figure 6: Key Rotation Time vs. File Size

- **Figure Number**: Figure 6
- **File Name**: `06_key_rotation_time.png`
- **Figure Title**: Key Rotation Time vs. File Size
- **What the Graph Represents**: The total duration required to complete access revocation and key rotation, including payload decryption, fresh AES-256 key sampling, re-encryption, version incrementing ($v1 \rightarrow v2$), key re-wrapping, disk storage update, and EVM `AccessRevoked` transaction logging.
- **Exact Data Source**: `results/performance_results.csv` (Column: `Key Rotation Time (ms)`)
- **Research Interpretation**:
  Key rotation latency spans from $108.76\text{ ms}$ ($100\text{ KB}$) to $140.52\text{ ms}$ ($5\text{ MB}$). The rotation duration reflects the compound overhead of payload re-encryption and EVM state update broadcast. The complete rotation workflow executes in sub-150 ms for a 5 MB payload, demonstrating that revocation and key update cycles introduce negligible administrative latency.

---

## Figure 7: Security Validation Results

- **Figure Number**: Figure 7
- **File Name**: `07_security_validation.png`
- **Figure Title**: Security Validation Experiment Results
- **What the Graph Represents**: A summary chart demonstrating the validation status across all 8 security experiments (A through H).
- **Exact Data Source**: `results/security_results.csv`
- **Research Interpretation**:
  The system achieved a 100% pass rate (8 out of 8 experiments) across all security test categories. The evaluations verified dynamic IV/key randomness, AES-GCM tamper detection, ECC key unwrapping isolation, early HTTP 403 access control rejection, key rotation version incrementation, and zero on-chain exposure of plaintext AES or private ECC keys. The empirical results confirm robust security guarantees without cryptographic or authorization vulnerabilities.

---

## Figure 8: Key Revocation Workflow & Access Control State Machine

- **Figure Number**: Figure 8
- **File Name**: `08_key_revocation_flow.png`
- **Figure Title**: Key Revocation Workflow & Access Control State Machine
- **What the Graph Represents**: A conceptual sequence diagram and state table detailing access permission states before revocation, during revocation execution, and after revocation across different user roles.
- **Exact Data Source**: `results/revocation_results.csv`
- **Research Interpretation**:
  The workflow visualization illustrates the operational transition during access revocation. Revoking a target user triggers automatic AES key rotation, file version incrementation ($v1 \rightarrow v2$), and EVM `AccessRevoked` event emission. Following revocation, access attempts by the revoked user are intercepted at the route guard level (`HTTP 403`), while authorized file owners and remaining grantees retain unbroken access to the updated version ($v2$).
