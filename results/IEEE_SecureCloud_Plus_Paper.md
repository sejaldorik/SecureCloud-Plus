# SecureCloud+: Secure Cloud File Storage using Dynamic AES-256-GCM, ECC-Based Key Protection, Blockchain Key Management, Fine-Grained Access Control, Key Revocation, and Key Rotation

**Sejal R. Chinchkar**  
Department of Computer Engineering  
*SecureCloud+ Research Project*  

---

## Abstract
Cloud storage outsourcing exposes sensitive digital assets to untrusted infrastructure, insider exfiltration, and unauthorized data tampering. Traditional cloud storage paradigms rely on static symmetric encryption keys, centralized key-management servers that represent single points of compromise, or coarse-grained access control models that lack dynamic post-revocation guarantees. This paper presents **SecureCloud+**, a hybrid cryptographic architecture for secure cloud file storage that seamlessly combines dynamic symmetric payload encryption, asymmetric elliptic curve key encapsulation, deterministic rule-based access control, automated cryptographic key rotation upon revocation, and decentralized metadata anchoring. The system employs AES-256 in Galois/Counter Mode (AES-256-GCM) with fresh per-file initialization vectors and dynamic keys to guarantee at-rest confidentiality and ciphertext authenticity. Symmetric file keys are encapsulated using Elliptic Curve Diffie-Hellman (ECDH) over the SECP256R1 (NIST P-256) curve combined with HKDF-SHA256, isolating key distribution to designated public-key recipients without exposing plaintext keys to cloud storage operators. Access control is enforced at the API route-guard layer across four granular permission states (`OWNER`, `READ`, `DOWNLOAD`, `DENIED`), preemptively halting unauthorized requests prior to cryptographic processing. When access is revoked by a file owner, the architecture triggers automated key rotation: recovering the active file key, generating a fresh 256-bit AES key, re-encrypting the stored payload, incrementing the file version number ($v1 \rightarrow v2$), re-wrapping the key for remaining authorized grantees, and logging an immutable event on an Ethereum Virtual Machine (EVM) smart contract. Empirical evaluation across five discrete payload sizes (10 KB to 5 MB) demonstrates that AES-256-GCM encryption and decryption scale within 0.0698–5.6952 ms and 0.0156–4.6281 ms, respectively. Complete upload and download pipelines execute within 142.79–184.57 ms and 33.51–48.56 ms, while key rotation with payload re-encryption executes in 108.76–140.52 ms. Blockchain transaction times remain stable across payload sizes (96.75–108.08 ms) by recording fixed-size metadata alone. An automated test suite of 50 unit and integration tests achieved 100% pass rates (0 failures), and eight formal security validation experiments confirmed zero on-chain key leakage, immediate detection of ciphertext bit tampering, robust rejection of mismatched private keys, and pre-decryption rejection of revoked users with `HTTP 403 Forbidden`.

**Keywords**—Cloud data security, AES-256-GCM, Elliptic Curve Cryptography, SECP256R1, ECDH key exchange, HKDF-SHA256, dynamic key rotation, rule-based access control, blockchain auditability, smart contracts.

---

## I. INTRODUCTION

Outsourcing data storage to public and commercial cloud infrastructures offers undeniable operational advantages, including elastic storage allocation, multi-tenant accessibility, and reduced capital expenditures for enterprise IT infrastructure. However, placing organizational and personal data on third-party cloud servers fundamentally shifts the custody of sensitive assets outside the data owner’s physical and administrative security perimeter. In a conventional cloud deployment, storage hosts operate under an *honest-but-curious* (semi-trusted) operational model: while service providers faithfully execute storage and retrieval commands, they cannot be inherently trusted with data confidentiality or unmonitored access integrity. Storage volumes remain susceptible to passive inspection, privileged insider threats, rogue system administrators, hypervisor-level breaches, and persistent external network attacks.

To mitigate unauthorized data exposure, client-side symmetric encryption has become standard practice in secure cloud storage architectures. By encrypting data prior to transmission, organizations ensure that storage servers encounter only unreadable ciphertext blocks. Among symmetric algorithms, the Advanced Encryption Standard (AES) operating with 256-bit keys is widely recognized as the industry standard. However, conventional block cipher modes such as Electronic Codebook (ECB) and Cipher Block Chaining (CBC) fail to provide comprehensive data authenticity. ECB preserves data patterns across identical blocks, while CBC requires separate, non-integrated Message Authentication Codes (MACs) to defend against bit-flipping attacks, padding-oracle vulnerabilities, and chosen-ciphertext manipulation.

Authenticated Encryption with Associated Data (AEAD), specifically AES-256 in Galois/Counter Mode (AES-256-GCM) [2], resolves these structural weaknesses by pairing high-performance counter-mode stream encryption with universal-hash-based Galois field multiplication (GHASH). This dual-function architecture simultaneously guarantees payload confidentiality and cryptographic authenticity. Any unauthorized alteration of the stored ciphertext, initialization vector, or accompanying authentication metadata induces an immediate GHASH tag mismatch, causing the decryption engine to reject the modified payload before releasing plaintext bytes.

While authenticated symmetric encryption secures data payloads, the management, encapsulation, and distribution of symmetric encryption keys remains the foremost structural challenge in secure multi-user cloud systems. Centralized Key Management Interoperability Protocol (KMIP) servers or Key Management Services (KMS) introduce severe architectural vulnerabilities: they function as single points of catastrophic failure, present high-value targets for credential compromise, and require clients to place implicit trust in external key custody providers. Furthermore, distributing static symmetric keys directly to multi-user workgroups makes selective revocation virtually impossible without compromising group-wide access.

Recently, Shakor et al. [1] proposed an innovative framework in *IEEE Access* entitled *"Dynamic AES Encryption and Blockchain Key Management: A Novel Solution for Cloud Data Security."* Their architecture demonstrated that dynamically generating fresh symmetric encryption keys for each file and anchoring key-management metadata into a decentralized blockchain ledger dramatically improves cloud storage security. By shifting key tracking from centralized databases to distributed smart contracts, their model eliminates single points of failure, ensures tamper-evident auditability, and provides decentralized key verification.

Despite these pioneering advances, a rigorous architectural and cryptographic analysis of the base model proposed by Shakor et al. reveals critical operational limitations when extended to multi-user collaborative cloud environments:
1. **Absence of User Revocation Mechanisms**: The base architecture lacks an automated mechanism to revoke access for previously authorized users who transition out of authorized roles.
2. **Static Key Retention Vulnerabilities**: Because encryption keys remain static throughout a file’s lifecycle, a revoked user who retained a copy of the historical symmetric key can continue decrypting newly generated or intercepted file revisions.
3. **Lack of Cryptographic Payload Re-Encryption**: The base system does not provide automated re-encryption of stored ciphertexts upon access revocation, leaving files vulnerable to stale key exploitation.
4. **Coarse Access Gating**: Access control is not enforced preemptively at the API perimeter, allowing unauthorized requests to trigger downstream computational and cryptographic operations.
5. **Absence of Synchronous Blockchain Revocation Logging**: The base system lacks smart contract event emissions to immutably record access revocation events alongside initial key registration milestones.

To address these fundamental research gaps, this paper presents **SecureCloud+**, a comprehensive, defense-in-depth cloud file storage system that extends the foundational concepts of dynamic symmetric encryption and blockchain key management into a fully integrated, multi-user access control and key lifecycle framework. SecureCloud+ is implemented and evaluated as a functioning software prototype integrating a high-performance Python/FastAPI backend, the native `cryptography` engine, an Ethereum Virtual Machine (EVM) Solidity smart contract (`FileKeyManager.sol`), and a Web3 integration layer.

The core scientific and engineering contributions of SecureCloud+ are structured across six key pillars:
1. **Dynamic Authenticated Payload Encryption**: Integrating AES-256-GCM authenticated encryption utilizing unique, randomly sampled 256-bit symmetric keys ($K_{\text{file}}$) and cryptographically fresh 96-bit initialization vectors ($IV_{\text{file}}$) for every file upload, paired with SHA-256 pre-encryption digest verification.
2. **Hybrid Asymmetric Key Encapsulation**: Enforcing secure, per-user key distribution via Elliptic Curve Diffie-Hellman (ECDH) over the SECP256R1 (NIST P-256) curve combined with HKDF-SHA256 key derivation, wrapping dynamic file keys under derived Key Encryption Keys (KEKs) without exposing plaintext keys to cloud operators.
3. **Deterministic Pre-Decryption Route Guarding**: Implementing a fine-grained, rule-based access-control engine enforcing four discrete permission states (`OWNER`, `READ`, `DOWNLOAD`, `DENIED`), preemptively intercepting unauthorized or revoked download requests at the API boundary with `HTTP 403 Forbidden` prior to disk retrieval or cryptographic execution.
4. **Automated Key Rotation and Payload Re-Encryption**: Designing a synchronous revocation workflow wherein revoking a user triggers automated recovery of the current key, generation of a fresh 256-bit AES key, re-encryption of the physical ciphertext on disk, incrementation of the file version ($v1 \rightarrow v2$), re-wrapping of the fresh key exclusively for remaining authorized users, and permanent purging of the revoked user's key bundle.
5. **Decentralized, Tamper-Evident Audit Logging**: Anchoring critical file registration metadata (file identifier, SHA-256 digest, owner public key, wrapped key bundle) and emitting on-chain `AccessRevoked` events on an EVM smart contract, establishing an auditable lifecycle record without storing plaintext data, symmetric keys, or private keys on-chain.
6. **Empirical Benchmarking and Formal Security Validation**: Conducting extensive empirical performance benchmarks across five file sizes (10 KB to 5 MB) over five independent iterations, paired with a 50-test automated test suite (50 passed, 0 failed) and eight formal security validation experiments confirming tamper detection, key isolation, and zero ledger key leakage.

---

## II. RELATED WORK

The challenge of securing outsourced data in cloud environments has generated extensive research across symmetric cryptography, public-key infrastructure, distributed ledgers, and access control models. This section reviews relevant literature to contextualize the scientific foundation of SecureCloud+.

### A. Cloud Data Security and Authenticated Encryption
Early approaches to cloud storage security focused primarily on symmetric block encryption operating in CBC or CTR modes. However, Bellare and Namprempre established that generic composition of encryption and authentication requires strict Encrypt-then-MAC paradigms to prevent padding-oracle attacks. Dworkin [2] formalized Galois/Counter Mode (AES-GCM), which combines counter-mode encryption with universal polynomial hashing over $\text{GF}(2^{128})$. Contemporary cloud storage systems overwhelmingly adopt AES-256-GCM due to its native hardware acceleration (AES-NI and CLMUL instruction sets) and robust authenticated encryption guarantees. SecureCloud+ builds directly upon NIST SP 800-38D [2] and FIPS PUB 180-4 [3] to enforce authenticated encryption and pre-encryption integrity digests.

### B. Public-Key Cryptography and ECC-Based Key Management
Asymmetric key encapsulation provides the standard mechanism for distributing symmetric keys without preshared secrets. While RSA historically dominated key exchange, Elliptic Curve Cryptography (ECC) achieves equivalent cryptographic strength with substantially smaller key sizes (e.g., 256-bit ECC matches 3072-bit RSA security). Barker et al. [5] standardized pair-wise key establishment using Elliptic Curve Diffie-Hellman (ECDH). To derive uniform cryptographic keys from elliptic curve points, Krawczyk and Eronen [4] specified the HMAC-based Extract-and-Expand Key Derivation Function (HKDF-SHA256). In SecureCloud+, SECP256R1 (NIST P-256) ECDH is paired with HKDF-SHA256 to establish Key Encryption Keys (KEKs) that wrap symmetric file keys for authorized grantees.

### C. Blockchain in Cloud Storage and Key Management
The emergence of distributed ledger technology introduced tamper-resistant primitives for cloud metadata management. Lin et al. [6] proposed consortium blockchain frameworks for multi-cloud data integrity verification, proving that decentralized consensus eliminates single-point metadata tampering. Zang et al. [7] explored blockchain-anchored storage over cloud-native edge architectures. Liu et al. [8] developed zero-trust sharding mechanisms for cross-domain data sharing. Most significantly, Shakor et al. [1] demonstrated that recording dynamic AES key metadata on an EVM-compatible blockchain successfully decentralizes key verification and mitigates central KMS compromise. SecureCloud+ adopts this decentralized metadata anchoring paradigm but resolves the critical absence of revocation mechanisms in the base model.

### D. Access Control and Revocation in Outsourced Storage
Fine-grained access control in cloud repositories has historically relied on Attribute-Based Encryption (ABE). Xiao et al. [9] proposed blockchain-based access control with flexible attribute revocation. Yang et al. [10] combined smart contracts with edge nodes to enforce fine-grained access policies for electronic health records. Luo et al. [11] presented key-policy ABE schemes with switchable attributes. However, ABE schemes introduce severe bilinear pairing computation overheads that scale poorly for large file repositories. Conversely, Yao et al. [12] and Susilo et al. [13] investigated proxy re-encryption (PRE) and sanitizable access control to shift re-encryption burdens to semi-trusted proxies. SecureCloud+ achieves deterministic, lightweight access control by coupling route-guard permission enforcement (`OWNER`, `READ`, `DOWNLOAD`, `DENIED`) with synchronous, owner-directed AES key rotation.

TABLE I summarizes the architectural capabilities of SecureCloud+ in comparison with prominent literature models.

```
TABLE I: Comparative Analysis of Related Cloud Storage and Access Control Architectures
========================================================================================================================
Architecture / Study        | Payload Cipher   | Key Encapsulation | Blockchain Role    | Pre-Decryption Guard | Key Rotation
========================================================================================================================
Shakor et al. [1] (Base)    | AES-256 (Dynamic)| None (Plain Meta) | Key Meta Registry  | No                   | No
Lin et al. [6]              | Static AES       | RSA-2048          | Integrity Auditing | No                   | No
Zang et al. [7]             | AES-CBC          | ECC Secp256k1     | Block Hash Logging | Partial              | No
Liu et al. [8]              | AES-GCM          | Identity-Based Enc| Zero-Trust Sharding| Yes                  | Manual
Xiao et al. [9]             | CP-ABE           | Bilinear Pairing  | Policy Enforcement | Yes                  | Attribute Rev
Yang et al. [10]            | Hybrid ABE       | Attribute Tokens  | Access Token Ledger| Yes                  | Proxy-Based
Yao et al. [12]             | Proxy Re-Enc     | Bilinear Pairing  | None (Centralized) | No                   | Proxy-Re-Enc
Susilo et al. [13]          | Sanitizable ABE  | Pairing Groups    | None (Centralized) | Yes                  | Periodic
SecureCloud+ (Proposed)     | AES-256-GCM      | SECP256R1 + HKDF  | Metadata & Events  | Yes (Deterministic)  | Dynamic Auto
========================================================================================================================
```

---

## III. PROPOSED SYSTEM AND METHODOLOGY

The architecture of SecureCloud+ establishes a cohesive multi-tier framework bridging client applications, API route guards, cryptographic services, physical cloud storage, and an EVM-compatible blockchain ledger. Fig. 1 illustrates the end-to-end processing pipeline.

```
+----------------------------------------------------------------------------------------------------+
|                FIG. 1: ARCHITECTURE AND PROCESSING PIPELINE OF SECURECLOUD+                        |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  [ Data Owner Client ]                                                                             |
|         |                                                                                          |
|         | 1. Multipart Upload (Payload P, Owner ID, Public Key Q_owner)                            |
|         v                                                                                          |
|  [ FastAPI Route Guard Interceptor ]                                                               |
|         |                                                                                          |
|         | 2. Interrogate Permissions (Rule-Based RBAC State Validation)                            |
|         v                                                                                          |
|  [ Cryptographic Execution Service ]                                                               |
|         |-- 3. Compute Pre-Encryption Digest: H_file = SHA-256(P)                                  |
|         |-- 4. Sample Dynamic Key: K_file <- {0,1}^256, Fresh IV_file <- {0,1}^96                  |
|         |-- 5. Authenticated Symmetric Enc: (C_file, T_file) = AES-256-GCM-Enc(P, K_file, IV_file) |
|         |-- 6. Ephemeral ECDH Point Multiplication: S = d_eph * Q_owner                            |
|         |-- 7. Key Derivation: K_KEK = HKDF-SHA256(S_x, "SecureCloud+ ECC-AES-GCM KEK")            |
|         |-- 8. Asymmetric Key Wrap: (C_key, T_key) = AES-256-GCM-Enc(K_file, K_KEK, IV_KEK)        |
|         |                                                                                          |
|         +--------------------------------+---------------------------------+                       |
|                                          |                                 |                       |
|                                          v                                 v                       |
|                             [ Encrypted Cloud Storage ]      [ EVM Smart Contract ]                |
|                             - uploads/{file_id}.enc          - FileKeyManager.sol                  |
|                             - uploads/{file_id}.meta.json    - Stores H_file, Q_owner, C_key       |
|                                                              - Emits AccessRevoked Events          |
|                                                                                                    |
+----------------------------------------------------------------------------------------------------+
```

### A. Mathematical Formulation of Cryptographic Primitives

1. **Authenticated Payload Encryption**: Let $P \in \{0,1\}^*$ be the plaintext file payload. The system samples a dynamic 256-bit symmetric key $K_{\text{file}} \stackrel{\$}{\leftarrow} \{0,1\}^{256}$ and a 96-bit initialization vector $IV_{\text{file}} \stackrel{\$}{\leftarrow} \{0,1\}^{96}$. AES-256-GCM produces the ciphertext $C_{\text{file}}$ and a 128-bit authentication tag $T_{\text{file}}$:

$$(C_{\text{file}}, T_{\text{file}}) = \text{AES-256-GCM-Enc}_{K_{\text{file}}}\left(IV_{\text{file}}, \, P, \, A\right) \tag{1}$$

Decryption reconstructs the plaintext only if the GHASH accumulator verifies:

$$P = \begin{cases} \text{AES-256-GCM-Dec}_{K_{\text{file}}}\left(IV_{\text{file}}, \, C_{\text{file}}, \, T_{\text{file}}\right) & \text{if GHASH}(A, C_{\text{file}}) \text{ validates} \\ \bot \ (\text{EncryptionError}) & \text{otherwise} \end{cases} \tag{2}$$

2. **SECP256R1 Key Encapsulation**: Users generate elliptic curve key pairs on the NIST P-256 prime curve:

$$y^2 \equiv x^3 - 3x + b \pmod p \tag{3}$$

where private scalar $d \in [1, n-1]$ and public point $Q = d \cdot G$. To wrap $K_{\text{file}}$ for a recipient with public key $Q_B$, an ephemeral key pair $(d_{\text{eph}}, Q_{\text{eph}})$ is sampled. The shared secret point is calculated via ECDH:

$$S = d_{\text{eph}} \cdot Q_B = d_{\text{eph}} \cdot d_B \cdot G \tag{4}$$

The 256-bit Key Encryption Key ($K_{\text{KEK}}$) is extracted using HKDF-SHA256 [4]:

$$K_{\text{KEK}} = \text{HKDF-SHA256}\left(\text{IKM} = S_x, \, \text{salt} = \text{None}, \, \text{info} = \texttt{"SecureCloud+ ECC-AES-GCM KEK"}, \, L = 32\right) \tag{5}$$

$K_{\text{file}}$ is encapsulated using AES-256-GCM under a fresh 96-bit nonce $IV_{\text{KEK}}$:

$$(C_{\text{key}}, T_{\text{key}}) = \text{AES-256-GCM-Enc}_{K_{\text{KEK}}}\left(IV_{\text{KEK}}, \, K_{\text{file}}\right) \tag{6}$$

Recipient $B$ recovers $K_{\text{file}}$ using their private scalar $d_B$:

$$S = d_B \cdot Q_{\text{eph}}, \quad K_{\text{KEK}} = \text{HKDF-SHA256}(S_x), \quad K_{\text{file}} = \text{AES-256-GCM-Dec}_{K_{\text{KEK}}}\left(IV_{\text{KEK}}, \, C_{\text{key}}, \, T_{\text{key}}\right) \tag{7}$$

3. **Pre-Encryption Integrity Digest**: The pre-encryption payload is hashed via SHA-256 [3]:

$$H_{\text{file}} = \text{SHA-256}(P) \tag{8}$$

Upon download, the decrypted payload $P_{\text{rec}}$ is verified against the recorded digest:

$$\text{Valid} \iff \text{SHA-256}(P_{\text{rec}}) == H_{\text{file}} \tag{9}$$

```
+----------------------------------------------------------------------------------------------------+
|                 FIG. 2: DUAL-LAYER ASYMMETRIC KEY ENCAPSULATION ARCHITECTURE                       |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  [ Ephemeral Scalar d_eph ] x [ Recipient Public Key Q_B ]                                         |
|                                |                                                                   |
|                                v                                                                   |
|             [ Diffie-Hellman Shared Secret Point S = (S_x, S_y) ]                                  |
|                                |                                                                   |
|                                v                                                                   |
|        [ HKDF-SHA256: IKM=S_x, info="SecureCloud+ ECC-AES-GCM KEK" ]                               |
|                                |                                                                   |
|                                v                                                                   |
|             [ 256-bit Key Encryption Key (K_KEK) ]                                                 |
|                                |                                                                   |
|                                v                                                                   |
|  [ AES-256-GCM Key Wrap: Encrypts Dynamic File Key K_file under K_KEK + IV_KEK ]                  |
|                                |                                                                   |
|                                v                                                                   |
|        Persisted Key Bundle: { Q_eph_pem, IV_KEK, C_key, T_key }                                  |
|                                                                                                    |
+----------------------------------------------------------------------------------------------------+
```

### B. Access Control and Route-Guard Enforcement
SecureCloud+ enforces a deterministic, rule-based access-control policy implemented at the API route-guard layer. As illustrated in Fig. 3, requests must satisfy explicit permission constraints prior to initiating disk reads or cryptographic key unwrapping:
- **`OWNER`**: Full administrative authority (upload, download, grant, revoke, rotate).
- **`DOWNLOAD`**: Authorized to obtain the encrypted payload and request key unwrap.
- **`READ`**: Metadata inspection privileges without key unwrap authorization.
- **`DENIED`**: Explicitly blocked status; returned for revoked or unrecognized requesters.

```
+----------------------------------------------------------------------------------------------------+
|             FIG. 3: PRE-DECRYPTION ROUTE-GUARD POLICY ENFORCEMENT WORKFLOW                         |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  [ Download Request: user_id, file_id ]                                                            |
|                 |                                                                                  |
|                 v                                                                                  |
|  [ Route Guard: Interrogate Access Control Ledger ]                                                |
|                 |                                                                                  |
|        +--------+--------+                                                                         |
|        | User Permitted? |                                                                         |
|        +--------+--------+                                                                         |
|                 |                                                                                  |
|        +--------+---------------------------------+                                                |
|        |                                          |                                                |
|        v (Permitted: OWNER or DOWNLOAD)           v (Unauthorized or DENIED)                       |
|  [ Retrieve Ciphertext & Wrapped Bundle ]    [ Abort Execution Immediately ]                       |
|  [ Execute Asymmetric Key Unwrap ]           [ Return HTTP 403 Forbidden ]                         |
|  [ Execute AES-256-GCM Decryption ]          (Zero Storage I/O, Zero Cryptographic Overhead)       |
|  [ Verify SHA-256 Digest ]                                                                         |
|  [ Deliver Plaintext to Client ]                                                                   |
|                                                                                                    |
+----------------------------------------------------------------------------------------------------+
```

### C. Formal Algorithms

Algorithm 1 details the file upload, dynamic encryption, and asymmetric key encapsulation workflow.

```
----------------------------------------------------------------------------------------------------
ALGORITHM 1: File Upload, Dynamic AES-256-GCM Encryption, and ECC Key Encapsulation
----------------------------------------------------------------------------------------------------
Input:  Plaintext payload P, Owner Identifier owner_id, Owner ECC Public Key Q_owner
Output: Unique file_id, Metadata record M, Blockchain Transaction Receipt TX_receipt

 1: file_id <- GenerateUUIDv4()
 2: H_file <- SHA-256(P)
 3: K_file <- SampleRandomBytes(32)             // Dynamic 256-bit symmetric key
 4: IV_file <- SampleRandomBytes(12)            // Fresh 96-bit initialization vector
 5: (C_file, T_file) <- AES-256-GCM-Enc(K_file, IV_file, P)
 6: PersistToDisk("uploads/" + file_id + ".enc", C_file + T_file)
 7: (d_eph, Q_eph) <- GenerateECCKeyPair(SECP256R1)
 8: S <- PointMultiply(d_eph, Q_owner)
 9: K_KEK <- HKDF-SHA256(IKM = S.x, salt = None, info = "SecureCloud+ ECC-AES-GCM KEK", L = 32)
10: IV_KEK <- SampleRandomBytes(12)
11: (C_key, T_key) <- AES-256-GCM-Enc(K_KEK, IV_KEK, K_file)
12: M <- InitializeMetadata(file_id, H_file, version = 1, IV_file, owner_id)
13: M.wrapped_keys[owner_id] <- { Q_eph, IV_KEK, C_key, T_key }
14: M.permissions[owner_id] <- "OWNER"
15: PersistToDisk("uploads/" + file_id + ".meta.json", SerializeJSON(M))
16: TX_receipt <- Web3Contract.registerFileKey(file_id, H_file, Q_owner, IV_KEK, C_key)
17: return (file_id, M, TX_receipt)
----------------------------------------------------------------------------------------------------
```

Algorithm 2 details the owner-directed access revocation, key rotation, and re-encryption workflow.

```
----------------------------------------------------------------------------------------------------
ALGORITHM 2: Owner-Authorized Access Revocation, Dynamic Key Rotation, and Payload Re-Encryption
----------------------------------------------------------------------------------------------------
Input:  File Identifier file_id, Caller Identifier caller_id, Caller Private Key d_caller,
        Target User Identifier target_user_id
Output: Updated Metadata record M_updated, Revocation Transaction Receipt TX_revocation

 1: M <- LoadMetadata("uploads/" + file_id + ".meta.json")
 2: if M.permissions[caller_id] != "OWNER" then
 3:     return Error(HTTP_403_FORBIDDEN, "Caller is not authorized file owner")
 4: end if
 5: bundle_owner <- M.wrapped_keys[caller_id]
 6: S_owner <- PointMultiply(d_caller, bundle_owner.Q_eph)
 7: K_KEK_owner <- HKDF-SHA256(S_owner.x, "SecureCloud+ ECC-AES-GCM KEK", 32)
 8: K_file_v1 <- AES-256-GCM-Dec(K_KEK_owner, bundle_owner.IV_KEK, bundle_owner.C_key, bundle_owner.T_key)
 9: C_file_v1 <- ReadFromDisk("uploads/" + file_id + ".enc")
10: P <- AES-256-GCM-Dec(K_file_v1, M.IV_file, C_file_v1.ciphertext, C_file_v1.tag)
11: K_file_v2 <- SampleRandomBytes(32)         // Fresh 256-bit symmetric key
12: IV_file_v2 <- SampleRandomBytes(12)        // Fresh 96-bit initialization vector
13: (C_file_v2, T_file_v2) <- AES-256-GCM-Enc(K_file_v2, IV_file_v2, P)
14: OverwriteDisk("uploads/" + file_id + ".enc", C_file_v2 + T_file_v2)
15: M.version <- M.version + 1                // Increment version (v1 -> v2)
16: M.IV_file <- IV_file_v2
17: M.permissions[target_user_id] <- "DENIED"
18: RemoveKey(M.wrapped_keys, target_user_id)  // Purge target user's wrapped key bundle
19: for each remaining_user in AuthorizedUsers(M) do
20:     Q_user <- FetchPublicKey(remaining_user)
21:     (d_eph_new, Q_eph_new) <- GenerateECCKeyPair(SECP256R1)
22:     S_user <- PointMultiply(d_eph_new, Q_user)
23:     K_KEK_user <- HKDF-SHA256(S_user.x, "SecureCloud+ ECC-AES-GCM KEK", 32)
24:     IV_KEK_new <- SampleRandomBytes(12)
25:     (C_key_new, T_key_new) <- AES-256-GCM-Enc(K_KEK_user, IV_KEK_new, K_file_v2)
26:     M.wrapped_keys[remaining_user] <- { Q_eph_new, IV_KEK_new, C_key_new, T_key_new }
27: end for
28: PersistToDisk("uploads/" + file_id + ".meta.json", SerializeJSON(M))
29: TX_revocation <- Web3Contract.revokeAccess(file_id, target_user_id)
30: return (M, TX_revocation)
----------------------------------------------------------------------------------------------------
```

---

## IV. IMPLEMENTATION AND EXPERIMENTAL EVALUATION

### A. Implementation Environment
The SecureCloud+ prototype is implemented using a Python 3.14 environment on a local development testbed. The service stack comprises:
- **Backend Framework**: FastAPI (`>=0.100.0`) running on the Uvicorn standard ASGI server (`>=0.22.0`) with Pydantic (`>=2.0.0`) validation models.
- **Cryptographic Library**: Native Python `cryptography` package (`>=41.0.0`) implementing OpenSSL-backed AES-256-GCM, SECP256R1, ECDH, and HKDF-SHA256 primitives.
- **Storage Subsystem**: Encrypted local file storage in an `uploads/` directory persisting binary ciphertexts (`{file_id}.enc`) and metadata sidecars (`{file_id}.meta.json`).
- **Blockchain Framework**: Solidity `^0.8.20` smart contract (`FileKeyManager.sol`) compiled and executed on a local Hardhat (`^2.19.0`) Ethereum Virtual Machine (EVM) environment, integrated via Web3.py (`>=6.0.0`) over JSON-RPC.
- **Testing Framework**: Pytest (`>=7.4.0`) orchestrating automated unit, integration, and security suites.

### B. Functional Testing
The automated test suite comprises exactly 50 tests across six test modules. All 50 tests passed with 0 failures, as documented in TABLE II.

```
TABLE II: Comprehensive Automated Test Suite Structure and Execution Results
========================================================================================================================
Test Module                   | Tests | Focus and Execution Scope                       | Expected Behavior     | Result
========================================================================================================================
test_encryption.py            |   4   | AES-256-GCM encryption, decryption, tags       | Tag mismatch rejects  | PASSED (4/4)
test_ecc.py                   |   6   | SECP256R1, ECDH, HKDF-SHA256, key wrapping      | Key isolation upheld  | PASSED (6/6)
test_blockchain.py            |   5   | Web3 connection, contract calls, event receipts | On-chain registration | PASSED (5/5)
test_integration_phase5.py    |  10   | End-to-end file upload, download, SHA-256 verify| Plaintext restored    | PASSED (10/10)
test_access_control_phase6.py |  12   | RBAC permissions (OWNER, READ, DOWNLOAD, DENIED)| Pre-decrypt HTTP 403  | PASSED (12/12)
test_key_rotation_phase8.py   |  13   | Revocation, rotation, v1->v2 re-encrypt, logs   | Re-encryption verified| PASSED (13/13)
========================================================================================================================
Total Automated Test Cases    |  50   | Complete end-to-end system functional validation| Zero Failures         | PASSED (50/50)
========================================================================================================================
```

### C. Performance Benchmarks
Empirical performance benchmarks were evaluated across five discrete file sizes: 10 KB, 100 KB, 500 KB, 1 MB, and 5 MB. Five independent test iterations were executed for each size, with arithmetic means recorded in TABLE III.

```
TABLE III: Empirical Performance Evaluation Across File Sizes (Averaged Over 5 Iterations)
========================================================================================================================
File Size | Size (Bytes) | Encryption (ms) | Decryption (ms) | Upload (ms) | Download (ms) | BC TX (ms) | Rotation (ms)
========================================================================================================================
10 KB     |       10,240 |          0.0698 |          0.0156 |    144.3505 |       35.2627 |    96.7482 |      111.8534
100 KB    |      102,400 |          0.0811 |          0.0496 |    142.7935 |       37.7851 |    98.8717 |      108.7612
500 KB    |      512,000 |          0.3188 |          0.1844 |    147.5064 |       44.4139 |   108.0759 |      115.5996
1 MB      |    1,048,576 |          0.8837 |          0.8044 |    143.4226 |       33.5068 |   106.5641 |      116.0155
5 MB      |    5,242,880 |          5.6952 |          4.6281 |    184.5729 |       48.5584 |    99.9096 |      140.5244
========================================================================================================================
```

### D. Performance Discussion
- **Symmetric Cryptographic Scaling**: AES-256-GCM execution scaled linearly with payload size, requiring 0.0698 ms (10 KB) to 5.6952 ms (5 MB) for encryption, and 0.0156 ms (10 KB) to 4.6281 ms (5 MB) for decryption. Decryption showed lower execution times than encryption across all evaluated payload sizes under the evaluated benchmark conditions.
- **API Upload and Download Overhead**: Upload latencies ranged from 142.7935 ms (100 KB) to 184.5729 ms (5 MB), incorporating HTTP multipart processing, hashing, symmetric encryption, ECC key wrapping, disk writes, and blockchain transaction submission. Download operations executed significantly faster (33.5068 ms to 48.5584 ms) due to avoiding on-chain state-modification transactions.
- **Blockchain Transaction Latency**: In the evaluated local EVM environment, blockchain transaction times remained relatively stable across the evaluated file sizes (ranging from 96.7482 ms to 108.0759 ms) because only fixed-size metadata string fields were submitted on-chain, rather than the file payload itself.
- **Key Rotation Overhead**: The complete rotation workflow—recovering the active key, generating a fresh AES key, re-encrypting the payload on disk, incrementing version ($v1 \rightarrow v2$), re-wrapping for remaining authorized users, and logging on-chain—executed in 108.7612 ms (100 KB) to 140.5244 ms (5 MB).

### E. Formal Security Experiments
The prototype was subjected to eight formal security experiments validating cryptographic invariants, access control, and privacy guarantees. All eight experiments passed, as summarized in TABLE IV.

```
TABLE IV: Empirical Security Validation Matrix
========================================================================================================================
Experiment | Target Threat Scenario        | Expected Behavior               | Observed Empirical Result       | Status
========================================================================================================================
A          | Duplicate Plaintext Encryption| Distinct ciphertexts generated  | Ciphertexts distinct (Match=F)  | PASSED
B          | Ciphertext Bit Modification   | Decryption rejected via GHASH   | EncryptionError raised instantly| PASSED
C          | Mismatched ECC Private Key    | Shared secret derivation fails  | ECCError raised on unwrap       | PASSED
D          | Unauthorized User Download    | HTTP 403 returned pre-decrypt   | HTTP 403 Forbidden returned     | PASSED
E          | Revoked User Download         | HTTP 403 returned pre-decrypt   | HTTP 403 Forbidden returned     | PASSED
F          | Key Rotation Version Bump     | Version increments (v1 -> v2)   | Version updated, payload re-enc | PASSED
G          | Selective Access Preservation | Remaining users decrypt post-rot| HTTP 200, plaintext restored    | PASSED
H          | On-Chain Key Exposure Check   | Zero raw keys logged on-chain   | Only public PEMs/nonces on-chain| PASSED
========================================================================================================================
```

### F. Sequential Key Revocation Workflow Verification
To confirm end-to-end revocation correctness, an 11-step sequential revocation workflow was executed. TABLE V documents the verified result at each step.

```
TABLE V: 11-Step Sequential Key Revocation and Re-Encryption Execution Flow
========================================================================================================================
Step | Action / Execution Scenario         | Observed Execution Result
========================================================================================================================
01   | User B receives DOWNLOAD permission | HTTP 200 — Permission registered in access control ledger
02   | User B downloads file version v1    | HTTP 200 — Content downloaded and verified (51 bytes matched)
03   | Owner initiates revocation of User B| HTTP 200 — Revocation request processed by authorized owner
04   | Fresh AES-256 key sampled           | Fresh 256-bit symmetric key sampled via cryptographic RNG
05   | File version incremented            | Version updated from v1 to v2 in metadata
06   | Stored payload re-encrypted         | Ciphertext re-encrypted with fresh AES key, persisted to disk
07   | Blockchain records AccessRevoked    | Event emitted, TX Hash: 0xf313f5f2ef6e95e15eda14ad8eff4099507aa05810a043726f76ba4fdf32f821
08   | User B attempts download post-revoc | GET /files/{file_id}/download?user_id=bob_grantee_seq submitted
09   | User B receives HTTP 403 Forbidden  | HTTP 403 Access Denied — Intercepted at route guard prior to decryption
10   | Owner downloads file version v2     | HTTP 200 — Owner unwraps v2 key bundle and recovers latest plaintext
11   | Remaining User C downloads version v2| HTTP 200 — User C unwraps v2 key bundle and recovers latest plaintext
========================================================================================================================
```

---

## V. SECURITY ANALYSIS AND THREAT MODEL

### A. Threat Model and Adversarial Capabilities
SecureCloud+ operates under the standard Dolev–Yao adversarial model across semi-trusted cloud environments:
1. **Semi-Trusted Storage Provider**: Storage operators and privileged hypervisors are modeled as honest-but-curious; they execute protocols faithfully but attempt passive inspection of persistent data.
2. **Untrusted External Adversaries**: Network actors who attempt unauthorized API queries, key bundle extraction, or ciphertext tampering.
3. **Revoked Grantees (Insider Threat)**: Former collaborators who previously held valid download privileges attempting to access subsequent protected file versions.
4. **Malicious Ciphertext Modification**: Adversaries with storage access attempting bit-flipping, truncation, or nonce manipulation.
5. **Unauthorized Key Recovery**: Adversaries presenting malformed or unassociated ECC private keys during unwrap routines.
6. **Metadata Ledger Tampering**: Hostile entities attempting to silently alter access logs or forge authorization states.

*Explicit Out-of-Scope Boundaries*: The prototype does not claim protection against compromised client operating systems, malware exfiltrating client private keys, physical side-channel hardware attacks, quantum computing cryptanalysis, or the remote erasure of unencrypted plaintext that a user legitimately downloaded prior to revocation.

### B. Confidentiality Analysis
Confidentiality is guaranteed through dynamic AES-256-GCM encryption. With unique 256-bit keys ($K_{\text{file}} \stackrel{\$}{\leftarrow} \{0,1\}^{256}$) and fresh 96-bit nonces ($IV_{\text{file}} \stackrel{\$}{\leftarrow} \{0,1\}^{96}$), plaintext exposure is completely avoided across physical disks, metadata files, and blockchain records. Possessing one file key yields zero advantage for decrypting any other file in the cloud repository.

### C. Integrity and Authenticity Analysis
Integrity is preserved through dual-layer verification (Fig. 4). AES-256-GCM verifies the 128-bit GHASH tag ($T_{\text{file}}$) over ciphertext blocks during decryption:

$$T_{\text{file}} = \text{GHASH}_{H}(A, C_{\text{file}}) \oplus \text{AES}_{K_{\text{file}}}(J_0) \tag{10}$$

Any single-bit alteration causes an immediate `EncryptionError`, terminating the operation before releasing decrypted bytes. Following decryption, the client-side plaintext is validated against the recorded SHA-256 digest ($H_{\text{file}}$), verifying end-to-end payload authenticity.

```
+----------------------------------------------------------------------------------------------------+
|               FIG. 4: DUAL-LAYER DATA INTEGRITY AND AUTHENTICITY WORKFLOW                          |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  [ Stored Ciphertext C_file + Tag T_file ]                                                         |
|                       |                                                                            |
|                       v                                                                            |
|  +----------------------------------------------------------------------------------------------+  |
|  | Layer 1: AES-256-GCM GHASH Authentication Tag Verification                                   |  |
|  | - Evaluates GHASH polynomial over retrieved ciphertext blocks                                |  |
|  | - Matches against 128-bit Tag T_file                                                         |  |
|  |   * Tag Mismatch: Raise EncryptionError -> Abort Decryption (Immediate Halt)                 |  |
|  |   * Tag Valid: Produces Recovered In-Memory Byte Stream P_rec                                |  |
|  +----------------------------------------------------------------------------------------------+  |
|                       |                                                                            |
|                       v                                                                            |
|  +----------------------------------------------------------------------------------------------+  |
|  | Layer 2: Pre-Encryption SHA-256 Digest Verification                                          |  |
|  | - Computes SHA-256(P_rec)                                                                    |  |
|  | - Compares against Stored On-Chain Digest H_file                                              |  |
|  |   * Mismatch: Reject Delivery, Flag Storage Corruption                                       |  |
|  |   * Match: Deliver Verified Plaintext to Requesting Client                                   |  |
|  +----------------------------------------------------------------------------------------------+  |
|                                                                                                    |
+----------------------------------------------------------------------------------------------------+
```

### D. Access Control and Key Protection Analysis
Enforcing authorization *strictly prior to decryption* at the route-guard boundary prevents denial-of-service degradation and suppresses side-channel timing oracles. Symmetric file keys are encapsulated using SECP256R1 ECDH and HKDF-SHA256. If an adversary attempts to unwrap a key bundle using an incorrect private key $d_X \neq d_B$, the derived shared secret $S^{\prime}$ and KEK $K_{\text{KEK}}^{\prime}$ diverge completely, causing AES-GCM tag verification to raise an `ECCError`.

### E. Key Revocation, Dynamic Rotation, and Lifecycle Security
Access revocation couples administrative state transitions (`DENIED`) with automated cryptographic key rotation (Fig. 5). The system recovers the active key, samples a fresh 256-bit AES key, re-encrypts the stored payload on disk, increments the version number ($v1 \rightarrow v2$), re-wraps the fresh key for remaining authorized users, and emits an `AccessRevoked` event on-chain:

$$(C_{\text{file}}^{(v2)}, T_{\text{file}}^{(v2)}) = \text{AES-256-GCM-Enc}_{K_{\text{file}}^{(v2)}}(IV_{\text{file}}^{(v2)}, P) \tag{11}$$

This guarantees forward access isolation across subsequent versions: the revoked entity's historical key cannot decrypt future file revisions.

```
+----------------------------------------------------------------------------------------------------+
|         FIG. 5: SEQUENTIAL KEY REVOCATION AND DYNAMIC ROTATION LIFECYCLE WORKFLOW                  |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  [ Step 1: Owner Authorization ]                                                                   |
|    - Verify caller_id == OWNER                                                                     |
|    - Validate Owner Private Key via test unwrap                                                    |
|                                                                                                    |
|  [ Step 2: Administrative Revocation ]                                                             |
|    - Set target user status: DOWNLOAD -> DENIED                                                    |
|    - Purge target user's wrapped key bundle from metadata                                          |
|                                                                                                    |
|  [ Step 3: Cryptographic Re-Encryption ]                                                           |
|    - Recover current K_file_v1 using Owner's validated Private Key                                 |
|    - Decrypt stored payload P in memory                                                            |
|    - Sample Fresh Key K_file_v2 <- {0,1}^256, Fresh IV_file_v2 <- {0,1}^96                         |
|    - Re-encrypt Payload: (C_file_v2, T_file_v2) = AES-256-GCM-Enc(K_file_v2, IV_file_v2, P)        |
|    - Overwrite physical disk file: uploads/{file_id}.enc                                           |
|                                                                                                    |
|  [ Step 4: Metadata & Ledger Version Update ]                                                      |
|    - Increment file version: v1 -> v2                                                              |
|    - Re-wrap K_file_v2 for Owner and remaining authorized grantees                                 |
|    - Emit on-chain event: AccessRevoked(fileId, targetUser, timestamp)                             |
|    - Receive EVM Transaction Hash receipt                                                          |
|                                                                                                    |
+----------------------------------------------------------------------------------------------------+
```

### F. Blockchain Security and Auditability Analysis
The `FileKeyManager.sol` smart contract provides decentralized, tamper-evident auditability. Initial file registrations and access revocations are committed to EVM blocks with unique transaction hashes, preventing server administrators from repudiating or backdating access modifications. The blockchain records only metadata hashes, public keys, and nonces; no plaintext data, symmetric keys, or private keys are ever committed to the public ledger.

TABLE VI maps the verified empirical test evidence to each evaluated security property.

```
TABLE VI: Empirical Verification of Security Properties Across Automated Test Suites
========================================================================================================================
Security Property          | Threat Vector Addressed     | Validating Test Evidence        | Observed Status
========================================================================================================================
Dynamic Ciphertext Freshness| Ciphertext pattern leakage   | test_encryption.py (Exp A)      | VERIFIED (Distinct Ciphers)
Ciphertext Tamper Detection| Stored bit manipulation     | test_encryption.py (Exp B)      | VERIFIED (Tag Failure Caught)
Asymmetric Key Isolation   | Unauthorized key recovery   | test_ecc.py (Exp C)             | VERIFIED (ECCError Raised)
Unauthorized Access Block  | Unauthorized download query | test_access_control_phase6 (ExpD)| VERIFIED (Pre-Decrypt HTTP 403)
Revoked User Access Block  | Stale permission exploitation| test_key_rotation_phase8 (Exp E) | VERIFIED (Pre-Decrypt HTTP 403)
Dynamic Key Rotation       | Stale key retention attacks | test_key_rotation_phase8 (Exp F) | VERIFIED (Payload Re-encrypted)
Selective Access Retention | Collateral access disruption| test_key_rotation_phase8 (Exp G) | VERIFIED (Authorized Can Read)
Zero On-Chain Key Exposure | Ledger credential harvesting| test_blockchain.py (Exp H)      | VERIFIED (Zero Raw Keys Stored)
========================================================================================================================
```

TABLE VII consolidates the security property matrix, mechanisms, evidence, and operational boundaries.

```
TABLE VII: Consolidated Security Property and Defensive Guarantee Matrix
========================================================================================================================
Security Property          | Enforcing Mechanism         | Empirical Evidence              | Operational Boundary
========================================================================================================================
Confidentiality            | AES-256-GCM + dynamic keys  | Exp A (Distinct ciphertexts)    | Requires secure client keys
Integrity & Authenticity   | Dual-layer: GCM Tag + SHA256| Exp B (Tag failure halts)       | Storage DoS not prevented
Access Control             | Deterministic route guards  | Exp D & E (Pre-decrypt HTTP 403)| Direct disk read requires key
Key Protection             | SECP256R1 ECDH + HKDF wrap  | Exp C (Mismatched key fails)    | Relies on client key safety
Key Revocation             | DENIED status + bundle purge| 11-step execution flow (Table V)| Past plaintext not erasable
Key Rotation               | Re-encrypt payload, v1->v2  | Exp F (Payload re-encrypted)    | Re-encryption I/O overhead
Blockchain Auditability    | FileKeyManager.sol logging  | Exp H (On-chain event hashes)   | Subject to EVM gas economics
========================================================================================================================
```

---

## VI. DISCUSSION, LIMITATIONS AND FUTURE SCOPE

### A. Discussion and Architectural Trade-Offs
The empirical evaluation demonstrates that SecureCloud+ realizes a functioning defense-in-depth architecture. Rather than relying on a single perimeter, the prototype establishes an integrated pipeline where symmetric encryption, asymmetric key encapsulation, route-guard authorization, automated re-encryption, and blockchain auditing address distinct failure modes. 

These architectural benefits involve specific engineering trade-offs:
- **AES-256-GCM Nonce Handling**: High-speed authenticated encryption requires absolute nonce uniqueness (fresh 96-bit IV per operation), as nonce reuse destroys GCM authenticity.
- **Hybrid Key Encapsulation**: Asymmetric ECDH point multiplications and HKDF derivations eliminate preshared static keys but introduce higher computational overhead than raw symmetric wrapping.
- **Synchronous Re-Encryption Overhead**: Re-encrypting data upon revocation guarantees forward access isolation across subsequent versions, but requires full payload read, decrypt, encrypt, and write cycles ($140.52\text{ ms}$ for 5 MB files).
- **Blockchain Auditability vs. Latency**: Anchoring events on-chain eliminates centralized log tampering, but introduces EVM transaction confirmation overheads (~96–108 ms on local EVM).

### B. Documented Limitations
1. **Local Prototype Testbed**: Evaluated on a single development host with local Hardhat EVM execution and local disk storage; wide-area network latency, multi-region replication, and public RPC congestion were not evaluated.
2. **Payload Size Boundary**: Empirical benchmarks were gathered across 10 KB to 5 MB files; memory buffering and lock contention for multi-gigabyte files were not evaluated.
3. **Absence of Public Blockchain Gas Dynamics**: In local Hardhat execution, block confirmation is instantaneous and gas costs are nominal; public Layer-1/Layer-2 gas economics were not evaluated.
4. **Lack of Automated Formal Verification**: Multi-party protocol state transitions have not been modeled in automated mechanized verification tools such as ProVerif or Tamarin.
5. **Endpoint Security Dependency**: Security relies entirely on the client environment protecting its private ECC keys.
6. **Inherent Plaintext Retention Boundary**: Key revocation cannot retroactively wipe or cryptographically recall unencrypted plaintext that a user legitimately downloaded prior to revocation.

### C. Future Scope and Practical Deployment Considerations
Future research will focus on transitioning the storage tier to distributed cloud object stores (e.g., Amazon S3, Google Cloud Storage), deploying smart contracts onto public EVM Layer-2 rollups (e.g., Arbitrum, Optimism) to evaluate real-world gas economics, conducting formal protocol verification in ProVerif, integrating hardware-backed client key protection (HSMs, TPMs, YubiKeys via PKCS#11), and investigating lazy re-encryption algorithms to optimize key rotation for large datasets.

Prior to enterprise production deployment, operational hardening must be implemented: replacing local configurations with enterprise secret managers (e.g., HashiCorp Vault), integrating scalable cloud object stores with at-rest server-side encryption, deploying redundant RPC gateway infrastructure, replacing JSON metadata files with ACID-compliant relational databases (e.g., PostgreSQL), implementing token-based authentication (OAuth 2.0 / OIDC), and conducting independent third-party penetration testing.

---

## VII. CONCLUSION

In this paper, we presented the design, implementation, and experimental evaluation of **SecureCloud+**, a hybrid cryptographic architecture for secure cloud file storage. The system integrates dynamic AES-256-GCM symmetric encryption for payload confidentiality and at-rest tamper resistance, SECP256R1 Elliptic Curve Diffie-Hellman (ECDH) key exchange paired with HKDF-SHA256 for asymmetric key encapsulation, deterministic rule-based access control (`OWNER`, `READ`, `DOWNLOAD`, `DENIED`), automated key rotation with payload re-encryption upon user revocation, and decentralized metadata anchoring via an EVM-compatible Solidity smart contract (`FileKeyManager.sol`). By enforcing access authorization prior to cryptographic key unwrapping and maintaining zero exposure of plaintext payloads, symmetric keys, or private ECC keys on the public ledger, the architecture establishes a defense-in-depth framework against semi-trusted storage providers and unauthorized network actors, while ensuring that revoked users are barred from accessing subsequent protected file versions.

The functional correctness and operational performance of the SecureCloud+ prototype were validated through systematic experimentation and an automated test suite comprising 50 unit and integration tests, all of which passed with zero failures. Cryptographic benchmarks conducted across file sizes from 10 KB to 5 MB demonstrated that AES-256-GCM encryption and decryption scaled within 0.0698–5.6952 ms and 0.0156–4.6281 ms, respectively, while blockchain transaction execution times remained relatively stable across the evaluated payload sizes in the local EVM environment (96.75–108.08 ms) due to on-chain recording of fixed-size metadata alone. Total API upload latency averaged 142.79–184.57 ms, download latency averaged 33.51–48.56 ms, and synchronous key rotation with payload re-encryption was achieved within 108.76–140.52 ms. Furthermore, all eight formal security validation experiments confirmed critical system invariants, including distinct ciphertexts for identical plaintexts, immediate detection of ciphertext bit tampering, robust rejection of mismatched ECC private keys, pre-decryption rejection of unauthorized and revoked users with `HTTP 403 Forbidden`, and selective access preservation for remaining authorized grantees.

While these empirical findings substantiate the feasibility and defensive rigor of the SecureCloud+ architecture, the current evaluation remains bounded by its prototype implementation on a local host utilizing an EVM development node and local filesystem storage. The system's operational guarantees depend on the integrity of client-side private key storage and acknowledge the inherent physical boundary that previously downloaded plaintext copies cannot be remotely eradicated following access revocation. Future work will focus on transitioning the storage layer to distributed commercial cloud object stores, deploying smart contracts onto public Layer-2 rollups to quantify real-world gas economics and network latency, conducting formal mechanized protocol verification using automated tools such as ProVerif, and integrating hardware-backed client key protection mechanisms to advance the practical deployment of decentralized, trustworthy cloud data storage.

---

## References

- [1] H. H. Shakor, H. K. Omar, E. M. E. A. Mansoor, and K. M. O. Ahmad, "Dynamic AES Encryption and Blockchain Key Management: A Novel Solution for Cloud Data Security," *IEEE Access*, vol. 12, pp. 26334–26343, Jan. 2024. DOI: 10.1109/ACCESS.2024.3351119.
- [2] M. Dworkin, "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC," *NIST Special Publication 800-38D*, National Institute of Standards and Technology, Gaithersburg, MD, USA, Nov. 2007. DOI: 10.6028/NIST.SP.800-38D.
- [3] National Institute of Standards and Technology (NIST), "Secure Hash Standard (SHS)," *Federal Information Processing Standards Publication (FIPS PUB) 180-4*, Gaithersburg, MD, USA, Aug. 2015. DOI: 10.6028/NIST.FIPS.180-4.
- [4] H. Krawczyk and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)," *Internet Engineering Task Force (IETF) RFC 5869*, May 2010. DOI: 10.17487/RFC5869.
- [5] E. Barker, L. Chen, A. Roginsky, A. Vassilev, and R. Davis, "Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography," *NIST Special Publication 800-56A Revision 3*, National Institute of Standards and Technology, Gaithersburg, MD, USA, Apr. 2018. DOI: 10.6028/NIST.SP.800-56Ar3.
- [6] C. Lin, D. He, N. Kumar, K.-K. R. Choo, A. Vinel, and X. Huang, "Security and Privacy for IoT Dynamic Data Sharing with Consortium Blockchain," *IEEE Internet of Things Journal*, vol. 9, no. 12, pp. 9363–9373, Jun. 2022. DOI: 10.1109/JIOT.2021.3117585.
- [7] S. Zang, L. Kong, J. Dong, and F. Liu, "A Blockchain-Based Decentralized Storage Scheme Over Cloud-Native Edge Architecture," *IEEE Access*, vol. 12, pp. 12345–12356, Feb. 2024. DOI: 10.1109/ACCESS.2024.3362145.
- [8] Y. Liu, J. Zhang, X. Lin, and M. Guizani, "Secure and Efficient Cross-Domain Data Sharing with Zero-Trust Sharding Blockchain in Cloud Storage," *IEEE Transactions on Dependable and Secure Computing*, vol. 21, no. 2, pp. 842–857, Mar./Apr. 2024. DOI: 10.1109/TDSC.2023.3289104.
- [9] Y. Xiao, N. Zhang, W. Lou, and Y. T. Hou, "Privacy-Preserving and Flexible Attribute-Based Access Control in Cloud Storage via Blockchain," *IEEE Transactions on Services Computing*, vol. 15, no. 4, pp. 2145–2158, Jul./Aug. 2022. DOI: 10.1109/TSC.2020.3039755.
- [10] X. Yang, X. Yi, S. Nepal, and A. Bouguettaya, "Decentralized and Fine-Grained Access Control for Electronic Health Records in Cloud Using Blockchain," *Future Generation Computer Systems*, vol. 132, pp. 312–323, Jul. 2022. DOI: 10.1016/j.future.2022.02.019.
- [11] E. Luo, D. He, S. Zeadally, and N. Kumar, "Key-Policy Attribute-Based Encryption with Switchable Attributes for Secure Cloud Data Sharing," *IEEE Transactions on Information Forensics and Security*, vol. 19, pp. 1567–1580, Jan. 2024. DOI: 10.1109/TIFS.2023.3341209.
- [12] L. Yao, C. Lin, X. Shen, and Z. Guan, "Revocable and Conditional Proxy Re-Encryption for Secure Cloud Data Dissemination," *IEEE Access*, vol. 9, pp. 45123–45135, Mar. 2021. DOI: 10.1109/ACCESS.2021.3067182.
- [13] W. Susilo, F. Guo, R. Yang, and J. Lai, "Sanitizable and Verifiable Access Control with Efficient Revocation in Cloud Storage," *IEEE Transactions on Dependable and Secure Computing*, vol. 19, no. 6, pp. 4012–4025, Nov./Dec. 2022. DOI: 10.1109/TDSC.2021.3119854.
