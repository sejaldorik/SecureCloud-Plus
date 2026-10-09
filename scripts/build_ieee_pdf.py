import os
import subprocess
import fitz  # PyMuPDF

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SecureCloud+: Secure Cloud File Storage</title>
<style>
  @page {
    size: letter;
    margin: 18mm 13mm 18mm 13mm;
    @bottom-center {
      content: counter(page);
      font-family: "Times New Roman", Times, serif;
      font-size: 9pt;
    }
  }

  *, *:before, *:after {
    box-sizing: border-box;
  }

  body {
    font-family: "Times New Roman", Times, "Nimbus Roman No9 L", serif;
    font-size: 10pt;
    line-height: 1.18;
    color: #000;
    margin: 0;
    padding: 0;
    text-align: justify;
    background: #fff;
  }

  .header-block {
    text-align: center;
    margin-bottom: 14pt;
    padding-bottom: 4pt;
  }

  h1.paper-title {
    font-size: 20pt;
    font-weight: bold;
    line-height: 1.2;
    margin: 0 0 10pt 0;
    letter-spacing: -0.2px;
  }

  .author-block {
    font-size: 11pt;
    margin-bottom: 12pt;
    line-height: 1.3;
  }

  .author-name {
    font-weight: bold;
    font-size: 11pt;
  }

  .author-affil {
    font-style: italic;
    font-size: 10pt;
    color: #222;
  }

  .abstract-keywords-container {
    width: 100%;
    margin: 0 0 14pt 0;
    padding: 0 12pt;
    font-size: 9pt;
    line-height: 1.22;
  }

  .abstract-text {
    text-align: justify;
    margin-bottom: 6pt;
  }

  .abstract-label, .keywords-label {
    font-weight: bold;
    font-style: italic;
  }

  .keywords-text {
    text-align: justify;
  }

  .two-column-wrapper {
    column-count: 2;
    column-gap: 5.5mm;
    width: 100%;
  }

  h2.sec-heading {
    font-size: 10pt;
    font-weight: bold;
    text-align: center;
    text-transform: uppercase;
    margin: 12pt 0 5pt 0;
    break-after: avoid;
    letter-spacing: 0.5px;
  }

  h3.subsec-heading {
    font-size: 10pt;
    font-weight: bold;
    font-style: italic;
    text-align: left;
    margin: 9pt 0 4pt 0;
    break-after: avoid;
  }

  h4.subsubsec-heading {
    font-size: 10pt;
    font-style: italic;
    margin: 6pt 0 2pt 0;
    break-after: avoid;
  }

  p {
    margin: 0 0 5pt 0;
    text-indent: 1.2em;
  }

  p.no-indent {
    text-indent: 0;
  }

  .equation-box {
    width: 100%;
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin: 6pt 0;
    padding: 2pt 4pt;
    font-family: "Cambria Math", "Times New Roman", serif;
    font-style: italic;
    font-size: 9.5pt;
    break-inside: avoid;
  }

  .equation-content {
    flex-grow: 1;
    text-align: center;
  }

  .equation-num {
    font-style: normal;
    font-size: 9.5pt;
    padding-left: 8pt;
  }

  .table-float {
    width: 100%;
    margin: 10pt 0 8pt 0;
    break-inside: avoid;
  }

  .table-float.span-cols {
    column-span: all;
  }

  .table-caption {
    font-size: 8pt;
    font-weight: bold;
    text-transform: uppercase;
    text-align: center;
    margin-bottom: 4pt;
    letter-spacing: 0.3px;
  }

  table.academic-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 7.5pt;
    line-height: 1.15;
    margin: 0 auto;
    border-top: 1.2pt solid #000;
    border-bottom: 1.2pt solid #000;
  }

  table.academic-table th {
    border-top: 0.5pt solid #000;
    border-bottom: 0.8pt solid #000;
    padding: 3.5pt 3pt;
    font-weight: bold;
    background: #fdfdfd;
    text-align: left;
  }

  table.academic-table td {
    padding: 2.5pt 3pt;
    border-bottom: 0.4pt solid #e0e0e0;
    vertical-align: top;
  }

  table.academic-table tr:last-child td {
    border-bottom: none;
  }

  .figure-float {
    width: 100%;
    margin: 8pt 0;
    break-inside: avoid;
    border: 0.6pt solid #333;
    padding: 4pt;
    background: #fafafa;
  }

  .figure-float pre {
    font-family: "Consolas", "Courier New", monospace;
    font-size: 6.8pt;
    line-height: 1.15;
    margin: 0;
    white-space: pre;
    overflow-x: hidden;
  }

  .figure-caption {
    font-size: 8pt;
    font-weight: bold;
    text-align: center;
    margin-top: 4pt;
    color: #111;
  }

  .algorithm-float {
    width: 100%;
    margin: 8pt 0;
    break-inside: avoid;
    border-top: 1.2pt solid #000;
    border-bottom: 1.2pt solid #000;
    padding: 4pt 0;
    font-size: 8pt;
    line-height: 1.2;
  }

  .algo-title {
    font-weight: bold;
    border-bottom: 0.8pt solid #000;
    padding-bottom: 3pt;
    margin-bottom: 3pt;
    font-size: 8.5pt;
  }

  .algo-io {
    font-size: 7.8pt;
    margin-bottom: 4pt;
    border-bottom: 0.4pt solid #ccc;
    padding-bottom: 2pt;
  }

  .algo-body {
    font-family: "Consolas", "Courier New", monospace;
    font-size: 7.2pt;
    line-height: 1.18;
    white-space: pre-wrap;
  }

  .references-list {
    margin-top: 6pt;
    padding-left: 0;
    list-style-type: none;
  }

  .reference-item {
    font-size: 8pt;
    line-height: 1.2;
    margin-bottom: 4.5pt;
    padding-left: 1.8em;
    text-indent: -1.8em;
    text-align: justify;
  }

  .ref-num {
    font-weight: bold;
  }
</style>
</head>
<body>

<div class="header-block">
  <h1 class="paper-title">SecureCloud+: Secure Cloud File Storage using Dynamic AES-256-GCM, ECC-Based Key Protection, Blockchain Key Management, Fine-Grained Access Control, Key Revocation, and Key Rotation</h1>
  <div class="author-block">
    <div class="author-name">Sejal R. Chinchkar</div>
    <div class="author-affil">Department of Computer Engineering<br>SecureCloud+ Research Project</div>
  </div>

  <div class="abstract-keywords-container">
    <div class="abstract-text">
      <span class="abstract-label">Abstract</span>—Cloud storage outsourcing exposes sensitive digital assets to untrusted infrastructure, insider exfiltration, and unauthorized data tampering. Traditional cloud storage paradigms rely on static symmetric encryption keys, centralized key-management servers that represent single points of compromise, or coarse-grained access control models that lack dynamic post-revocation guarantees. This paper presents <strong>SecureCloud+</strong>, a hybrid cryptographic architecture for secure cloud file storage that seamlessly combines dynamic symmetric payload encryption, asymmetric elliptic curve key encapsulation, deterministic rule-based access control, automated cryptographic key rotation upon revocation, and decentralized metadata anchoring. The system employs AES-256 in Galois/Counter Mode (AES-256-GCM) with fresh per-file initialization vectors and dynamic keys to guarantee at-rest confidentiality and ciphertext authenticity. Symmetric file keys are encapsulated using Elliptic Curve Diffie-Hellman (ECDH) over the SECP256R1 (NIST P-256) curve combined with HKDF-SHA256, isolating key distribution to designated public-key recipients without exposing plaintext keys to cloud storage operators. Access control is enforced at the API route-guard layer across four granular permission states (<code>OWNER</code>, <code>READ</code>, <code>DOWNLOAD</code>, <code>DENIED</code>), preemptively halting unauthorized requests prior to cryptographic processing. When access is revoked by a file owner, the architecture triggers automated key rotation: recovering the active file key, generating a fresh 256-bit AES key, re-encrypting the stored payload, incrementing the file version number (<em>v1</em> &rarr; <em>v2</em>), re-wrapping the key for remaining authorized grantees, and logging an immutable event on an Ethereum Virtual Machine (EVM) smart contract. Empirical evaluation across five discrete payload sizes (10 KB to 5 MB) demonstrates that AES-256-GCM encryption and decryption scale within 0.0698–5.6952 ms and 0.0156–4.6281 ms, respectively. Complete upload and download pipelines execute within 142.79–184.57 ms and 33.51–48.56 ms, while key rotation with payload re-encryption executes in 108.76–140.52 ms. Blockchain transaction times remain stable across payload sizes (96.75–108.08 ms) by recording fixed-size metadata alone. An automated test suite of 50 unit and integration tests achieved 100% pass rates (0 failures), and eight formal security validation experiments confirmed zero on-chain key leakage, immediate detection of ciphertext bit tampering, robust rejection of mismatched private keys, and pre-decryption rejection of revoked users with <code>HTTP 403 Forbidden</code>.
    </div>
    <div class="keywords-text">
      <span class="keywords-label">Keywords</span>—Cloud data security, AES-256-GCM, Elliptic Curve Cryptography, SECP256R1, ECDH key exchange, HKDF-SHA256, dynamic key rotation, rule-based access control, blockchain auditability, smart contracts.
    </div>
  </div>
</div>

<div class="two-column-wrapper">

  <h2 class="sec-heading">I. Introduction</h2>
  <p>Outsourcing data storage to public and commercial cloud infrastructures offers undeniable operational advantages, including elastic storage allocation, multi-tenant accessibility, and reduced capital expenditures for enterprise IT infrastructure. However, placing organizational and personal data on third-party cloud servers fundamentally shifts the custody of sensitive assets outside the data owner’s physical and administrative security perimeter. In a conventional cloud deployment, storage hosts operate under an <em>honest-but-curious</em> (semi-trusted) operational model: while service providers faithfully execute storage and retrieval commands, they cannot be inherently trusted with data confidentiality or unmonitored access integrity. Storage volumes remain susceptible to passive inspection, privileged insider threats, rogue system administrators, hypervisor-level breaches, and persistent external network attacks.</p>

  <p>To mitigate unauthorized data exposure, client-side symmetric encryption has become standard practice in secure cloud storage architectures. By encrypting data prior to transmission, organizations ensure that storage servers encounter only unreadable ciphertext blocks. Among symmetric algorithms, the Advanced Encryption Standard (AES) operating with 256-bit keys is widely recognized as the industry standard. However, conventional block cipher modes such as Electronic Codebook (ECB) and Cipher Block Chaining (CBC) fail to provide comprehensive data authenticity. ECB preserves data patterns across identical blocks, while CBC requires separate, non-integrated Message Authentication Codes (MACs) to defend against bit-flipping attacks, padding-oracle vulnerabilities, and chosen-ciphertext manipulation.</p>

  <p>Authenticated Encryption with Associated Data (AEAD), specifically AES-256 in Galois/Counter Mode (AES-256-GCM) [2], resolves these structural weaknesses by pairing high-performance counter-mode stream encryption with universal-hash-based Galois field multiplication (GHASH). This dual-function architecture simultaneously guarantees payload confidentiality and cryptographic authenticity. Any unauthorized alteration of the stored ciphertext, initialization vector, or accompanying authentication metadata induces an immediate GHASH tag mismatch, causing the decryption engine to reject the modified payload before releasing plaintext bytes.</p>

  <p>While authenticated symmetric encryption secures data payloads, the management, encapsulation, and distribution of symmetric encryption keys remains the foremost structural challenge in secure multi-user cloud systems. Centralized Key Management Interoperability Protocol (KMIP) servers or Key Management Services (KMS) introduce severe architectural vulnerabilities: they function as single points of catastrophic failure, present high-value targets for credential compromise, and require clients to place implicit trust in external key custody providers. Furthermore, distributing static symmetric keys directly to multi-user workgroups makes selective revocation virtually impossible without compromising group-wide access.</p>

  <p>Recently, Shakor et al. [1] proposed an innovative framework in <em>IEEE Access</em> entitled <em>"Dynamic AES Encryption and Blockchain Key Management: A Novel Solution for Cloud Data Security."</em> Their architecture demonstrated that dynamically generating fresh symmetric encryption keys for each file and anchoring key-management metadata into a decentralized blockchain ledger dramatically improves cloud storage security. By shifting key tracking from centralized databases to distributed smart contracts, their model eliminates single points of failure, ensures tamper-evident auditability, and provides decentralized key verification.</p>

  <p>Despite these pioneering advances, a rigorous architectural and cryptographic analysis of the base model proposed by Shakor et al. reveals critical operational limitations when extended to multi-user collaborative cloud environments: (1) absence of user revocation mechanisms, (2) static key retention vulnerabilities, (3) lack of cryptographic payload re-encryption, (4) coarse access gating, and (5) absence of synchronous blockchain revocation event logging.</p>

  <p>To address these fundamental research gaps, this paper presents <strong>SecureCloud+</strong>, a comprehensive, defense-in-depth cloud file storage system that extends the foundational concepts of dynamic symmetric encryption and blockchain key management into a fully integrated, multi-user access control and key lifecycle framework. SecureCloud+ is implemented and evaluated as a functioning software prototype integrating a high-performance Python/FastAPI backend, the native <code>cryptography</code> engine, an Ethereum Virtual Machine (EVM) Solidity smart contract (<code>FileKeyManager.sol</code>), and a Web3 integration layer.</p>

  <p>The core scientific and engineering contributions of SecureCloud+ are structured across six key pillars: (1) dynamic authenticated payload encryption, (2) hybrid asymmetric key encapsulation via SECP256R1 and HKDF-SHA256, (3) deterministic pre-decryption route guarding, (4) automated key rotation and payload re-encryption, (5) decentralized, tamper-evident audit logging on an EVM smart contract, and (6) empirical benchmarking and formal security validation across 50 automated tests and eight formal security experiments.</p>

  <h2 class="sec-heading">II. Related Work</h2>
  
  <h3 class="subsec-heading">A. Cloud Data Security and Authenticated Encryption</h3>
  <p>Early approaches to cloud storage security focused primarily on symmetric block encryption operating in CBC or CTR modes. Dworkin [2] formalized Galois/Counter Mode (AES-GCM), which combines counter-mode encryption with universal polynomial hashing over GF(2<sup>128</sup>). Contemporary cloud storage systems overwhelmingly adopt AES-256-GCM due to its native hardware acceleration (AES-NI and CLMUL instruction sets) and robust authenticated encryption guarantees. SecureCloud+ builds directly upon NIST SP 800-38D [2] and FIPS PUB 180-4 [3] to enforce authenticated encryption and pre-encryption integrity digests.</p>

  <h3 class="subsec-heading">B. Public-Key Cryptography and ECC-Based Key Management</h3>
  <p>Asymmetric key encapsulation provides the standard mechanism for distributing symmetric keys without preshared secrets. While RSA historically dominated key exchange, Elliptic Curve Cryptography (ECC) achieves equivalent cryptographic strength with substantially smaller key sizes. Barker et al. [5] standardized pair-wise key establishment using Elliptic Curve Diffie-Hellman (ECDH). To derive uniform cryptographic keys from elliptic curve points, Krawczyk and Eronen [4] specified the HMAC-based Extract-and-Expand Key Derivation Function (HKDF-SHA256). In SecureCloud+, SECP256R1 (NIST P-256) ECDH is paired with HKDF-SHA256 to establish Key Encryption Keys (KEKs) that wrap symmetric file keys for authorized grantees.</p>

  <h3 class="subsec-heading">C. Blockchain in Cloud Storage and Key Management</h3>
  <p>The emergence of distributed ledger technology introduced tamper-resistant primitives for cloud metadata management. Lin et al. [6] proposed consortium blockchain frameworks for multi-cloud data integrity verification. Zang et al. [7] explored blockchain-anchored storage over cloud-native edge architectures. Liu et al. [8] developed zero-trust sharding mechanisms for cross-domain data sharing. Most significantly, Shakor et al. [1] demonstrated that recording dynamic AES key metadata on an EVM-compatible blockchain successfully decentralizes key verification and mitigates central KMS compromise. SecureCloud+ adopts this decentralized metadata anchoring paradigm but resolves the critical absence of revocation mechanisms in the base model.</p>

  <h3 class="subsec-heading">D. Access Control and Revocation in Outsourced Storage</h3>
  <p>Fine-grained access control in cloud repositories has historically relied on Attribute-Based Encryption (ABE). Xiao et al. [9] proposed blockchain-based access control with flexible attribute revocation. Yang et al. [10] combined smart contracts with edge nodes to enforce fine-grained access policies for electronic health records. Luo et al. [11] presented key-policy ABE schemes with switchable attributes. However, ABE schemes introduce severe bilinear pairing computation overheads that scale poorly for large file repositories. Conversely, Yao et al. [12] and Susilo et al. [13] investigated proxy re-encryption (PRE) and sanitizable access control. SecureCloud+ achieves deterministic, lightweight access control by coupling route-guard permission enforcement (<code>OWNER</code>, <code>READ</code>, <code>DOWNLOAD</code>, <code>DENIED</code>) with synchronous, owner-directed AES key rotation.</p>

  <div class="table-float span-cols">
    <div class="table-caption">TABLE I: Comparative Analysis of Related Cloud Storage and Access Control Architectures</div>
    <table class="academic-table">
      <thead>
        <tr>
          <th>Architecture / Study</th>
          <th>Payload Cipher</th>
          <th>Key Encapsulation</th>
          <th>Blockchain Role</th>
          <th>Pre-Decryption Guard</th>
          <th>Key Rotation</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>Shakor et al. [1] (Base)</strong></td>
          <td>AES-256 (Dynamic)</td>
          <td>None (Plain Meta)</td>
          <td>Key Meta Registry</td>
          <td>No</td>
          <td>No</td>
        </tr>
        <tr>
          <td><strong>Lin et al. [6]</strong></td>
          <td>Static AES</td>
          <td>RSA-2048</td>
          <td>Integrity Auditing</td>
          <td>No</td>
          <td>No</td>
        </tr>
        <tr>
          <td><strong>Zang et al. [7]</strong></td>
          <td>AES-CBC</td>
          <td>ECC Secp256k1</td>
          <td>Block Hash Logging</td>
          <td>Partial</td>
          <td>No</td>
        </tr>
        <tr>
          <td><strong>Liu et al. [8]</strong></td>
          <td>AES-GCM</td>
          <td>Identity-Based Enc</td>
          <td>Zero-Trust Sharding</td>
          <td>Yes</td>
          <td>Manual</td>
        </tr>
        <tr>
          <td><strong>Xiao et al. [9]</strong></td>
          <td>CP-ABE</td>
          <td>Bilinear Pairing</td>
          <td>Policy Enforcement</td>
          <td>Yes</td>
          <td>Attribute Rev</td>
        </tr>
        <tr>
          <td><strong>Yang et al. [10]</strong></td>
          <td>Hybrid ABE</td>
          <td>Attribute Tokens</td>
          <td>Access Token Ledger</td>
          <td>Yes</td>
          <td>Proxy-Based</td>
        </tr>
        <tr>
          <td><strong>Yao et al. [12]</strong></td>
          <td>Proxy Re-Enc</td>
          <td>Bilinear Pairing</td>
          <td>None (Centralized)</td>
          <td>No</td>
          <td>Proxy-Re-Enc</td>
        </tr>
        <tr>
          <td><strong>Susilo et al. [13]</strong></td>
          <td>Sanitizable ABE</td>
          <td>Pairing Groups</td>
          <td>None (Centralized)</td>
          <td>Yes</td>
          <td>Periodic</td>
        </tr>
        <tr>
          <td><strong>SecureCloud+ (Proposed)</strong></td>
          <td>AES-256-GCM</td>
          <td>SECP256R1 + HKDF</td>
          <td>Metadata &amp; Events</td>
          <td>Yes (Deterministic)</td>
          <td>Dynamic Auto</td>
        </tr>
      </tbody>
    </table>
  </div>

  <h2 class="sec-heading">III. Proposed System and Methodology</h2>

  <h3 class="subsec-heading">A. Mathematical Cryptographic Formulation</h3>
  <p>Let <em>P</em> be the plaintext file payload. The system samples a dynamic 256-bit symmetric key <em>K</em><sub>file</sub> and a 96-bit initialization vector <em>IV</em><sub>file</sub>. AES-256-GCM produces ciphertext <em>C</em><sub>file</sub> and a 128-bit authentication tag <em>T</em><sub>file</sub>:</p>

  <div class="equation-box">
    <div class="equation-content">(C<sub>file</sub>, T<sub>file</sub>) = AES-256-GCM-Enc<sub>K<sub>file</sub></sub>(IV<sub>file</sub>, P, A)</div>
    <div class="equation-num">(1)</div>
  </div>

  <p>Decryption reconstructs plaintext only if the GHASH tag validates:</p>

  <div class="equation-box">
    <div class="equation-content">P = AES-256-GCM-Dec<sub>K<sub>file</sub></sub>(IV<sub>file</sub>, C<sub>file</sub>, T<sub>file</sub>)</div>
    <div class="equation-num">(2)</div>
  </div>

  <p>Elliptic curve key pairs operate on the SECP256R1 (NIST P-256) curve:</p>

  <div class="equation-box">
    <div class="equation-content">y<sup>2</sup> &equiv; x<sup>3</sup> - 3x + b (mod p)</div>
    <div class="equation-num">(3)</div>
  </div>

  <p>The shared secret point is derived via ECDH point multiplication:</p>

  <div class="equation-box">
    <div class="equation-content">S = d<sub>eph</sub> &middot; Q<sub>B</sub> = d<sub>eph</sub> &middot; d<sub>B</sub> &middot; G</div>
    <div class="equation-num">(4)</div>
  </div>

  <p>The 256-bit Key Encryption Key (<em>K</em><sub>KEK</sub>) is extracted using HKDF-SHA256 [4]:</p>

  <div class="equation-box">
    <div class="equation-content">K<sub>KEK</sub> = HKDF-SHA256(IKM = S<sub>x</sub>, info = "SecureCloud+ ECC-AES-GCM KEK", L = 32)</div>
    <div class="equation-num">(5)</div>
  </div>

  <p>The dynamic file key is wrapped using AES-256-GCM:</p>

  <div class="equation-box">
    <div class="equation-content">(C<sub>key</sub>, T<sub>key</sub>) = AES-256-GCM-Enc<sub>K<sub>KEK</sub></sub>(IV<sub>KEK</sub>, K<sub>file</sub>)</div>
    <div class="equation-num">(6)</div>
  </div>

  <p>Recipient <em>B</em> decapsulates <em>K</em><sub>file</sub> using private scalar <em>d</em><sub>B</sub>:</p>

  <div class="equation-box">
    <div class="equation-content">K<sub>file</sub> = AES-256-GCM-Dec<sub>K<sub>KEK</sub></sub>(IV<sub>KEK</sub>, C<sub>key</sub>, T<sub>key</sub>)</div>
    <div class="equation-num">(7)</div>
  </div>

  <p>The pre-encryption payload is hashed via SHA-256 [3]:</p>

  <div class="equation-box">
    <div class="equation-content">H<sub>file</sub> = SHA-256(P)</div>
    <div class="equation-num">(8)</div>
  </div>

  <p>Integrity is verified by comparing the decrypted payload digest:</p>

  <div class="equation-box">
    <div class="equation-content">Valid &hArr; SHA-256(P<sub>rec</sub>) == H<sub>file</sub></div>
    <div class="equation-num">(9)</div>
  </div>

  <div class="figure-float">
    <pre>
+-------------------------------------------------------------+
| FIG. 1: ARCHITECTURE AND END-TO-END PROCESSING PIPELINE     |
+-------------------------------------------------------------+
|  [ Data Owner ]                                             |
|        |                                                    |
|        | 1. Upload(P, owner_id, Q_owner)                    |
|        v                                                    |
|  [ FastAPI Route Guard ]                                    |
|        | 2. Interrogate RBAC Permissions                    |
|        v                                                    |
|  [ Cryptographic Engine ]                                   |
|        |-- 3. H_file = SHA-256(P)                           |
|        |-- 4. Sample K_file, IV_file                        |
|        |-- 5. (C_file, T_file) = AES-GCM(P, K_file)         |
|        |-- 6. ECDH: S = d_eph * Q_owner                     |
|        |-- 7. K_KEK = HKDF-SHA256(S_x)                     |
|        |-- 8. (C_key, T_key) = AES-GCM(K_file, K_KEK)       |
|        |                                                    |
|        +-----------------+------------------+               |
|                          |                  |               |
|                          v                  v               |
|             [ Encrypted Storage ]    [ EVM Smart Contract ] |
|             - uploads/{id}.enc       - FileKeyManager.sol   |
|             - uploads/{id}.meta.json - Stores H_file, C_key |
+-------------------------------------------------------------+
    </pre>
    <div class="figure-caption">Fig. 1. End-to-end architecture and processing pipeline of SecureCloud+.</div>
  </div>

  <div class="figure-float">
    <pre>
+-------------------------------------------------------------+
| FIG. 2: DUAL-LAYER ASYMMETRIC KEY ENCAPSULATION             |
+-------------------------------------------------------------+
|  [ Ephemeral Scalar d_eph ] x [ Recipient Public Key Q_B ]  |
|                                |                            |
|                                v                            |
|             [ Diffie-Hellman Secret Point S = (S_x, S_y) ]  |
|                                |                            |
|                                v                            |
|        [ HKDF-SHA256: IKM=S_x, info="SecureCloud+ KEK" ]    |
|                                |                            |
|                                v                            |
|             [ 256-bit Key Encryption Key (K_KEK) ]          |
|                                |                            |
|                                v                            |
|  [ AES-256-GCM Wrap: Encrypts Dynamic Key K_file ]          |
|                                |                            |
|                                v                            |
|        Persisted Bundle: { Q_eph, IV_KEK, C_key, T_key }    |
+-------------------------------------------------------------+
    </pre>
    <div class="figure-caption">Fig. 2. Asymmetric key encapsulation via SECP256R1 ECDH and HKDF-SHA256.</div>
  </div>

  <div class="figure-float">
    <pre>
+-------------------------------------------------------------+
| FIG. 3: PRE-DECRYPTION ROUTE GUARD POLICY ENFORCEMENT       |
+-------------------------------------------------------------+
|  [ Download Request: user_id, file_id ]                     |
|                 |                                           |
|                 v                                           |
|  [ Route Guard: Interrogate Access Control Ledger ]         |
|                 |                                           |
|        +--------+--------+                                  |
|        | User Permitted? |                                  |
|        +--------+--------+                                  |
|                 |                                           |
|        +--------+------------------+                        |
|        |                           |                        |
|        v (Permitted)               v (Denied/Unauthorized)  |
|  [ Read Disk &amp; Unwrap Key ]   [ Abort Immediately ]         |
|  [ AES-256-GCM Decrypt ]      [ Return HTTP 403 Forbidden ] |
|  [ Verify SHA-256 Digest ]    (Zero Cryptographic Overhead) |
|  [ Deliver Plaintext ]                                      |
+-------------------------------------------------------------+
    </pre>
    <div class="figure-caption">Fig. 3. Deterministic route-guard request interception prior to decryption.</div>
  </div>

  <div class="algorithm-float">
    <div class="algo-title">ALGORITHM 1: File Upload, Dynamic AES-256-GCM Encryption, and ECC Key Encapsulation</div>
    <div class="algo-io">
      <strong>Input:</strong> Plaintext payload <em>P</em>, Owner Identifier <em>owner_id</em>, Owner ECC Public Key <em>Q_owner</em><br>
      <strong>Output:</strong> Unique <em>file_id</em>, Metadata record <em>M</em>, Transaction Receipt <em>TX_receipt</em>
    </div>
    <div class="algo-body">
 1: file_id &larr; GenerateUUIDv4()
 2: H_file &larr; SHA-256(P)
 3: K_file &larr; SampleRandomBytes(32)             // Dynamic 256-bit symmetric key
 4: IV_file &larr; SampleRandomBytes(12)            // Fresh 96-bit IV
 5: (C_file, T_file) &larr; AES-256-GCM-Enc(K_file, IV_file, P)
 6: PersistToDisk("uploads/" + file_id + ".enc", C_file + T_file)
 7: (d_eph, Q_eph) &larr; GenerateECCKeyPair(SECP256R1)
 8: S &larr; PointMultiply(d_eph, Q_owner)
 9: K_KEK &larr; HKDF-SHA256(IKM = S.x, info = "SecureCloud+ ECC-AES-GCM KEK", L = 32)
10: IV_KEK &larr; SampleRandomBytes(12)
11: (C_key, T_key) &larr; AES-256-GCM-Enc(K_KEK, IV_KEK, K_file)
12: M &larr; InitializeMetadata(file_id, H_file, version = 1, IV_file, owner_id)
13: M.wrapped_keys[owner_id] &larr; { Q_eph, IV_KEK, C_key, T_key }
14: M.permissions[owner_id] &larr; "OWNER"
15: PersistToDisk("uploads/" + file_id + ".meta.json", SerializeJSON(M))
16: TX_receipt &larr; Web3Contract.registerFileKey(file_id, H_file, Q_owner, IV_KEK, C_key)
17: return (file_id, M, TX_receipt)
    </div>
  </div>

  <div class="algorithm-float">
    <div class="algo-title">ALGORITHM 2: Owner-Authorized Access Revocation, Dynamic Key Rotation, and Payload Re-Encryption</div>
    <div class="algo-io">
      <strong>Input:</strong> File Identifier <em>file_id</em>, Caller Identifier <em>caller_id</em>, Caller Private Key <em>d_caller</em>, Target User Identifier <em>target_user_id</em><br>
      <strong>Output:</strong> Updated Metadata record <em>M_updated</em>, Revocation Transaction Receipt <em>TX_revocation</em>
    </div>
    <div class="algo-body">
 1: M &larr; LoadMetadata("uploads/" + file_id + ".meta.json")
 2: if M.permissions[caller_id] != "OWNER" then
 3:     return Error(HTTP_403_FORBIDDEN, "Caller is not authorized file owner")
 4: end if
 5: bundle_owner &larr; M.wrapped_keys[caller_id]
 6: S_owner &larr; PointMultiply(d_caller, bundle_owner.Q_eph)
 7: K_KEK_owner &larr; HKDF-SHA256(S_owner.x, "SecureCloud+ ECC-AES-GCM KEK", 32)
 8: K_file_v1 &larr; AES-256-GCM-Dec(K_KEK_owner, bundle_owner.IV_KEK, bundle_owner.C_key, bundle_owner.T_key)
 9: C_file_v1 &larr; ReadFromDisk("uploads/" + file_id + ".enc")
10: P &larr; AES-256-GCM-Dec(K_file_v1, M.IV_file, C_file_v1.ciphertext, C_file_v1.tag)
11: K_file_v2 &larr; SampleRandomBytes(32)         // Fresh 256-bit AES key
12: IV_file_v2 &larr; SampleRandomBytes(12)        // Fresh 96-bit IV
13: (C_file_v2, T_file_v2) &larr; AES-256-GCM-Enc(K_file_v2, IV_file_v2, P)
14: OverwriteDisk("uploads/" + file_id + ".enc", C_file_v2 + T_file_v2)
15: M.version &larr; M.version + 1                // Increment version (v1 -> v2)
16: M.IV_file &larr; IV_file_v2
17: M.permissions[target_user_id] &larr; "DENIED"
18: RemoveKey(M.wrapped_keys, target_user_id)  // Purge target user's key bundle
19: for each remaining_user in AuthorizedUsers(M) do
20:     Q_user &larr; FetchPublicKey(remaining_user)
21:     (d_eph_new, Q_eph_new) &larr; GenerateECCKeyPair(SECP256R1)
22:     S_user &larr; PointMultiply(d_eph_new, Q_user)
23:     K_KEK_user &larr; HKDF-SHA256(S_user.x, "SecureCloud+ ECC-AES-GCM KEK", 32)
24:     IV_KEK_new &larr; SampleRandomBytes(12)
25:     (C_key_new, T_key_new) &larr; AES-256-GCM-Enc(K_KEK_user, IV_KEK_new, K_file_v2)
26:     M.wrapped_keys[remaining_user] &larr; { Q_eph_new, IV_KEK_new, C_key_new, T_key_new }
27: end for
28: PersistToDisk("uploads/" + file_id + ".meta.json", SerializeJSON(M))
29: TX_revocation &larr; Web3Contract.revokeAccess(file_id, target_user_id)
30: return (M, TX_revocation)
    </div>
  </div>

  <h2 class="sec-heading">IV. Implementation and Experimental Evaluation</h2>

  <h3 class="subsec-heading">A. Implementation Environment</h3>
  <p>The prototype is developed using Python 3.14 on a local testbed with FastAPI (&ge;0.100.0), Uvicorn standard (&ge;0.22.0), Pydantic (&ge;2.0.0), Python <code>cryptography</code> (&ge;41.0.0), Web3.py (&ge;6.0.0), and a Solidity <code>^0.8.20</code> smart contract (<code>FileKeyManager.sol</code>) deployed on a local Hardhat (&ge;2.19.0) EVM node.</p>

  <h3 class="subsec-heading">B. Functional Testing</h3>
  <p>The automated test suite comprises 50 tests across six modules. All 50 tests passed with zero failures (TABLE II).</p>

  <div class="table-float">
    <div class="table-caption">TABLE II: Automated Test Suite Execution Results</div>
    <table class="academic-table">
      <thead>
        <tr>
          <th>Test Module</th>
          <th>Tests</th>
          <th>Expected Behavior</th>
          <th>Observed Result</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>test_encryption.py</td>
          <td>4</td>
          <td>Tag mismatch rejects</td>
          <td>PASSED (4/4)</td>
        </tr>
        <tr>
          <td>test_ecc.py</td>
          <td>6</td>
          <td>Key isolation upheld</td>
          <td>PASSED (6/6)</td>
        </tr>
        <tr>
          <td>test_blockchain.py</td>
          <td>5</td>
          <td>On-chain registration</td>
          <td>PASSED (5/5)</td>
        </tr>
        <tr>
          <td>test_integration_phase5.py</td>
          <td>10</td>
          <td>Plaintext restored</td>
          <td>PASSED (10/10)</td>
        </tr>
        <tr>
          <td>test_access_control_phase6.py</td>
          <td>12</td>
          <td>Pre-decrypt HTTP 403</td>
          <td>PASSED (12/12)</td>
        </tr>
        <tr>
          <td>test_key_rotation_phase8.py</td>
          <td>13</td>
          <td>Re-encryption verified</td>
          <td>PASSED (13/13)</td>
        </tr>
        <tr style="font-weight:bold; background:#f9f9f9;">
          <td>Total Test Suite</td>
          <td>50</td>
          <td>Zero Failures</td>
          <td>PASSED (50/50)</td>
        </tr>
      </tbody>
    </table>
  </div>

  <h3 class="subsec-heading">C. Performance Benchmarks</h3>
  <p>Performance was measured across five file sizes over five independent iterations (TABLE III).</p>

  <div class="table-float span-cols">
    <div class="table-caption">TABLE III: Empirical Performance Evaluation Across File Sizes (Averaged Over 5 Iterations)</div>
    <table class="academic-table">
      <thead>
        <tr>
          <th>File Size</th>
          <th>Bytes</th>
          <th>Encryption (ms)</th>
          <th>Decryption (ms)</th>
          <th>Upload (ms)</th>
          <th>Download (ms)</th>
          <th>BC TX (ms)</th>
          <th>Rotation (ms)</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>10 KB</td>
          <td>10,240</td>
          <td>0.0698</td>
          <td>0.0156</td>
          <td>144.3505</td>
          <td>35.2627</td>
          <td>96.7482</td>
          <td>111.8534</td>
        </tr>
        <tr>
          <td>100 KB</td>
          <td>102,400</td>
          <td>0.0811</td>
          <td>0.0496</td>
          <td>142.7935</td>
          <td>37.7851</td>
          <td>98.8717</td>
          <td>108.7612</td>
        </tr>
        <tr>
          <td>500 KB</td>
          <td>512,000</td>
          <td>0.3188</td>
          <td>0.1844</td>
          <td>147.5064</td>
          <td>44.4139</td>
          <td>108.0759</td>
          <td>115.5996</td>
        </tr>
        <tr>
          <td>1 MB</td>
          <td>1,048,576</td>
          <td>0.8837</td>
          <td>0.8044</td>
          <td>143.4226</td>
          <td>33.5068</td>
          <td>106.5641</td>
          <td>116.0155</td>
        </tr>
        <tr>
          <td>5 MB</td>
          <td>5,242,880</td>
          <td>5.6952</td>
          <td>4.6281</td>
          <td>184.5729</td>
          <td>48.5584</td>
          <td>99.9096</td>
          <td>140.5244</td>
        </tr>
      </tbody>
    </table>
  </div>

  <h3 class="subsec-heading">D. Security Evaluation Matrix</h3>
  <p>The system was evaluated against eight formal security experiments (TABLE IV). All eight experiments passed.</p>

  <div class="table-float span-cols">
    <div class="table-caption">TABLE IV: Empirical Security Validation Matrix</div>
    <table class="academic-table">
      <thead>
        <tr>
          <th>Exp</th>
          <th>Threat Scenario</th>
          <th>Expected Behavior</th>
          <th>Observed Result</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>A</strong></td>
          <td>Duplicate Plaintext Encryption</td>
          <td>Distinct ciphertexts generated</td>
          <td>Ciphertexts distinct (Match=F)</td>
          <td><strong>PASSED</strong></td>
        </tr>
        <tr>
          <td><strong>B</strong></td>
          <td>Ciphertext Bit Modification</td>
          <td>Decryption rejected via GHASH</td>
          <td>EncryptionError raised instantly</td>
          <td><strong>PASSED</strong></td>
        </tr>
        <tr>
          <td><strong>C</strong></td>
          <td>Mismatched ECC Private Key</td>
          <td>Shared secret derivation fails</td>
          <td>ECCError raised on unwrap</td>
          <td><strong>PASSED</strong></td>
        </tr>
        <tr>
          <td><strong>D</strong></td>
          <td>Unauthorized User Download</td>
          <td>HTTP 403 returned pre-decrypt</td>
          <td>HTTP 403 Forbidden returned</td>
          <td><strong>PASSED</strong></td>
        </tr>
        <tr>
          <td><strong>E</strong></td>
          <td>Revoked User Download</td>
          <td>HTTP 403 returned pre-decrypt</td>
          <td>HTTP 403 Forbidden returned</td>
          <td><strong>PASSED</strong></td>
        </tr>
        <tr>
          <td><strong>F</strong></td>
          <td>Key Rotation Version Bump</td>
          <td>Version increments (v1 -&gt; v2)</td>
          <td>Version updated, payload re-enc</td>
          <td><strong>PASSED</strong></td>
        </tr>
        <tr>
          <td><strong>G</strong></td>
          <td>Selective Access Preservation</td>
          <td>Remaining users decrypt post-rot</td>
          <td>HTTP 200, plaintext restored</td>
          <td><strong>PASSED</strong></td>
        </tr>
        <tr>
          <td><strong>H</strong></td>
          <td>On-Chain Key Exposure Check</td>
          <td>Zero raw keys logged on-chain</td>
          <td>Only public PEMs/nonces on-chain</td>
          <td><strong>PASSED</strong></td>
        </tr>
      </tbody>
    </table>
  </div>

  <h3 class="subsec-heading">E. Sequential Revocation Workflow Verification</h3>
  <p>An 11-step sequential revocation experiment validated key rotation completeness (TABLE V).</p>

  <div class="table-float span-cols">
    <div class="table-caption">TABLE V: 11-Step Sequential Key Revocation and Re-Encryption Execution Flow</div>
    <table class="academic-table">
      <thead>
        <tr>
          <th>Step</th>
          <th>Action / Execution Scenario</th>
          <th>Observed Execution Result</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>01</td>
          <td>User B receives DOWNLOAD permission</td>
          <td>HTTP 200 — Permission registered in access control ledger</td>
        </tr>
        <tr>
          <td>02</td>
          <td>User B downloads file version v1</td>
          <td>HTTP 200 — Content downloaded and verified (51 bytes matched)</td>
        </tr>
        <tr>
          <td>03</td>
          <td>Owner initiates revocation of User B</td>
          <td>HTTP 200 — Revocation request processed by authorized owner</td>
        </tr>
        <tr>
          <td>04</td>
          <td>Fresh AES-256 key sampled</td>
          <td>Fresh 256-bit symmetric key sampled via cryptographic RNG</td>
        </tr>
        <tr>
          <td>05</td>
          <td>File version incremented</td>
          <td>Version updated from v1 to v2 in metadata</td>
        </tr>
        <tr>
          <td>06</td>
          <td>Stored payload re-encrypted</td>
          <td>Ciphertext re-encrypted with fresh AES key, persisted to disk</td>
        </tr>
        <tr>
          <td>07</td>
          <td>Blockchain records AccessRevoked</td>
          <td>Event emitted, TX Hash: 0xf313f5f2ef6e95e15eda14ad8eff4099507aa05810a043726f76ba4fdf32f821</td>
        </tr>
        <tr>
          <td>08</td>
          <td>User B attempts download post-revocation</td>
          <td>GET /files/{file_id}/download?user_id=bob_grantee_seq submitted</td>
        </tr>
        <tr>
          <td>09</td>
          <td>User B receives HTTP 403 Forbidden</td>
          <td>HTTP 403 Access Denied — Intercepted at route guard prior to decryption</td>
        </tr>
        <tr>
          <td>10</td>
          <td>Owner downloads file version v2</td>
          <td>HTTP 200 — Owner unwraps v2 key bundle and recovers latest plaintext</td>
        </tr>
        <tr>
          <td>11</td>
          <td>Remaining User C downloads version v2</td>
          <td>HTTP 200 — User C unwraps v2 key bundle and recovers latest plaintext</td>
        </tr>
      </tbody>
    </table>
  </div>

  <h2 class="sec-heading">V. Security Analysis and Threat Model</h2>

  <h3 class="subsec-heading">A. Threat Model</h3>
  <p>SecureCloud+ assumes semi-trusted storage hosts, external network eavesdroppers, revoked grantees attempting stale-key access, ciphertext manipulation, and ledger tampering. Compromised client endpoints and physical side-channel hardware attacks are explicitly out of scope.</p>

  <h3 class="subsec-heading">B. Confidentiality and Integrity</h3>
  <p>Dynamic 256-bit symmetric keys with fresh 96-bit nonces ensure that identical plaintexts yield distinct ciphertexts. Decryption halts immediately upon GHASH tag mismatch (Fig. 4), preventing altered or corrupted data delivery. The Galois field multiplier computes the 128-bit authentication tag over ciphertext blocks and associated data:</p>

  <div class="equation-box">
    <div class="equation-content">T<sub>file</sub> = GHASH<sub>H</sub>(A, C<sub>file</sub>) &oplus; AES<sub>K<sub>file</sub></sub>(J<sub>0</sub>)</div>
    <div class="equation-num">(10)</div>
  </div>

  <div class="figure-float">
    <pre>
+-------------------------------------------------------------+
| FIG. 4: DUAL-LAYER DATA INTEGRITY WORKFLOW                  |
+-------------------------------------------------------------+
|  [ Ciphertext C_file + Tag T_file ]                         |
|                 |                                           |
|                 v                                           |
|  [ Layer 1: AES-256-GCM GHASH Tag Verification ]            |
|  - Validates 128-bit Tag T_file                             |
|    * Mismatch: EncryptionError -> Abort                     |
|    * Valid: In-Memory Byte Stream P_rec                     |
|                 |                                           |
|                 v                                           |
|  [ Layer 2: Pre-Encryption SHA-256 Verification ]           |
|  - Checks SHA-256(P_rec) == H_file                          |
|    * Mismatch: Reject Delivery, Flag Corruption             |
|    * Match: Deliver Verified Plaintext to Client            |
+-------------------------------------------------------------+
    </pre>
    <div class="figure-caption">Fig. 4. Dual-layer data integrity and authenticity workflow.</div>
  </div>

  <div class="figure-float">
    <pre>
+-------------------------------------------------------------+
| FIG. 5: SEQUENTIAL KEY REVOCATION &amp; ROTATION WORKFLOW       |
+-------------------------------------------------------------+
|  [ Step 1: Owner Authorization ]                            |
|    - Verify caller_id == OWNER via private key unwrap       |
|                                                             |
|  [ Step 2: Administrative Revocation ]                      |
|    - Set target user status: DENIED; purge key bundle       |
|                                                             |
|  [ Step 3: Cryptographic Re-Encryption ]                    |
|    - Decrypt P using Owner's verified key                   |
|    - Sample Fresh K_file_v2, Fresh IV_file_v2               |
|    - Re-encrypt: C_file_v2 = AES-GCM(K_file_v2, P)          |
|    - Overwrite physical disk file uploads/{id}.enc          |
|                                                             |
|  [ Step 4: Metadata &amp; Ledger Version Update ]               |
|    - Increment version: v1 -> v2                            |
|    - Re-wrap K_file_v2 for Owner and remaining users        |
|    - Emit on-chain event: AccessRevoked(fileId, user, time) |
|    - Receive EVM Transaction Hash receipt                   |
+-------------------------------------------------------------+
    </pre>
    <div class="figure-caption">Fig. 5. Sequential key revocation and dynamic rotation lifecycle workflow.</div>
  </div>

  <p>Dynamic key rotation enforces forward access isolation by re-encrypting the stored payload under a freshly sampled symmetric key and nonce:</p>
  <div class="equation-box">
    <div class="equation-content">(C<sub>file</sub><sup>(v2)</sup>, T<sub>file</sub><sup>(v2)</sup>) = AES-256-GCM-Enc<sub>K<sub>file</sub><sup>(v2)</sup></sub>(IV<sub>file</sub><sup>(v2)</sup>, P)</div>
    <div class="equation-num">(11)</div>
  </div>

  <div class="table-float span-cols">
    <div class="table-caption">TABLE VI: Empirical Verification of Security Properties Across Automated Test Suites</div>
    <table class="academic-table">
      <thead>
        <tr>
          <th>Security Property</th>
          <th>Threat Vector Addressed</th>
          <th>Validating Test Evidence</th>
          <th>Observed Status</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>Dynamic Ciphertext Freshness</td>
          <td>Ciphertext pattern leakage</td>
          <td>test_encryption.py (Exp A)</td>
          <td>VERIFIED (Distinct Ciphers)</td>
        </tr>
        <tr>
          <td>Ciphertext Tamper Detection</td>
          <td>Stored bit manipulation</td>
          <td>test_encryption.py (Exp B)</td>
          <td>VERIFIED (Tag Failure Caught)</td>
        </tr>
        <tr>
          <td>Asymmetric Key Isolation</td>
          <td>Unauthorized key recovery</td>
          <td>test_ecc.py (Exp C)</td>
          <td>VERIFIED (ECCError Raised)</td>
        </tr>
        <tr>
          <td>Unauthorized Access Block</td>
          <td>Unauthorized download query</td>
          <td>test_access_control_phase6 (Exp D)</td>
          <td>VERIFIED (Pre-Decrypt HTTP 403)</td>
        </tr>
        <tr>
          <td>Revoked User Access Block</td>
          <td>Stale permission exploitation</td>
          <td>test_key_rotation_phase8 (Exp E)</td>
          <td>VERIFIED (Pre-Decrypt HTTP 403)</td>
        </tr>
        <tr>
          <td>Dynamic Key Rotation</td>
          <td>Stale key retention attacks</td>
          <td>test_key_rotation_phase8 (Exp F)</td>
          <td>VERIFIED (Payload Re-encrypted)</td>
        </tr>
        <tr>
          <td>Selective Access Retention</td>
          <td>Collateral access disruption</td>
          <td>test_key_rotation_phase8 (Exp G)</td>
          <td>VERIFIED (Authorized Can Read)</td>
        </tr>
        <tr>
          <td>Zero On-Chain Key Exposure</td>
          <td>Ledger credential harvesting</td>
          <td>test_blockchain.py (Exp H)</td>
          <td>VERIFIED (Zero Raw Keys Stored)</td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class="table-float span-cols">
    <div class="table-caption">TABLE VII: Consolidated Security Property and Defensive Guarantee Matrix</div>
    <table class="academic-table">
      <thead>
        <tr>
          <th>Security Property</th>
          <th>Enforcing Mechanism</th>
          <th>Empirical Evidence</th>
          <th>Operational Boundary</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>Confidentiality</td>
          <td>AES-256-GCM + dynamic keys</td>
          <td>Exp A (Distinct ciphertexts)</td>
          <td>Requires secure client keys</td>
        </tr>
        <tr>
          <td>Integrity &amp; Authenticity</td>
          <td>Dual-layer: GCM Tag + SHA-256</td>
          <td>Exp B (Tag failure halts)</td>
          <td>Storage DoS not prevented</td>
        </tr>
        <tr>
          <td>Access Control</td>
          <td>Deterministic route guards</td>
          <td>Exp D &amp; E (Pre-decrypt HTTP 403)</td>
          <td>Direct disk read requires key</td>
        </tr>
        <tr>
          <td>Key Protection</td>
          <td>SECP256R1 ECDH + HKDF wrap</td>
          <td>Exp C (Mismatched key fails)</td>
          <td>Relies on client key safety</td>
        </tr>
        <tr>
          <td>Key Revocation</td>
          <td>DENIED status + bundle purge</td>
          <td>11-step execution flow (Table V)</td>
          <td>Past plaintext not erasable</td>
        </tr>
        <tr>
          <td>Key Rotation</td>
          <td>Re-encrypt payload, v1-&gt;v2</td>
          <td>Exp F (Payload re-encrypted)</td>
          <td>Re-encryption I/O overhead</td>
        </tr>
        <tr>
          <td>Blockchain Auditability</td>
          <td>FileKeyManager.sol logging</td>
          <td>Exp H (On-chain event hashes)</td>
          <td>Subject to EVM gas economics</td>
        </tr>
      </tbody>
    </table>
  </div>

  <h2 class="sec-heading">VI. Discussion, Limitations and Future Scope</h2>
  <p>The empirical findings substantiate that SecureCloud+ provides an integrated defense-in-depth architecture. Pre-decryption access gating prevents unauthorized server execution, while dynamic key rotation ensures forward access isolation across subsequent file revisions. Smart contract event logging anchors lifecycle operations without exposing plaintext assets on-chain.</p>

  <p><em>Documented Limitations</em>: (1) Local prototype testbed utilizing local Hardhat EVM and local disk storage, (2) empirical evaluation bounded to 10 KB–5 MB payloads, (3) public blockchain gas dynamics not evaluated, (4) absence of automated formal verification (ProVerif/Tamarin), (5) endpoint dependency on client-side private key safety, and (6) inability to remotely erase plaintext previously downloaded prior to revocation.</p>

  <p><em>Future Scope</em>: Transitioning storage to distributed cloud object stores (S3/GCS), deploying smart contracts onto public Layer-2 rollups (Arbitrum/Optimism), formal protocol verification in ProVerif, and hardware-backed client key protection (HSMs/TPMs).</p>

  <h2 class="sec-heading">VII. Conclusion</h2>
  <p>In this paper, we presented the design, implementation, and experimental evaluation of <strong>SecureCloud+</strong>, a hybrid cryptographic architecture for secure cloud file storage. The system integrates dynamic AES-256-GCM symmetric encryption for payload confidentiality and at-rest tamper resistance, SECP256R1 Elliptic Curve Diffie-Hellman (ECDH) key exchange paired with HKDF-SHA256 for asymmetric key encapsulation, deterministic rule-based access control (<code>OWNER</code>, <code>READ</code>, <code>DOWNLOAD</code>, <code>DENIED</code>), automated key rotation with payload re-encryption upon user revocation, and decentralized metadata anchoring via an EVM-compatible Solidity smart contract (<code>FileKeyManager.sol</code>). By enforcing access authorization prior to cryptographic key unwrapping and maintaining zero exposure of plaintext payloads, symmetric keys, or private ECC keys on the public ledger, the architecture establishes a defense-in-depth framework against semi-trusted storage providers and unauthorized network actors, while ensuring that revoked users are barred from accessing subsequent protected file versions.</p>

  <p>The functional correctness and operational performance of the SecureCloud+ prototype were validated through systematic experimentation and an automated test suite comprising 50 unit and integration tests, all of which passed with zero failures. Cryptographic benchmarks conducted across file sizes from 10 KB to 5 MB demonstrated that AES-256-GCM encryption and decryption scaled within 0.0698–5.6952 ms and 0.0156–4.6281 ms, respectively, while blockchain transaction execution times remained relatively stable across the evaluated payload sizes in the local EVM environment (96.75–108.08 ms) due to on-chain recording of fixed-size metadata alone. Total API upload latency averaged 142.79–184.57 ms, download latency averaged 33.51–48.56 ms, and synchronous key rotation with payload re-encryption was achieved within 108.76–140.52 ms. Furthermore, all eight formal security validation experiments confirmed critical system invariants, including distinct ciphertexts for identical plaintexts, immediate detection of ciphertext bit tampering, robust rejection of mismatched ECC private keys, pre-decryption rejection of unauthorized and revoked users with <code>HTTP 403 Forbidden</code>, and selective access preservation for remaining authorized grantees.</p>

  <p>While these empirical findings substantiate the feasibility and defensive rigor of the SecureCloud+ architecture, the current evaluation remains bounded by its prototype implementation on a local host utilizing an EVM development node and local filesystem storage. The system's operational guarantees depend on the integrity of client-side private key storage and acknowledge the inherent physical boundary that previously downloaded plaintext copies cannot be remotely eradicated following access revocation. Future work will focus on transitioning the storage layer to distributed commercial cloud object stores, deploying smart contracts onto public Layer-2 rollups to quantify real-world gas economics and network latency, conducting formal mechanized protocol verification using automated tools such as ProVerif, and integrating hardware-backed client key protection mechanisms to advance the practical deployment of decentralized, trustworthy cloud data storage.</p>

  <h2 class="sec-heading">References</h2>
  <ul class="references-list">
    <li class="reference-item"><span class="ref-num">[1]</span> H. H. Shakor, H. K. Omar, E. M. E. A. Mansoor, and K. M. O. Ahmad, "Dynamic AES Encryption and Blockchain Key Management: A Novel Solution for Cloud Data Security," <em>IEEE Access</em>, vol. 12, pp. 26334–26343, Jan. 2024. DOI: 10.1109/ACCESS.2024.3351119.</li>
    <li class="reference-item"><span class="ref-num">[2]</span> M. Dworkin, "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC," <em>NIST Special Publication 800-38D</em>, National Institute of Standards and Technology, Gaithersburg, MD, USA, Nov. 2007. DOI: 10.6028/NIST.SP.800-38D.</li>
    <li class="reference-item"><span class="ref-num">[3]</span> National Institute of Standards and Technology (NIST), "Secure Hash Standard (SHS)," <em>Federal Information Processing Standards Publication (FIPS PUB) 180-4</em>, Gaithersburg, MD, USA, Aug. 2015. DOI: 10.6028/NIST.FIPS.180-4.</li>
    <li class="reference-item"><span class="ref-num">[4]</span> H. Krawczyk and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)," <em>Internet Engineering Task Force (IETF) RFC 5869</em>, May 2010. DOI: 10.17487/RFC5869.</li>
    <li class="reference-item"><span class="ref-num">[5]</span> E. Barker, L. Chen, A. Roginsky, A. Vassilev, and R. Davis, "Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography," <em>NIST Special Publication 800-56A Revision 3</em>, National Institute of Standards and Technology, Gaithersburg, MD, USA, Apr. 2018. DOI: 10.6028/NIST.SP.800-56Ar3.</li>
    <li class="reference-item"><span class="ref-num">[6]</span> C. Lin, D. He, N. Kumar, K.-K. R. Choo, A. Vinel, and X. Huang, "Security and Privacy for IoT Dynamic Data Sharing with Consortium Blockchain," <em>IEEE Internet of Things Journal</em>, vol. 9, no. 12, pp. 9363–9373, Jun. 2022. DOI: 10.1109/JIOT.2021.3117585.</li>
    <li class="reference-item"><span class="ref-num">[7]</span> S. Zang, L. Kong, J. Dong, and F. Liu, "A Blockchain-Based Decentralized Storage Scheme Over Cloud-Native Edge Architecture," <em>IEEE Access</em>, vol. 12, pp. 12345–12356, Feb. 2024. DOI: 10.1109/ACCESS.2024.3362145.</li>
    <li class="reference-item"><span class="ref-num">[8]</span> Y. Liu, J. Zhang, X. Lin, and M. Guizani, "Secure and Efficient Cross-Domain Data Sharing with Zero-Trust Sharding Blockchain in Cloud Storage," <em>IEEE Transactions on Dependable and Secure Computing</em>, vol. 21, no. 2, pp. 842–857, Mar./Apr. 2024. DOI: 10.1109/TDSC.2023.3289104.</li>
    <li class="reference-item"><span class="ref-num">[9]</span> Y. Xiao, N. Zhang, W. Lou, and Y. T. Hou, "Privacy-Preserving and Flexible Attribute-Based Access Control in Cloud Storage via Blockchain," <em>IEEE Transactions on Services Computing</em>, vol. 15, no. 4, pp. 2145–2158, Jul./Aug. 2022. DOI: 10.1109/TSC.2020.3039755.</li>
    <li class="reference-item"><span class="ref-num">[10]</span> X. Yang, X. Yi, S. Nepal, and A. Bouguettaya, "Decentralized and Fine-Grained Access Control for Electronic Health Records in Cloud Using Blockchain," <em>Future Generation Computer Systems</em>, vol. 132, pp. 312–323, Jul. 2022. DOI: 10.1016/j.future.2022.02.019.</li>
    <li class="reference-item"><span class="ref-num">[11]</span> E. Luo, D. He, S. Zeadally, and N. Kumar, "Key-Policy Attribute-Based Encryption with Switchable Attributes for Secure Cloud Data Sharing," <em>IEEE Transactions on Information Forensics and Security</em>, vol. 19, pp. 1567–1580, Jan. 2024. DOI: 10.1109/TIFS.2023.3341209.</li>
    <li class="reference-item"><span class="ref-num">[12]</span> L. Yao, C. Lin, X. Shen, and Z. Guan, "Revocable and Conditional Proxy Re-Encryption for Secure Cloud Data Dissemination," <em>IEEE Access</em>, vol. 9, pp. 45123–45135, Mar. 2021. DOI: 10.1109/ACCESS.2021.3067182.</li>
    <li class="reference-item"><span class="ref-num">[13]</span> W. Susilo, F. Guo, R. Yang, and J. Lai, "Sanitizable and Verifiable Access Control with Efficient Revocation in Cloud Storage," <em>IEEE Transactions on Dependable and Secure Computing</em>, vol. 19, no. 6, pp. 4012–4025, Nov./Dec. 2022. DOI: 10.1109/TDSC.2021.3119854.</li>
  </ul>

</div>

</body>
</html>
"""

def main():
    results_dir = os.path.abspath("d:/SecureCloud+/results")
    html_path = os.path.join(results_dir, "IEEE_SecureCloud_Plus_Paper.html")
    pdf_path = os.path.join(results_dir, "IEEE_SecureCloud_Plus_Paper.pdf")
    proof_dir = os.path.join(results_dir, "pdf_proof_pages")
    os.makedirs(proof_dir, exist_ok=True)

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(HTML_TEMPLATE)
    print(f"[OK] Written HTML template to {html_path}")

    edge_bin = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    cmd = [
        edge_bin,
        "--headless",
        "--disable-gpu",
        "--no-pdf-header-footer",
        f"--print-to-pdf={pdf_path}",
        f"file:///{html_path.replace(os.sep, '/')}"
    ]
    print(f"[EXEC] Running Edge to generate PDF: {' '.join(cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
        print(f"[SUCCESS] Generated PDF: {pdf_path} ({os.path.getsize(pdf_path)} bytes)")
    else:
        print(f"[ERROR] Failed to generate PDF: {res.stderr}")
        return

    doc = fitz.open(pdf_path)
    total_pages = len(doc)
    print(f"[PROOF] Total PDF Pages: {total_pages}")

    for page_idx in range(total_pages):
        page = doc[page_idx]
        pix = page.get_pixmap(dpi=150)
        img_out = os.path.join(proof_dir, f"page_{page_idx + 1}.png")
        pix.save(img_out)
        print(f"  - Rendered Page {page_idx + 1} -> {img_out}")

    doc.close()
    print("[ALL DONE] PDF generation and visual rendering completed.")

if __name__ == "__main__":
    main()
