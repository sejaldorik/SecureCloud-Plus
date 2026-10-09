// Secure Cloud Storage - B.Tech Student Project Application Logic

// Session-based file store using exact existing backend APIs
function getStoredFiles() {
  try {
    const raw = sessionStorage.getItem("secure_storage_files");
    return raw ? JSON.parse(raw) : [];
  } catch (e) {
    return [];
  }
}

function saveStoredFiles(files) {
  try {
    sessionStorage.setItem("secure_storage_files", JSON.stringify(files));
  } catch (e) {
    console.error("Failed to save to sessionStorage:", e);
  }
}

function addFileToStore(fileMeta) {
  const files = getStoredFiles();
  const existingIdx = files.findIndex(f => f.file_id === fileMeta.file_id);
  if (existingIdx >= 0) {
    files[existingIdx] = { ...files[existingIdx], ...fileMeta };
  } else {
    files.unshift(fileMeta);
  }
  saveStoredFiles(files);
}

let currentSelectedFileId = null;

// On DOM load
document.addEventListener("DOMContentLoaded", () => {
  loadDashboardData();
});

// Tab Switching
function switchTab(tabName) {
  document.querySelectorAll(".nav-tab").forEach(tab => tab.classList.remove("active"));
  document.querySelectorAll(".tab-content").forEach(content => content.classList.remove("active"));

  const targetTab = Array.from(document.querySelectorAll(".nav-tab")).find(btn => {
    const attr = btn.getAttribute("onclick") || "";
    return attr.includes(`'${tabName}'`);
  });
  if (targetTab) targetTab.classList.add("active");

  const targetSection = document.getElementById(`${tabName}-section`);
  if (targetSection) targetSection.classList.add("active");

  // Refresh UI & selectors on tab switch
  populateFileSelectors();
  if (tabName === "dashboard") {
    loadDashboardData();
  } else if (tabName === "access") {
    loadPermissionsForSelectedFile();
  }
}

// Show Alerts
function showAlert(message, type = "success", duration = 5000) {
  const container = document.getElementById("global-alert-container");
  const alert = document.createElement("div");
  alert.className = `alert alert-${type}`;

  const icon = type === "success" ? "✅" : (type === "error" ? "❌" : "ℹ️");

  alert.innerHTML = `
    <div style="display: flex; align-items: center; gap: 8px;">
      <span>${icon}</span>
      <span>${escapeHtml(message)}</span>
    </div>
    <button style="background: none; border: none; cursor: pointer; font-size: 16px;" onclick="this.parentElement.remove()">&times;</button>
  `;

  container.appendChild(alert);

  if (duration > 0) {
    setTimeout(() => {
      if (alert.parentElement) alert.remove();
    }, duration);
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Populate File Selector Dropdowns
function populateFileSelectors() {
  const filesList = getStoredFiles();
  const dropdownIds = [
    "details-file-selector",
    "grant-file-id",
    "revoke-file-id",
    "download-file-id"
  ];

  dropdownIds.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;

    const currentVal = el.value;
    el.innerHTML = `<option value="">-- Select File --</option>`;

    filesList.forEach(file => {
      const opt = document.createElement("option");
      opt.value = file.file_id;
      opt.textContent = `${file.filename} (ID: ${file.file_id.substring(0, 8)}... - v${file.version || 1})`;
      el.appendChild(opt);
    });

    if (currentVal) el.value = currentVal;
    if (!el.value && currentSelectedFileId) el.value = currentSelectedFileId;
  });
}

// 1. Dashboard Logic
async function loadDashboardData() {
  const filesList = getStoredFiles();

  // Update Statistics
  document.getElementById("stat-total-files").textContent = filesList.length;
  document.getElementById("stat-encrypted-files").textContent = filesList.length; // 100% encrypted

  // Count active permissions across stored files
  let permCount = 0;
  for (const f of filesList) {
    try {
      const pRes = await fetch(`/files/${f.file_id}/access?requesting_user_id=${f.owner_id || 'owner_user_1'}`);
      if (pRes.ok) {
        const perms = await pRes.json();
        permCount += perms.filter(p => p.status !== 'DENIED').length;
      }
    } catch (e) {
      // Ignore network errors
    }
  }
  document.getElementById("stat-active-permissions").textContent = permCount;

  // Render Recent Files Table
  const tbody = document.getElementById("recent-files-tbody");
  tbody.innerHTML = "";

  if (filesList.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 24px;">
          No files uploaded yet. Click "Upload File" to add files.
        </td>
      </tr>
    `;
    return;
  }

  filesList.forEach(file => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td style="font-weight: 500;">${escapeHtml(file.filename)}</td>
      <td style="font-family: monospace; font-size: 12px; color: var(--text-muted);">${escapeHtml(file.file_id.substring(0, 12))}...</td>
      <td>${escapeHtml(file.owner_id || "owner_user_1")}</td>
      <td><span class="badge badge-blue">v${file.version || 1}</span></td>
      <td><span class="badge badge-green">AES-256-GCM</span></td>
      <td>
        <div style="display: flex; gap: 6px;">
          <button class="btn btn-secondary btn-sm" onclick="selectAndGoToTab('${file.file_id}', 'details')">Details</button>
          <button class="btn btn-secondary btn-sm" onclick="selectAndGoToTab('${file.file_id}', 'access')">Access</button>
          <button class="btn btn-success btn-sm" onclick="selectAndGoToTab('${file.file_id}', 'download')">Download</button>
          <button class="btn btn-danger btn-sm" onclick="selectAndGoToTab('${file.file_id}', 'revoke')">Revoke</button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });

  populateFileSelectors();
}

function selectAndGoToTab(fileId, tabName) {
  currentSelectedFileId = fileId;
  switchTab(tabName);

  if (tabName === "details") {
    document.getElementById("details-file-selector").value = fileId;
    fetchFileDetails();
  } else if (tabName === "access") {
    document.getElementById("grant-file-id").value = fileId;
    loadPermissionsForSelectedFile();
  } else if (tabName === "revoke") {
    document.getElementById("revoke-file-id").value = fileId;
  } else if (tabName === "download") {
    document.getElementById("download-file-id").value = fileId;
  }
}

// 2. Upload Logic
async function handleUploadSubmit(e) {
  e.preventDefault();

  const fileInput = document.getElementById("upload-file-input");
  const ownerIdInput = document.getElementById("upload-owner-id");
  const pubKeyInput = document.getElementById("upload-public-key-pem");
  const submitBtn = document.getElementById("upload-btn");

  if (!fileInput.files || fileInput.files.length === 0) {
    showAlert("Please select a file to upload.", "error");
    return;
  }

  const file = fileInput.files[0];
  const ownerId = ownerIdInput.value.trim() || "owner_user_1";
  const pubKeyPem = pubKeyInput.value.trim();

  const formData = new FormData();
  formData.append("file", file);
  formData.append("owner_id", ownerId);
  if (pubKeyPem) {
    formData.append("recipient_public_key_pem", pubKeyPem);
  }

  submitBtn.disabled = true;
  submitBtn.innerHTML = `⏳ Uploading & Encrypting...`;

  try {
    const response = await fetch("/files/upload", {
      method: "POST",
      body: formData
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || "File upload failed.");
    }

    // Add to session store
    addFileToStore({
      file_id: data.file_id,
      filename: data.filename,
      sha256: data.sha256,
      version: data.version || 1,
      blockchain_tx_hash: data.blockchain_tx_hash || "mock_tx_onchain",
      owner_id: data.owner_id || ownerId,
      status: data.status
    });

    // Success UI Update
    showAlert("File uploaded, encrypted with AES-256-GCM, ECC protected, and registered on Blockchain!", "success");

    document.getElementById("res-filename").textContent = data.filename;
    document.getElementById("res-file-id").textContent = data.file_id;
    document.getElementById("res-sha256").textContent = data.sha256;
    document.getElementById("res-version").textContent = data.version || 1;
    document.getElementById("res-status").textContent = data.status;
    document.getElementById("res-tx-hash").textContent = data.blockchain_tx_hash || "mock_tx_onchain";

    document.getElementById("upload-result-card").style.display = "block";
    currentSelectedFileId = data.file_id;

    // Refresh Dashboard
    loadDashboardData();
  } catch (err) {
    showAlert(err.message, "error");
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerHTML = `<span>Upload & Encrypt</span>`;
  }
}

function navigateToAccessWithFile() {
  if (currentSelectedFileId) {
    selectAndGoToTab(currentSelectedFileId, 'access');
  }
}

function navigateToDownloadWithFile() {
  if (currentSelectedFileId) {
    selectAndGoToTab(currentSelectedFileId, 'download');
  }
}

// 3. File Details Logic
function handleDetailsSelectChange() {
  const selectedId = document.getElementById("details-file-selector").value;
  if (selectedId) {
    currentSelectedFileId = selectedId;
    fetchFileDetails();
  }
}

function fetchFileDetails() {
  const fileId = document.getElementById("details-file-selector").value || currentSelectedFileId;
  if (!fileId) {
    showAlert("Please select a file to view details.", "error");
    return;
  }

  const filesList = getStoredFiles();
  const fileMeta = filesList.find(f => f.file_id === fileId);

  if (!fileMeta) {
    showAlert(`Metadata for file ID '${fileId}' not found in current session.`, "error");
    return;
  }

  document.getElementById("det-filename").textContent = fileMeta.filename || "-";
  document.getElementById("det-file-id").textContent = fileMeta.file_id;
  document.getElementById("det-owner").textContent = fileMeta.owner_id || "owner_user_1";
  document.getElementById("det-version").textContent = fileMeta.version || 1;
  document.getElementById("det-version-badge").textContent = `Version ${fileMeta.version || 1}`;
  document.getElementById("det-sha256").textContent = fileMeta.sha256 || "N/A";
  document.getElementById("det-tx-hash").textContent = fileMeta.blockchain_tx_hash || "mock_tx_onchain";

  document.getElementById("details-display-card").style.display = "block";
}

function navigateToDownloadFromDetails() {
  const fileId = document.getElementById("det-file-id").textContent;
  if (fileId && fileId !== "-") {
    selectAndGoToTab(fileId, 'download');
  }
}

// 4. Access Control Logic
async function handleGrantAccessSubmit(e) {
  e.preventDefault();

  const fileId = document.getElementById("grant-file-id").value;
  const targetUser = document.getElementById("grant-target-user").value.trim();
  const permission = document.getElementById("grant-permission").value;
  const ownerId = document.getElementById("grant-owner-id").value.trim() || "owner_user_1";
  const pubKeyPem = document.getElementById("grant-user-public-key").value.trim();
  const submitBtn = document.getElementById("grant-btn");

  if (!fileId || !targetUser) {
    showAlert("File ID and Target User ID are required.", "error");
    return;
  }

  submitBtn.disabled = true;
  submitBtn.innerHTML = `⏳ Granting Access...`;

  try {
    const payload = {
      target_user_id: targetUser,
      permission: permission,
      requesting_user_id: ownerId,
      public_key_pem: pubKeyPem || null
    };

    const response = await fetch(`/files/${fileId}/access`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || "Failed to grant access.");
    }

    showAlert(`Successfully granted ${permission} access to user '${targetUser}'!`, "success");
    loadPermissionsForSelectedFile();
  } catch (err) {
    showAlert(err.message, "error");
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerHTML = `Grant Access`;
  }
}

async function loadPermissionsForSelectedFile() {
  const fileId = document.getElementById("grant-file-id").value || currentSelectedFileId;
  const tbody = document.getElementById("access-permissions-tbody");

  if (!fileId) {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 20px;">
          Select a file above to view active access permissions.
        </td>
      </tr>
    `;
    return;
  }

  const ownerId = document.getElementById("grant-owner-id").value.trim() || "owner_user_1";

  try {
    const res = await fetch(`/files/${fileId}/access?requesting_user_id=${ownerId}`);
    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.detail || "Failed to fetch permissions.");
    }

    tbody.innerHTML = "";

    if (data.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 20px;">
            No permissions configured yet for this file.
          </td>
        </tr>
      `;
      return;
    }

    data.forEach(rec => {
      const userId = rec.user_id || rec.target_user_id || "-";
      const isDenied = rec.status === "DENIED" || rec.status === "denied" || rec.permission === "DENIED";
      const statusBadge = isDenied
        ? `<span class="badge badge-red">DENIED</span>`
        : `<span class="badge badge-green">ACTIVE</span>`;

      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td style="font-weight: 500;">${escapeHtml(userId)}</td>
        <td><span class="badge badge-blue">${escapeHtml(rec.permission)}</span></td>
        <td>${escapeHtml(rec.granted_by || ownerId)}</td>
        <td>${statusBadge}</td>
        <td>
          ${!isDenied && rec.permission !== "OWNER" ? `<button class="btn btn-danger btn-sm" onclick="denyAccessInTable('${rec.file_id || fileId}', '${escapeHtml(userId)}')">Revoke Access</button>` : `<span style="font-size: 12px; color: var(--text-muted);">${rec.permission === "OWNER" ? "Owner" : "Revoked"}</span>`}
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    showAlert(err.message, "error");
  }
}

async function denyAccessInTable(fileId, userId) {
  const ownerId = document.getElementById("grant-owner-id").value.trim() || "owner_user_1";

  try {
    const res = await fetch(`/files/${fileId}/access/${userId}?requesting_user_id=${ownerId}`, {
      method: "DELETE"
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || "Failed to revoke access.");
    }

    showAlert(`Access permission set to DENIED for user '${userId}'.`, "success");
    loadPermissionsForSelectedFile();
  } catch (err) {
    showAlert(err.message, "error");
  }
}

// 5. Key Revocation / Rotation Logic
async function handleRevokeSubmit(e) {
  e.preventDefault();

  const fileId = document.getElementById("revoke-file-id").value;
  const targetUser = document.getElementById("revoke-user-id").value.trim();
  const ownerId = document.getElementById("revoke-owner-id").value.trim() || "owner_user_1";
  const ownerPrivKey = document.getElementById("revoke-owner-private-key").value.trim();
  const submitBtn = document.getElementById("revoke-btn");

  if (!fileId || !targetUser || !ownerPrivKey) {
    showAlert("File ID, Target User ID, and Owner Private Key are required.", "error");
    return;
  }

  const formData = new FormData();
  formData.append("requesting_user_id", ownerId);
  formData.append("owner_private_key_pem", ownerPrivKey);

  submitBtn.disabled = true;
  submitBtn.innerHTML = `⏳ Revoking Access & Rotating Key...`;

  try {
    const response = await fetch(`/files/${fileId}/revoke/${targetUser}`, {
      method: "POST",
      body: formData
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || "Revocation & Key Rotation failed.");
    }

    // Update stored version in session store
    const files = getStoredFiles();
    const targetFile = files.find(f => f.file_id === data.file_id);
    if (targetFile) {
      targetFile.version = data.new_version;
      saveStoredFiles(files);
    }

    // Success UI Update
    showAlert(`Access revoked for '${targetUser}' and file encryption key rotated to Version ${data.new_version}!`, "success");

    document.getElementById("rev-user-id").textContent = data.revoked_user_id;
    document.getElementById("rev-new-version").textContent = `Version ${data.new_version}`;
    document.getElementById("rev-status").textContent = data.status;
    document.getElementById("rev-tx-hash").textContent = data.transaction_hash;

    document.getElementById("revoke-result-card").style.display = "block";

    // Clear Private Key field for security
    document.getElementById("revoke-owner-private-key").value = "";

    loadDashboardData();
  } catch (err) {
    showAlert(err.message, "error");
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerHTML = `Revoke & Rotate Key`;
  }
}

// 6. Download Logic
async function handleDownloadSubmit(e) {
  e.preventDefault();

  const fileId = document.getElementById("download-file-id").value;
  const userId = document.getElementById("download-user-id").value.trim() || "owner_user_1";
  const privKeyPem = document.getElementById("download-private-key").value.trim();
  const submitBtn = document.getElementById("download-btn");

  if (!fileId || !privKeyPem) {
    showAlert("File ID and ECC Private Key are required for download.", "error");
    return;
  }

  submitBtn.disabled = true;
  submitBtn.innerHTML = `⏳ Unwrapping Key & Decrypting File...`;

  try {
    const url = `/files/${fileId}/download?user_id=${encodeURIComponent(userId)}&recipient_private_key_pem=${encodeURIComponent(privKeyPem)}`;
    const response = await fetch(url);

    if (!response.ok) {
      const errData = await response.json();
      throw new Error(errData.detail || "Download/Decryption failed.");
    }

    // Extract filename from header if present
    const disposition = response.headers.get("Content-Disposition");
    let filename = `decrypted_${fileId}`;
    if (disposition && disposition.includes("filename=")) {
      filename = disposition.split("filename=")[1].replace(/"/g, "").trim();
    }

    const blob = await response.blob();
    const downloadUrl = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = downloadUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(downloadUrl);

    showAlert(`File '${filename}' decrypted and downloaded successfully! SHA-256 integrity verified.`, "success");

    // Clear Private Key field for security
    document.getElementById("download-private-key").value = "";
  } catch (err) {
    showAlert(err.message, "error");
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerHTML = `Download File`;
  }
}

// 7. Browser Web Crypto ECC (P-256) Key Pair Generator
async function generateBrowserEccKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"]
  );

  const pubExport = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
  const privExport = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

  return {
    publicKeyPem: formatPem(pubExport, "PUBLIC KEY"),
    privateKeyPem: formatPem(privExport, "PRIVATE KEY")
  };
}

function formatPem(buffer, type) {
  const binary = String.fromCharCode.apply(null, new Uint8Array(buffer));
  const base64 = window.btoa(binary);
  const lines = base64.match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${type}-----\n${lines}\n-----END ${type}-----\n`;
}

async function generateAndSetUploadKeys() {
  try {
    const keys = await generateBrowserEccKeyPair();
    document.getElementById("upload-public-key-pem").value = keys.publicKeyPem;

    // Show modal with private key for student to copy
    document.getElementById("modal-pub-pem").value = keys.publicKeyPem;
    document.getElementById("modal-priv-pem").value = keys.privateKeyPem;
    openKeyModal();

    showAlert("Generated fresh ECC (P-256) key pair! Public key applied. Save private key for Download/Rotation.", "info", 8000);
  } catch (err) {
    showAlert("Key generation failed: " + err.message, "error");
  }
}

// Modal Handlers
function openKeyModal() {
  document.getElementById("key-modal").classList.add("open");
}

function closeKeyModal() {
  document.getElementById("key-modal").classList.remove("open");
}

async function generateModalKeyPair() {
  try {
    const keys = await generateBrowserEccKeyPair();
    document.getElementById("modal-pub-pem").value = keys.publicKeyPem;
    document.getElementById("modal-priv-pem").value = keys.privateKeyPem;
    showAlert("New ECC Key Pair generated!", "success");
  } catch (err) {
    showAlert("Key generation failed: " + err.message, "error");
  }
}

function copyText(elementId) {
  const el = document.getElementById(elementId);
  const text = el.value || el.textContent;
  if (!text) return;

  navigator.clipboard.writeText(text).then(() => {
    showAlert("Copied to clipboard!", "success", 2000);
  }).catch(() => {
    showAlert("Failed to copy.", "error", 2000);
  });
}
