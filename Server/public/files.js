const authFetch = (input, init) => fetch(input, { credentials: 'same-origin', ...init });
const params = new URLSearchParams(window.location.search);
const agentId = params.get('agent');
const initialPath = params.get('path') ?? '';

const agentLabel = document.getElementById('agentLabel');
const statusMessage = document.getElementById('statusMessage');
const pathLabel = document.getElementById('currentPathLabel');
const tableBody = document.getElementById('fileTableBody');
const upButton = document.getElementById('upButton');
const refreshButton = document.getElementById('refreshButton');
const uploadForm = document.getElementById('uploadForm');
const uploadInput = document.getElementById('uploadInput');
const uploadName = document.getElementById('uploadName');

let currentPath = '';
let parentPath = '';

function setStatus(text, error = false) {
  statusMessage.textContent = text;
  statusMessage.dataset.error = error ? 'true' : 'false';
}

function renderTableMessage(text) {
  tableBody.innerHTML = `<tr><td colspan="5" class="empty">${text}</td></tr>`;
}

function formatBytes(bytes) {
  if (typeof bytes !== 'number' || Number.isNaN(bytes)) {
    return '—';
  }

  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }

  return `${value.toFixed(1)} ${units[index]}`;
}

function renderEntries(entries) {
  tableBody.innerHTML = '';
  if (!Array.isArray(entries) || entries.length === 0) {
    renderTableMessage('No items found in this directory.');
    return;
  }

  entries.forEach((entry) => {
    const row = document.createElement('tr');
    const nameCell = document.createElement('td');
    nameCell.className = 'name-cell';
    const icon = document.createElement('span');
    icon.className = 'name-icon';
    icon.textContent = entry.isDirectory ? '📁' : '📄';
    const label = document.createElement('span');
    label.textContent = entry.name ?? 'Unnamed';
    nameCell.appendChild(icon);
    nameCell.appendChild(label);
    row.appendChild(nameCell);

    const typeCell = document.createElement('td');
    typeCell.textContent = entry.isDirectory ? 'Directory' : 'File';
    row.appendChild(typeCell);

    const sizeCell = document.createElement('td');
    sizeCell.textContent = entry.isDirectory ? '—' : formatBytes(entry.size);
    row.appendChild(sizeCell);

    const modifiedCell = document.createElement('td');
    modifiedCell.textContent = entry.lastModifiedUtc
      ? new Date(entry.lastModifiedUtc).toLocaleString()
      : '—';
    row.appendChild(modifiedCell);

    const actionCell = document.createElement('td');
    const actionButton = document.createElement('button');
    actionButton.type = 'button';
    actionButton.textContent = entry.isDirectory ? 'Open' : 'Download';
    actionButton.className = 'action-btn';
    actionButton.addEventListener('click', () => {
      if (entry.isDirectory) {
        loadDirectory(entry.path);
      } else {
        downloadEntry(entry);
      }
    });
    actionCell.appendChild(actionButton);
    row.appendChild(actionCell);

    tableBody.appendChild(row);
  });
}

function combinePaths(base, name) {
  if (!base) {
    return name;
  }

  const separator = base.includes('/') ? '/' : '\\';
  const normalizedBase = base.endsWith(separator) ? base : `${base}${separator}`;
  return `${normalizedBase}${name}`;
}

async function downloadEntry(entry) {
  if (!agentId || !entry?.path) {
    return;
  }

  setStatus('Downloading file…', false);
  try {
    const response = await authFetch(`/files/${agentId}/download?path=${encodeURIComponent(entry.path)}`);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = entry.name ?? 'download';
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);
    setStatus('Download started.');
  } catch (error) {
    setStatus(`Failed to download: ${error.message}`, true);
  }
}

async function loadDirectory(path) {
  if (!agentId) {
    return;
  }

  setStatus('Loading directory…');
  renderTableMessage('Loading…');

  try {
    const query = path ? `?path=${encodeURIComponent(path)}` : '';
    const response = await authFetch(`/files/${agentId}/list${query}`, { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    currentPath = payload.path ?? path ?? '';
    parentPath = payload.parentPath ?? currentPath;
    pathLabel.textContent = currentPath || 'Unknown path';
    renderEntries(payload.entries);
    upButton.disabled = !parentPath || parentPath === currentPath;

    if (payload.error) {
      setStatus(`Partial warning: ${payload.error}`, true);
    } else {
      setStatus('Directory loaded.');
    }
  } catch (error) {
    renderTableMessage('Unable to load directory.');
    setStatus(error.message, true);
  }
}

async function refreshAgentName() {
  if (!agentId) {
    return;
  }

  try {
    const response = await authFetch('/clients', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error('Failed to load agent info.');
    }

    const agents = await response.json();
    const agent = agents.find((entry) => entry.id === agentId);
    if (agent) {
      agentLabel.textContent = `Browsing ${agent.name}`;
      document.title = `Files • ${agent.name}`;
    } else {
      agentLabel.textContent = `Browsing agent ${agentId}`;
    }
  } catch (error) {
    agentLabel.textContent = `Agent ${agentId}`;
  }
}

async function handleUpload(event) {
  event.preventDefault();
  if (!agentId) {
    return;
  }

  const file = uploadInput.files?.[0];
  if (!file) {
    setStatus('Select a file to upload.', true);
    return;
  }

  const targetName = uploadName.value.trim() || file.name;
  const destinationPath = combinePaths(currentPath, targetName);

  setStatus('Uploading file…');
  try {
    const buffer = await file.arrayBuffer();
    const base64 = arrayBufferToBase64(buffer);
    const response = await authFetch(`/files/${agentId}/upload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: destinationPath, data: base64 }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(error || `HTTP ${response.status}`);
    }

    const body = await response.json();
    setStatus(body.message ?? 'Upload request sent.');
    await loadDirectory(currentPath);
  } catch (error) {
    setStatus(`Upload failed: ${error.message}`, true);
  }
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }

  return btoa(binary);
}

function bindEvents() {
  upButton?.addEventListener('click', () => {
    if (parentPath && parentPath !== currentPath) {
      loadDirectory(parentPath);
    }
  });

  refreshButton?.addEventListener('click', () => {
    loadDirectory(currentPath);
  });

  uploadForm?.addEventListener('submit', handleUpload);
}

async function start() {
  if (!agentId) {
    setStatus('Agent parameter missing.', true);
    return;
  }

  bindEvents();
  await refreshAgentName();
  await loadDirectory(initialPath);
}

start();
