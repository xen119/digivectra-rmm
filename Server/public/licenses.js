const statusEl = document.getElementById('statusMessage');
const tableBody = document.getElementById('licenseTableBody');
const generateButton = document.getElementById('generateLicense');
const tenantFilterGroup = document.getElementById('tenantFilterGroup');
const tenantSelect = document.getElementById('licenseTenantSelect');

const authFetch = (input, init = {}) => fetch(input, { credentials: 'same-origin', ...init });

const tenantMap = new Map();
let isGlobalView = false;
let selectedTenantId = null;
let resolvedTenantId = null;

function setStatus(message, variant = '') {
  if (!statusEl) {
    return;
  }
  statusEl.textContent = message;
  statusEl.classList.remove('error', 'success');
  if (variant) {
    statusEl.classList.add(variant);
  }
}

function formatDate(value) {
  if (!value) {
    return '—';
  }
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function createLicenseRow(entry) {
  const row = document.createElement('tr');
  row.className = 'license-row';

  const codeCell = document.createElement('td');
  codeCell.textContent = entry.code;

  const statusCell = document.createElement('td');
  const statusSpan = document.createElement('span');
  const isRevoked = Boolean(entry.revokedAt);
  statusSpan.className = `status-pill ${isRevoked ? 'revoked' : 'active'}`;
  statusSpan.textContent = isRevoked ? 'Revoked' : 'Active';
  statusCell.appendChild(statusSpan);

  const assignedCell = document.createElement('td');
  if (entry.assignedAgentId) {
    const primary = document.createElement('div');
    primary.textContent = entry.assignedAgentName
      ? `${entry.assignedAgentName} (${entry.assignedAgentId})`
      : entry.assignedAgentId;
    primary.style.fontWeight = '600';
    assignedCell.appendChild(primary);

    if (entry.agentStatus) {
      const statusLine = document.createElement('small');
      statusLine.textContent = entry.agentStatus;
      statusLine.style.color = 'rgba(255, 255, 255, 0.7)';
      assignedCell.appendChild(statusLine);
    }

    if (entry.assignedAt) {
      const when = document.createElement('div');
      when.className = 'assigned-at';
      when.textContent = `Assigned ${formatDate(entry.assignedAt)}`;
      assignedCell.appendChild(when);
    }
  } else {
    assignedCell.textContent = '—';
  }

  const createdCell = document.createElement('td');
  createdCell.textContent = formatDate(entry.createdAt);

  const usedCell = document.createElement('td');
  usedCell.textContent = entry.lastUsedAt ? formatDate(entry.lastUsedAt) : 'Never';

  const actionCell = document.createElement('td');
  if (!isRevoked) {
    const revokeButton = document.createElement('button');
    revokeButton.type = 'button';
    revokeButton.textContent = 'Revoke';
    revokeButton.addEventListener('click', () => {
      if (window.confirm('Revoke this license and disconnect any agent that uses it?')) {
        revokeLicense(entry.code);
      }
    });
    actionCell.appendChild(revokeButton);
  } else {
    actionCell.textContent = '—';
  }

  if (entry.assignedAgentId && !isRevoked) {
    const unassignButton = document.createElement('button');
    unassignButton.type = 'button';
    unassignButton.textContent = 'Unassign';
    unassignButton.addEventListener('click', () => {
      if (window.confirm('Release this license so it can be reused?')) {
        unassignLicense(entry.code);
      }
    });
    actionCell.appendChild(unassignButton);
  }

  row.appendChild(codeCell);
  row.appendChild(assignedCell);
  row.appendChild(statusCell);
  row.appendChild(createdCell);
  row.appendChild(usedCell);
  row.appendChild(actionCell);
  return row;
}

async function populateTenantSelect() {
  if (!tenantSelect) {
    return;
  }

  try {
    const response = await authFetch('/tenants', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    const tenants = Array.isArray(payload.tenants) ? payload.tenants : [];

    tenantSelect.innerHTML = '';
    tenantMap.clear();

    tenants.forEach((tenant) => {
      if (!tenant?.id) {
        return;
      }
      tenantMap.set(tenant.id, tenant);
      const option = document.createElement('option');
      option.value = tenant.id;
      option.textContent = tenant.name ? `${tenant.name} (${tenant.id})` : tenant.id;
      tenantSelect.appendChild(option);
    });
  } catch (error) {
    console.error('Unable to load tenant list', error);
    tenantFilterGroup?.classList.add('hidden');
  }
}

async function initializeTenantFilter() {
  if (!tenantFilterGroup || !tenantSelect) {
    return;
  }

  try {
    const response = await authFetch('/tenants/current', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    const currentTenantId = payload?.tenant?.id;
    resolvedTenantId = currentTenantId || resolvedTenantId;
    selectedTenantId = currentTenantId || selectedTenantId;

    if (payload?.isGlobal) {
      isGlobalView = true;
      tenantFilterGroup.classList.remove('hidden');
      await populateTenantSelect();
      tenantSelect.value = selectedTenantId || resolvedTenantId || '';
    } else {
      tenantFilterGroup.classList.add('hidden');
    }
  } catch (error) {
    console.error('Unable to initialize tenant selector', error);
    tenantFilterGroup.classList.add('hidden');
  }
}

async function loadLicenses() {
  setStatus('Loading licenses...');
  try {
    const params = new URLSearchParams();
    if (isGlobalView && selectedTenantId) {
      params.set('tenantId', selectedTenantId);
    }
    const query = params.toString() ? `?${params.toString()}` : '';
    const response = await authFetch(`/licenses${query}`);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    const entries = Array.isArray(data.licenses) ? data.licenses : [];
    const tenantIdFromResponse = typeof data.tenantId === 'string' && data.tenantId.trim()
      ? data.tenantId.trim()
      : null;
    const displayedTenantId = tenantIdFromResponse || selectedTenantId;
    if (displayedTenantId) {
      resolvedTenantId = displayedTenantId;
      selectedTenantId = displayedTenantId;
      if (tenantSelect) {
        tenantSelect.value = selectedTenantId;
      }
    }

    tableBody.innerHTML = '';
    if (!entries.length) {
      const placeholder = document.createElement('tr');
      placeholder.innerHTML = '<td colspan="5">No licenses issued yet.</td>';
      tableBody.appendChild(placeholder);
    } else {
      entries.forEach((entry) => tableBody.appendChild(createLicenseRow(entry)));
    }

    const tenantName = tenantMap.get(selectedTenantId ?? resolvedTenantId)?.name
      || selectedTenantId
      || resolvedTenantId
      || 'this tenant';
    setStatus(`Showing ${entries.length} license${entries.length === 1 ? '' : 's'} for ${tenantName}.`, entries.length ? 'success' : '');
  } catch (error) {
    console.error('Unable to load licenses', error);
    setStatus('Unable to load licenses.', 'error');
  }
}

async function createLicense() {
  if (!generateButton) {
    return;
  }

  generateButton.disabled = true;
  setStatus('Creating license...');
  try {
    const payload = {};
    if (isGlobalView && selectedTenantId) {
      payload.tenantId = selectedTenantId;
    }

    const response = await authFetch('/licenses', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    await loadLicenses();
    setStatus('New license created.', 'success');
  } catch (error) {
    console.error('Unable to create license', error);
    setStatus('Unable to create license.', 'error');
  } finally {
    generateButton.disabled = false;
  }
}

async function revokeLicense(code) {
  setStatus('Revoking license...');
  try {
    const response = await authFetch('/licenses/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    await loadLicenses();
    setStatus('License revoked.', 'success');
  } catch (error) {
    console.error('Unable to revoke license', error);
    setStatus('Unable to revoke license.', 'error');
  }
}

async function unassignLicense(code) {
  setStatus('Releasing license...');
  try {
    const response = await authFetch('/licenses/unassign', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    await loadLicenses();
    setStatus('License released.', 'success');
  } catch (error) {
    console.error('Unable to release license', error);
    setStatus('Unable to release license.', 'error');
  }
}

if (tenantSelect) {
  tenantSelect.addEventListener('change', () => {
    selectedTenantId = tenantSelect.value || null;
    loadLicenses();
  });
}

if (generateButton) {
  generateButton.addEventListener('click', createLicense);
}

(async function init() {
  await initializeTenantFilter();
  await loadLicenses();
})();
