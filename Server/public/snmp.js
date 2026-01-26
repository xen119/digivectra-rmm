const authFetch = (input, init = {}) => fetch(input, { credentials: 'same-origin', ...init });
const statusEl = document.getElementById('status');
const recordsBody = document.getElementById('recordsBody');
const refreshButton = document.getElementById('refreshButton');
const limitInput = document.getElementById('limitInput');
const agentInput = document.getElementById('agentInput');

const scanStatusEl = document.getElementById('scanStatus');
const scanForm = document.getElementById('scanForm');
const agentSelect = document.getElementById('scanAgent');
const liveDevicesList = document.getElementById('liveDevicesList');
const scanSummaryEl = document.getElementById('scanSummary');
const clearHistoryButton = document.getElementById('clearHistoryButton');
const tenantBadge = document.getElementById('tenantBadge');

const MAX_LIVE_DEVICES = 120;
let liveDeviceCount = 0;
let activeScanRequestId = null;
let activeScanAgentId = null;
let scanEventSource = null;

function sanitizeNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function resetLiveDevices() {
  if (!liveDevicesList) {
    return;
  }
  liveDeviceCount = 0;
  liveDevicesList.innerHTML = '<li class="empty">No devices discovered yet.</li>';
}

function appendLiveDevice(device) {
  if (!liveDevicesList || !device) {
    return;
  }

  const placeholder = liveDevicesList.querySelector('li.empty');
  if (placeholder) {
    placeholder.remove();
  }

  const entry = document.createElement('li');
  const name = device.sysName || device.sysDescr || device.sysObjectId || 'unknown';
  entry.textContent = `${device.ip || 'unknown'} — ${name}`;
  liveDevicesList.appendChild(entry);
  liveDeviceCount += 1;

  while (liveDevicesList.childElementCount > MAX_LIVE_DEVICES) {
    liveDevicesList.removeChild(liveDevicesList.firstElementChild);
  }
}

function updateScanSummary(message) {
  if (!scanSummaryEl) {
    return;
  }
  scanSummaryEl.textContent = message;
}

function closeScanStream() {
  if (scanEventSource) {
    scanEventSource.close();
    scanEventSource = null;
  }
  activeScanRequestId = null;
  activeScanAgentId = null;
}

function handleSnmpResult(event) {
  if (!event?.data) {
    return;
  }
  try {
    const payload = JSON.parse(event.data);
    const devices = Array.isArray(payload.devices) ? payload.devices : [];
    if (!devices.length) {
      return;
    }

    for (const device of devices) {
      appendLiveDevice(device);
    }

    updateScanSummary(`Live discoveries: ${liveDeviceCount} device${liveDeviceCount === 1 ? '' : 's'}`);
  } catch (error) {
    console.error('Unable to parse SNMP result event', error);
  }
}

function handleSnmpComplete(event) {
  if (!event?.data) {
    return;
  }
  try {
    const payload = JSON.parse(event.data);
    const scanned = Number.isFinite(payload.scanned) ? payload.scanned : null;
    const found = Number.isFinite(payload.found) ? payload.found : liveDeviceCount;
    const duration = Number.isFinite(payload.durationMs) ? payload.durationMs : null;
    updateScanSummary(`Scan complete: ${found ?? 0} found${scanned !== null ? ` / ${scanned} scanned` : ''}${duration !== null ? ` (${duration} ms)` : ''}`);
    scanStatusEl.textContent = 'Scan completed.';
    loadSnmpRecords();
  } catch (error) {
    console.error('Unable to parse SNMP completion event', error);
    scanStatusEl.textContent = 'Scan completed.';
  } finally {
    closeScanStream();
  }
}

function handleSnmpError(event) {
  if (!event?.data) {
    scanStatusEl.textContent = 'Scan failed.';
    closeScanStream();
    return;
  }
  try {
    const payload = JSON.parse(event.data);
    const message = typeof payload.message === 'string' ? payload.message : 'Scan error.';
    scanStatusEl.textContent = `Scan failed: ${message}`;
  } catch (error) {
    console.error('Unable to parse SNMP error event', error);
    scanStatusEl.textContent = 'Scan failed.';
  } finally {
    closeScanStream();
  }
}

async function clearSnmpHistory() {
  if (!clearHistoryButton || !statusEl) {
    return;
  }

  clearHistoryButton.setAttribute('disabled', 'true');
  statusEl.textContent = 'Clearing SNMP discovery history...';

  try {
    const response = await authFetch('/snmp/discoveries/clear', { method: 'POST' });
    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new Error(text || `HTTP ${response.status}`);
    }

    statusEl.textContent = 'History cleared.';
    loadSnmpRecords();
  } catch (error) {
    console.error('Unable to clear SNMP history', error);
    statusEl.textContent = `Unable to clear history: ${error.message}`;
  } finally {
    clearHistoryButton.removeAttribute('disabled');
  }
}

function startSnmpStream(agentId, requestId) {
  if (!agentId || !requestId || typeof EventSource === 'undefined') {
    updateScanSummary('Live updates not available in this browser.');
    return;
  }

  closeScanStream();
  if (liveDevicesList) {
    resetLiveDevices();
  }
  updateScanSummary('Listening for live discoveries...');

  const url = `/clients/${encodeURIComponent(agentId)}/snmp/${encodeURIComponent(requestId)}/events`;
  const source = new EventSource(url, { withCredentials: true });
  scanEventSource = source;
  scanEventSource.addEventListener('snmp-result', handleSnmpResult);
  scanEventSource.addEventListener('snmp-complete', handleSnmpComplete);
  scanEventSource.addEventListener('snmp-error', handleSnmpError);
  scanEventSource.addEventListener('error', () => {
    updateScanSummary('Waiting for scan updates...');
  });
}

async function loadSnmpRecords() {
  if (!recordsBody || !statusEl) {
    return;
  }

  statusEl.textContent = 'Loading SNMP discovery history...';
  recordsBody.innerHTML = '<tr><td colspan="7">Loading...</td></tr>';

  try {
    const params = new URLSearchParams();
    params.set('limit', sanitizeNumber(limitInput?.value, 50));
    const agentFilter = agentInput?.value?.trim();
    if (agentFilter) {
      params.set('agent', agentFilter);
    }

    const response = await authFetch(`/snmp/discoveries?${params.toString()}`);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    const records = Array.isArray(data.records) ? data.records : [];
    renderRecords(records);
    statusEl.textContent = `Showing ${records.length} record${records.length === 1 ? '' : 's'}`;
  } catch (error) {
    console.error('Failed to load SNMP discovery history', error);
    recordsBody.innerHTML = '<tr><td colspan="7">Unable to load records.</td></tr>';
    statusEl.textContent = 'Unable to load SNMP discovery history.';
  }
}

function renderRecords(records) {
  if (!recordsBody) {
    return;
  }

  if (!records.length) {
    recordsBody.innerHTML = '<tr><td colspan="7">No records found.</td></tr>';
    return;
  }

  recordsBody.innerHTML = '';
  for (const record of records) {
    const row = document.createElement('tr');

    const timestamp = document.createElement('td');
    timestamp.textContent = new Date(record.completedAt ?? record.startedAt ?? Date.now()).toLocaleString();
    row.appendChild(timestamp);

    const agent = document.createElement('td');
    agent.textContent = record.agentName || record.agentId || 'unknown';
    row.appendChild(agent);

    const statusCell = document.createElement('td');
    const pill = document.createElement('span');
    pill.className = `pill ${record.status || 'unknown'}`;
    pill.textContent = record.status === 'error' ? 'Error' : 'Complete';
    statusCell.appendChild(pill);
    if (record.message) {
      const note = document.createElement('div');
      note.textContent = record.message;
      note.style.fontSize = '0.75rem';
      note.style.marginTop = '0.25rem';
      statusCell.appendChild(note);
    }
    row.appendChild(statusCell);

    const devicesCell = document.createElement('td');
    const details = document.createElement('details');
    const summary = document.createElement('summary');
    const deviceCount = Array.isArray(record.devices) ? record.devices.length : 0;
    summary.textContent = `${deviceCount} device${deviceCount === 1 ? '' : 's'}`;
    details.appendChild(summary);
    details.className = 'record-details';

    if (deviceCount > 0) {
      const list = document.createElement('ul');
      list.className = 'device-list';
      for (const device of record.devices) {
        const item = document.createElement('li');
        const name = device.sysName || device.sysDescr || device.sysObjectId || 'unknown';
        item.textContent = `${device.ip || 'unknown'} – ${name}`;
        list.appendChild(item);
      }
      details.appendChild(list);
    } else {
      const empty = document.createElement('div');
      empty.textContent = 'No devices discovered';
      empty.style.fontSize = '0.75rem';
      empty.style.color = '#6b7280';
      details.appendChild(empty);
    }
    devicesCell.appendChild(details);
    row.appendChild(devicesCell);

    const scannedCell = document.createElement('td');
    scannedCell.textContent = typeof record.scanned === 'number' ? record.scanned.toString() : '—';
    row.appendChild(scannedCell);

    const foundCell = document.createElement('td');
    foundCell.textContent = typeof record.found === 'number' ? record.found.toString() : '—';
    row.appendChild(foundCell);

    const durationCell = document.createElement('td');
    durationCell.textContent = typeof record.durationMs === 'number' ? record.durationMs.toString() : '—';
    row.appendChild(durationCell);

    recordsBody.appendChild(row);
  }
}

async function loadAgentOptions() {
  if (!agentSelect) {
    return;
  }

  agentSelect.disabled = true;
  agentSelect.innerHTML = '<option value="">Loading agents...</option>';

  try {
    const response = await authFetch('/clients?cache=no-store');
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const agents = await response.json();
    agentSelect.innerHTML = '';
    if (Array.isArray(agents) && agents.length > 0) {
      for (const agent of agents) {
        const option = document.createElement('option');
        option.value = agent.id ?? '';
        option.textContent = `${agent.name ?? agent.id ?? 'unnamed'} (${agent.remoteAddress ?? 'unknown'})`;
        if (agent.snmpDiscoveryEnabled === false) {
          option.textContent += ' (SNMP disabled)';
        }
        agentSelect.appendChild(option);
      }
    } else {
      agentSelect.innerHTML = '<option value="">No agents available</option>';
    }
  } catch (error) {
    console.error('Unable to load agents for SNMP scan', error);
    agentSelect.innerHTML = '<option value="">Failed to load agents</option>';
  } finally {
    agentSelect.disabled = false;
  }
}

async function loadTenantInfo() {
  if (!tenantBadge) {
    return;
  }

  try {
    const response = await authFetch('/tenants/current', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    const tenant = data?.tenant;
    const name = tenant?.name ?? 'unknown';
    const suffix = tenant?.description ? ` – ${tenant.description}` : '';
    tenantBadge.textContent = `Tenant: ${name}${suffix}`;
  } catch (error) {
    console.error('Unable to load tenant info', error);
    tenantBadge.textContent = 'Tenant: unknown';
  }
}

async function handleScanSubmit(event) {
  event.preventDefault();
  if (!scanForm || !scanStatusEl || !agentSelect) {
    return;
  }

  const agentId = agentSelect.value;
  if (!agentId) {
    scanStatusEl.textContent = 'Select an agent first.';
    return;
  }

  const submitButton = scanForm.querySelector('button');
  submitButton?.setAttribute('disabled', 'true');
  scanStatusEl.textContent = 'Starting SNMP scan…';
  updateScanSummary('Awaiting live results…');
  resetLiveDevices();
  closeScanStream();

  try {
    const response = await authFetch(`/clients/${encodeURIComponent(agentId)}/snmp/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new Error(text || `HTTP ${response.status}`);
    }

    const data = await response.json();
    activeScanRequestId = data.requestId ?? null;
    activeScanAgentId = agentId;
    scanStatusEl.textContent = `Scan started (request: ${activeScanRequestId ?? 'unknown'}).`;
    if (activeScanRequestId) {
      startSnmpStream(agentId, activeScanRequestId);
    } else {
      updateScanSummary('Awaiting live results…');
    }
    loadSnmpRecords();
  } catch (error) {
    console.error('Unable to start SNMP scan', error);
    scanStatusEl.textContent = `Scan failed: ${error.message}`;
    updateScanSummary('Scan not running.');
  } finally {
    submitButton?.removeAttribute('disabled');
  }
}

refreshButton?.addEventListener('click', () => {
  loadSnmpRecords();
  loadAgentOptions();
  loadTenantInfo();
});

clearHistoryButton?.addEventListener('click', clearSnmpHistory);

scanForm?.addEventListener('submit', handleScanSubmit);
window.addEventListener('beforeunload', closeScanStream);

setInterval(loadSnmpRecords, 60_000);
loadSnmpRecords();
loadAgentOptions();
loadTenantInfo();
