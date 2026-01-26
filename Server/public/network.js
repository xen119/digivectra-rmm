const authFetch = (input, init = {}) => fetch(input, { credentials: 'same-origin', ...init });
const statusEl = document.getElementById('status');
const recordsBody = document.getElementById('recordsBody');
const refreshButton = document.getElementById('refreshButton');
const limitInput = document.getElementById('limitInput');
const agentInput = document.getElementById('agentInput');

const scanStatusEl = document.getElementById('scanStatus');
const scanForm = document.getElementById('scanForm');
const agentSelect = document.getElementById('scanAgent');
const liveHostsList = document.getElementById('liveHostsList');
const scanSummaryEl = document.getElementById('scanSummary');
const clearHistoryButton = document.getElementById('clearHistoryButton');
const tenantBadge = document.getElementById('tenantBadge');
const wakeStatusEl = document.getElementById('wakeStatus');

const MAX_LIVE_HOSTS = 120;
let liveHostCount = 0;
let activeScanRequestId = null;
let activeScanAgentId = null;
let scanEventSource = null;

function sanitizeNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function resetLiveHosts() {
  if (!liveHostsList) {
    return;
  }
  liveHostCount = 0;
  liveHostsList.innerHTML = '<li class="empty">No hosts discovered yet.</li>';
}

function appendLiveHost(host) {
  if (!liveHostsList || !host) {
    return;
  }

  const placeholder = liveHostsList.querySelector('li.empty');
  if (placeholder) {
    placeholder.remove();
  }

  const entry = createHostListItem(host, activeScanAgentId);
  liveHostsList.appendChild(entry);
  liveHostCount += 1;

  while (liveHostsList.childElementCount > MAX_LIVE_HOSTS) {
    liveHostsList.removeChild(liveHostsList.firstElementChild);
  }
}

function createHostListItem(host, agentId) {
  const entry = document.createElement('li');

  const meta = document.createElement('div');
  meta.className = 'host-meta';
  const shortName = host.hostName || 'unknown';
  const macPart = host.macAddress ? ` (${host.macAddress})` : '';
  const title = document.createElement('span');
  title.textContent = `${host.ip || 'unknown'}: ${shortName}${macPart}`;
  meta.appendChild(title);
  const services = document.createElement('span');
  services.className = 'host-services';
  const serviceText = Array.isArray(host.services) && host.services.length
    ? ` - Services: ${host.services.join(', ')}`
    : ' - Services: none detected';
  services.textContent = serviceText;
  meta.appendChild(services);
  entry.appendChild(meta);

  const actions = document.createElement('div');
  const button = document.createElement('button');
  button.type = 'button';
  button.textContent = 'Wake';
  button.className = 'wake-button';
  button.disabled = !host.macAddress || !agentId;
  button.addEventListener('click', () => sendWakeOnLan(agentId, host.macAddress, host.ip, button));
  actions.appendChild(button);
  entry.appendChild(actions);

  return entry;
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

function handleNetworkResult(event) {
  if (!event?.data) {
    return;
  }
  try {
    const payload = JSON.parse(event.data);
    const devices = Array.isArray(payload.devices) ? payload.devices : [];
    for (const host of devices) {
      appendLiveHost(host);
    }
    updateScanSummary(`Live discoveries: ${liveHostCount} host${liveHostCount === 1 ? '' : 's'}`);
  } catch (error) {
    console.error('Unable to parse network scanner result event', error);
  }
}

function handleNetworkComplete(event) {
  if (!event?.data) {
    return;
  }
  try {
    const payload = JSON.parse(event.data);
    const scanned = Number.isFinite(payload.scanned) ? payload.scanned : null;
    const found = Number.isFinite(payload.found) ? payload.found : liveHostCount;
    const duration = Number.isFinite(payload.durationMs) ? payload.durationMs : null;
    updateScanSummary(`Scan complete: ${found ?? 0} found${scanned !== null ? ` / ${scanned} scanned` : ''}${duration !== null ? ` (${duration} ms)` : ''}`);
    scanStatusEl.textContent = 'Scan completed.';
    loadNetworkRecords();
  } catch (error) {
    console.error('Unable to parse network scanner completion event', error);
    scanStatusEl.textContent = 'Scan completed.';
  } finally {
    closeScanStream();
  }
}

function handleNetworkError(event) {
  if (!event?.data) {
    scanStatusEl.textContent = 'Scan failed.';
    closeScanStream();
    return;
  }
  try {
    const payload = JSON.parse(event.data);
    const message = typeof payload.message === 'string' ? payload.message : 'Scan error.';
    scanStatusEl.textContent = `Scan failed: ${message}`;
    updateScanSummary('Scan not running.');
  } catch (error) {
    console.error('Unable to parse network scanner error event', error);
    scanStatusEl.textContent = 'Scan failed.';
  } finally {
    closeScanStream();
  }
}

function handleWakeResult(event) {
  if (!wakeStatusEl || !event?.data) {
    return;
  }
  try {
    const payload = JSON.parse(event.data);
    const target = payload.macAddress ? `MAC ${payload.macAddress}` : 'Wake-on-LAN';
    const message = payload.message ?? 'Result received.';
    const success = payload.success === true;
    wakeStatusEl.textContent = `${target}: ${message}`;
    wakeStatusEl.classList.toggle('success', success);
    wakeStatusEl.classList.toggle('error', !success);
  } catch (error) {
    console.error('Unable to parse Wake-on-LAN event', error);
    wakeStatusEl.textContent = 'Wake-on-LAN result received.';
    wakeStatusEl.classList.remove('success', 'error');
  }
}

function startNetworkStream(agentId, requestId) {
  if (!agentId || !requestId || typeof EventSource === 'undefined') {
    updateScanSummary('Live updates not available in this browser.');
    return;
  }

  closeScanStream();
  resetLiveHosts();
  updateScanSummary('Listening for live hosts...');

  const url = `/clients/${encodeURIComponent(agentId)}/network-scanner/${encodeURIComponent(requestId)}/events`;
  const source = new EventSource(url, { withCredentials: true });
  scanEventSource = source;
  scanEventSource.addEventListener('network-scanner-result', handleNetworkResult);
  scanEventSource.addEventListener('network-scanner-complete', handleNetworkComplete);
  scanEventSource.addEventListener('network-scanner-error', handleNetworkError);
  scanEventSource.addEventListener('network-scanner-wake-result', handleWakeResult);
  scanEventSource.addEventListener('error', () => {
    updateScanSummary('Waiting for scan updates...');
  });

  activeScanAgentId = agentId;
  activeScanRequestId = requestId;
}

 async function loadNetworkRecords() {
  if (!recordsBody || !statusEl) {
    return;
  }

  statusEl.textContent = 'Loading network scanner history...';
  recordsBody.innerHTML = '<tr><td colspan="7">Loading...</td></tr>';

  try {
    const params = new URLSearchParams();
    params.set('limit', sanitizeNumber(limitInput?.value, 50));
    const agentFilter = agentInput?.value?.trim();
    if (agentFilter) {
      params.set('agent', agentFilter);
    }

    const response = await authFetch(`/network-scanner/discoveries?${params.toString()}`);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    const records = Array.isArray(data.records) ? data.records : [];
    renderRecords(records);
    statusEl.textContent = `Showing ${records.length} record${records.length === 1 ? '' : 's'}`;
  } catch (error) {
    console.error('Failed to load network scanner history', error);
    recordsBody.innerHTML = '<tr><td colspan="7">Unable to load records.</td></tr>';
    statusEl.textContent = 'Unable to load network scanner history.';
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

    const hostsCell = document.createElement('td');
    const details = document.createElement('details');
    const summary = document.createElement('summary');
    const deviceCount = Array.isArray(record.devices) ? record.devices.length : 0;
    summary.textContent = `${deviceCount} host${deviceCount === 1 ? '' : 's'}`;
    details.appendChild(summary);
    details.className = 'record-details';

    if (deviceCount > 0) {
      const list = document.createElement('ul');
      list.className = 'device-list';
      for (const device of record.devices) {
        const item = createHostListItem(device, record.agentId);
        list.appendChild(item);
      }
      details.appendChild(list);
    } else {
      const empty = document.createElement('div');
      empty.textContent = 'No hosts discovered';
      empty.style.fontSize = '0.75rem';
      empty.style.color = '#6b7280';
      details.appendChild(empty);
    }
    hostsCell.appendChild(details);
    row.appendChild(hostsCell);

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
        agentSelect.appendChild(option);
      }
    } else {
      agentSelect.innerHTML = '<option value="">No agents available</option>';
    }
  } catch (error) {
    console.error('Unable to load agents for network scanner', error);
    agentSelect.innerHTML = '<option value="">Failed to load agents</option>';
  } finally {
    agentSelect.disabled = false;
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
  scanStatusEl.textContent = 'Starting network scanner scan.';
  updateScanSummary('Awaiting live results…');
  resetLiveHosts();
  closeScanStream();

  try {
  const response = await authFetch(`/clients/${encodeURIComponent(agentId)}/network-scanner/scan`, {
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
      startNetworkStream(agentId, activeScanRequestId);
    }
    loadNetworkRecords();
  } catch (error) {
    console.error('Unable to start network scanner scan', error);
    scanStatusEl.textContent = `Scan failed: ${error.message}`;
    updateScanSummary('Scan not running.');
  } finally {
    submitButton?.removeAttribute('disabled');
  }
}

async function sendWakeOnLan(agentId, macAddress, targetIp, button) {
  if (!agentId || !macAddress || !button) {
    return;
  }

  button.disabled = true;
  if (wakeStatusEl) {
    wakeStatusEl.textContent = `Sending Wake-on-LAN to ${macAddress}…`;
    wakeStatusEl.classList.remove('success', 'error');
  }

  try {
    const payload = { macAddress };
    if (targetIp) {
      payload.targetIp = targetIp;
    }

    const response = await authFetch(`/clients/${encodeURIComponent(agentId)}/network-scanner/wake`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new Error(text || `HTTP ${response.status}`);
    }

    const data = await response.json();
    if (wakeStatusEl) {
      wakeStatusEl.textContent = `Wake-on-LAN queued (request: ${data.requestId ?? 'unknown'}).`;
      wakeStatusEl.classList.add('success');
      wakeStatusEl.classList.remove('error');
    }
  } catch (error) {
    console.error('Unable to send Wake-on-LAN', error);
    if (wakeStatusEl) {
      wakeStatusEl.textContent = `Wake failed: ${error.message}`;
      wakeStatusEl.classList.add('error');
      wakeStatusEl.classList.remove('success');
    }
  } finally {
    button.disabled = false;
  }
}

async function clearNetworkHistory() {
  if (!clearHistoryButton || !statusEl) {
    return;
  }

  clearHistoryButton.setAttribute('disabled', 'true');
  statusEl.textContent = 'Clearing network scanner history...';

  try {
    const response = await authFetch('/network-scanner/discoveries/clear', { method: 'POST' });
    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new Error(text || `HTTP ${response.status}`);
    }

    statusEl.textContent = 'History cleared.';
    loadNetworkRecords();
  } catch (error) {
    console.error('Unable to clear network scanner history', error);
    statusEl.textContent = `Unable to clear history: ${error.message}`;
  } finally {
    clearHistoryButton.removeAttribute('disabled');
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

refreshButton?.addEventListener('click', () => {
  loadNetworkRecords();
  loadAgentOptions();
  loadTenantInfo();
});

clearHistoryButton?.addEventListener('click', clearNetworkHistory);

scanForm?.addEventListener('submit', handleScanSubmit);
window.addEventListener('beforeunload', closeScanStream);

setInterval(loadNetworkRecords, 60_000);
loadNetworkRecords();
loadAgentOptions();
loadTenantInfo();
