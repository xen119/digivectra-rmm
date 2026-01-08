const params = new URLSearchParams(window.location.search);
const agentId = params.get('agent');
const agentHeading = document.getElementById('agentHeading');
const statusEl = document.getElementById('status');
const processBody = document.getElementById('processBody');
const refreshButton = document.getElementById('refreshButton');
const logEl = document.getElementById('log');
const authFetch = (input, init) => fetch(input, { credentials: 'same-origin', ...init });
const sortSelect = document.getElementById('sortSelect');
const intervalInput = document.getElementById('intervalInput');
let retryTimer;
let autoRefreshTimer;
let snapshotCache = null;
let sortKey = 'cpu';
let refreshIntervalSeconds = 15;

refreshButton?.addEventListener('click', () => loadProcesses(true));
sortSelect?.addEventListener('change', () => {
  sortKey = sortSelect.value;
  renderProcesses(snapshotCache);
});

intervalInput?.addEventListener('change', () => {
  const value = Number(intervalInput.value);
  if (!Number.isFinite(value) || value < 5) {
    refreshIntervalSeconds = 5;
    intervalInput.value = '5';
  } else {
    refreshIntervalSeconds = Math.round(value);
  }
  restartAutoRefresh();
});

if (!agentId) {
  statusEl.textContent = 'Agent identifier missing.';
  if (refreshButton) {
    refreshButton.disabled = true;
  }
} else {
  initialize();
}

async function initialize() {
  await fetchAgentName();
  await loadProcesses(true);
  restartAutoRefresh();
}

async function fetchAgentName() {
  try {
    const response = await authFetch('/clients', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error('Failed to fetch agent list');
    }

    const agents = await response.json();
    const agent = Array.isArray(agents) ? agents.find((entry) => entry.id === agentId) : null;
    if (agent && agentHeading) {
      agentHeading.textContent = `Tasks for ${agent.name}`;
    }
  } catch (error) {
    console.error(error);
  }
}

async function loadProcesses(force = false) {
  if (!agentId) {
    return;
  }

  setStatus(force ? 'Refreshing task information...' : 'Loading task information...');
  clearRetryTimer();

  try {
    if (force) {
      const refreshResponse = await authFetch(`/processes/${agentId}/refresh`, { method: 'POST' });
      if (!refreshResponse.ok) {
        throw new Error('Failed to refresh process list');
      }
      await delay(500);
    }

    const response = await authFetch(`/processes/${agentId}/data`, { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    snapshotCache = payload?.snapshot ?? null;
    renderProcesses(snapshotCache);
  } catch (error) {
    console.error(error);
    setStatus(`Failed to load processes (${error.message}).`);
    scheduleRetry(2000);
  }
}

function renderProcesses(snapshot) {
  processBody.innerHTML = '';
  if (!snapshot || !Array.isArray(snapshot.processes) || snapshot.processes.length === 0) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 8;
    cell.textContent = 'No process data available.';
    cell.style.textAlign = 'center';
    row.appendChild(cell);
    processBody.appendChild(row);
    setStatus('Process snapshot unavailable.');
    scheduleRetry(1000);
    return;
  }

  const processes = sortProcesses(snapshot.processes);
  setStatus(`Snapshot captured at ${new Date(snapshot.retrievedAt).toLocaleTimeString()}.`);
  clearRetryTimer();

  processes.forEach((process) => {
    const row = document.createElement('tr');

    row.appendChild(createCell(process.processId));
    row.appendChild(createCell(process.name));
    row.appendChild(createPercentCell(process.cpuPercent));
    row.appendChild(createPercentCell(process.memoryPercent));
    row.appendChild(createPercentCell(process.diskPercent));
    row.appendChild(createPercentCell(process.networkPercent));
    row.appendChild(createCell(process.threads));

    const actionCell = document.createElement('td');
    const killButton = document.createElement('button');
    killButton.type = 'button';
    killButton.className = 'table-button';
    killButton.textContent = 'Kill';
    killButton.addEventListener('click', () => killProcess(process.processId, killButton));
    actionCell.appendChild(killButton);
    row.appendChild(actionCell);

    processBody.appendChild(row);
  });
}

function sortProcesses(list) {
  if (!Array.isArray(list)) {
    return [];
  }

  const metric = sortKey;
  return [...list].sort((a, b) => {
    const aValue = getMetricValue(a, metric);
    const bValue = getMetricValue(b, metric);
    if (aValue === bValue) {
      return a.name.localeCompare(b.name);
    }
    return bValue - aValue;
  });
}

function getMetricValue(process, metric) {
  switch (metric) {
    case 'memory':
      return process.memoryPercent ?? 0;
    case 'disk':
      return process.diskPercent ?? 0;
    case 'network':
      return process.networkPercent ?? 0;
    case 'cpu':
    default:
      return process.cpuPercent ?? 0;
  }
}

function createCell(value) {
  const cell = document.createElement('td');
  cell.textContent = value ?? '';
  return cell;
}

function createPercentCell(value) {
  const cell = document.createElement('td');
  const display = typeof value === 'number' ? value.toFixed(1) : '0.0';
  cell.innerHTML = `<span class="percent">${display}%</span>`;
  return cell;
}

async function killProcess(pid, button) {
  if (!agentId) {
    return;
  }

  button.disabled = true;
  button.classList.add('killing');
  setStatus(`Sending kill request for PID ${pid}...`);

  try {
    const response = await authFetch(`/processes/${agentId}/kill`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ processId: pid }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    logMessage(`Kill request sent for PID ${pid}.`);
    await loadProcesses(true);
  } catch (error) {
    console.error(error);
    setStatus(`Failed to kill process ${pid} (${error.message}).`);
  } finally {
    button.disabled = false;
    button.classList.remove('killing');
  }
}

function setStatus(text) {
  if (!statusEl) {
    return;
  }

  statusEl.textContent = text;
}

function logMessage(message) {
  if (!logEl) {
    return;
  }

  const entry = document.createElement('div');
  entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
  logEl.appendChild(entry);
  logEl.scrollTop = logEl.scrollHeight;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function scheduleRetry(ms = 1000) {
  clearRetryTimer();
  retryTimer = setTimeout(() => loadProcesses(), ms);
}

function clearRetryTimer() {
  if (retryTimer) {
    clearTimeout(retryTimer);
    retryTimer = undefined;
  }
}

function restartAutoRefresh() {
  clearAutoRefresh();
  if (refreshIntervalSeconds > 0) {
    autoRefreshTimer = setInterval(() => loadProcesses(true), refreshIntervalSeconds * 1000);
  }
}

function clearAutoRefresh() {
  if (autoRefreshTimer) {
    clearInterval(autoRefreshTimer);
    autoRefreshTimer = undefined;
  }
}
