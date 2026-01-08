const params = new URLSearchParams(window.location.search);
const agentId = params.get('agent');
const agentHeading = document.getElementById('agentHeading');
const statusEl = document.getElementById('status');
const bsodList = document.getElementById('bsodList');
const refreshButton = document.getElementById('refreshButton');
let summaryCache = null;
const authFetch = (input, init) => fetch(input, { credentials: 'same-origin', ...init });

refreshButton?.addEventListener('click', () => loadBsod(true));

if (!agentId) {
  statusEl.textContent = 'Agent identifier missing.';
  refreshButton.disabled = true;
} else {
  initialize();
}

async function initialize() {
  await fetchAgentName();
  await loadBsod(true);
}

async function fetchAgentName() {
  try {
    const response = await authFetch('/clients', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error('Failed to fetch agent');
    }

    const agents = await response.json();
    const agent = Array.isArray(agents) ? agents.find((entry) => entry.id === agentId) : null;
    if (agent && agentHeading) {
      agentHeading.textContent = `BSODs for ${agent.name}`;
    }
  } catch (error) {
    console.error(error);
  }
}

async function loadBsod(force = false) {
  if (!agentId) {
    return;
  }

  setStatus(force ? 'Refreshing BSOD data...' : 'Loading BSOD data...');

  try {
    if (force) {
      const refreshResponse = await authFetch(`/bsod/${agentId}/refresh`, { method: 'POST' });
      if (!refreshResponse.ok) {
        throw new Error('Failed to refresh BSOD data');
      }
      await delay(500);
    }

    const response = await authFetch(`/bsod/${agentId}/data`, { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    summaryCache = payload?.summary ?? null;
    renderSummary(summaryCache);
  } catch (error) {
    console.error(error);
    setStatus(`Failed to load BSOD data (${error.message}).`);
  }
}

function renderSummary(summary) {
  bsodList.innerHTML = '';

  if (!summary || !Array.isArray(summary.events) || summary.events.length === 0) {
    const empty = document.createElement('li');
    empty.className = 'bsod-entry empty';
    empty.textContent = 'No BSOD events recorded.';
    bsodList.appendChild(empty);
    setStatus(summary ? `Total BSOD events: ${summary.totalCount}` : 'No BSOD events yet.');
    return;
  }

  setStatus(`Total BSOD events: ${summary.totalCount}`);

  summary.events.forEach((event) => {
    const entry = document.createElement('li');
    entry.className = 'bsod-entry';
    const time = document.createElement('time');
    time.textContent = new Date(event.timestampUtc).toLocaleString();
    const description = document.createElement('div');
    description.textContent = event.description || 'No details available.';
    entry.appendChild(time);
    entry.appendChild(description);
    bsodList.appendChild(entry);
  });
}

function setStatus(text) {
  if (!statusEl) {
    return;
  }
  statusEl.textContent = text;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
