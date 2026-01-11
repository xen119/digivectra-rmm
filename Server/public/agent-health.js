const authFetch = (input, init = {}) => fetch(input, { credentials: 'same-origin', ...init });
const LEVELS = ['Critical', 'Error', 'Warning', 'Information'];

const refreshButton = document.getElementById('refreshButton');
const agentTitle = document.getElementById('agentTitle');
const agentMeta = document.getElementById('agentMeta');
const levelGrid = document.getElementById('levelGrid');
const agentError = document.getElementById('agentError');
const detailPanel = document.getElementById('detailPanel');
const detailMeta = document.getElementById('detailMeta');
const detailLabel = document.getElementById('detailLabel');
const detailCount = document.getElementById('detailCount');
const detailList = document.getElementById('detailList');

const params = new URLSearchParams(window.location.search);
const agentId = params.get('agent') ?? '';
const agentName = params.get('name') ?? '';

document.addEventListener('DOMContentLoaded', () => {
  if (!agentId) {
    showError('Agent ID is required. Append ?agent=<id> to the URL.');
    return;
  }

  agentTitle.textContent = agentName ? `Events for ${agentName}` : 'Agent events';
  refreshButton?.addEventListener('click', () => loadAgentStats(true));
  loadAgentStats();
});

function showError(message) {
  agentMeta.textContent = 'Unable to load agent data.';
  agentError.textContent = message;
  levelGrid.innerHTML = '<div class="placeholder">No data available.</div>';
}

async function loadAgentStats(force = false) {
  agentMeta.textContent = 'Refreshing event counts…';
  agentError.textContent = '';
  if (!levelGrid) {
    return;
  }

  levelGrid.innerHTML = '<div class="placeholder">Loading counts…</div>';

  try {
    const response = await authFetch(`/system-health/agent/${encodeURIComponent(agentId)}`, { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`Server returned ${response.status}`);
    }

    const payload = await response.json();
    const counts = payload?.eventStats;
    agentMeta.textContent = payload?.since
      ? `Counts since ${formatDate(payload.since)} · refreshed ${formatDate(payload.retrievedAt ?? new Date().toISOString())}`
      : 'Counts for the past week';
    if (payload?.error) {
      agentError.textContent = payload.error;
    }

    renderLevels(counts, payload);
  } catch (error) {
    showError(`Unable to load stats: ${error.message}`);
  }
}

function renderLevels(counts, payload) {
  if (!levelGrid) {
    return;
  }

  const agentStatus = payload?.status ?? 'unknown';
  detailLabel.textContent = `Event entries · ${agentStatus.toUpperCase()}`;
  detailMeta.textContent = 'Select a level to load entries.';
  detailCount.textContent = '';
  detailList.innerHTML = '<div class="placeholder">Click a severity badge above.</div>';

  levelGrid.innerHTML = '';
  LEVELS.forEach((level) => {
    const count = counts ? counts[level] : null;
    const pill = document.createElement('button');
    pill.type = 'button';
    pill.className = `level-pill ${level.toLowerCase()}${!counts ? ' disabled' : ''}`;
    pill.innerHTML = `<span>${level}</span><strong>${typeof count === 'number' ? count : '–'}</strong>`;
    pill.disabled = !counts;
    if (counts) {
      pill.addEventListener('click', () => loadEntries(level));
    }
    levelGrid.appendChild(pill);
  });
}

function loadEntries(level) {
  if (!detailList) {
    return;
  }
  detailMeta.textContent = `Loading ${level} entries…`;
  detailCount.textContent = '';
  detailList.innerHTML = '<div class="placeholder">Loading events…</div>';

  authFetch(`/system-health/${encodeURIComponent(agentId)}/entries?level=${encodeURIComponent(level)}`, { cache: 'no-store' })
    .then((response) => {
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      return response.json();
    })
    .then((payload) => {
      const entries = Array.isArray(payload.entries) ? payload.entries : [];
      detailMeta.textContent = `${entries.length} event${entries.length === 1 ? '' : 's'} loaded`;
      detailCount.textContent = payload.level ? payload.level : level;
      if (!entries.length) {
        detailList.innerHTML = '<div class="placeholder">No entries found.</div>';
        return;
      }
      renderEventEntries(entries);
    })
    .catch((error) => {
      detailMeta.textContent = `Failed to load ${level} entries`;
      detailCount.textContent = '';
      detailList.innerHTML = `<div class="placeholder">Error: ${error.message}</div>`;
    });
}

function renderEventEntries(entries) {
  if (!detailList) {
    return;
  }
  detailList.innerHTML = '';
  entries.forEach((entry) => {
    const item = document.createElement('div');
    item.className = 'event-item';
    const title = document.createElement('h4');
    title.textContent = `${entry.log ?? 'Event log'} · ${entry.ProviderName ?? entry.providerName ?? 'Unknown source'}`;
    const meta = document.createElement('p');
    meta.className = 'event-meta';
    const timeText = entry.time ? formatDate(entry.time) : 'Unknown time';
    meta.textContent = `${timeText} · Event ID ${entry.Id ?? entry.id ?? 'n/a'}`;
    const message = document.createElement('p');
    message.className = 'event-message';
    message.textContent = entry.message ?? 'No description available.';
    item.appendChild(title);
    item.appendChild(meta);
    item.appendChild(message);
    detailList.appendChild(item);
  });
}

function formatDate(value) {
  if (!value) {
    return 'Unknown time';
  }
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) {
    return value;
  }
  return dt.toLocaleString();
}
