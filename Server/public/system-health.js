const authFetch = (input, init = {}) => fetch(input, { credentials: 'same-origin', ...init });

const LEVELS = ['Critical', 'Error', 'Warning', 'Information'];
const statusEl = document.getElementById('statusMessage');
const refreshButton = document.getElementById('refreshButton');
const agentsContainer = document.getElementById('agentsContainer');
const detailPanel = document.getElementById('eventDetail');
const detailTitle = document.getElementById('detailTitle');
const detailMeta = document.getElementById('detailMeta');
const detailStatus = document.getElementById('detailStatus');
const detailList = document.getElementById('eventList');
const detailClose = document.getElementById('detailClose');

document.addEventListener('DOMContentLoaded', () => {
  refreshButton?.addEventListener('click', () => loadAgents(true));
  detailClose?.addEventListener('click', hideDetailPanel);
  loadAgents();
});

async function loadAgents(force = false) {
  setStatus('Refreshing event log counts…');
  if (!agentsContainer) {
    return;
  }
  agentsContainer.innerHTML = '<div class="placeholder">Loading agents…</div>';

  try {
    const response = await authFetch('/system-health/agents', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`Server returned ${response.status}`);
    }
    const payload = await response.json();
    const agents = Array.isArray(payload?.agents) ? payload.agents : [];
    renderAgents(agents);
    const when = payload?.summary?.retrievedAt ? new Date(payload.summary.retrievedAt).toLocaleString() : 'now';
    setStatus(`Updated ${when}`);
  } catch (error) {
    setStatus(`Unable to load system health: ${error.message}`, true);
    agentsContainer.innerHTML = '<div class="placeholder">Unable to load agent data.</div>';
  }
}

function renderAgents(list) {
  if (!agentsContainer) {
    return;
  }

  if (!list.length) {
    agentsContainer.innerHTML = '<div class="placeholder">No agents connected.</div>';
    return;
  }

  agentsContainer.innerHTML = '';
  list.forEach((agent) => {
    const card = document.createElement('article');
    card.className = 'agent-card';

    const header = document.createElement('div');
    header.className = 'agent-header';
    header.innerHTML = `
      <div>
        <h3>${agent.name ?? agent.agentId ?? 'Unknown agent'}</h3>
        <p class="agent-meta">
          ${agent.os ?? 'Unknown OS'} · ${agent.group ?? 'Ungrouped'}
          ${agent.loggedInUser ? `· User: ${agent.loggedInUser}` : ''}
        </p>
      </div>
    `;

    const pill = document.createElement('span');
    pill.className = `status-pill ${agent.status === 'online' ? 'online' : 'offline'}`;
    pill.textContent = (agent.status ?? 'offline').toUpperCase();
    header.appendChild(pill);
    card.appendChild(header);

    const levelGrid = document.createElement('div');
    levelGrid.className = 'level-grid';
    LEVELS.forEach((level) => {
      const count = agent.eventStats?.[level];
      const button = document.createElement('button');
      button.className = `level-pill ${level.toLowerCase()}${agent.eventStats ? '' : ' disabled'}`;
      button.innerHTML = `<span>${level}</span><strong>${typeof count === 'number' ? count : '–'}</strong>`;
      button.disabled = !agent.eventStats;
      if (agent.eventStats) {
        button.addEventListener('click', () => loadEventEntries(agent.agentId, level, agent.name));
      }
      levelGrid.appendChild(button);
    });
    card.appendChild(levelGrid);

    if (agent.since || agent.retrievedAt) {
      const meta = document.createElement('div');
      meta.className = 'agent-meta';
      const when = agent.since ? `Counts since ${formatDate(agent.since)}` : 'Counts for the past week';
      const updated = agent.retrievedAt ? ` · refreshed ${formatDate(agent.retrievedAt)}` : '';
      meta.textContent = `${when}${updated}`;
      card.appendChild(meta);
    }

    if (agent.offline) {
      const note = document.createElement('div');
      note.className = 'agent-note';
      note.textContent = agent.error ?? 'Agent offline or data is stale.';
      card.appendChild(note);
    } else if (agent.error) {
      const note = document.createElement('div');
      note.className = 'agent-note';
      note.textContent = agent.error;
      card.appendChild(note);
    }

    agentsContainer.appendChild(card);
  });
}

function loadEventEntries(agentId, level, agentName) {
  if (!detailPanel || !detailList || !detailTitle || !detailMeta || !detailStatus) {
    return;
  }

  detailPanel.classList.remove('hidden');
  detailTitle.textContent = `${agentName ?? 'Agent'} · ${level}`;
  detailMeta.textContent = `Loading ${level} entries…`;
  detailStatus.textContent = '';
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
      detailMeta.textContent = payload.level ? `Latest ${payload.level} events` : `Latest ${level} events`;
      detailStatus.textContent = `${entries.length} event${entries.length === 1 ? '' : 's'}`;
      if (!entries.length) {
        detailList.innerHTML = '<div class="placeholder">No events found.</div>';
        return;
      }
      renderEventEntries(entries);
    })
    .catch((error) => {
      detailList.innerHTML = '<div class="placeholder">Unable to load events.</div>';
      detailMeta.textContent = `Failed to load ${level} events`;
      detailStatus.textContent = error.message;
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
    const timeText = entry.time ? formatDate(entry.time) : 'Unknown time';
    const title = document.createElement('div');
    title.innerHTML = `<h4>${entry.log ?? 'Event log'} · ${entry.ProviderName ?? entry.providerName ?? 'Unknown provider'}</h4>`;
    const meta = document.createElement('p');
    meta.className = 'event-meta';
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

function hideDetailPanel() {
  detailPanel?.classList.add('hidden');
}

function setStatus(message, isError = false) {
  if (!statusEl) {
    return;
  }
  statusEl.textContent = message;
  statusEl.style.color = isError ? '#fda4af' : '#8b949e';
}

function formatDate(value) {
  if (!value) {
    return 'Unknown time';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}
