const historyList = document.getElementById('historyList');
const titleEl = document.getElementById('title');
const subtitleEl = document.getElementById('subtitle');
const params = new URLSearchParams(window.location.search);
const agentId = params.get('agent') ?? '';
const profileId = params.get('profile') ?? '';
const profileNameParam = params.get('name') ?? '';

document.addEventListener('DOMContentLoaded', () => {
  const displayProfile = profileNameParam || 'monitor';
  titleEl.textContent = `${displayProfile} history`;
  const agentText = agentId ? `Agent: ${agentId}` : 'Agent: unknown';
  subtitleEl.textContent = `${agentText} · Profile: ${profileId || 'any'}`;
  loadHistory();
});

async function loadHistory() {
  if (!historyList) {
    return;
  }

  historyList.innerHTML = '<p class="status">Loading history...</p>';

  try {
    const url = new URL('/monitoring/events/history', window.location.origin);
    if (agentId) {
      url.searchParams.set('agentId', agentId);
    }
    if (profileId) {
      url.searchParams.set('profileId', profileId);
    }

    const response = await fetch(url, { credentials: 'same-origin' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const events = await response.json();
    renderHistory(events);
  } catch (error) {
    historyList.innerHTML = `<p class="status">Failed to load history: ${error.message}</p>`;
  }
}

function renderHistory(events) {
  if (!historyList) {
    return;
  }

  if (!Array.isArray(events) || events.length === 0) {
    historyList.innerHTML = '<p class="status">No history recorded yet.</p>';
    return;
  }

  events.sort((a, b) => {
    const timeA = new Date(a.payload?.timestamp ?? a.timestamp ?? '').getTime();
    const timeB = new Date(b.payload?.timestamp ?? b.timestamp ?? '').getTime();
    return timeB - timeA;
  });

  const rows = events.map((entry) => {
    const payload = entry.payload ?? {};
    const timestamp = payload.timestamp
      ? new Date(payload.timestamp).toLocaleString()
      : new Date().toLocaleString();
    const status = payload.status ?? (payload.triggered ? 'triggered' : 'resolved');
    const metrics = Array.isArray(payload.metrics) && payload.metrics.length > 0
      ? payload.metrics.join(', ')
      : 'Metrics unavailable';
    return `
      <div class="event">
        <span>${timestamp}</span>
        <span class="badge ${status === 'triggered' ? 'triggered' : 'resolved'}">${status}</span>
        <span>${metrics}</span>
        <span>${entry.eventName ?? 'monitoring-state'}</span>
      </div>
    `;
  }).join('');

  historyList.innerHTML = rows;
}
