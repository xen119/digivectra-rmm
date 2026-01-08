const agentId = new URLSearchParams(window.location.search).get('agent');
const historyEl = document.getElementById('chatHistory');
const emptyHistory = document.getElementById('emptyHistory');
const chatForm = document.getElementById('chatForm');
const chatInput = document.getElementById('chatInput');
const statusLabel = document.getElementById('statusLabel');
const statusText = document.getElementById('statusText');
const agentNameEl = document.getElementById('agentName');
const authFetch = (input, init) => fetch(input, { credentials: 'same-origin', ...init });

if (!agentId) {
  statusText.textContent = 'Missing agent identifier.';
  statusLabel.textContent = 'Invalid';
  if (chatInput) {
    chatInput.disabled = true;
  }
  const submit = chatForm?.querySelector('button');
  if (submit) {
    submit.disabled = true;
  }
} else {
  initializeChat();
}

async function initializeChat() {
  await refreshAgentName();
  const eventSource = new EventSource(`/chat/${encodeURIComponent(agentId)}/events`, { withCredentials: true });
  eventSource.addEventListener('open', () => {
    setStatus('Connected');
    statusText.textContent = 'Listening for chat messages from the agent.';
  });
  eventSource.addEventListener('chat', (event) => {
    const payload = JSON.parse(event.data);
    renderMessage(payload);
  });
  eventSource.addEventListener('error', () => {
    setStatus('Disconnected');
    statusText.textContent = 'Connection interrupted. Reload to retry.';
  });

  chatForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const text = chatInput.value.trim();
    if (!text) {
      return;
    }

    chatInput.disabled = true;
    try {
      const response = await authFetch(`/chat/${encodeURIComponent(agentId)}/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text }),
      });

      if (!response.ok) {
        throw new Error(`Send failed (${response.status})`);
      }

      chatInput.value = '';
      statusText.textContent = 'Message sent.';
    } catch (error) {
      console.error(error);
      statusText.textContent = 'Failed to send message.';
    } finally {
      chatInput.disabled = false;
      chatInput.focus();
    }
  });
}

function renderMessage(entry) {
  if (!entry || !entry.text) {
    return;
  }

  emptyHistory?.remove();

  const message = document.createElement('div');
  message.className = `chat-message ${entry.direction === 'agent' ? 'agent' : 'server'}`;

  const meta = document.createElement('div');
  meta.className = 'meta';
  const who = entry.direction === 'agent' ? `Agent ${entry.agentName ?? ''}`.trim() : 'You';
  const timestamp = entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : '';
  meta.textContent = timestamp ? `${who} • ${timestamp}` : who;

  const text = document.createElement('div');
  text.textContent = entry.text;

  message.appendChild(meta);
  message.appendChild(text);
  historyEl.appendChild(message);
  historyEl.scrollTop = historyEl.scrollHeight;
}

async function refreshAgentName() {
  try {
    const response = await authFetch('/clients', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error('Unable to load agent list.');
    }

    const agents = await response.json();
    const target = Array.isArray(agents) ? agents.find((entry) => entry.id === agentId) : null;
    agentNameEl.textContent = target?.name ?? `Unknown (${agentId})`;
  } catch (error) {
    console.error(error);
    agentNameEl.textContent = `Unknown (${agentId})`;
  }
}

function setStatus(text) {
  if (statusLabel) {
    statusLabel.textContent = text;
  }
}
