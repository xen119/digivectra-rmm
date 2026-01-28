(() => {
  const agentId = new URLSearchParams(window.location.search).get('agent');
  const historyEl = document.getElementById('chatHistory');
  const emptyHistory = document.getElementById('emptyHistory');
  const chatForm = document.getElementById('chatForm');
  const chatInput = document.getElementById('chatInput');
  const statusLabel = document.getElementById('statusLabel');
  const statusText = document.getElementById('statusText');
  const agentNameEl = document.getElementById('agentName');
  const chatAuthFetch = window.chatAuthFetch ?? ((input, init) => fetch(input, { credentials: 'same-origin', ...init }));
  const chatPanel = document.querySelector('.chat-panel');
  const chatIndicator = document.getElementById('chatIndicator');
  const markIndicator = () => {
    if (chatIndicator) {
      chatIndicator.classList.add('chat-indicator--active');
    }
  };
  const clearIndicator = () => {
    if (chatIndicator) {
      chatIndicator.classList.remove('chat-indicator--active');
    }
  };
  window.clearChatIndicator = clearIndicator;

  const sendMessage = async (text) => {
    if (!agentId) {
      return;
    }

    if (chatInput) {
      chatInput.disabled = true;
    }
    try {
      const response = await chatAuthFetch(`/chat/${encodeURIComponent(agentId)}/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text }),
      });

      if (!response.ok) {
        throw new Error(`Send failed (${response.status})`);
      }

      if (chatInput) {
        chatInput.value = '';
      }
      statusText.textContent = 'Message sent.';
    } catch (error) {
      console.error(error);
      statusText.textContent = 'Failed to send message.';
    } finally {
      if (chatInput) {
        chatInput.disabled = false;
        chatInput.focus();
      }
    }
  };

  chatForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const text = chatInput?.value.trim() ?? '';
    if (!text) {
      return;
    }

    await sendMessage(text);
  });

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
    initializeChat(agentId);
  }

  async function initializeChat(currentAgentId) {
    await refreshAgentName(currentAgentId);
    const eventSource = new EventSource(`/chat/${encodeURIComponent(currentAgentId)}/events`, { withCredentials: true });
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
    const who = entry.direction === 'agent'
      ? `${entry.user ?? `Agent ${entry.agentName ?? 'Unknown'}`}`.trim()
      : 'You';
    const roleSuffix = entry.role ? ` (${entry.role})` : '';
    const timestamp = entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : '';
    meta.textContent = timestamp ? `${who}${roleSuffix} • ${timestamp}` : `${who}${roleSuffix}`;

    const text = document.createElement('div');
    text.textContent = entry.text;

    message.appendChild(meta);
    message.appendChild(text);
    historyEl?.appendChild(message);
    if (historyEl) {
      historyEl.scrollTop = historyEl.scrollHeight;
    }

    if (chatPanel?.classList.contains('collapsed')) {
      markIndicator();
    } else {
      clearIndicator();
    }
  }

  async function refreshAgentName(currentAgentId) {
    try {
      const response = await chatAuthFetch('/clients', { cache: 'no-store' });
      if (!response.ok) {
        throw new Error('Unable to load agent list.');
      }

      const agents = await response.json();
      const target = Array.isArray(agents) ? agents.find((entry) => entry.id === currentAgentId) : null;
      if (agentNameEl) {
        agentNameEl.textContent = target?.name ?? `Unknown (${currentAgentId})`;
      }
    } catch (error) {
      console.error(error);
      if (agentNameEl) {
        agentNameEl.textContent = `Unknown (${currentAgentId})`;
      }
    }
  }

  function setStatus(text) {
    if (statusLabel) {
      statusLabel.textContent = text;
    }
  }
})();
