const statusEl = document.getElementById('aiStatusMessage');
const messageList = document.getElementById('aiMessageList');
const activityList = document.getElementById('aiActivityList');
const sessionIdEl = document.getElementById('aiSessionId');
const aiConfigStatusEl = document.getElementById('aiConfigStatus');
const aiPromptForm = document.getElementById('aiPromptForm');
const aiPromptInput = document.getElementById('aiPromptInput');
const aiSendButton = document.getElementById('aiSendButton');

let sessionId = null;
let aiReady = false;

const authFetch = (input, init = {}) => fetch(input, { credentials: 'same-origin', ...init });

function setStatus(message, variant = 'info') {
  if (!statusEl) {
    return;
  }
  statusEl.textContent = message;
  statusEl.dataset.state = variant;
}

function setFormReady(enabled) {
  if (aiPromptInput) {
    aiPromptInput.disabled = !enabled;
  }
  if (aiSendButton) {
    aiSendButton.disabled = !enabled;
  }
}

function clearMessagePlaceholder() {
  const placeholder = messageList?.querySelector('.ai-empty');
  if (placeholder) {
    placeholder.remove();
  }
}

function renderChatEntry(role, content) {
  if (!messageList || !content) {
    return;
  }

  clearMessagePlaceholder();

  const wrapper = document.createElement('div');
  wrapper.className = `ai-message ${role}`;
  const bubble = document.createElement('div');
  bubble.className = 'ai-bubble';
  bubble.textContent = content;
  wrapper.appendChild(bubble);
  messageList.appendChild(wrapper);
  messageList.scrollTop = messageList.scrollHeight;
}

function stringifyValue(value, maxLength = 200) {
  if (typeof value === 'string') {
    return value.length > maxLength ? `${value.slice(0, maxLength)}…` : value;
  }
  try {
    return JSON.stringify(value);
  } catch {
    return '';
  }
}

function renderToolCall(toolCall) {
  if (!messageList || !toolCall) {
    return;
  }

  clearMessagePlaceholder();

  const container = document.createElement('div');
  container.className = 'ai-tool-call';

  const name = document.createElement('strong');
  name.textContent = `Tool: ${toolCall.name ?? 'unknown'}`;
  container.appendChild(name);

  const args = document.createElement('p');
  args.textContent = `Arguments: ${stringifyValue(toolCall.arguments ?? 'none')}`;
  container.appendChild(args);

  if (toolCall.result !== undefined) {
    const result = document.createElement('p');
    result.textContent = `Result: ${stringifyValue(toolCall.result)}`;
    container.appendChild(result);
  }

  if (toolCall.error) {
    const error = document.createElement('p');
    error.textContent = `Error: ${toolCall.error}`;
    container.appendChild(error);
  }

  messageList.appendChild(container);
  messageList.scrollTop = messageList.scrollHeight;
}

function formatEntryType(type) {
  switch (type) {
    case 'prompt':
      return 'Prompt';
    case 'response':
      return 'Response';
    case 'tool':
      return 'Tool';
    default:
      return type?.replace(/-/g, ' ') ?? 'Entry';
  }
}

function formatTimestamp(value) {
  if (!value) {
    return 'Unknown time';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return 'Unknown time';
  }
  return date.toLocaleString();
}

function renderActivityLog(entries) {
  if (!activityList) {
    return;
  }

  activityList.innerHTML = '';
  if (!Array.isArray(entries) || !entries.length) {
    activityList.innerHTML = '<p class="ai-empty">No activity recorded yet.</p>';
    return;
  }

  for (const entry of entries) {
    const card = document.createElement('div');
    card.className = 'ai-activity-entry';

    const header = document.createElement('div');
    header.textContent = `${formatEntryType(entry.type)} · ${formatTimestamp(entry.timestamp)}`;
    card.appendChild(header);

    const detail = document.createElement('small');
    if (entry.type === 'tool') {
      detail.textContent = `${entry.tool ?? 'tool'}(${stringifyValue(entry.arguments ?? '')}) → ${stringifyValue(entry.result ?? entry.error ?? '')}`;
    } else {
      detail.textContent = entry.text ?? '';
    }
    card.appendChild(detail);
    activityList.appendChild(card);
  }
}

async function loadActivityLog() {
  if (!activityList) {
    return;
  }

  try {
    const response = await authFetch('/ai/history?limit=20', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    renderActivityLog(Array.isArray(data.history) ? data.history : []);
  } catch (error) {
    console.error(error);
    activityList.innerHTML = '<p class="ai-empty">Unable to load history.</p>';
  }
}

async function loadAiSettings() {
  try {
    const response = await authFetch('/settings/ai', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    aiReady = Boolean(data.apiKeyConfigured);
    if (aiConfigStatusEl) {
      aiConfigStatusEl.textContent = aiReady
        ? 'OpenAI API key is configured.'
        : 'Configure the OpenAI API key in Settings to enable the agent.';
    }
    setStatus(
      aiReady ? 'AI assistant is ready.' : 'API key is missing. Open Settings to configure it.',
      aiReady ? 'success' : 'warning',
    );
    setFormReady(aiReady);
  } catch (error) {
    console.error(error);
    aiReady = false;
    if (aiConfigStatusEl) {
      aiConfigStatusEl.textContent = 'Unable to load AI configuration.';
    }
    setStatus('Unable to load AI configuration.', 'error');
    setFormReady(false);
  }
}

async function ensureSession() {
  try {
    const response = await authFetch('/ai/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    sessionId = data.sessionId;
    if (sessionIdEl) {
      sessionIdEl.textContent = sessionId ? sessionId.slice(0, 8) : '—';
    }
  } catch (error) {
    console.error(error);
    setStatus('Unable to start an AI session.', 'error');
  }
}

async function sendMessage(text) {
  if (!aiReady) {
    setStatus('Enable the API key before sending messages.', 'warning');
    return;
  }
  if (!sessionId) {
    setStatus('Session unavailable. Reload the page.', 'error');
    return;
  }

  setFormReady(false);
  renderChatEntry('user', text);

  try {
    const response = await authFetch('/ai/message', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sessionId, text }),
    });
    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new Error(`HTTP ${response.status} ${body}`);
    }
    const data = await response.json();
    sessionId = data.sessionId ?? sessionId;
    if (sessionIdEl) {
      sessionIdEl.textContent = sessionId ? sessionId.slice(0, 8) : '—';
    }
    if (data.toolCall) {
      renderToolCall(data.toolCall);
    }
    if (typeof data.message === 'string' && data.message) {
      renderChatEntry('assistant', data.message);
    }
    setStatus('Assistant replied.', 'success');
    loadActivityLog();
  } catch (error) {
    console.error(error);
    setStatus('AI request failed. Try again.', 'error');
  } finally {
    aiPromptInput.value = '';
    setFormReady(aiReady);
    aiPromptInput.focus();
  }
}

function handleSubmit(event) {
  event.preventDefault();
  const text = aiPromptInput.value.trim();
  if (!text) {
    return;
  }
  sendMessage(text);
}

async function init() {
  setFormReady(false);
  setStatus('Loading AI configuration…');
  await loadAiSettings();
  await ensureSession();
  loadActivityLog();
  aiPromptForm?.addEventListener('submit', handleSubmit);
}

window.addEventListener('DOMContentLoaded', init);
