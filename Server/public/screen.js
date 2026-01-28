const statusEl = document.getElementById('status');
const frameEl = document.getElementById('frame');
const cursorEl = document.getElementById('remoteCursor');
const controlButton = document.getElementById('controlButton');
const controlInstructions = document.getElementById('controlInstructions');
const displayButtonsContainer = document.getElementById('displayButtons');
const desktopViewButton = document.getElementById('desktopViewButton');
const keyMapContainer = document.getElementById('keyMapList');

const authFetch = (input, init) => fetch(input, { credentials: 'same-origin', ...init });

const params = new URLSearchParams(window.location.search);
const agentId = params.get('agent');
let agentName = agentId;
let sessionId;
let source;
let pc;
let controlChannel;
let controlEnabled = false;
let selectedScreenId = null;
let captureScale = 1.0;
let viewMode = 'single';
let lastCursorPayload = null;
let remoteUserInputBlocked = false;
let remoteScreenBlanked = false;
let pendingRemoteUserInputBlock = null;
let pendingRemoteScreenBlank = null;

const keyMapEntries = [
  { label: 'Alt + Tab', keys: ['Alt', 'Tab'] },
  { label: 'Alt + Shift + Tab', keys: ['Alt', 'Shift', 'Tab'] },
  { label: 'Win key', keys: ['Meta'] },
  { label: 'Ctrl + Shift + Esc', keys: ['Control', 'Shift', 'Escape'] },
  { label: 'F1', keys: ['F1'] },
  { label: 'F5', keys: ['F5'] },
  { label: 'F11', keys: ['F11'] },
];

if (controlButton) {
  controlButton.addEventListener('click', () => {
    if (!isControlChannelOpen()) {
      return;
    }

    setControlEnabled(!controlEnabled);
  });
}

if (frameEl) {
  frameEl.addEventListener('mousemove', handleMouseMove);
  frameEl.addEventListener('mousedown', (event) => handleMouseButton(event, 'down'));
  frameEl.addEventListener('mouseup', (event) => handleMouseButton(event, 'up'));
  frameEl.addEventListener('wheel', handleMouseWheel, { passive: false });
  frameEl.addEventListener('contextmenu', (event) => {
    if (controlEnabled) {
      event.preventDefault();
    }
  });
  frameEl.addEventListener('load', () => {
    if (lastCursorPayload) {
      updateRemoteCursor(lastCursorPayload);
    }
  });
}

if (desktopViewButton) {
  desktopViewButton.addEventListener('click', async () => {
    if (viewMode === 'desktop') {
      return;
    }

    viewMode = 'desktop';
    selectedScreenId = null;
    updateDisplayButtons();
    await restartScreenSession();
  });
}

window.addEventListener('keydown', (event) => handleKeyEvent(event, 'down'), true);
window.addEventListener('keyup', (event) => handleKeyEvent(event, 'up'), true);
window.addEventListener('blur', () => {
  if (controlEnabled) {
    setControlEnabled(false);
  }
});
window.addEventListener('resize', () => {
  if (lastCursorPayload) {
    updateRemoteCursor(lastCursorPayload);
  }
});

if (!agentId) {
  statusEl.textContent = 'Agent identifier missing.';
} else {
  initialize();
}

async function initialize() {
  await refreshAgentInfo();
  await loadScreenOptions();
  await startScreenSession();
}

async function loadScreenOptions() {
  if (!agentId || !displayButtonsContainer) {
    return;
  }

  try {
    const response = await authFetch(`/screen/${agentId}/screens`, { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    const screens = Array.isArray(payload.screens) ? payload.screens : [];
    if (screens.length === 0) {
      displayButtonsContainer.innerHTML = '<span class="empty">No displays found.</span>';
      return;
    }

    displayButtonsContainer.innerHTML = '';
    screens.forEach((screen, index) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'display-button';
      button.dataset.screenId = screen.id;
      button.textContent = `Mon${index + 1}`;
      button.title = `${screen.name ?? screen.id} (${screen.width ?? '?'}x${screen.height ?? '?'})`;

      button.addEventListener('click', async () => {
        if (viewMode === 'desktop') {
          viewMode = 'single';
        }
        if (selectedScreenId === screen.id && viewMode === 'single') {
          return;
        }

        selectedScreenId = screen.id;
        viewMode = 'single';
        updateDisplayButtons();
        await restartScreenSession();
      });

      displayButtonsContainer.appendChild(button);
    });

    selectedScreenId = screens[0].id;
    viewMode = 'single';
    updateDisplayButtons();
  } catch (error) {
    console.error('Failed to load screen list', error);
    displayButtonsContainer.innerHTML = '<span class="empty">Unable to load displays.</span>';
  }
}

async function startScreenSession() {
  try {
    const requestBody = { agentId };
    if (selectedScreenId) {
      requestBody.screenId = selectedScreenId;
    }
    requestBody.scale = captureScale;
    requestBody.captureAllScreens = viewMode === 'desktop';

    const response = await authFetch('/screen/request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    sessionId = data.sessionId;
    source = new EventSource(`/screen/${sessionId}/events`);

    source.addEventListener('offer', async (event) => {
      await handleOffer(JSON.parse(event.data));
    });

    source.addEventListener('candidate', async (event) => {
      const payload = JSON.parse(event.data);
      if (pc) {
        await pc.addIceCandidate(payload);
      }
    });

    source.addEventListener('status', (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.agentName) {
          agentName = payload.agentName;
        }

        if (payload.state) {
          const prefix = payload.state === 'offer-ready' ? 'Offer ready for' : 'Requesting screen stream for';
          const isDesktopView = Boolean(payload.captureAllScreens);
          const viewLabel = isDesktopView ? 'Full desktop view' : 'Single display view';
          statusEl.textContent = `${prefix} ${agentName} · ${viewLabel}`;
          viewMode = isDesktopView ? 'desktop' : 'single';
          if (!isDesktopView && payload.screenId) {
            selectedScreenId = payload.screenId;
          }
          updateDisplayButtons();
        }
      } catch (error) {
        console.error('Failed to parse screen status event', error);
      }
    });

    source.addEventListener('error', () => {
      if (source.readyState === EventSource.CLOSED) {
        statusEl.textContent = 'Screen stream closed by the agent.';
      }
    });

    pollOffer(sessionId);

    source.addEventListener('closed', () => {
      statusEl.textContent = 'Screen session ended.';
      pc?.close();
      pc = null;
    });
  } catch (error) {
    console.error(error);
    statusEl.textContent = 'Failed to start screen stream.';
  }
}

async function restartScreenSession() {
  if (sessionId) {
    await stopExistingSession();
  }

  await startScreenSession();
}

async function stopExistingSession() {
  if (source) {
    source.close();
    source = null;
  }

  if (pc) {
    pc.close();
    pc = null;
  }

  if (sessionId) {
    await authFetch(`/screen/${sessionId}/stop`, { method: 'POST' });
    sessionId = null;
  }
}

async function refreshAgentInfo() {
  if (!agentId) {
    return;
  }

  try {
    const response = await authFetch('/clients', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error('agent lookup failed');
    }

    const agents = await response.json();
    const agent = agents.find((entry) => entry.id === agentId);
    if (agent) {
      agentName = agent.name;
      statusEl.textContent = `Requesting screen stream for ${agentName}`;
    }
  } catch (error) {
    console.error(error);
  }
}

async function handleOffer(payload) {
  if (pc) {
    return;
  }

  pc = new RTCPeerConnection();

  pc.onicecandidate = (event) => {
    if (event.candidate) {
      postCandidate(event.candidate);
    }
  };

  pc.ondatachannel = (event) => {
    const channel = event.channel;
    controlChannel = channel;
    channel.onopen = () => {
      if (controlButton) {
        controlButton.disabled = false;
      }

      if (controlInstructions) {
        controlInstructions.textContent = 'Click to enable remote control.';
      }
      syncBlockInputState();
      syncBlankScreenState();
      renderKeyMappings();
    };

    channel.onclose = () => {
      controlChannel = null;
      setControlEnabled(false);
      if (controlButton) {
        controlButton.disabled = true;
      }

      if (controlInstructions) {
        controlInstructions.textContent = 'Control channel closed.';
      }
      renderKeyMappings();
    };

    channel.onmessage = async (messageEvent) => {
      try {
        let payloadText;
        if (typeof messageEvent.data === 'string') {
          payloadText = messageEvent.data;
        } else if (messageEvent.data instanceof ArrayBuffer) {
          payloadText = new TextDecoder().decode(messageEvent.data);
        } else if (messageEvent.data instanceof Blob) {
          payloadText = await messageEvent.data.text();
        } else {
          return;
        }

        const frame = JSON.parse(payloadText);
        if (frame.type === 'frame' && frame.image) {
          frameEl.src = `data:image/png;base64,${frame.image}`;
        } else if (frame.type === 'cursor') {
          updateRemoteCursor(frame);
        }
      } catch (error) {
        console.error('Failed to decode frame', error);
      }
    };
  };

  await pc.setRemoteDescription({ type: payload.sdpType.toLowerCase(), sdp: payload.sdp });
  const answer = await pc.createAnswer();
  await pc.setLocalDescription(answer);
  await postAnswer(answer);
  statusEl.textContent = `Streaming screen for ${agentName}`;
}

async function postAnswer(answer) {
  await authFetch(`/screen/${sessionId}/answer`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(answer),
  });
}

async function postCandidate(candidate) {
  await authFetch(`/screen/${sessionId}/candidate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(candidate),
  });
}

window.addEventListener('beforeunload', () => {
  source?.close();
  if (sessionId) {
    authFetch(`/screen/${sessionId}/stop`, { method: 'POST' });
  }
});

function isControlChannelOpen() {
  return controlChannel?.readyState === 'open';
}

function setControlEnabled(enabled) {
  controlEnabled = enabled;
  if (controlButton) {
    controlButton.textContent = enabled ? 'Disable control' : 'Enable control';
  }

  updateControlInstructions();
  renderKeyMappings();
}

const blockInputToggle = document.getElementById('blockInputToggle');
const blankScreenToggle = document.getElementById('blankScreenToggle');

function updateControlInstructions() {
  if (!controlInstructions) {
    return;
  }

  if (remoteUserInputBlocked) {
    controlInstructions.textContent = controlEnabled
      ? 'Remote user mouse & keyboard are blocked while control is active.'
      : 'Remote user input is blocked while control is disabled.';
    return;
  }

  controlInstructions.textContent = controlEnabled
    ? 'Control is active (press Esc to release).'
    : 'Click to enable remote control.';
}

blockInputToggle?.addEventListener('change', () => {
  remoteUserInputBlocked = blockInputToggle.checked;
  updateControlInstructions();
  syncBlockInputState();
});

blankScreenToggle?.addEventListener('change', () => {
  remoteScreenBlanked = blankScreenToggle.checked;
  syncBlankScreenState();
});

function renderKeyMappings() {
  if (!keyMapContainer) {
    return;
  }

  keyMapContainer.innerHTML = '';
  keyMapEntries.forEach((entry) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'key-map-button';
    button.textContent = entry.label;
    button.dataset.keys = entry.keys.join(',');
    button.disabled = !controlEnabled || !isControlChannelOpen();
    button.addEventListener('click', () => {
      const keys = entry.keys;
      sendKeyCombo(keys);
    });
    keyMapContainer.appendChild(button);
  });
}

renderKeyMappings();

function sendControlMessage(payload) {
  if (!controlEnabled || !isControlChannelOpen()) {
    return;
  }

  try {
    controlChannel?.send(JSON.stringify(payload));
  } catch (error) {
    console.error('Failed to send control message', error);
  }
}

function sendKeyCombo(keys) {
  if (!keys.length) {
    return;
  }
  if (!controlEnabled || !isControlChannelOpen()) {
    return;
  }

  keys.forEach((key) => {
    sendControlMessage({
      type: 'keyboard',
      action: 'down',
      key,
      code: key,
    });
  });

  setTimeout(() => {
    keys.slice().reverse().forEach((key) => {
      sendControlMessage({
        type: 'keyboard',
        action: 'up',
        key,
        code: key,
      });
    });
  }, 80);
}

function syncBlockInputState() {
  if (!isControlChannelOpen()) {
    pendingRemoteUserInputBlock = remoteUserInputBlocked;
    return;
  }

  const blockState = pendingRemoteUserInputBlock ?? remoteUserInputBlocked;
  pendingRemoteUserInputBlock = null;

  const payload = {
    type: 'block-input',
    block: blockState,
  };

  try {
    controlChannel?.send(JSON.stringify(payload));
  } catch (error) {
    console.error('Failed to update block input state', error);
  }
}

function syncBlankScreenState() {
  if (!isControlChannelOpen()) {
    pendingRemoteScreenBlank = remoteScreenBlanked;
    return;
  }

  const blankState = pendingRemoteScreenBlank ?? remoteScreenBlanked;
  pendingRemoteScreenBlank = null;

  const payload = {
    type: 'blank-screen',
    blank: blankState,
  };

  try {
    controlChannel?.send(JSON.stringify(payload));
  } catch (error) {
    console.error('Failed to update blank screen state', error);
  }
}

function handleKeyEvent(event, action) {
  if (!controlEnabled || !isControlChannelOpen()) {
    return;
  }

  sendControlMessage({
    type: 'keyboard',
    action,
    key: event.key,
    code: event.code,
  });

  if (action === 'down') {
    event.preventDefault();
    if (event.key === 'Escape') {
      setControlEnabled(false);
    }
  } else {
    event.preventDefault();
  }
}

function handleMouseMove(event) {
  if (!controlEnabled || !isControlChannelOpen()) {
    return;
  }

  const coords = getFrameCoordinates(event);
  sendControlMessage({
    type: 'mouse',
    action: 'move',
    x: coords.x,
    y: coords.y,
  });

  event.preventDefault();
}

function handleMouseButton(event, action) {
  if (!controlEnabled || !isControlChannelOpen()) {
    return;
  }

  const buttonName = mapMouseButton(event.button);
  if (!buttonName) {
    return;
  }

  const coords = getFrameCoordinates(event);
  sendControlMessage({
    type: 'mouse',
    action,
    button: buttonName,
    x: coords.x,
    y: coords.y,
  });

  event.preventDefault();
}

function handleMouseWheel(event) {
  if (!controlEnabled || !isControlChannelOpen()) {
    return;
  }

  sendControlMessage({
    type: 'mouse',
    action: 'wheel',
    delta: event.deltaY,
  });

  event.preventDefault();
}

function updateDisplayButtons() {
  if (!displayButtonsContainer) {
    return;
  }

  const buttons = displayButtonsContainer.querySelectorAll('.display-button');
  buttons.forEach((button) => {
    const matches = button.dataset.screenId === selectedScreenId;
    const active = viewMode === 'single' && matches;
    button.classList.toggle('active', active);
  });

  if (desktopViewButton) {
    desktopViewButton.classList.toggle('active', viewMode === 'desktop');
  }
}

function getFrameCoordinates(event) {
  const rect = frameEl?.getBoundingClientRect();
  if (!rect) {
    return { x: 0, y: 0 };
  }

  const x = rect.width ? Math.min(Math.max(event.clientX - rect.left, 0), rect.width) : 0;
  const y = rect.height ? Math.min(Math.max(event.clientY - rect.top, 0), rect.height) : 0;
  return {
    x: rect.width ? x / rect.width : 0,
    y: rect.height ? y / rect.height : 0,
  };
}

function mapMouseButton(button) {
  switch (button) {
    case 0:
      return 'left';
    case 1:
      return 'middle';
    case 2:
      return 'right';
    default:
      return null;
  }
}

function updateRemoteCursor(payload) {
  lastCursorPayload = payload;
  if (!cursorEl || !frameEl) {
    return;
  }

  const rect = frameEl.getBoundingClientRect();
  if (!rect.width || !rect.height) {
    cursorEl.style.opacity = '0';
    return;
  }

  const x = clampNormalized(payload.x);
  const y = clampNormalized(payload.y);
  cursorEl.style.left = `${x * rect.width}px`;
  cursorEl.style.top = `${y * rect.height}px`;
  cursorEl.style.opacity = payload.visible ? '1' : '0';
}

function clampNormalized(value) {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return 0;
  }

  return Math.min(Math.max(value, 0), 1);
}

async function pollOffer(id) {
  if (!id) {
    return;
  }

  while (!pc) {
    try {
      const response = await authFetch(`/screen/${id}/offer`, { cache: 'no-store' });
      if (!response.ok) {
        throw new Error(`serve ${response.status}`);
      }

      const payload = await response.json();
      if (payload?.agentName) {
        agentName = payload.agentName;
      }
      if (payload?.ready === false) {
        await new Promise((resolve) => setTimeout(resolve, 250));
        continue;
      }

      if (payload?.sdp) {
        await handleOffer(payload);
        return;
      }
    } catch (error) {
      console.error('Failed to poll for screen offer', error);
    }

    await new Promise((resolve) => setTimeout(resolve, 500));
  }
}

function clampScale(value) {
  const min = 0.35;
  const max = 1.0;
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return 0.75;
  }

  return Math.min(Math.max(value, min), max);
}

function setupChatCollapse() {
  const chatPanel = document.querySelector('.chat-panel');
  const chatToggle = document.getElementById('chatToggle');
  const layout = document.querySelector('.screen-layout');
  if (!chatPanel || !chatToggle) {
    return;
  }

  chatToggle.addEventListener('click', () => {
    const collapsed = chatPanel.classList.toggle('collapsed');
    if (layout) {
      layout.classList.toggle('chat-collapsed', collapsed);
    }
    chatToggle.textContent = collapsed ? 'Show chat' : 'Hide chat';
    chatToggle.setAttribute('aria-expanded', (!collapsed).toString());
    if (!collapsed && typeof window.clearChatIndicator === 'function') {
      window.clearChatIndicator();
    }
  });
}

setupChatCollapse();

const shellSummaryEl = document.getElementById('shellSummary');
const shellStatusEl = document.getElementById('shellStatus');
const shellLogEl = document.getElementById('shellLog');
const shellForm = document.getElementById('shellForm');
const shellInput = document.getElementById('shellInput');
const shellSubmit = document.getElementById('shellSubmit');
let shellSource;
let shellAgentName = agentName;

if (!agentId) {
  if (shellSummaryEl) {
    shellSummaryEl.textContent = 'Agent identifier missing.';
  }
  if (shellSubmit) {
    shellSubmit.disabled = true;
  }
} else {
  shellSource = new EventSource(`/shell/${agentId}`);

  shellSource.addEventListener('shell', (event) => {
    try {
      const payload = JSON.parse(event.data);
      const prefix = payload.stream === 'stderr' ? '[stderr]' : '[stdout]';
      appendShellLine(`${prefix} ${payload.output}`);
    } catch (error) {
      console.error(error);
    }
  });

  shellSource.onopen = () => {
    if (shellSummaryEl) {
      shellSummaryEl.textContent = `Streaming shell for ${shellAgentName || agentId}`;
    }
    if (shellStatusEl) {
      shellStatusEl.textContent = 'Connected';
    }
  };

  shellSource.onerror = () => {
    if (shellSummaryEl) {
      shellSummaryEl.textContent = 'Reconnecting to agent…';
    }
    if (shellStatusEl) {
      shellStatusEl.textContent = 'Reconnecting…';
    }
  };

  refreshShellAgentInfo();
}

async function refreshShellAgentInfo() {
  if (!agentId) {
    return;
  }

  try {
    const response = await authFetch('/clients', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error('agent lookup failed');
    }

    const agents = await response.json();
    const agent = Array.isArray(agents) ? agents.find((entry) => entry.id === agentId) : null;
    if (agent) {
      shellAgentName = agent.name;
      if (shellSummaryEl) {
        shellSummaryEl.textContent = `Streaming shell for ${agent.name}`;
      }
    }
  } catch (error) {
    console.error(error);
  }
}

shellForm?.addEventListener('submit', async (event) => {
  event.preventDefault();

  if (!agentId) {
    return;
  }

  const command = shellInput?.value.trim();
  if (!command) {
    return;
  }

  try {
    await authFetch(`/shell/${agentId}/input`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      body: command,
    });
    if (shellStatusEl) {
      shellStatusEl.textContent = 'Command sent';
    }
  } catch (error) {
    console.error(error);
    appendShellLine('[local] failed to send command.');
    if (shellStatusEl) {
      shellStatusEl.textContent = 'Send failed';
    }
  }

  if (shellInput) {
    shellInput.value = '';
  }
});

function appendShellLine(text) {
  if (!shellLogEl) {
    return;
  }

  shellLogEl.textContent += `${text}\n`;
  shellLogEl.scrollTop = shellLogEl.scrollHeight;
}

const aiStatusEl = document.getElementById('screenAiConfigStatus');
const aiMessageList = document.getElementById('screenAiMessageList');
const aiForm = document.getElementById('screenAiForm');
const aiInput = document.getElementById('screenAiInput');
const aiButton = document.getElementById('screenAiButton');
const aiActivityEl = document.getElementById('screenAiActivity');
const aiSessionIdEl = document.getElementById('screenAiSessionId');

let aiSessionId = null;
let aiReady = false;

function setAiStatus(message, variant = 'info') {
  if (!aiStatusEl) {
    return;
  }
  aiStatusEl.textContent = message;
  aiStatusEl.dataset.state = variant;
}

function setAiFormReady(enabled) {
  if (aiInput) {
    aiInput.disabled = !enabled;
  }
  if (aiButton) {
    aiButton.disabled = !enabled;
  }
}

function clearAiPlaceholder() {
  const placeholder = aiMessageList?.querySelector('.ai-empty');
  placeholder?.remove();
}

function renderAiEntry(role, content) {
  if (!aiMessageList || !content) {
    return;
  }
  clearAiPlaceholder();
  const wrapper = document.createElement('div');
  wrapper.className = `ai-message ${role}`;
  const bubble = document.createElement('div');
  bubble.className = 'ai-bubble';
  bubble.textContent = content;
  wrapper.appendChild(bubble);
  aiMessageList.appendChild(wrapper);
  aiMessageList.scrollTop = aiMessageList.scrollHeight;
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

function updateAiActivity(entries) {
  if (!aiActivityEl) {
    return;
  }
  if (!Array.isArray(entries) || entries.length === 0) {
    aiActivityEl.textContent = 'No recent activity.';
    return;
  }
  const latest = entries[0];
  const label = latest.type ? latest.type.replace(/-/g, ' ') : 'entry';
  aiActivityEl.textContent = `${label} · ${formatTimestamp(latest.timestamp)} · ${latest.text ?? '—'}`;
}

async function loadAiActivityLog() {
  if (!aiActivityEl) {
    return;
  }
  try {
    const response = await authFetch('/ai/history?limit=3', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    updateAiActivity(Array.isArray(data.history) ? data.history : []);
  } catch (error) {
    console.error(error);
    aiActivityEl.textContent = 'Unable to load activity.';
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
    if (aiStatusEl) {
      aiStatusEl.textContent = aiReady ? 'AI assistant ready.' : 'Configure OpenAI key in Settings.';
    }
    setAiFormReady(aiReady);
  } catch (error) {
    console.error(error);
    aiReady = false;
    if (aiStatusEl) {
      aiStatusEl.textContent = 'Unable to load AI configuration.';
    }
    setAiFormReady(false);
  }
}

async function ensureAiSession() {
  try {
    const response = await authFetch('/ai/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    aiSessionId = data.sessionId;
    if (aiSessionIdEl) {
      aiSessionIdEl.textContent = aiSessionId ? aiSessionId.slice(0, 8) : '—';
    }
  } catch (error) {
    console.error(error);
    setAiStatus('Unable to start AI session.', 'error');
  }
}

async function sendAiMessage(text) {
  if (!aiReady) {
    setAiStatus('Enable the AI API key first.', 'warning');
    return;
  }
  if (!aiSessionId) {
    setAiStatus('Session unavailable.', 'error');
    return;
  }
  setAiFormReady(false);
  renderAiEntry('user', text);
  try {
    const response = await authFetch('/ai/message', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sessionId: aiSessionId, text }),
    });
    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new Error(`HTTP ${response.status} ${body}`);
    }
    const data = await response.json();
    aiSessionId = data.sessionId ?? aiSessionId;
    if (aiSessionIdEl) {
      aiSessionIdEl.textContent = aiSessionId ? aiSessionId.slice(0, 8) : '—';
    }
    if (typeof data.message === 'string' && data.message) {
      renderAiEntry('assistant', data.message);
    }
    setAiStatus('Assistant replied.', 'success');
    loadAiActivityLog();
  } catch (error) {
    console.error(error);
    setAiStatus('AI request failed. Try again.', 'error');
  } finally {
    if (aiInput) {
      aiInput.value = '';
      aiInput.focus();
    }
    setAiFormReady(aiReady);
  }
}

function handleAiSubmit(event) {
  event.preventDefault();
  const text = aiInput?.value.trim();
  if (!text) {
    return;
  }
  sendAiMessage(text);
}

async function initAiAssistant() {
  setAiFormReady(false);
  setAiStatus('Loading AI configuration…');
  await loadAiSettings();
  await ensureAiSession();
  await loadAiActivityLog();
  aiForm?.addEventListener('submit', handleAiSubmit);
}

initAiAssistant();

const tabButtons = document.querySelectorAll('.tab-button');
const tabPanels = document.querySelectorAll('[data-tab-panel]');

function showTab(target) {
  tabButtons.forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.tabTarget === target);
  });
  tabPanels.forEach((panel) => {
    panel.classList.toggle('active', panel.dataset.tabPanel === target);
  });
}

tabButtons.forEach((button) => {
  button.addEventListener('click', () => {
    const target = button.dataset.tabTarget;
    if (target) {
      showTab(target);
    }
  });
});

showTab('chat');
