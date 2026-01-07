const statusEl = document.getElementById('status');
const frameEl = document.getElementById('frame');
const controlButton = document.getElementById('controlButton');
const controlInstructions = document.getElementById('controlInstructions');
const screenSelect = document.getElementById('screenSelect');

const params = new URLSearchParams(window.location.search);
const agentId = params.get('agent');
let agentName = agentId;
let sessionId;
let source;
let pc;
let controlChannel;
let controlEnabled = false;
let selectedScreenId = null;

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
}

if (screenSelect) {
  screenSelect.addEventListener('change', async () => {
    if (!screenSelect.value || screenSelect.value === selectedScreenId) {
      return;
    }

    selectedScreenId = screenSelect.value;
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
  if (!screenSelect || !agentId) {
    return;
  }

    try {
      const response = await fetch(`/screen/${agentId}/screens`, { cache: 'no-store' });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    const screens = Array.isArray(payload.screens) ? payload.screens : [];
    if (screens.length === 0) {
      screenSelect.disabled = true;
      return;
    }

    screenSelect.innerHTML = '';
    screens.forEach((screen) => {
      const option = document.createElement('option');
      option.value = screen.id;
      option.textContent = `${screen.name ?? screen.id} (${screen.width ?? '?'}x${screen.height ?? '?'})`;
      screenSelect.appendChild(option);
    });

    selectedScreenId = screens[0].id;
    screenSelect.disabled = false;
    } catch (error) {
      console.error('Failed to load screen list', error);
      screenSelect.disabled = true;
    }
  }

async function startScreenSession() {
  try {
    const requestBody = { agentId };
    if (selectedScreenId) {
      requestBody.screenId = selectedScreenId;
    }

    const response = await fetch('/screen/request', {
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
          statusEl.textContent = `${prefix} ${agentName}`;
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
    await fetch(`/screen/${sessionId}/stop`, { method: 'POST' });
    sessionId = null;
  }
}

async function refreshAgentInfo() {
  if (!agentId) {
    return;
  }

  try {
    const response = await fetch('/clients', { cache: 'no-store' });
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
  await fetch(`/screen/${sessionId}/answer`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(answer),
  });
}

async function postCandidate(candidate) {
  await fetch(`/screen/${sessionId}/candidate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(candidate),
  });
}

window.addEventListener('beforeunload', () => {
  source?.close();
  if (sessionId) {
    fetch(`/screen/${sessionId}/stop`, { method: 'POST' });
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

  if (controlInstructions) {
    controlInstructions.textContent = enabled
      ? 'Control is active (press Esc to release).'
      : 'Click to enable remote control.';
  }
}

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

async function pollOffer(id) {
  if (!id) {
    return;
  }

  while (!pc) {
    try {
      const response = await fetch(`/screen/${id}/offer`, { cache: 'no-store' });
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
