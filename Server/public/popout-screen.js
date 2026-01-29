const params = new URLSearchParams(window.location.search);
const agentId = params.get('agent');
const assignedScreenId = params.get('screenId') || 'desktop';
const captureAllScreens = assignedScreenId === 'desktop';
const frameEl = document.getElementById('popoutFrame');
const cursorEl = document.getElementById('popoutCursor');
const statusEl = document.getElementById('popoutStatus');
const instructionsEl = document.getElementById('popoutInstructions');

const authFetch = (input, init) => fetch(input, { credentials: 'same-origin', ...init });

let sessionId;
let source;
let pc;
let controlChannel;
let agentName = agentId;

function updateStatus(text) {
  if (statusEl) {
    statusEl.textContent = text;
  }
}

function updateInstructions(text) {
  if (instructionsEl) {
    instructionsEl.textContent = text;
  }
}

async function initPopout() {
  if (!agentId) {
    updateStatus('Agent identifier missing.');
    return;
  }

  updateStatus('Requesting screen stream…');
  updateInstructions('Click inside the view to send input. Press Esc to release control.');

  try {
    const payload = {
      agentId,
      scale: 1.0,
      captureAllScreens,
    };
    if (!captureAllScreens) {
      payload.screenId = assignedScreenId;
    }

    const response = await authFetch('/screen/request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`Unexpected response (${response.status})`);
    }

    const data = await response.json();
    sessionId = data.sessionId;

    source = new EventSource(`/screen/${sessionId}/events`);
    source.addEventListener('offer', (event) => handleOffer(JSON.parse(event.data)));
    source.addEventListener('candidate', async (event) => {
      const candidate = JSON.parse(event.data);
      if (pc) {
        await pc.addIceCandidate(candidate);
      }
    });
    source.addEventListener('status', (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.agentName) {
          agentName = payload.agentName;
        }

        const viewLabel = captureAllScreens ? 'Full desktop' : 'Single display';
        if (payload.state) {
          const prefix = payload.state === 'offer-ready'
            ? 'Offer ready for'
            : 'Requesting screen stream for';
          updateStatus(`${prefix} ${agentName} · ${viewLabel}`);
        } else {
          updateStatus(`${agentName} · ${viewLabel}`);
        }
      } catch (error) {
        console.error('Failed to parse popout status event', error);
      }
    });
    source.addEventListener('error', () => {
      if (source.readyState === EventSource.CLOSED) {
        updateStatus('Stream closed by the agent.');
      }
    });
    source.addEventListener('closed', () => {
      updateStatus('Screen session ended.');
    });

    pollOffer(sessionId);
  } catch (error) {
    console.error('Popout init failed', error);
    updateStatus('Failed to start popout stream.');
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

  pc.oniceconnectionstatechange = () => {
    if (!pc) {
      return;
    }

    if (pc.iceConnectionState === 'connected' || pc.iceConnectionState === 'completed') {
      updateInstructions('Control channel ready. Interact inside this window.');
    }
  };

  pc.ondatachannel = (event) => {
    controlChannel = event.channel;
    controlChannel.onmessage = async (messageEvent) => {
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
          if (frameEl) {
            frameEl.src = `data:image/png;base64,${frame.image}`;
          }
        } else if (frame.type === 'cursor') {
          updateRemoteCursor(frame);
        }
      } catch (error) {
        console.error('Failed to decode popout frame', error);
      }
    };

    controlChannel.onclose = () => {
      controlChannel = null;
      updateInstructions('Control channel closed.');
    };
  };

  await pc.setRemoteDescription({ type: payload.sdpType.toLowerCase(), sdp: payload.sdp });
  const answer = await pc.createAnswer();
  await pc.setLocalDescription(answer);
  await postAnswer(answer);

  updateStatus(`Streaming screen from ${agentName}`);
}

async function postAnswer(answer) {
  if (!sessionId) {
    return;
  }

  await authFetch(`/screen/${sessionId}/answer`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(answer),
  });
}

async function postCandidate(candidate) {
  if (!sessionId) {
    return;
  }

  await authFetch(`/screen/${sessionId}/candidate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(candidate),
  });
}

function sendControlMessage(payload) {
  if (!controlChannel || controlChannel.readyState !== 'open') {
    return;
  }

  try {
    controlChannel.send(JSON.stringify(payload));
  } catch (error) {
    console.error('Failed to send popout control message', error);
  }
}

function isControlReady() {
  return controlChannel?.readyState === 'open';
}

function handleKeyEvent(event, action) {
  if (!isControlReady()) {
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
  } else {
    event.preventDefault();
  }
}

function handleMouseMove(event) {
  if (!isControlReady()) {
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
  if (!isControlReady()) {
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
  if (!isControlReady()) {
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

function clampNormalized(value) {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return 0;
  }

  return Math.min(Math.max(value, 0), 1);
}

function updateRemoteCursor(payload) {
  if (!cursorEl || !frameEl || !payload) {
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

async function pollOffer(id) {
  if (!id) {
    return;
  }

  while (!pc) {
    try {
      const response = await authFetch(`/screen/${id}/offer`, { cache: 'no-store' });
      if (!response.ok) {
        throw new Error(`Unexpected status ${response.status}`);
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
      console.error('Failed to poll for popout offer', error);
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }
}

window.addEventListener('keydown', (event) => handleKeyEvent(event, 'down'), true);
window.addEventListener('keyup', (event) => handleKeyEvent(event, 'up'), true);

if (frameEl) {
  frameEl.addEventListener('mousemove', handleMouseMove);
  frameEl.addEventListener('mousedown', (event) => handleMouseButton(event, 'down'));
  frameEl.addEventListener('mouseup', (event) => handleMouseButton(event, 'up'));
  frameEl.addEventListener('wheel', handleMouseWheel, { passive: false });
  frameEl.addEventListener('contextmenu', (event) => {
    if (isControlReady()) {
      event.preventDefault();
    }
  });
}

window.addEventListener('beforeunload', () => {
  source?.close();
  if (sessionId) {
    authFetch(`/screen/${sessionId}/stop`, { method: 'POST' });
  }
});

initPopout();
