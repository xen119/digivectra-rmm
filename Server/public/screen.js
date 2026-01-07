const statusEl = document.getElementById('status');
const frameEl = document.getElementById('frame');

const params = new URLSearchParams(window.location.search);
const agentId = params.get('agent');
let agentName = agentId;
let sessionId;
let source;
let pc;

if (!agentId) {
  statusEl.textContent = 'Agent identifier missing.';
} else {
  initialize();
}

async function initialize() {
  await refreshAgentInfo();
  try {
    const response = await fetch('/screen/request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agentId }),
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
