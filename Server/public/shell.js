const summaryEl = document.getElementById('summary');
const logEl = document.getElementById('log');
const formEl = document.getElementById('command-form');
const inputEl = document.getElementById('command-input');
const authFetch = (input, init) => fetch(input, { credentials: 'same-origin', ...init });

const params = new URLSearchParams(window.location.search);
const agentId = params.get('agent');
let agentName = agentId;
let source;

if (!agentId) {
  summaryEl.textContent = 'Agent identifier missing.';
  formEl.querySelector('button').disabled = true;
} else {
  source = new EventSource(`/shell/${agentId}`);

  source.addEventListener('shell', (event) => {
    try {
      const payload = JSON.parse(event.data);
      const prefix = payload.stream === 'stderr' ? '[stderr]' : '[stdout]';
      appendLine(`${prefix} ${payload.output}`);
    } catch (error) {
      console.error(error);
    }
  });

  source.onopen = () => {
    summaryEl.textContent = `Streaming shell for ${agentName || agentId}`;
  };

  source.onerror = () => {
    summaryEl.textContent = 'Reconnecting to agent…';
  };

  refreshAgentInfo();
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
      summaryEl.textContent = `Streaming shell for ${agent.name}`;
    }
  } catch (error) {
    console.error(error);
  }
}

formEl.addEventListener('submit', async (event) => {
  event.preventDefault();

  if (!agentId) {
    return;
  }

  const command = inputEl.value.trim();
  if (!command) {
    return;
  }

  try {
    await authFetch(`/shell/${agentId}/input`, {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
      },
      body: command,
    });
  } catch (error) {
    console.error(error);
    appendLine('[local] failed to send command.');
  }

  inputEl.value = '';
});

function appendLine(text) {
  logEl.textContent += `${text}\n`;
  logEl.scrollTop = logEl.scrollHeight;
}
