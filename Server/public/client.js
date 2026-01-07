const statusEl = document.getElementById('status');
const listEl = document.getElementById('agents');

async function refreshAgents() {
  try {
    const response = await fetch('/clients', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const agents = await response.json();
    if (agents.length === 0) {
      statusEl.textContent = 'No agents currently connected.';
    } else {
      statusEl.textContent = `Showing ${agents.length} connected agent${agents.length === 1 ? '' : 's'}.`;
    }

    listEl.innerHTML = '';
    for (const agent of agents) {
      const item = document.createElement('li');
      const title = document.createElement('strong');
      title.textContent = agent.name;
      const meta = document.createElement('span');
      const connectedAt = new Date(agent.connectedAt).toLocaleTimeString();
      meta.textContent = `${agent.remoteAddress} · connected at ${connectedAt}`;

      const actions = document.createElement('div');
      const streamButton = document.createElement('button');
      streamButton.type = 'button';
      streamButton.textContent = 'Stream shell';
      streamButton.addEventListener('click', () => {
        window.open(`shell.html?agent=${encodeURIComponent(agent.id)}`, '_blank', 'noopener');
      });
      const screenButton = document.createElement('button');
      screenButton.type = 'button';
      screenButton.textContent = 'Stream screen';
      screenButton.addEventListener('click', () => {
        window.open(`screen.html?agent=${encodeURIComponent(agent.id)}`, '_blank', 'noopener');
      });
      actions.appendChild(streamButton);
      actions.appendChild(screenButton);

      item.appendChild(title);
      item.appendChild(meta);
      item.appendChild(actions);
      listEl.appendChild(item);
    }
  } catch (error) {
    statusEl.textContent = 'Failed to load agents.';
    listEl.innerHTML = '';
    console.error(error);
  }
}

refreshAgents();
setInterval(refreshAgents, 3000);
