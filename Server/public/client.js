const statusEl = document.getElementById('status');
const listEl = document.getElementById('agents');
const groupPanel = document.getElementById('groupPanel');
const newGroupForm = document.getElementById('newGroupForm');
const newGroupInput = document.getElementById('newGroupName');

const OS_ICONS = {
  windows: '🪟',
  linux: '🐧',
  macos: '🍎',
  unknown: '💻',
};

let cachedGroups = [];

newGroupForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const name = newGroupInput?.value?.trim();
  if (!name) {
    return;
  }

  try {
    const response = await fetch('/groups', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    });

    if (!response.ok) {
      throw new Error('Failed to create group');
    }

    newGroupInput.value = '';
    await refreshAgents();
  } catch (error) {
    console.error(error);
  }
});

async function refreshAgents() {
  try {
    const groups = await fetchGroups();
    cachedGroups = groups;

    const response = await fetch('/clients', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const agents = await response.json();
    statusEl.textContent = agents.length === 0
      ? 'No agents currently connected.'
      : `Showing ${agents.length} connected agent${agents.length === 1 ? '' : 's'}.`;

    renderAgentGroups(agents, groups);
  } catch (error) {
    statusEl.textContent = 'Failed to load agents.';
    listEl.innerHTML = '';
    console.error(error);
  }
}

async function fetchGroups() {
  try {
    const response = await fetch('/groups', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error('Could not fetch groups');
    }

    const data = await response.json();
    if (Array.isArray(data.groups)) {
      return data.groups;
    }
  } catch (error) {
    console.error(error);
  }

  return cachedGroups;
}

function renderAgentGroups(agents, groups) {
  listEl.innerHTML = '';
  const grouped = agents.reduce((acc, agent) => {
    const groupName = agent.group ?? 'Ungrouped';
    if (!acc[groupName]) {
      acc[groupName] = [];
    }
    acc[groupName].push(agent);
    return acc;
  }, {});

  const allGroupNames = Array.from(new Set([...groups, ...Object.keys(grouped)]));
  if (allGroupNames.length === 0) {
    listEl.textContent = 'No groups available.';
    return;
  }

  allGroupNames.forEach((groupName) => {
    const groupAgents = grouped[groupName] ?? [];

    const groupBlock = document.createElement('section');
    groupBlock.className = 'group-block';

    const header = document.createElement('div');
    header.className = 'group-header';
    const title = document.createElement('h2');
    title.textContent = `${groupName} (${groupAgents.length})`;
    header.appendChild(title);
    groupBlock.appendChild(header);

    if (groupAgents.length === 0) {
      const empty = document.createElement('p');
      empty.textContent = 'No agents in this group.';
      groupBlock.appendChild(empty);
    } else {
      const agentList = document.createElement('div');
      agentList.className = 'agent-list';
      groupAgents.forEach((agent) => {
        const card = createAgentCard(agent, allGroupNames);
        agentList.appendChild(card);
      });
      groupBlock.appendChild(agentList);
    }

    listEl.appendChild(groupBlock);
  });
}

function createAgentCard(agent, groups) {
  const card = document.createElement('div');
  card.className = 'agent-card';

  const header = document.createElement('div');
  header.className = 'agent-row';

      const icon = document.createElement('span');
      icon.className = 'os-icon';
      icon.textContent = getOsIcon(agent.platform);
      icon.title = agent.platform ?? 'Unknown';
      header.appendChild(icon);

      const name = document.createElement('strong');
      name.textContent = agent.name;
      header.appendChild(name);

      const statusPill = document.createElement('span');
      statusPill.className = `status-pill ${agent.status === 'online' ? 'online' : 'offline'}`;
      statusPill.textContent = agent.status === 'online'
        ? 'Online'
        : `Offline${agent.lastSeen ? ` since ${new Date(agent.lastSeen).toLocaleTimeString()}` : ''}`;
      header.appendChild(statusPill);

  const groupSelect = document.createElement('select');
  groupSelect.className = 'group-select';
  groups.forEach((groupName) => {
    const option = document.createElement('option');
    option.value = groupName;
    option.textContent = groupName;
    if (groupName === (agent.group ?? 'Ungrouped')) {
      option.selected = true;
    }
    groupSelect.appendChild(option);
  });

  groupSelect.addEventListener('change', async () => {
    await assignAgentGroup(agent.id, groupSelect.value);
  });

  header.appendChild(groupSelect);
  card.appendChild(header);

  const meta = document.createElement('span');
  meta.className = 'agent-meta';
  const connectedAt = new Date(agent.connectedAt).toLocaleTimeString();
  meta.textContent = `${formatPlatform(agent.platform)} · ${agent.os ?? 'Unknown OS'} · ${agent.remoteAddress} · connected at ${connectedAt}`;
  card.appendChild(meta);

  const actions = document.createElement('div');
  actions.className = 'actions';
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
  card.appendChild(actions);

  return card;
}

async function assignAgentGroup(agentId, groupName) {
  try {
    await fetch('/groups/assign', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agentId, group: groupName }),
    });
    await refreshAgents();
  } catch (error) {
    console.error(error);
  }
}

refreshAgents();
setInterval(refreshAgents, 5000);

function getOsIcon(platform) {
  if (!platform) {
    return OS_ICONS.unknown;
  }

  const key = platform.toLowerCase();
  if (key.includes('windows')) {
    return OS_ICONS.windows;
  }

  if (key.includes('linux')) {
    return OS_ICONS.linux;
  }

  if (key.includes('mac')) {
    return OS_ICONS.macos;
  }

  return OS_ICONS.unknown;
}

function formatPlatform(platform) {
  if (!platform) {
    return 'Unknown';
  }

  return platform;
}
