const statusEl = document.getElementById('status');
const listEl = document.getElementById('agents');
const groupPanel = document.getElementById('groupPanel');
const newGroupForm = document.getElementById('newGroupForm');
const newGroupInput = document.getElementById('newGroupName');
const logoutButton = document.getElementById('logoutButton');
const authFetch = (input, init) => fetch(input, { credentials: 'same-origin', ...init });
let monitoringStateSource;

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
    const response = await authFetch('/groups', {
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

    const response = await authFetch('/clients', { cache: 'no-store' });
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
    const response = await authFetch('/groups', { cache: 'no-store' });
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
  card.dataset.agentId = agent.id ?? '';

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

  if (Array.isArray(agent.monitoringProfiles) && agent.monitoringProfiles.length > 0) {
    const monitoringRow = document.createElement('div');
    monitoringRow.className = 'monitoring-pill-row';
    agent.monitoringProfiles.forEach((profile) => {
      const pill = document.createElement('button');
      pill.type = 'button';
      pill.className = 'monitor-pill';
      pill.dataset.profileId = profile.id ?? '';
      pill.dataset.label = profile.name ?? 'Monitor';
      const label = profile.name ?? 'Monitor';
      const status = profile.alert ? 'triggered' : 'resolved';
      const enabled = Boolean(agent.monitoringEnabled);
      pill.title = profile.metrics?.length ? `Metrics: ${profile.metrics.join(', ')}` : 'Monitoring';
      applyMonitoringPillState(pill, { label, status, enabled });
      pill.addEventListener('click', () => {
        const agentId = agent.id ?? '';
        const profileId = profile.id ?? '';
        window.open(`monitoring-history.html?agent=${encodeURIComponent(agentId)}&profile=${encodeURIComponent(profileId)}&name=${encodeURIComponent(label)}`, '_blank', 'noopener');
      });
      monitoringRow.appendChild(pill);
    });
    card.appendChild(monitoringRow);
  }

  const meta = document.createElement('span');
  meta.className = 'agent-meta';
  const connectedAt = new Date(agent.connectedAt).toLocaleTimeString();
  meta.textContent = `${formatPlatform(agent.platform)} · ${agent.os ?? 'Unknown OS'} · ${agent.remoteAddress} · connected at ${connectedAt}`;
  card.appendChild(meta);

  const specLine = document.createElement('div');
  specLine.className = 'agent-spec';
  specLine.textContent = formatDeviceSpecs(agent.specs);
  card.appendChild(specLine);
  const loginLine = document.createElement('div');
  loginLine.className = 'agent-login';
  loginLine.textContent = agent.loggedInUser
    ? `Logged in user: ${agent.loggedInUser}`
    : 'Logged in user: unknown';
  card.appendChild(loginLine);

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
  const updateCount = typeof agent.updatesSummary?.totalCount === 'number'
    ? agent.updatesSummary.totalCount
    : 0;
  const updatesButton = document.createElement('button');
  updatesButton.type = 'button';
  updatesButton.textContent = `Updates: ${updateCount}`;
  updatesButton.title = agent.updatesSummary?.retrievedAt
    ? `Last refreshed ${new Date(agent.updatesSummary.retrievedAt).toLocaleString()}`
    : 'No update info yet';
  updatesButton.className = `updates-button ${updateCount === 0 ? 'ok' : 'warn'}`;
  updatesButton.addEventListener('click', () => {
    window.open(`updates.html?agent=${encodeURIComponent(agent.id)}`, '_blank', 'noopener');
  });

  actions.appendChild(streamButton);
  actions.appendChild(screenButton);
  actions.appendChild(updatesButton);
  const tasksButton = document.createElement('button');
  tasksButton.type = 'button';
  tasksButton.textContent = 'Manage tasks';
  tasksButton.addEventListener('click', () => {
    window.open(`processes.html?agent=${encodeURIComponent(agent.id)}`, '_blank', 'noopener');
  });
  actions.appendChild(tasksButton);
  const filesButton = document.createElement('button');
  filesButton.type = 'button';
  filesButton.textContent = 'Files';
  filesButton.addEventListener('click', () => {
    window.open(`files.html?agent=${encodeURIComponent(agent.id)}`, '_blank', 'noopener');
  });
  actions.appendChild(filesButton);
  const chatButton = document.createElement('button');
  chatButton.type = 'button';
  chatButton.textContent = 'Chat';
  chatButton.addEventListener('click', () => {
    window.open(`chat.html?agent=${encodeURIComponent(agent.id)}`, '_blank', 'noopener');
  });
  actions.appendChild(chatButton);
  const bsodCount = typeof agent.bsodSummary?.totalCount === 'number'
    ? agent.bsodSummary.totalCount
    : 0;
  const bsodButton = document.createElement('button');
  bsodButton.type = 'button';
  bsodButton.textContent = `BSODs: ${bsodCount}`;
  bsodButton.title = bsodCount === 0 ? 'No blue screens detected' : 'View BSOD history';
  bsodButton.className = `bsod-button ${bsodCount === 0 ? 'ok' : 'warn'}`;
  bsodButton.addEventListener('click', () => {
    window.open(`bsod.html?agent=${encodeURIComponent(agent.id)}`, '_blank', 'noopener');
  });
  actions.appendChild(bsodButton);
  card.appendChild(actions);

  return card;
}

async function assignAgentGroup(agentId, groupName) {
  try {
    await authFetch('/groups/assign', {
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
startMonitoringStateStream();

logoutButton?.addEventListener('click', async () => {
  try {
    await authFetch('/auth/logout', { method: 'POST' });
  } finally {
    window.location.href = '/login.html';
  }
});

function startMonitoringStateStream() {
  if (monitoringStateSource) {
    monitoringStateSource.close();
  }

  monitoringStateSource = new EventSource('/monitoring/events');
  monitoringStateSource.addEventListener('monitoring-state', (event) => {
    try {
      const payload = JSON.parse(event.data);
      updateAgentMonitoringIndicator(payload);
    } catch (error) {
      console.error('Monitoring state event parsing failed', error);
    }
  });
  monitoringStateSource.onerror = (error) => {
    console.error('Monitoring state SSE error', error);
    monitoringStateSource?.close();
    setTimeout(startMonitoringStateStream, 5000);
  };
}

function updateAgentMonitoringIndicator(payload) {
  const agentId = payload?.agentId;
  if (!agentId) {
    return;
  }

  const card = document.querySelector(`.agent-card[data-agent-id="${agentId}"]`);
  if (!card) {
    return;
  }

  const profileId = payload?.profileId;
  if (!profileId) {
    return;
  }

  const pill = card.querySelector(`.monitor-pill[data-profile-id="${profileId}"]`);
  if (!pill) {
    return;
  }

  const label = payload.profileName ?? pill.dataset.label ?? 'Monitor';
  const status = payload.status ?? (payload.triggered ? 'triggered' : 'resolved');
  const enabled = typeof payload.monitoringEnabled === 'boolean'
    ? payload.monitoringEnabled
    : pill.dataset.monitoringEnabled === 'true';
  applyMonitoringPillState(pill, { label, status, enabled });
}

function applyMonitoringPillState(pill, { label, status, enabled }) {
  if (!pill) {
    return;
  }

  const stateClass = status === 'triggered' ? 'alert' : enabled ? 'ok' : 'disabled';
  pill.className = `monitor-pill ${stateClass}`;
  const suffix = status === 'triggered' ? ' • Alert' : status === 'resolved' ? ' • Resolved' : '';
  pill.textContent = `${label}${suffix}`;
  pill.dataset.label = label;
  pill.dataset.status = status;
  pill.dataset.monitoringEnabled = enabled ? 'true' : 'false';
}

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

function formatDeviceSpecs(specs) {
  if (!specs) {
    return 'Device info unavailable.';
  }

  const parts = [];
  const manufacturerParts = [];
  if (specs.Manufacturer) {
    manufacturerParts.push(specs.Manufacturer);
  }
  if (specs.Model) {
    manufacturerParts.push(specs.Model);
  }
  if (manufacturerParts.length > 0) {
    parts.push(manufacturerParts.join(' '));
  }

  if (specs.Edition) {
    parts.push(`Edition: ${specs.Edition}`);
  }

  if (specs.SerialNumber) {
    parts.push(`SN: ${specs.SerialNumber}`);
  }

  if (specs.CpuName) {
    const cpu = specs.CpuCores ? `${specs.CpuName} (${specs.CpuCores} cores)` : specs.CpuName;
    parts.push(`CPU: ${cpu}`);
  }

  if (specs.TotalMemoryBytes) {
    parts.push(`RAM: ${formatBytes(specs.TotalMemoryBytes)}`);
  }

  if (Array.isArray(specs.Storages) && specs.Storages.length > 0) {
    const storageList = specs.Storages.map((drive) => {
      const name = drive.Name ? `${drive.Name}` : 'Drive';
      const total = drive.TotalBytes ? formatBytes(drive.TotalBytes) : '?';
      const free = drive.FreeBytes ? formatBytes(drive.FreeBytes) : '?';
      return `${name}: ${total} total, ${free} free`;
    });
    parts.push(storageList.join(' | '));
  }

  return parts.length > 0 ? parts.join(' · ') : 'Device info unavailable.';
}

function formatBytes(bytes) {
  if (!bytes || typeof bytes !== 'number') {
    return '0 B';
  }

  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let index = 0;
  while (value >= 1024 && index < sizes.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(1)} ${sizes[index]}`;
}
