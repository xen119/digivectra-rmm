const statusEl = document.getElementById('status');
const listEl = document.getElementById('agents');
const groupPanel = document.getElementById('groupPanel');
const newGroupForm = document.getElementById('newGroupForm');
const newGroupInput = document.getElementById('newGroupName');
const logoutButton = document.getElementById('logoutButton');
const authFetch = (input, init) => fetch(input, { credentials: 'same-origin', ...init });

async function applySidebarSettings() {
  try {
    const response = await authFetch('/settings/navigation', { cache: 'no-store' });
    if (!response.ok) {
      return;
    }

    const data = await response.json();
    const hidden = Array.isArray(data.items)
      ? data.items.filter((item) => item.visible === false).map((item) => item.id)
      : [];

    for (const id of hidden) {
      const link = document.querySelector(`.sidebar-link[data-nav-id="${id}"]`);
      link?.classList.add('hidden');
    }
  } catch (error) {
    console.warn('Unable to load navigation settings', error);
  }
}

applySidebarSettings();
const chatIndicators = new Map();
const chatState = new Map();
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
  chatIndicators.clear();
  listEl.innerHTML = '';
  const grouped = agents.reduce((acc, agent) => {
    const groupName = agent.group ?? 'Ungrouped';
    if (!acc[groupName]) {
      acc[groupName] = [];
    }
    acc[groupName].push(agent);
    return acc;
  }, {});

  const uniqueGroupNames = new Set([...groups, ...Object.keys(grouped)]);
  const groupedNames = Array.from(uniqueGroupNames)
    .filter((name) => name !== 'Ungrouped')
    .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
  const allGroupNames = ['Ungrouped', ...groupedNames];
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

  const rebootPill = createRebootPill(agent);
  if (rebootPill) {
    header.appendChild(rebootPill);
  }

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
  const remoteDisplay = agent.remoteAddress ?? 'unknown';
  const internalDisplay = agent.internalIp ?? remoteDisplay;
  const externalDisplay = agent.externalIp ?? remoteDisplay;
  meta.textContent = `${formatPlatform(agent.platform)} · ${agent.os ?? 'Unknown OS'} · remote: ${remoteDisplay} · internal IP: ${internalDisplay} · external IP: ${externalDisplay} · connected at ${connectedAt}`;
  card.appendChild(meta);

  const securityRow = document.createElement('div');
  securityRow.className = 'security-pill-row';
  let securityCount = 0;
  const bitlocker = agent.bitlockerStatus;
  if (bitlocker?.protectionStatus) {
    const pill = document.createElement('span');
    const labelParts = [`BitLocker ${bitlocker.protectionStatus}`];
    const lockStatus = bitlocker.lockStatus?.trim();
    if (lockStatus && lockStatus.toLowerCase() !== bitlocker.protectionStatus.trim().toLowerCase()) {
      labelParts.push(lockStatus);
    }

    const percentage = typeof bitlocker.percentageEncrypted === 'number'
      ? formatPercentage(bitlocker.percentageEncrypted)
      : null;
    if (percentage) {
      labelParts.push(`${percentage}% encrypted`);
    }

    const className = getBitlockerStatusClass(bitlocker.protectionStatus, bitlocker.percentageEncrypted);
    pill.className = `bitlocker-pill bitlocker-pill--${className}`;
    applyBitlockerPillStyle(pill, className);
    pill.textContent = labelParts.join(' · ');

    const titleParts = [];
    if (bitlocker.volume) {
      titleParts.push(`Volume: ${bitlocker.volume}`);
    }
    if (Array.isArray(bitlocker.keyProtectors) && bitlocker.keyProtectors.length > 0) {
      titleParts.push(`Protectors: ${bitlocker.keyProtectors.join(', ')}`);
    }
    if (titleParts.length) {
      pill.title = titleParts.join(' · ');
    }

    securityRow.appendChild(pill);
    securityCount += 1;
  }

  const avStatus = agent.avStatus;
  if (avStatus?.status) {
    const avPill = document.createElement('span');
    const label = `${avStatus.name}: ${avStatus.status}`;
    const avClass = getAvStatusClass(avStatus.status, avStatus.definition);
    avPill.className = `av-pill av-pill--${avClass}`;
    avPill.textContent = label;
    const title = [avStatus.definition, avStatus.productState ? `state ${avStatus.productState}` : null]
      .filter(Boolean)
      .join(' · ');
    if (title) {
      avPill.title = title;
    }
    applyAvPillStyle(avPill, avClass);
    avPill.style.marginLeft = '0.5rem';
    securityRow.appendChild(avPill);
    securityCount += 1;
  }

  if (securityCount > 0) {
    card.appendChild(securityRow);
  }

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

  const warrantyLine = document.createElement('div');
  const warrantyClasses = ['agent-warranty'];
  if (agent.warranty?.status === 'active' || agent.warranty?.status === 'expired') {
    warrantyClasses.push(`agent-warranty--${agent.warranty.status}`);
  }
  warrantyLine.className = warrantyClasses.join(' ');
  warrantyLine.textContent = formatWarrantyInfo(agent.warranty);
  card.appendChild(warrantyLine);

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
  const softwareButton = document.createElement('button');
  softwareButton.type = 'button';
  const softwareCount = typeof agent.softwareSummary?.totalCount === 'number'
    ? agent.softwareSummary.totalCount
    : '-';
  softwareButton.textContent = `Software: ${softwareCount}`;
  softwareButton.addEventListener('click', () => {
    const params = new URLSearchParams();
    if (agent.id) {
      params.set('agent', agent.id);
    }
    if (agent.name) {
      params.set('name', agent.name);
    }
    window.open(`software.html?${params.toString()}`, '_blank', 'noopener');
  });
  actions.appendChild(softwareButton);
  const servicesButton = document.createElement('button');
  servicesButton.type = 'button';
  servicesButton.textContent = 'Services';
  servicesButton.addEventListener('click', () => {
    const params = new URLSearchParams();
    if (agent.id) {
      params.set('agent', agent.id);
    }
    if (agent.name) {
      params.set('name', agent.name);
    }
    window.open(`services.html?${params.toString()}`, '_blank', 'noopener');
  });
  actions.appendChild(servicesButton);
const chatButton = document.createElement('button');
  chatButton.type = 'button';
  chatButton.className = 'chat-pill';
  const chatLabel = document.createElement('span');
  chatLabel.className = 'chat-pill__label';
  chatLabel.textContent = 'Chat';
  chatButton.appendChild(chatLabel);
  chatButton.addEventListener('click', async () => {
    markChatRead(agent.id);
    updateChatIndicator(agent.id, 0);
    try {
      await authFetch(`/chat/${encodeURIComponent(agent.id)}/read`, { method: 'POST' });
      updateChatIndicator(agent.id, 0);
    } catch {
      // ignore
    }
    window.open(`chat.html?agent=${encodeURIComponent(agent.id)}`, '_blank', 'noopener');
  });
  chatIndicators.set(agent.id, { button: chatButton, label: chatLabel });
  updateChatIndicator(agent.id, agent.chatNotifications ?? 0);
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
  const eventButton = document.createElement('button');
  eventButton.type = 'button';
  eventButton.textContent = 'Event log';
  eventButton.addEventListener('click', () => {
    const params = new URLSearchParams();
    if (agent.id) {
      params.set('agent', agent.id);
    }
    if (agent.name) {
      params.set('name', agent.name);
    }
    window.open(`agent-health.html?${params.toString()}`, '_blank', 'noopener');
  });
  actions.appendChild(eventButton);
  const firewallPill = document.createElement('button');
  firewallPill.type = 'button';
  firewallPill.className = 'firewall-pill';
  firewallPill.textContent = 'Firewall';
  firewallPill.addEventListener('click', () => {
    const params = new URLSearchParams();
    if (agent.id) {
      params.set('agent', agent.id);
    }
    if (agent.name) {
      params.set('name', agent.name);
    }
    window.open(`firewall.html?${params.toString()}`, '_blank', 'noopener');
  });
  actions.appendChild(firewallPill);
  card.appendChild(actions);

  return card;
}

function createRebootPill(agent) {
  if (!agent.pendingReboot) {
    return null;
  }

  const hasPendingUpdates = typeof agent.updatesSummary?.totalCount === 'number'
    ? agent.updatesSummary.totalCount > 0
    : false;
  const pill = document.createElement('span');
  pill.className = `reboot-status-pill ${hasPendingUpdates ? 'update-restart-pill' : 'reboot-pill'}`;
  pill.textContent = hasPendingUpdates ? 'Pending update + restart' : 'Pending reboot';
  if (hasPendingUpdates) {
    pill.title = 'Install pending updates and restart required';
  }
  pill.tabIndex = 0;
  pill.setAttribute('role', 'button');
  pill.addEventListener('click', () => handleRebootPillClick(agent.id));
  pill.addEventListener('keypress', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      handleRebootPillClick(agent.id);
    }
  });
  return pill;
}

async function handleRebootPillClick(agentId) {
  if (!agentId) {
    return;
  }

  const confirmed = window.confirm('This will force an immediate restart and install updates. Are you sure?');
  if (!confirmed) {
    return;
  }

  try {
    const response = await authFetch(`/clients/${encodeURIComponent(agentId)}/action`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'update-restart' }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    console.log('Restart action dispatched');
  } catch (error) {
    console.error('Unable to trigger update+restart', error);
  }
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
  monitoringStateSource.addEventListener('chat-notification', (event) => {
    try {
      const payload = JSON.parse(event.data);
      updateChatIndicator(payload.agentId, payload.count, payload.timestamp ?? Date.now());
    } catch (error) {
      console.error('Chat notification parsing failed', error);
    }
  });
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
  pill.textContent = label;
  pill.dataset.label = label;
  pill.dataset.status = status;
  pill.dataset.monitoringEnabled = enabled ? 'true' : 'false';
}

function removeChatSuppression(agentId) {
  suppressedChatNotifications.delete(agentId);
}

function markChatRead(agentId) {
  if (!agentId) {
    return;
  }

  const state = chatState.get(agentId) ?? {};
  state.lastReadTimestamp = Date.now();
  state.awaitingZero = true;
  chatState.set(agentId, state);
}

function updateChatIndicator(agentId, count, timestamp = Date.now(), messageTimestamp = timestamp) {
  const entry = chatIndicators.get(agentId);
  if (!entry) {
    return;
  }

  if (count > 0) {
    const state = chatState.get(agentId) ?? {};
    if (state.awaitingZero) {
      return;
    }
    if (state.lastReadTimestamp && messageTimestamp <= state.lastReadTimestamp) {
      return;
    }
    if (state.lastMessageTimestamp && messageTimestamp <= state.lastMessageTimestamp) {
      return;
    }
    entry.button.classList.add('chat-pill--active');
    entry.button.style.setProperty('background-color', '#b91c1c');
    entry.button.style.setProperty('border-color', '#b91c1c');
    entry.button.style.setProperty('color', '#fff7ed');
    entry.label.textContent = `Chat: ${count}`;
    if (state) {
      state.awaitingZero = false;
      state.lastCount = count;
      state.lastMessageTimestamp = messageTimestamp;
      state.lastReadTimestamp = state.lastReadTimestamp ?? 0;
    } else {
      chatState.set(agentId, {
        lastCount: count,
        awaitingZero: false,
        lastMessageTimestamp: messageTimestamp,
        lastReadTimestamp: 0,
      });
    }
  } else {
    entry.button.classList.remove('chat-pill--active');
    entry.button.style.removeProperty('background-color');
    entry.button.style.removeProperty('border-color');
    entry.button.style.removeProperty('color');
    entry.label.textContent = 'Chat';
    const state = chatState.get(agentId);
    if (state) {
      state.awaitingZero = false;
      state.lastCount = 0;
      state.lastMessageTimestamp = 0;
      state.lastReadTimestamp = Date.now();
    }
  }
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

function formatPercentage(value) {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return null;
  }

  return Number.isInteger(value) ? value.toString() : value.toFixed(1);
}

function getBitlockerStatusClass(status, percentage) {
  if (!status) {
    return 'unknown';
  }

  const normalized = status.toLowerCase();
  if (normalized.includes('on') || normalized.includes('enabled')) {
    if (typeof percentage === 'number' && percentage < 100) {
      return 'partial';
    }

    return 'on';
  }

  if (normalized.includes('off') || normalized.includes('disabled')) {
    return 'off';
  }

  return 'unknown';
}

function getAvStatusClass(status, definition) {
  const normalized = status?.toLowerCase() ?? '';
  if (normalized.includes('enabled') || normalized.includes('on') || normalized.includes('up to date')) {
    return 'healthy';
  }

  if (normalized.includes('out of date') || normalized.includes('deprecated') || (definition?.toLowerCase().includes('out of date'))) {
    return 'stale';
  }

  if (normalized.includes('disabled') || normalized.includes('off')) {
    return 'missing';
  }

  return 'unknown';
}

function applyAvPillStyle(pill, className) {
  const config = {
    healthy: { background: '#0f766e', color: '#ecfeff', border: '#0f766e' },
    stale: { background: '#f59e0b', color: '#0f0303', border: '#f59e0b' },
    missing: { background: '#b91c1c', color: '#fff1f2', border: '#b91c1c' },
    unknown: { background: '#0f172a', color: '#f8fafc', border: '#0f172a' },
  }[className] ?? { background: '#0f172a', color: '#f8fafc', border: '#0f172a' };

  pill.style.backgroundColor = config.background;
  pill.style.color = config.color;
  pill.style.borderColor = config.border;
}

function applyBitlockerPillStyle(pill, className) {
  const config = {
    on: { background: '#0f766e', color: '#ecfeff', border: '#0f766e' },
    partial: { background: '#f59e0b', color: '#0f0303', border: '#f59e0b' },
    off: { background: '#b91c1c', color: '#fff1f2', border: '#b91c1c' },
    unknown: { background: '#1e293b', color: '#f8fafc', border: '#1e293b' },
  }[className] ?? { background: '#0f172a', color: '#f8fafc', border: '#0f172a' };

  pill.style.backgroundColor = config.background;
  pill.style.color = config.color;
  pill.style.borderColor = config.border;
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

function formatWarrantyInfo(warranty) {
  if (!warranty) {
    return 'Warranty info unavailable.';
  }

  if (warranty.error) {
    return `Warranty lookup failed: ${warranty.error}`;
  }

  const parts = [];
  if (warranty.description) {
    parts.push(warranty.description);
  }
  if (warranty.serviceLevel) {
    parts.push(warranty.serviceLevel);
  }
  if (warranty.status === 'active') {
    parts.push('Active');
  } else if (warranty.status === 'expired') {
    parts.push('Expired');
  }
  if (warranty.endDate) {
    const parsed = new Date(warranty.endDate);
    if (!Number.isNaN(parsed)) {
      parts.push(`Expires ${parsed.toLocaleDateString()}`);
    }
  }

  if (!parts.length) {
    return 'Warranty info unavailable.';
  }

  return `Warranty: ${parts.join(' · ')}`;
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
