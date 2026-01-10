const statusMessage = document.getElementById('statusMessage');
const refreshButton = document.getElementById('refreshButton');
const lastUpdated = document.getElementById('lastUpdated');
const tableBody = document.getElementById('softwareTableBody');
const totalSoftwareCount = document.getElementById('totalSoftwareCount');
const totalAgentCount = document.getElementById('totalAgentCount');
const pendingUninstallCount = document.getElementById('pendingUninstallCount');
const rejectedPairCount = document.getElementById('rejectedPairCount');
const logList = document.getElementById('logList');

const ROLE_WEIGHT = { viewer: 0, operator: 1, admin: 2 };
let currentRole = 'viewer';
let isLoadingInventory = false;

function setStatus(text, isError = false) {
  if (!statusMessage) {
    return;
  }

  statusMessage.textContent = text;
  statusMessage.style.color = isError ? '#f87171' : '#94a3b8';
}

function canManageSoftware() {
  return ROLE_WEIGHT[currentRole] >= ROLE_WEIGHT.operator;
}

async function loadUserRole() {
  try {
    const response = await fetch('/auth/me', { credentials: 'same-origin' });
    if (!response.ok) {
      throw new Error('Unable to determine user role');
    }
    const payload = await response.json();
    currentRole = payload.role ?? 'viewer';
  } catch (error) {
    console.error(error);
    currentRole = 'viewer';
  }
}

async function refreshInventory(force = false) {
  if (isLoadingInventory && !force) {
    return;
  }

  isLoadingInventory = true;
  setStatus('Loading software catalog...');

  try {
    const response = await fetch('/software', { credentials: 'same-origin' });
    if (!response.ok) {
      throw new Error(`Server returned ${response.status}`);
    }

    const payload = await response.json();
    const summary = payload?.summary ?? {};
    updateSummary(summary);
    renderSoftwareTable(Array.isArray(payload?.software) ? payload.software : []);
    setStatus('Software catalog is up to date.');
    if (lastUpdated) {
      lastUpdated.textContent = `Last refreshed ${new Date().toLocaleString()}`;
    }
  } catch (error) {
    console.error(error);
    setStatus('Failed to load software inventory.', true);
    renderSoftwareTable([]);
  } finally {
    isLoadingInventory = false;
  }
}

function updateSummary(summary = {}) {
  totalSoftwareCount.textContent = summary.totalSoftware ?? 0;
  totalAgentCount.textContent = summary.totalAgents ?? 0;
  pendingUninstallCount.textContent = summary.pendingUninstalls ?? 0;
  rejectedPairCount.textContent = summary.rejectedPairs ?? 0;
}

function renderSoftwareTable(entries) {
  if (!tableBody) {
    return;
  }

  tableBody.innerHTML = '';

  if (!entries.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.setAttribute('colspan', '7');
    cell.className = 'empty';
    cell.textContent = 'No software entries available.';
    row.appendChild(cell);
    tableBody.appendChild(row);
    return;
  }

  const sorted = [...entries].sort((a, b) => (b.agentCount ?? 0) - (a.agentCount ?? 0));
  sorted.forEach((software) => {
    const row = document.createElement('tr');

    const nameCell = document.createElement('td');
    const title = document.createElement('strong');
    title.textContent = software.name ?? 'Unnamed';
    nameCell.appendChild(title);
    const meta = document.createElement('div');
    meta.className = 'secondary';
    meta.textContent = `${software.agentCount ?? 0} agent${(software.agentCount ?? 0) === 1 ? '' : 's'}`;
    nameCell.appendChild(meta);
    row.appendChild(nameCell);

    const versionCell = document.createElement('td');
    versionCell.textContent = software.version || '-';
    row.appendChild(versionCell);

    const publisherCell = document.createElement('td');
    publisherCell.textContent = software.publisher || '-';
    row.appendChild(publisherCell);

    const sourceCell = document.createElement('td');
    sourceCell.textContent = software.source || '-';
    row.appendChild(sourceCell);

    const statusCell = document.createElement('td');
    const status = (software.status ?? 'pending').toLowerCase();
    const statusPill = document.createElement('span');
    statusPill.className = `status-pill ${status}`;
    statusPill.textContent = status.charAt(0).toUpperCase() + status.slice(1);
    statusCell.appendChild(statusPill);
    row.appendChild(statusCell);

    const actionCell = document.createElement('td');
    actionCell.appendChild(createActionButtons(software));
    row.appendChild(actionCell);

    tableBody.appendChild(row);

    const agentRow = document.createElement('tr');
    const agentCell = document.createElement('td');
    agentCell.colSpan = 6;
    agentCell.appendChild(createAgentList(software.agents ?? []));
    agentRow.appendChild(agentCell);
    tableBody.appendChild(agentRow);
  });
}

function createAgentList(agents) {
  const container = document.createElement('div');
  container.className = 'agent-list-wrapper';

  if (!agents.length) {
    const empty = document.createElement('p');
    empty.className = 'empty';
    empty.textContent = 'No agents reporting this software.';
    container.appendChild(empty);
    return container;
  }

  const list = document.createElement('ul');
  list.className = 'agent-list';
  agents.forEach((agent) => {
    const li = document.createElement('li');
    const name = document.createElement('span');
    name.className = 'agent-name';
    name.textContent = agent.agentName ?? 'Unknown';

    const statusWrapper = document.createElement('span');
    statusWrapper.className = 'agent-status';
    const currentStatus = agent.status === 'online' ? 'online' : 'offline';
    statusWrapper.classList.add(currentStatus);
    statusWrapper.textContent = currentStatus.charAt(0).toUpperCase() + currentStatus.slice(1);

    li.appendChild(name);
    li.appendChild(statusWrapper);
    list.appendChild(li);
  });

  container.appendChild(list);
  return container;
}

function createActionButtons(software) {
  const wrapper = document.createElement('div');
  wrapper.className = 'action-buttons';

  if (!canManageSoftware()) {
    const hint = document.createElement('span');
    hint.className = 'secondary';
    hint.textContent = 'Operator/admin privileges required';
    wrapper.appendChild(hint);
    return wrapper;
  }

  const approveButton = document.createElement('button');
  approveButton.type = 'button';
  approveButton.className = 'approve';
  approveButton.textContent = 'Approve';
  approveButton.disabled = software.status === 'approved';

  const rejectButton = document.createElement('button');
  rejectButton.type = 'button';
  rejectButton.className = 'reject';
  rejectButton.textContent = 'Reject';
  rejectButton.disabled = software.status === 'rejected';

  approveButton.addEventListener('click', () => handleAction(software.id, 'approve', approveButton, rejectButton));
  rejectButton.addEventListener('click', () => handleAction(software.id, 'reject', approveButton, rejectButton));

  wrapper.appendChild(approveButton);
  wrapper.appendChild(rejectButton);
  return wrapper;
}

async function handleAction(softwareId, action, approveButton, rejectButton) {
  if (!canManageSoftware()) {
    setStatus('Insufficient privileges.', true);
    return;
  }

  approveButton.disabled = true;
  rejectButton.disabled = true;
  setStatus(action === 'approve' ? 'Approving software...' : 'Rejecting software...', false);

  try {
    const response = await fetch('/software/approval', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ softwareId, action }),
    });

    if (!response.ok) {
      throw new Error(`Server returned ${response.status}`);
    }

    setStatus('Action accepted. Refreshing catalog...');
    await refreshInventory(true);
  } catch (error) {
    console.error(error);
    setStatus('Action failed. Check logs for details.', true);
  } finally {
    approveButton.disabled = false;
    rejectButton.disabled = false;
  }
}

async function refreshLogs() {
  if (!logList) {
    return;
  }

  try {
    const response = await fetch('/software/logs', { credentials: 'same-origin' });
    if (!response.ok) {
      throw new Error(`Server returned ${response.status}`);
    }

    const payload = await response.json();
    renderLog(payload.logs ?? []);
  } catch (error) {
    console.error(error);
    logList.innerHTML = '<p class="empty">Unable to load uninstall log.</p>';
  }
}

function renderLog(entries) {
  if (!logList) {
    return;
  }

  logList.innerHTML = '';

  if (!entries.length) {
    logList.innerHTML = '<p class="empty">No uninstall activity logged yet.</p>';
    return;
  }

  entries.slice(0, 15).forEach((entry) => {
    const card = document.createElement('article');
    card.className = 'log-entry';

    const timeLabel = document.createElement('time');
    timeLabel.textContent = formatTimestamp(entry.timestamp);
    card.appendChild(timeLabel);

    const title = document.createElement('strong');
    title.textContent = `${entry.softwareName || 'Software'} · ${entry.agentName || entry.agentId || 'Unknown agent'}`;
    card.appendChild(title);

    const message = document.createElement('span');
    message.textContent = entry.message || 'Automatic uninstall attempt';
    card.appendChild(message);

    logList.appendChild(card);
  });
}

function formatTimestamp(value) {
  const timestamp = value ? new Date(value) : new Date();
  if (Number.isNaN(timestamp.getTime())) {
    return new Date().toLocaleString();
  }
  return timestamp.toLocaleString();
}

refreshButton?.addEventListener('click', () => refreshInventory(true));

loadUserRole()
  .then(() => refreshInventory(true))
  .catch(() => refreshInventory(true));

refreshLogs();
setInterval(() => refreshInventory(true), 30000);
setInterval(refreshLogs, 60000);
