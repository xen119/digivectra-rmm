const authFetch = (input, init = {}) => fetch(input, { credentials: 'same-origin', ...init });
const patchStatusEl = document.getElementById('patchStatus');
const patchListEl = document.getElementById('patchList');
const patchCountEl = document.getElementById('patchCount');
const pendingCountEl = document.getElementById('pendingCount');
const approvedCountEl = document.getElementById('approvedCount');
const rebootCountEl = document.getElementById('rebootCount');
const patchSelect = document.getElementById('schedulePatch');
const scheduleAgents = document.getElementById('scheduleAgents');
const scheduleForm = document.getElementById('scheduleForm');
const scheduleMessageEl = document.getElementById('scheduleMessage');
const runAtInput = document.getElementById('scheduleRunAt');
const repeatValueInput = document.getElementById('scheduleRepeatValue');
const repeatUnitSelect = document.getElementById('scheduleRepeatUnit');
const refreshPatchesButton = document.getElementById('refreshPatches');
const refreshSchedulesButton = document.getElementById('refreshSchedules');
const scheduleTable = document.getElementById('scheduleTable');
const scheduleTableBody = scheduleTable?.querySelector('tbody');
const scheduleEmpty = document.getElementById('scheduleEmpty');
const scheduleSubmitButton = scheduleForm?.querySelector('button[type="submit"]');
const historyList = document.getElementById('historyList');
const tabButtons = document.querySelectorAll('[data-tab-button]');
const tabPanels = document.querySelectorAll('[data-tab-panel]');
const categorySelect = document.getElementById('scheduleCategory');

const PATCH_ACTIONS = [
  { id: 'update-restart', label: 'Update + restart' },
  { id: 'restart', label: 'Restart now' },
  { id: 'shutdown', label: 'Shutdown now' },
];

let activePatches = [];
let activeSchedules = [];
let historyEntries = [];

function isoDateForInput(date) {
  const pad = (value) => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function setActiveTab(tabId) {
  tabPanels.forEach((panel) => {
    if (panel.getAttribute('data-tab-panel') === tabId) {
      panel.classList.add('active');
    } else {
      panel.classList.remove('active');
    }
  });

  tabButtons.forEach((button) => {
    if (button.getAttribute('data-tab-button') === tabId) {
      button.classList.add('active');
    } else {
      button.classList.remove('active');
    }
  });
}

function renderPatchSummary(summary = {}) {
  if (patchCountEl) {
    patchCountEl.textContent = String(summary.totalPatches ?? 0);
  }
  if (pendingCountEl) {
    pendingCountEl.textContent = String(summary.pendingApprovals ?? 0);
  }
  if (approvedCountEl) {
    approvedCountEl.textContent = String(summary.approvedPairs ?? 0);
  }
  if (rebootCountEl) {
    rebootCountEl.textContent = String(summary.pendingReboots ?? 0);
  }
}

function renderPatchList(patches = activePatches) {
  if (!patchListEl) {
    return;
  }

  if (patches.length === 0) {
    patchListEl.innerHTML = '<div class="empty">No pending patches at the moment.</div>';
    return;
  }

  patchListEl.innerHTML = '';
  patches.forEach((patch) => {
    patchListEl.appendChild(createPatchCard(patch));
  });
}

function createPatchCard(patch) {
  const card = document.createElement('article');
  card.className = 'patch-card';

  const header = document.createElement('div');
  header.className = 'patch-header';
  const title = document.createElement('div');
  const heading = document.createElement('h3');
  heading.textContent = patch.title;
  const meta = document.createElement('p');
  meta.className = 'patch-meta';
  meta.textContent = patch.categories.map((category) => category.name).join(', ') || 'Uncategorized';
  title.appendChild(heading);
  title.appendChild(meta);
  header.appendChild(title);

  const idSpan = document.createElement('span');
  idSpan.className = 'patch-id';
  idSpan.textContent = patch.id;
  header.appendChild(idSpan);

  card.appendChild(header);

  if (patch.description) {
    const description = document.createElement('p');
    description.className = 'patch-description';
    description.textContent = patch.description;
    card.appendChild(description);
  }

  if (Array.isArray(patch.kbArticleIDs) && patch.kbArticleIDs.length > 0) {
    const kbContainer = document.createElement('div');
    kbContainer.className = 'kb-list';
    patch.kbArticleIDs.forEach((kb) => {
      const pill = document.createElement('span');
      pill.className = 'kb-pill';
      pill.textContent = kb;
      kbContainer.appendChild(pill);
    });
    card.appendChild(kbContainer);
  }

  if (patch.agents.length > 0) {
    const agentList = document.createElement('div');
    agentList.className = 'agent-grid';
    patch.agents.forEach((agent) => {
      agentList.appendChild(createAgentEntry(agent, patch.id));
    });
    card.appendChild(agentList);
  } else {
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = 'No agents currently report this patch.';
    card.appendChild(empty);
  }

  return card;
}

function createAgentEntry(agent, patchId) {
  const label = document.createElement('label');
  label.className = 'agent-entry';

  const checkbox = document.createElement('input');
  checkbox.type = 'checkbox';
  checkbox.checked = Boolean(agent.approved);
  checkbox.dataset.agentId = agent.agentId;
  checkbox.dataset.patchId = patchId;
  checkbox.addEventListener('change', () => toggleApproval(agent, patchId, checkbox));
  label.appendChild(checkbox);

  const details = document.createElement('div');
  details.className = 'agent-details';
  const topLine = document.createElement('span');
  topLine.textContent = `${agent.agentName} ${agent.group ? `· ${agent.group}` : ''}`;
  details.appendChild(topLine);

  const statusLine = document.createElement('span');
  statusLine.textContent = agent.status === 'online' ? 'Online' : 'Offline';
  statusLine.className = `pill ${agent.status === 'online' ? 'online' : 'offline'}`;
  details.appendChild(statusLine);

  if (agent.pendingReboot) {
    const rebootPill = document.createElement('span');
    rebootPill.className = 'pill reboot';
    rebootPill.textContent = 'Pending reboot';
    details.appendChild(rebootPill);
  }

  label.appendChild(details);

  if (agent.status === 'online') {
    const actionRow = document.createElement('div');
    actionRow.className = 'agent-action-row';
    PATCH_ACTIONS.forEach((action) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.textContent = action.label;
      button.className = 'secondary';
      button.addEventListener('click', () => performAgentAction(agent.agentId, action.id, button));
      actionRow.appendChild(button);
    });
    label.appendChild(actionRow);
  }

  return label;
}

async function toggleApproval(agent, patchId, checkbox) {
  checkbox.disabled = true;
  const payload = {
    agentId: agent.agentId,
    updateId: patchId,
    approved: checkbox.checked,
  };

  try {
    const response = await authFetch('/patches/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    await loadPatchData(true);
  } catch (error) {
    checkbox.checked = !checkbox.checked;
    console.error('Approval toggle failed', error);
    showScheduleMessage('Failed to update approval.', 'error');
  } finally {
    checkbox.disabled = false;
  }
}

async function performAgentAction(agentId, action, button) {
  if (!agentId || !action) {
    return;
  }

  button.disabled = true;

  try {
    const response = await authFetch(`/clients/${encodeURIComponent(agentId)}/action`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    showScheduleMessage('Action requested; check the log for the result.', 'success');
    loadHistory(true);
  } catch (error) {
    console.error('Agent action failed', error);
    showScheduleMessage('Failed to trigger action.', 'error');
  } finally {
    button.disabled = false;
  }
}

function populateCategorySelect() {
  if (!categorySelect) {
    return;
  }

  const categoryMap = new Map();
  activePatches.forEach((patch) => {
    const category = patch.primaryCategory;
    if (!category || !category.name) {
      return;
    }

    if (!categoryMap.has(category.name)) {
      categoryMap.set(category.name, category.purpose ?? '');
    }
  });

  categorySelect.innerHTML = '<option value="">Select a category</option>';
  Array.from(categoryMap.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .forEach(([name, purpose]) => {
      const option = document.createElement('option');
      option.value = name;
      option.textContent = `${name}${purpose ? ` · ${purpose}` : ''}`;
      categorySelect.appendChild(option);
    });

  updateScheduleAgents();
}

function populatePatchSelect() {
  if (!patchSelect) {
    return;
  }

  patchSelect.innerHTML = '<option value="">Select a patch</option>';
  activePatches.forEach((patch) => {
    const option = document.createElement('option');
    option.value = patch.id;
    option.textContent = `${patch.title} (${patch.id.slice(0, 8)})`;
  patchSelect.appendChild(option);
  });

  updateScheduleAgents();
}

function getCurrentPatchIds() {
  if (patchSelect?.value) {
    return [patchSelect.value];
  }

  const selectedCategory = categorySelect?.value;
  if (!selectedCategory) {
    return [];
  }

  return activePatches
    .filter((patch) => (Array.isArray(patch.categories) ? patch.categories.some((category) => category.name === selectedCategory) : false))
    .map((patch) => patch.id)
    .filter(Boolean);
}

function getSelectedPatches() {
  if (patchSelect?.value) {
    const patch = activePatches.find((entry) => entry.id === patchSelect.value);
    return patch ? [patch] : [];
  }

  const selectedCategory = categorySelect?.value;
  if (!selectedCategory) {
    return [];
  }

  return activePatches.filter((patch) => patch.primaryCategory?.name === selectedCategory);
}

function getSelectedPatchIds() {
  return getSelectedPatches().map((patch) => patch.id).filter(Boolean);
}

function sortAgents(agentA, agentB) {
  if (agentA.agentName && agentB.agentName) {
    return agentA.agentName.localeCompare(agentB.agentName);
  }
  return agentA.agentId.localeCompare(agentB.agentId);
}

function updateScheduleAgents() {
  if (!scheduleAgents) {
    return;
  }

  const patches = getSelectedPatches();
  if (!patches.length) {
    const hint = patchSelect?.value
      ? 'Selected patch no longer exists.'
      : 'Choose a patch or category to see the approved agents for that selection.';
    scheduleAgents.innerHTML = `<p class="empty">${hint}</p>`;
    updateScheduleButtonState();
    return;
  }

  const agentMap = new Map();
  patches.forEach((patch) => {
    patch.agents.forEach((agent) => {
      if (!agent.approved) {
        return;
      }

      if (!agentMap.has(agent.agentId)) {
        agentMap.set(agent.agentId, { ...agent });
      }
    });
  });

  const approvedAgents = Array.from(agentMap.values()).sort(sortAgents);
  if (approvedAgents.length === 0) {
    scheduleAgents.innerHTML = '<p class="empty">No approved agents yet for this selection.</p>';
    updateScheduleButtonState();
    return;
  }

  scheduleAgents.innerHTML = '';
  const list = document.createElement('ul');
  list.className = 'approval-list';
  approvedAgents.forEach((agent) => {
    const item = document.createElement('li');
    const title = document.createElement('span');
    title.textContent = `${agent.agentName} · ${agent.status === 'online' ? 'Online' : 'Offline'}`;
    item.appendChild(title);
    if (agent.pendingReboot) {
      const rebootPill = document.createElement('span');
      rebootPill.className = 'pill reboot';
      rebootPill.textContent = 'Pending reboot';
      item.appendChild(rebootPill);
    }
    list.appendChild(item);
  });
  scheduleAgents.appendChild(list);

  updateScheduleButtonState();
}

function updateScheduleButtonState(isSubmitting = false) {
  if (!scheduleSubmitButton) {
    return;
  }

  const hasSelection = getSelectedPatchIds().length > 0;
  scheduleSubmitButton.disabled = !hasSelection || isSubmitting;
}

async function handleScheduleSubmit(event) {
  event.preventDefault();
  if (!patchSelect || !runAtInput || !repeatValueInput || !repeatUnitSelect) {
    return;
  }

  updateScheduleButtonState(true);

  const selectedPatchIds = getSelectedPatchIds();
  if (!selectedPatchIds.length) {
    showScheduleMessage('Please select a patch or category.');
    updateScheduleButtonState();
    return;
  }

  const runAtValue = runAtInput.value;
  let runAt = Date.parse(runAtValue);
  if (Number.isNaN(runAt)) {
    runAt = Date.now();
  }

  const repeatValue = Number(repeatValueInput.value);
  const repeatUnit = repeatUnitSelect.value;
  const multiplier = {
    seconds: 1_000,
    minutes: 60_000,
    hours: 3_600_000,
    days: 86_400_000,
  }[repeatUnit] ?? 60_000;
  const repeatMs = repeatValue > 0 ? repeatValue * multiplier : 0;

  try {
    const response = await authFetch('/patches/schedule', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
      name: patchSelect?.value
        ? `${patchSelect.selectedOptions[0]?.textContent ?? 'Patch schedule'}`
        : `Category ${categorySelect?.value ?? 'selection'}`,
      patchIds: selectedPatchIds,
      category: !patchSelect?.value ? categorySelect?.value : null,
        runAt,
        repeatMs,
      }),
    });

    if (!response.ok) {
      const payload = await response.json().catch(() => null);
      const message = payload?.error ?? `HTTP ${response.status}`;
      showScheduleMessage(message, 'error');
      return;
    }

    showScheduleMessage('Schedule saved.', 'success');
    loadSchedules();
    loadHistory(true);
  } catch (error) {
    console.error('Scheduling failed', error);
    showScheduleMessage('Unable to save schedule.', 'error');
  } finally {
    updateScheduleButtonState();
  }
}

function showScheduleMessage(text, type = '') {
  if (!scheduleMessageEl) {
    return;
  }

  scheduleMessageEl.textContent = text;
  scheduleMessageEl.className = `schedule-message ${type}`;
}

async function loadPatchData(force = false) {
  if (patchStatusEl) {
    patchStatusEl.textContent = force ? 'Refreshing patch data...' : 'Loading patch data...';
  }

  try {
    const response = await authFetch('/patches', { cache: force ? 'no-store' : 'default' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    activePatches = Array.isArray(payload.patches) ? payload.patches : [];
    renderPatchSummary(payload.summary);
    renderPatchList();
    populatePatchSelect();
    populateCategorySelect();
    if (patchStatusEl) {
      patchStatusEl.textContent = activePatches.length === 0
        ? 'All systems are up to date.'
        : `Showing ${activePatches.length} pending patch${activePatches.length === 1 ? '' : 'es'}.`;
    }
  } catch (error) {
    console.error('Failed to load patches', error);
    if (patchStatusEl) {
      patchStatusEl.textContent = 'Failed to load patch data.';
    }
    if (patchListEl) {
      patchListEl.innerHTML = '<div class="empty">Unable to display patches.</div>';
    }
  }
}

async function loadSchedules() {
  try {
    const response = await authFetch('/patches/schedules', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    activeSchedules = Array.isArray(payload.schedules) ? payload.schedules : [];
    renderScheduleTable();
  } catch (error) {
    console.error('Failed to load schedules', error);
    activeSchedules = [];
    renderScheduleTable();
  }
}

async function loadHistory(force = false) {
  if (!historyList) {
    return;
  }

  try {
    const response = await authFetch('/patches/history', { cache: force ? 'no-store' : 'default' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    historyEntries = Array.isArray(payload.history) ? payload.history : [];
    renderHistory(historyEntries);
  } catch (error) {
    console.error('Failed to load history', error);
    historyEntries = [];
    renderHistory([]);
  }
}

function renderHistory(entries = []) {
  if (!historyList) {
    return;
  }

  if (!entries.length) {
    historyList.innerHTML = '<div class="empty">Nothing logged yet.</div>';
    return;
  }

  historyList.innerHTML = '';
  entries.forEach((entry) => {
    const container = document.createElement('div');
    container.className = 'history-entry';

    const title = document.createElement('strong');
    const patchIds = Array.isArray(entry.patchIds) ? entry.patchIds.join(', ') : '';
    if (entry.type === 'dispatch') {
      title.textContent = `Dispatched ${patchIds || 'patches'} to ${entry.agentId}`;
    } else if (entry.type === 'result') {
      title.textContent = `${entry.success ? 'Success' : 'Failure'} (${entry.agentId})`;
    } else if (entry.type === 'schedule-deleted') {
      title.textContent = `Schedule ${entry.scheduleId} deleted`;
    } else {
      title.textContent = entry.type ?? 'Log';
    }

    const detail = document.createElement('p');
    detail.className = 'history-meta';
    detail.textContent = `${new Date(entry.timestamp).toLocaleString()} · ${entry.scheduleName ?? entry.scheduleId ?? ''}`;

    const extras = document.createElement('span');
    extras.className = 'history-meta';
    if (entry.type === 'result') {
      extras.textContent = entry.message ?? '';
    } else if (entry.type === 'dispatch') {
      extras.textContent = `Schedule ${entry.scheduleId}`;
    } else {
      extras.textContent = '';
    }

    container.appendChild(title);
    container.appendChild(detail);
    if (extras.textContent) {
      container.appendChild(extras);
    }
    historyList.appendChild(container);
  });
}

function renderScheduleTable() {
  if (!scheduleTableBody) {
    return;
  }

  if (!activeSchedules.length) {
    scheduleTableBody.innerHTML = '';
    if (scheduleEmpty) {
      scheduleEmpty.style.display = '';
    }
    if (scheduleTable) {
      scheduleTable.style.display = 'none';
    }
    return;
  }

  if (scheduleTable) {
    scheduleTable.style.display = '';
  }
  if (scheduleEmpty) {
    scheduleEmpty.style.display = 'none';
  }

  scheduleTableBody.innerHTML = '';
  activeSchedules.forEach((schedule) => {
    const row = document.createElement('tr');
    const patchesCell = document.createElement('td');
    patchesCell.textContent = schedule.patchIds.join(', ');

    const targetsCell = document.createElement('td');
    if (schedule.dynamic) {
      targetsCell.textContent = schedule.category
        ? `Category: ${schedule.category}`
        : 'Dynamic category schedule';
    } else {
      targetsCell.textContent = schedule.agentIds.join(', ') || 'None';
    }

    const nextRunCell = document.createElement('td');
    nextRunCell.textContent = schedule.nextRun
      ? new Date(schedule.nextRun).toLocaleString()
      : 'Pending';

    const repeatCell = document.createElement('td');
    repeatCell.textContent = schedule.repeatMs ? `${schedule.repeatMs / 1000}s` : 'One-time';

    const pendingCell = document.createElement('td');
    pendingCell.textContent = schedule.pendingAgents.length ? schedule.pendingAgents.join(', ') : 'None';

    row.appendChild(createTextCell(schedule.name));
    row.appendChild(patchesCell);
    row.appendChild(targetsCell);
    row.appendChild(nextRunCell);
    row.appendChild(repeatCell);
    row.appendChild(pendingCell);
    const actionCell = document.createElement('td');
    const deleteButton = document.createElement('button');
    deleteButton.type = 'button';
    deleteButton.className = 'secondary';
    deleteButton.textContent = 'Delete';
    deleteButton.addEventListener('click', () => deleteSchedule(schedule.id));
    actionCell.appendChild(deleteButton);
    row.appendChild(actionCell);
    scheduleTableBody.appendChild(row);
  });
}

function createTextCell(content) {
  const cell = document.createElement('td');
  cell.textContent = content;
  return cell;
}

async function deleteSchedule(scheduleId) {
  if (!scheduleId) {
    return;
  }

  if (!confirm('Delete this schedule? This cannot be undone.')) {
    return;
  }

  try {
    const response = await authFetch(`/patches/schedules/${scheduleId}`, { method: 'DELETE' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    loadSchedules();
    loadHistory(true);
  } catch (error) {
    console.error('Failed to delete schedule', error);
    showScheduleMessage('Unable to delete schedule.', 'error');
  }
}

function initializeScheduleForm() {
  if (runAtInput) {
    runAtInput.value = isoDateForInput(new Date(Date.now() + 5 * 60_000));
  }

    patchSelect?.addEventListener('change', () => {
      categorySelect?.selectedIndex && (categorySelect.selectedIndex = 0);
      updateScheduleAgents();
    });
    categorySelect?.addEventListener('change', () => {
      if (patchSelect) {
        patchSelect.selectedIndex = 0;
      }
      updateScheduleAgents();
    });
  scheduleForm?.addEventListener('submit', handleScheduleSubmit);
  refreshPatchesButton?.addEventListener('click', () => loadPatchData(true));
  refreshSchedulesButton?.addEventListener('click', () => {
    loadSchedules();
    loadHistory(true);
  });
  tabButtons.forEach((button) => {
    button.addEventListener('click', () => {
      const tabId = button.getAttribute('data-tab-button');
      if (tabId) {
        setActiveTab(tabId);
      }
    });
  });
  setActiveTab('approval');
}

function initialize() {
  initializeScheduleForm();
  loadPatchData();
  loadSchedules();
  loadHistory();
  setInterval(() => loadPatchData(true), 30_000);
  setInterval(() => loadHistory(true), 30_000);
}

initialize();
