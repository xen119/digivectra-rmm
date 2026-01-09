const fetchWithCredentials = (input, init = {}) => fetch(input, { credentials: 'same-origin', ...init });
const form = document.getElementById('scheduleForm');
const targetsSelect = document.getElementById('scheduleTargets');
const scriptSelect = document.getElementById('scheduleScriptSelect');
const table = document.getElementById('scheduleTable');
const tableBody = table?.querySelector('tbody');
const emptyState = document.getElementById('scheduleEmpty');

let schedules = [];

async function loadResources() {
  await Promise.all([populateTargets(), populateScripts()]);
}

async function populateTargets() {
  if (!targetsSelect) {
    return;
  }

  targetsSelect.innerHTML = '';
  try {
    const [agentsRes, groupsRes] = await Promise.all([
      fetchWithCredentials('/clients', { cache: 'no-store' }),
      fetchWithCredentials('/groups', { cache: 'no-store' }),
    ]);

    const agents = agentsRes.ok ? await agentsRes.json() : [];
    const groups = groupsRes.ok ? (await groupsRes.json()).groups ?? [] : [];

    if (agents.length === 0 && groups.length === 0) {
      const option = document.createElement('option');
      option.disabled = true;
      option.textContent = 'No targets available';
      targetsSelect.appendChild(option);
      return;
    }

    if (agents.length > 0) {
      const header = document.createElement('optgroup');
      header.label = 'Agents';
      agents
        .slice()
        .sort((a, b) => ((a.name ?? '').localeCompare(b.name ?? '')))
        .forEach((agent) => {
          const option = document.createElement('option');
          option.value = `agent:${agent.id}`;
          option.dataset.type = 'agent';
          option.textContent = `${agent.name ?? agent.id} (${agent.status ?? 'unknown'})`;
          header.appendChild(option);
        });
      targetsSelect.appendChild(header);
    }

    if (groups.length > 0) {
      const header = document.createElement('optgroup');
      header.label = 'Groups';
      groups
        .slice()
        .sort()
        .forEach((group) => {
          const option = document.createElement('option');
          option.value = `group:${group}`;
          option.dataset.type = 'group';
          option.textContent = `Group: ${group}`;
          header.appendChild(option);
        });
      targetsSelect.appendChild(header);
    }
  } catch (error) {
    targetsSelect.innerHTML = '<option disabled>Unable to load targets</option>';
    console.warn('Scheduler targets load failed', error);
  }
}

async function populateScripts() {
  if (!scriptSelect) {
    return;
  }

  scriptSelect.innerHTML = '<option value="">Loading scripts…</option>';
  try {
    const response = await fetchWithCredentials('/scripts', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const scripts = await response.json();
    scriptSelect.innerHTML = '<option value="">Select a script or patch</option>';
    scripts.forEach((script) => {
      const option = document.createElement('option');
      option.value = script.name;
      option.textContent = `${script.name} (${script.language ?? 'unknown'})`;
      scriptSelect.appendChild(option);
    });
  } catch (error) {
    scriptSelect.innerHTML = '<option value="">Unable to load scripts</option>';
    console.warn('Scheduler script list failed', error);
  }
}

function loadSchedules() {
  try {
    const stored = localStorage.getItem('rmm-schedules');
    schedules = stored ? JSON.parse(stored) : [];
  } catch {
    schedules = [];
  }
  renderSchedules();
}

function saveSchedules() {
  localStorage.setItem('rmm-schedules', JSON.stringify(schedules));
}

function renderSchedules() {
  if (!table || !tableBody || !emptyState) {
    return;
  }

  if (schedules.length === 0) {
    table.style.display = 'none';
    emptyState.style.display = '';
    return;
  }

  table.style.display = '';
  emptyState.style.display = 'none';
  tableBody.innerHTML = '';

  schedules.forEach((schedule) => {
    const row = document.createElement('tr');
    const targetBadges = schedule.targets
      .map((target) => `<span class="badge">${target.label}</span>`)
      .join('');
    row.innerHTML = `
      <td>${schedule.name}</td>
      <td>${targetBadges}</td>
      <td>${schedule.interval} ${schedule.intervalUnit}</td>
      <td>${schedule.script}</td>
      <td>${schedule.notes ?? '—'}</td>
    `;
    tableBody.appendChild(row);
  });
}

function parseSelectedTargets() {
  if (!targetsSelect) {
    return [];
  }

  return Array.from(targetsSelect.selectedOptions).map((option) => ({
    type: option.dataset.type || 'agent',
    id: option.value,
    label: option.textContent?.trim() || option.value,
  }));
}

form?.addEventListener('submit', (event) => {
  event.preventDefault();
  const name = document.getElementById('scheduleName')?.value?.trim();
  const targets = parseSelectedTargets();
  const interval = parseInt(document.getElementById('scheduleInterval')?.value ?? '0', 10);
  const intervalUnit = document.getElementById('scheduleIntervalUnit')?.value ?? 'minutes';
  const script = document.getElementById('scheduleScriptSelect')?.value;
  const notes = document.getElementById('scheduleNotes')?.value?.trim();

  if (!name || targets.length === 0 || !script || Number.isNaN(interval) || interval <= 0) {
    alert('Please complete the schedule form.');
    return;
  }

  schedules.push({
    id: crypto.randomUUID(),
    name,
    targets,
    interval,
    intervalUnit,
    script,
    notes,
    createdAt: new Date().toISOString(),
  });
  saveSchedules();
  renderSchedules();
  form.reset();
});

loadResources().then(loadSchedules);
