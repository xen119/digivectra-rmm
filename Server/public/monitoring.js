const authFetch = (input, init = {}) => fetch(input, { credentials: 'same-origin', ...init });

const statusMessage = document.getElementById('statusMessage');
const monitoringProfilesList = document.getElementById('monitoringProfilesList');
const alertProfilesList = document.getElementById('alertProfilesList');
const profileAlertSelect = document.getElementById('profileAlertSelect');
const remediationScriptSelect = document.getElementById('remediationScriptSelect');
const assignmentProfileSelect = document.getElementById('assignmentProfileSelect');
const assignmentForm = document.getElementById('assignmentForm');
const assignmentTargetType = document.getElementById('assignmentTargetType');
const assignmentAgentSelect = document.getElementById('assignmentAgentSelect');
const assignmentGroupSelect = document.getElementById('assignmentGroupSelect');
const agentTargetLabel = document.getElementById('agentTargetLabel');
const groupTargetLabel = document.getElementById('groupTargetLabel');
const eventLog = document.getElementById('eventLog');

let monitoringProfiles = [];
let alertProfiles = [];
let remediationScripts = [];
let targetAgents = [];
let targetGroups = [];

document.addEventListener('DOMContentLoaded', init);

function init() {
  document.getElementById('alertProfileForm')?.addEventListener('submit', handleAlertProfileSubmit);
  document.getElementById('monitoringProfileForm')?.addEventListener('submit', handleMonitoringProfileSubmit);
  assignmentForm?.addEventListener('submit', handleAssignment);
  assignmentTargetType?.addEventListener('change', handleTargetTypeChange);
  handleTargetTypeChange();
  refreshAll();
  startEventStream();
}

async function refreshAll() {
  await Promise.all([
    loadAlertProfiles(),
    loadMonitoringProfiles(),
    loadRemediationScripts(),
    loadAssignmentTargets(),
    loadMonitoringHistory(),
  ]);
}

async function loadAlertProfiles() {
  try {
    const response = await authFetch('/alert-profiles', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error('Failed to load alert profiles');
    }

    alertProfiles = await response.json();
    renderAlertProfiles();
    populateAlertSelects();
    statusMessage.textContent = 'Configuration loaded.';
  } catch (error) {
    statusMessage.textContent = `Alert profile load failed: ${error.message}`;
  }
}

function renderAlertProfiles() {
  if (!alertProfilesList) return;
  if (alertProfiles.length === 0) {
    alertProfilesList.innerHTML = '<div class="list-item">No alert profiles yet.</div>';
    return;
  }

  alertProfilesList.innerHTML = '';
  alertProfiles.forEach((profile) => {
    const item = document.createElement('div');
    item.className = 'list-item';
    item.innerHTML = `<strong>${profile.name}</strong>
      <div class="badge">${profile.dashboard ? 'Dashboard' : 'No dashboard'}</div>
      <div>Emails: ${profile.emails?.length > 0 ? profile.emails.join(', ') : 'none'}</div>
      <div>Remediation: ${profile.remediationScript ?? 'none'}</div>`;
    alertProfilesList.appendChild(item);
  });
}

async function loadMonitoringProfiles() {
  try {
    const response = await authFetch('/monitoring/profiles', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error('Failed to load monitoring profiles');
    }

    monitoringProfiles = await response.json();
    renderMonitoringProfiles();
    populateProfileSelects();
    statusMessage.textContent = 'Monitoring profiles ready.';
  } catch (error) {
    statusMessage.textContent = `Monitoring profile load failed: ${error.message}`;
  }
}

function renderMonitoringProfiles() {
  if (!monitoringProfilesList) {
    return;
  }

  if (monitoringProfiles.length === 0) {
    monitoringProfilesList.innerHTML = '<div class="list-item">No monitoring profiles yet.</div>';
    return;
  }

  monitoringProfilesList.innerHTML = '';
  monitoringProfiles.forEach((profile) => {
    const rules = profile.rules?.map((rule) => `${rule.metric.toUpperCase()} ≥ ${rule.threshold} (window ${rule.windowSeconds || 30}s)`);
    const assignments = [
      profile.assignedAgents?.length ? `Agents: ${profile.assignedAgents.join(', ')}` : null,
      profile.assignedGroups?.length ? `Groups: ${profile.assignedGroups.join(', ')}` : null,
    ].filter(Boolean);

    const item = document.createElement('div');
    item.className = 'list-item';
    item.innerHTML = `<strong>${profile.name}</strong>
      <div>${profile.description ?? 'No description'}</div>
      <div>Rules: ${rules?.join(' | ') ?? 'none'}</div>
      <div>Alert: ${profile.alertProfileId ?? 'none'}</div>
      <div>${assignments.length ? assignments.join(' | ') : 'Not assigned'}</div>`;
    monitoringProfilesList.appendChild(item);
  });
}

async function loadRemediationScripts() {
  try {
    const response = await authFetch('/remediation/scripts', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error('Failed to load remediation scripts');
    }

    remediationScripts = await response.json();
    renderScriptOptions();
  } catch (error) {
    console.warn('Remediation scripts load failed', error);
  }
}

function renderScriptOptions() {
  if (remediationScriptSelect) {
    remediationScriptSelect.innerHTML = '<option value="">— none —</option>';
    remediationScripts.forEach((entry) => {
      const option = document.createElement('option');
      option.value = entry.name;
      option.textContent = `${entry.name} (${entry.language})`;
      remediationScriptSelect.appendChild(option);
    });
  }
}

function populateAlertSelects() {
  [profileAlertSelect].forEach((select) => {
    if (!select) return;
    select.innerHTML = '<option value="">— choose alert profile —</option>';
    alertProfiles.forEach((profile) => {
      const option = document.createElement('option');
      option.value = profile.id;
      option.textContent = profile.name;
      select.appendChild(option);
    });
  });
}

function populateProfileSelects() {
  if (!assignmentProfileSelect) {
    return;
  }

  assignmentProfileSelect.innerHTML = '';
  monitoringProfiles.forEach((profile) => {
    const option = document.createElement('option');
    option.value = profile.id;
    option.textContent = profile.name;
    assignmentProfileSelect.appendChild(option);
  });
}

async function loadAssignmentTargets() {
  await Promise.all([loadAgentTargets(), loadGroupTargets()]);
}

async function loadAgentTargets() {
  if (!assignmentAgentSelect) {
    targetAgents = [];
    return;
  }

  try {
    const response = await authFetch('/clients', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const agents = await response.json();
    targetAgents = Array.isArray(agents) ? agents : [];
    populateAgentSelect();
  } catch (error) {
    console.warn('Failed to load assignment agents', error);
    assignmentAgentSelect.innerHTML = '<option value="">Unable to load agents</option>';
  }
}

async function loadGroupTargets() {
  if (!assignmentGroupSelect) {
    targetGroups = [];
    return;
  }

  try {
    const response = await authFetch('/groups', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    targetGroups = Array.isArray(payload?.groups) ? payload.groups : [];
    populateGroupSelect();
  } catch (error) {
    console.warn('Failed to load assignment groups', error);
    assignmentGroupSelect.innerHTML = '<option value="">Unable to load groups</option>';
  }
}

function populateAgentSelect() {
  if (!assignmentAgentSelect) {
    return;
  }

  assignmentAgentSelect.innerHTML = '<option value="">Select an agent</option>';
  targetAgents
    .slice()
    .sort((a, b) => (a?.name ?? '').localeCompare(b?.name ?? ''))
    .forEach((agent) => {
      const option = document.createElement('option');
      option.value = agent.id;
      const label = agent.name ? `${agent.name} (${agent.id})` : agent.id;
      const status = agent.status === 'online' ? ' • online' : '';
      option.textContent = `${label}${status}`;
      assignmentAgentSelect.appendChild(option);
    });
}

function populateGroupSelect() {
  if (!assignmentGroupSelect) {
    return;
  }

  assignmentGroupSelect.innerHTML = '<option value="">Select a group</option>';
  targetGroups
    .slice()
    .sort((a, b) => (a ?? '').localeCompare(b ?? ''))
    .forEach((group) => {
      const option = document.createElement('option');
      option.value = group;
      option.textContent = group;
      assignmentGroupSelect.appendChild(option);
    });
}

function handleTargetTypeChange() {
  const type = assignmentTargetType?.value ?? 'agent';
  if (agentTargetLabel) {
    agentTargetLabel.style.display = type === 'agent' ? '' : 'none';
  }
  if (groupTargetLabel) {
    groupTargetLabel.style.display = type === 'group' ? '' : 'none';
  }
  if (assignmentAgentSelect) {
    assignmentAgentSelect.disabled = type !== 'agent';
  }
  if (assignmentGroupSelect) {
    assignmentGroupSelect.disabled = type !== 'group';
  }
}

async function loadMonitoringHistory() {
  if (!eventLog) {
    return;
  }

  try {
    const response = await authFetch('/monitoring/events/history', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error('Failed to load history');
    }

    const history = await response.json();
    if (!Array.isArray(history)) {
      return;
    }

    eventLog.innerHTML = '';
    const entries = history.slice(-40);
    entries.forEach((entry) => {
      appendEvent(entry.eventName, entry.payload, { prepend: false });
    });
  } catch (error) {
    console.warn('Monitoring history load failed', error);
  }
}

async function handleAlertProfileSubmit(event) {
  event.preventDefault();
  const name = document.getElementById('alertName')?.value.trim();
  const emailValue = document.getElementById('alertEmails')?.value ?? '';
  const useDashboard = document.getElementById('alertDashboard')?.value === 'true';
  const scriptName = remediationScriptSelect?.value || null;

  if (!name) {
    statusMessage.textContent = 'Alert profile name is required.';
    return;
  }

  const payload = {
    name,
    emails: emailValue.split(',').map((email) => email.trim()).filter(Boolean),
    dashboard: useDashboard,
    remediationScript: scriptName,
  };

  try {
    const response = await authFetch('/alert-profiles', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    statusMessage.textContent = 'Alert profile created.';
    document.getElementById('alertProfileForm').reset();
    await refreshAll();
  } catch (error) {
    statusMessage.textContent = `Failed to create alert profile: ${error.message}`;
  }
}

async function handleMonitoringProfileSubmit(event) {
  event.preventDefault();
  const name = document.getElementById('profileName')?.value.trim();
  const metric = document.getElementById('metricSelect')?.value;
  const threshold = parseFloat(document.getElementById('threshold')?.value ?? '');
  const windowSeconds = parseInt(document.getElementById('windowSeconds')?.value ?? '30', 10);
  const description = document.getElementById('profileDescription')?.value.trim() || '';
  const alertId = profileAlertSelect?.value || null;

  if (!name || !metric || Number.isNaN(threshold)) {
    statusMessage.textContent = 'Fill out the monitoring profile form completely.';
    return;
  }

  const payload = {
    name,
    description,
    alertProfileId: alertId,
    rules: [
      {
        metric,
        threshold,
        windowSeconds,
      },
    ],
  };

  try {
    const response = await authFetch('/monitoring/profiles', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    statusMessage.textContent = 'Monitoring profile added.';
    document.getElementById('monitoringProfileForm').reset();
    await refreshAll();
  } catch (error) {
    statusMessage.textContent = `Failed to create monitoring profile: ${error.message}`;
  }
}

async function handleAssignment(event) {
  event.preventDefault();
  const profileId = assignmentProfileSelect?.value;
  const targetType = assignmentTargetType?.value ?? 'agent';
  const targetId = targetType === 'group'
    ? assignmentGroupSelect?.value?.trim()
    : assignmentAgentSelect?.value?.trim();

  if (!profileId || !targetType || !targetId) {
    statusMessage.textContent = 'Select a profile and specify a target.';
    return;
  }

  try {
    const response = await authFetch(`/monitoring/profiles/${encodeURIComponent(profileId)}/assign`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetType, targetId }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    statusMessage.textContent = 'Profile assignment saved.';
    assignmentForm?.reset();
    handleTargetTypeChange();
    await loadMonitoringProfiles();
  } catch (error) {
    statusMessage.textContent = `Assignment failed: ${error.message}`;
  }
}

function startEventStream() {
  const source = new EventSource('/monitoring/events');
  source.addEventListener('alert', (event) => appendEvent('Alert', JSON.parse(event.data)));
  source.addEventListener('remediation-result', (event) => appendEvent('Remediation', JSON.parse(event.data)));
  source.addEventListener('remediation-request', (event) =>
    appendEvent('Remediation requested', JSON.parse(event.data))
  );
  source.addEventListener('monitoring-state', (event) => appendEvent('monitoring-state', JSON.parse(event.data)));
  source.onerror = (error) => {
    console.error('Monitoring SSE error', error);
    source.close();
    setTimeout(startEventStream, 5000);
  };
}

function appendEvent(label, payload, options = {}) {
  if (!eventLog) {
    return;
  }

  const entry = document.createElement('div');
  entry.className = 'event';
  const entryLabel = formatEventLabel(label);
  const valueText = formatEventValue(payload);
  entry.innerHTML = `<span class="badge">${entryLabel}</span>
    <div>${payload.agentName} (${payload.agentId})</div>
    <div>${valueText}</div>
    <div>${new Date(payload.timestamp).toLocaleString()}</div>`;

  const prepend = options.prepend !== false;
  if (prepend) {
    eventLog.prepend(entry);
  } else {
    eventLog.append(entry);
  }
  while (eventLog.childNodes.length > 40) {
    eventLog.removeChild(eventLog.lastChild);
  }
}

function formatEventLabel(label) {
  if (!label) {
    return 'Event';
  }

  const map = {
    'monitoring-state': 'Monitoring state',
    'remediation-result': 'Remediation result',
    'remediation-request': 'Remediation request',
  };

  if (map[label]) {
    return map[label];
  }

  return label.replace(/[-_]/g, ' ').replace(/\b\w/g, (match) => match.toUpperCase());
}

function formatEventValue(payload) {
  if (!payload) {
    return 'Event data unavailable';
  }

  if (payload.status) {
    return `State: ${capitalize(payload.status)}`;
  }

  if (Array.isArray(payload.metrics) && payload.metrics.length > 0) {
    return `Metrics: ${payload.metrics.join(', ')}`;
  }

  if (typeof payload.value === 'number') {
    const metric = payload.metric?.toUpperCase() ?? 'Metric';
    return `${metric} reached ${payload.value.toFixed(1)}`;
  }

  if (payload.scriptName) {
    return `Script ${payload.scriptName}`;
  }

  if (payload.message) {
    return payload.message;
  }

  if (payload.metric) {
    return payload.metric;
  }

  return 'Event';
}

function capitalize(value) {
  if (!value) {
    return '';
  }

  return `${value.charAt(0).toUpperCase()}${value.slice(1)}`;
}
