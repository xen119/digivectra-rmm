const authFetch = (input, init = {}) => fetch(input, { credentials: 'same-origin', ...init });

const statusEl = document.getElementById('gpoStatus');
const profilesContainer = document.getElementById('gpoProfiles');
const addProfileBtn = document.getElementById('addGpoProfile');
const reloadBtn = document.getElementById('reloadGpo');
const saveBtn = document.getElementById('saveGpo');
const exportBtn = document.getElementById('exportGpo');
const importInput = document.getElementById('importGpo');
const agentSelect = document.getElementById('gpoAgentSelect');
const profileSelect = document.getElementById('gpoProfileSelect');
const assignBtn = document.getElementById('assignGpo');
const runBtn = document.getElementById('runGpo');
const assignmentList = document.getElementById('gpoAssignmentList');

let gpoConfig = { defaultProfileId: null, profiles: [], assignments: {} };
let gpoAssignments = {};
let gpoAgents = [];

document.addEventListener('DOMContentLoaded', init);

async function init() {
  addProfileBtn?.addEventListener('click', handleAddProfile);
  reloadBtn?.addEventListener('click', loadGpoProfiles);
  saveBtn?.addEventListener('click', saveGpoProfiles);
  exportBtn?.addEventListener('click', exportGpo);
  importInput?.addEventListener('change', handleImport);
  assignBtn?.addEventListener('click', handleAssign);
  runBtn?.addEventListener('click', handleRun);
  await Promise.all([loadAgents(), loadGpoProfiles()]);
}

async function loadGpoProfiles() {
  setStatus('Loading GPO profiles...');
  try {
    const response = await authFetch('/gpo/profiles', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    gpoConfig = await response.json();
    gpoAssignments = gpoConfig.assignments ?? {};
    renderProfiles();
    renderAssignments();
    populateProfileSelect();
    setStatus('GPO profiles loaded.', 'success');
  } catch (error) {
    console.error(error);
    setStatus('Failed to load GPO profiles.', 'error');
  }
}

async function loadAgents() {
  try {
    const response = await authFetch('/clients', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    gpoAgents = Array.isArray(data) ? data : [];
    populateAgentSelect();
  } catch (error) {
    console.error('Failed to load agents', error);
  }
}

function renderProfiles() {
  if (!profilesContainer) {
    return;
  }

  profilesContainer.innerHTML = '';
  const profiles = Array.isArray(gpoConfig.profiles) ? gpoConfig.profiles : [];
  profiles.forEach((profile) => {
    const card = document.createElement('article');
    card.className = 'profile-card';
    card.dataset.profileId = profile.id;

    const header = document.createElement('header');
    const title = document.createElement('h3');
    title.textContent = `${profile.label ?? profile.id}`;
    header.appendChild(title);
    const defaultBadge = document.createElement('button');
    defaultBadge.type = 'button';
    defaultBadge.textContent = gpoConfig.defaultProfileId === profile.id ? 'Default' : 'Set default';
    defaultBadge.addEventListener('click', () => {
      gpoConfig.defaultProfileId = profile.id;
      renderProfiles();
    });
    header.appendChild(defaultBadge);
    card.appendChild(header);

    const idLabel = document.createElement('label');
    idLabel.textContent = 'Profile ID';
    const idInput = document.createElement('input');
    idInput.value = profile.id ?? '';
    idInput.dataset.key = 'id';
    idLabel.appendChild(idInput);
    card.appendChild(idLabel);

    const labelLabel = document.createElement('label');
    labelLabel.textContent = 'Label';
    const labelInput = document.createElement('input');
    labelInput.value = profile.label ?? '';
    labelInput.dataset.key = 'label';
    labelLabel.appendChild(labelInput);
    card.appendChild(labelLabel);

    const descLabel = document.createElement('label');
    descLabel.textContent = 'Description';
    const descInput = document.createElement('input');
    descInput.value = profile.description ?? '';
    descInput.dataset.key = 'description';
    descLabel.appendChild(descInput);
    card.appendChild(descLabel);

    const templateLabel = document.createElement('label');
    templateLabel.textContent = 'INF template';
    const templateInput = document.createElement('textarea');
    templateInput.value = profile.template ?? '';
    templateInput.dataset.key = 'template';
    templateLabel.appendChild(templateInput);
    card.appendChild(templateLabel);

    const removeButton = document.createElement('button');
    removeButton.type = 'button';
    removeButton.textContent = 'Remove profile';
    removeButton.addEventListener('click', () => {
      gpoConfig.profiles = profiles.filter((entry) => entry.id !== profile.id);
      if (gpoConfig.defaultProfileId === profile.id) {
        gpoConfig.defaultProfileId = gpoConfig.profiles[0]?.id ?? null;
      }
      renderProfiles();
      populateProfileSelect();
    });
    card.appendChild(removeButton);

    profilesContainer.appendChild(card);
  });

  if (!profiles.length) {
    const info = document.createElement('p');
    info.textContent = 'No GPO profiles defined yet. Use the button below to add one.';
    profilesContainer.appendChild(info);
  }
}

function handleAddProfile() {
  const nextId = `gpo-${Date.now()}`;
  gpoConfig.profiles = [
    ...(Array.isArray(gpoConfig.profiles) ? gpoConfig.profiles : []),
    { id: nextId, label: `New profile ${nextId}`, description: '', template: '' },
  ];
  renderProfiles();
  populateProfileSelect();
}

function collectProfiles() {
  if (!profilesContainer) {
    return [];
  }
  const cards = profilesContainer.querySelectorAll('.profile-card');
  const collected = [];
  cards.forEach((card) => {
    const inputs = card.querySelectorAll('input, textarea');
    const entry = { id: '', label: '', description: '', template: '' };
    inputs.forEach((input) => {
      const key = input.dataset.key;
      if (!key) {
        return;
      }
      entry[key] = input.value;
    });
    if (entry.id) {
      collected.push(entry);
    }
  });
  return collected;
}

async function saveGpoProfiles() {
  const profiles = collectProfiles();
  if (!profiles.length) {
    setStatus('Add at least one profile before saving.', 'error');
    return;
  }

  const payload = {
    defaultProfileId: gpoConfig.defaultProfileId ?? profiles[0]?.id,
    profiles,
  };

  try {
    const response = await authFetch('/gpo/profiles', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(text || `HTTP ${response.status}`);
    }
    setStatus('GPO profiles saved.', 'success');
    await loadGpoProfiles();
  } catch (error) {
    console.error(error);
    setStatus('Failed to save GPO profiles.', 'error');
  }
}

function populateProfileSelect() {
  if (!profileSelect) {
    return;
  }
  profileSelect.innerHTML = '<option value="">Choose profile</option>';
  (Array.isArray(gpoConfig.profiles) ? gpoConfig.profiles : []).forEach((profile) => {
    const option = document.createElement('option');
    option.value = profile.id;
    option.textContent = profile.label ?? profile.id;
    profileSelect.appendChild(option);
  });
}

function populateAgentSelect() {
  if (!agentSelect) {
    return;
  }
  agentSelect.innerHTML = '<option value="">Select agent</option>';
  gpoAgents.forEach((agent) => {
    const option = document.createElement('option');
    option.value = agent.id;
    option.textContent = agent.name ? `${agent.name} (${agent.id})` : agent.id;
    agentSelect.appendChild(option);
  });
}

function renderAssignments() {
  if (!assignmentList) {
    return;
  }
  const assignments = gpoAssignments ?? {};
  const rows = Object.entries(assignments);
  assignmentList.innerHTML = '';
  if (!rows.length) {
    assignmentList.textContent = 'No assignments yet.';
    return;
  }
  rows.forEach(([agentId, profileId]) => {
    const profile = (gpoConfig.profiles ?? []).find((entry) => entry.id === profileId);
    const label = profile?.label ?? profileId;
    const row = document.createElement('div');
    row.textContent = `${agentId}: ${label}`;
    assignmentList.appendChild(row);
  });
}

async function handleAssign() {
  const agentId = agentSelect?.value?.trim() || null;
  const profileId = profileSelect?.value?.trim() || null;
  if (!agentId || !profileId) {
    setStatus('Select both an agent and a profile.', 'error');
    return;
  }
  try {
    const response = await authFetch('/gpo/assignments', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agentId, profileId }),
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(text || `HTTP ${response.status}`);
    }
    gpoAssignments[agentId] = profileId;
    renderAssignments();
    setStatus('Assignment saved. GPO definitions will be pushed to the agent.', 'success');
  } catch (error) {
    console.error(error);
    setStatus('Failed to set assignment.', 'error');
  }
}

async function handleRun() {
  const agentId = agentSelect?.value?.trim() || null;
  if (!agentId) {
    setStatus('Select an agent to apply the GPO.', 'error');
    return;
  }
  try {
    const response = await authFetch('/gpo/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agentId }),
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(text || `HTTP ${response.status}`);
    }
    setStatus('GPO apply request sent.', 'success');
  } catch (error) {
    console.error(error);
    setStatus('Failed to trigger apply.', 'error');
  }
}

function exportGpo() {
  const blob = new Blob([JSON.stringify(gpoConfig, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'gpo-policies.json';
  anchor.click();
  URL.revokeObjectURL(url);
  setStatus('JSON exported.', 'success');
}

function handleImport(event) {
  const file = event.target?.files?.[0];
  if (!file) {
    return;
  }
  const reader = new FileReader();
  reader.onload = (loadEvent) => {
    try {
      const parsed = JSON.parse(loadEvent.target?.result ?? '{}');
      gpoConfig = {
        defaultProfileId: parsed.defaultProfileId ?? null,
        profiles: Array.isArray(parsed.profiles) ? parsed.profiles : [],
        assignments: parsed.assignments ?? {},
      };
      gpoAssignments = gpoConfig.assignments ?? {};
      renderProfiles();
      renderAssignments();
      populateProfileSelect();
      setStatus('JSON imported. Save to persist.', 'success');
    } catch (error) {
      console.error(error);
      setStatus('Invalid JSON file.', 'error');
    }
  };
  reader.readAsText(file);
  if (importInput) {
    importInput.value = '';
  }
}

function setStatus(message, variant = 'info') {
  if (!statusEl) {
    return;
  }
  statusEl.textContent = message;
  statusEl.classList.remove('success', 'error');
  if (variant === 'success') {
    statusEl.classList.add('success');
  } else if (variant === 'error') {
    statusEl.classList.add('error');
  }
}
