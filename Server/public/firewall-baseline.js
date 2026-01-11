const authFetch = (input, init = {}) => fetch(input, { credentials: 'same-origin', ...init });

const baselineList = document.getElementById('baselineList');
const createForm = document.getElementById('createForm');
const profileNameInput = document.getElementById('profileName');
const profileDescriptionInput = document.getElementById('profileDescription');
const profileRulesInput = document.getElementById('profileRules');
const ruleAgentSelect = document.getElementById('ruleAgent');
const ruleLibraryContainer = document.getElementById('ruleLibrary');
let ruleLibrary = [];

window.addEventListener('DOMContentLoaded', () => {
  loadBaselines();
  loadAgents();
});

window.addEventListener('DOMContentLoaded', () => {
  loadBaselines();
});

createForm?.addEventListener('submit', (event) => {
  event.preventDefault();
  createProfile();
});

async function loadAgents() {
  if (!ruleAgentSelect) {
    return;
  }

  try {
    const response = await authFetch('/clients');
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    const onlineStates = new Set(['online', 'connected']);
    const onlineAgents = Array.isArray(payload) ? payload.filter((agent) => onlineStates.has(agent.status)) : [];
    ruleAgentSelect.innerHTML = '<option value="">Select an online agent</option>';
    onlineAgents.forEach((agent) => {
      const option = document.createElement('option');
      option.value = agent.id;
      option.textContent = agent.name ?? agent.id;
      ruleAgentSelect.appendChild(option);
    });
    if (onlineAgents.length && ruleAgentSelect.value === '') {
      ruleAgentSelect.value = onlineAgents[0].id;
      loadRuleLibrary(onlineAgents[0].id);
    }
  } catch (error) {
    // ignore failure; user can still type rules manually
  }
}

ruleAgentSelect?.addEventListener('change', () => {
  const agentId = ruleAgentSelect?.value;
  if (agentId) {
    loadRuleLibrary(agentId);
  } else {
    renderRuleLibrary([]);
  }
});

async function loadRuleLibrary(agentId) {
  if (!ruleLibraryContainer) {
    return;
  }

  ruleLibraryContainer.innerHTML = '<div class="placeholder">Loading rule library…</div>';
  try {
    const response = await authFetch(`/firewall/rule-library${agentId ? `?agent=${encodeURIComponent(agentId)}` : ''}`, { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    ruleLibrary = Array.isArray(payload.rules) ? payload.rules.map((rule) => ({
      ...rule,
      enabled: Boolean(rule.enabled),
    })) : [];
    renderRuleLibrary(ruleLibrary);
  } catch (error) {
    ruleLibraryContainer.innerHTML = `<div class="placeholder">Unable to load rules: ${error.message}</div>`;
  }
}

function renderRuleLibrary(rules) {
  if (!ruleLibraryContainer) {
    return;
  }

  if (!rules.length) {
    ruleLibraryContainer.innerHTML = '<div class="placeholder">No rules found for the selected agent.</div>';
    return;
  }

  ruleLibraryContainer.innerHTML = '';
  rules.forEach((rule, idx) => {
    const row = document.createElement('div');
    row.className = 'rule-entry';
    const name = document.createElement('span');
    name.textContent = rule.name;
    const toggle = document.createElement('button');
    toggle.className = 'toggle';
    toggle.type = 'button';
    toggle.innerHTML = `<span>${rule.enabled ? 'Enabled' : 'Disabled'}</span>`;
    toggle.addEventListener('click', () => {
      rule.enabled = !rule.enabled;
      toggle.innerHTML = `<span>${rule.enabled ? 'Enabled' : 'Disabled'}</span>`;
    });
    const addButton = document.createElement('button');
    addButton.type = 'button';
    addButton.innerHTML = `<span>➕</span>`;
    addButton.addEventListener('click', () => toggleRuleEntry(rule, addButton));

    row.appendChild(name);
    row.appendChild(toggle);
    row.appendChild(addButton);
    ruleLibraryContainer.appendChild(row);
  });
}

function toggleRuleEntry(rule, button) {
  if (!profileRulesInput || !rule?.name) {
    return;
  }

  const entryValue = `${rule.name}|${rule.enabled}`;
  const lines = profileRulesInput.value
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);

  const existsIndex = lines.findIndex((line) => line === entryValue);
  if (existsIndex >= 0) {
    lines.splice(existsIndex, 1);
    button.innerHTML = `<span>➕</span>`;
  } else {
    lines.push(entryValue);
    button.innerHTML = `<span>−</span>`;
  }

  profileRulesInput.value = lines.join('\n');
}

async function loadBaselines() {
  if (!baselineList) {
    return;
  }

  baselineList.innerHTML = '<div class="placeholder">Loading profiles…</div>';

  try {
    const response = await authFetch('/firewall/baseline', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    renderBaselines(Array.isArray(payload?.profiles) ? payload.profiles : []);
  } catch (error) {
    baselineList.innerHTML = `<div class="placeholder">Unable to load baselines: ${error.message}</div>`;
  }
}

function renderBaselines(profiles) {
  if (!baselineList) {
    return;
  }

  if (!profiles.length) {
    baselineList.innerHTML = '<div class="placeholder">No baseline profiles defined yet.</div>';
    return;
  }

  baselineList.innerHTML = '';
  profiles.forEach((profile) => {
    const card = document.createElement('div');
    card.className = 'baseline-card';

    const rulesCount = Array.isArray(profile.rules) ? profile.rules.length : 0;
    const assignedAgents = Array.isArray(profile.assignedAgents) ? profile.assignedAgents.length : 0;
    const assignedGroups = Array.isArray(profile.assignedGroups) ? profile.assignedGroups : [];

    card.innerHTML = `
      <div class="baseline-meta">
        <strong>${profile.name}</strong>
        <span> · ${rulesCount} rule${rulesCount === 1 ? '' : 's'} · ${assignedAgents} agent${assignedAgents === 1 ? '' : 's'} · ${assignedGroups.length} group${assignedGroups.length === 1 ? '' : 's'}</span>
      </div>
      <p class="baseline-meta">${profile.description || 'No description provided.'}</p>
      <div class="baseline-rules">
        ${(Array.isArray(profile.rules) && profile.rules.length)
          ? profile.rules.map((rule) => `<span class="rule-chip">${rule.ruleName || 'Unnamed rule'} · ${rule.enabled ? 'enable' : 'disable'}</span>`).join('')
          : '<span class="placeholder">No rules defined.</span>'}
      </div>
      <div class="assignment-row">
        <div class="text-field">
          <label>Agents (comma separated)</label>
          <input type="text" data-agents="${profile.id}" value="${(profile.assignedAgents ?? []).join(', ')}" placeholder="agent-id,..." />
        </div>
        <div class="text-field">
          <label>Groups (comma separated)</label>
          <input type="text" data-groups="${profile.id}" value="${(profile.assignedGroups ?? []).join(', ')}" placeholder="group-name,..." />
        </div>
      </div>
      <div class="actions">
        <button data-apply="${profile.id}" class="primary"><span>⚡</span>Push baseline</button>
        <button data-save="${profile.id}" class="secondary"><span>💾</span>Save assignment</button>
      </div>
    `;

    baselineList.appendChild(card);
  });

  baselineList.querySelectorAll('[data-save]').forEach((button) => {
    button.addEventListener('click', handleSaveAssignment);
  });

  baselineList.querySelectorAll('[data-apply]').forEach((button) => {
    button.addEventListener('click', handleApplyBaseline);
  });
}

async function createProfile() {
  const name = profileNameInput?.value.trim() ?? '';
  const description = profileDescriptionInput?.value.trim() ?? '';
  const rawRules = profileRulesInput?.value.split('\n') ?? [];
  const rules = rawRules.map((line) => {
    const [ruleName, enabledValue] = line.split('|').map((part) => part?.trim());
    if (!ruleName) {
      return null;
    }
    return { ruleName, enabled: enabledValue?.toLowerCase() === 'true' };
  }).filter((entry) => entry);

  if (!name) {
    alert('Profile name is required.');
    return;
  }

  const payload = { name, description, rules };
  try {
    const response = await authFetch('/firewall/baseline', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    profileNameInput.value = '';
    profileDescriptionInput.value = '';
    profileRulesInput.value = '';
    loadBaselines();
  } catch (error) {
    alert(`Unable to create baseline: ${error.message}`);
  }
}

function handleSaveAssignment(event) {
  const button = event.currentTarget;
  const profileId = button.getAttribute('data-save');
  if (!profileId) {
    return;
  }

  const agentInput = baselineList?.querySelector(`input[data-agents="${profileId}"]`);
  const groupInput = baselineList?.querySelector(`input[data-groups="${profileId}"]`);
  const agents = (agentInput?.value ?? '').split(',').map((value) => value.trim()).filter((value) => value);
  const groups = (groupInput?.value ?? '').split(',').map((value) => value.trim()).filter((value) => value);

  authFetch(`/firewall/baseline/${encodeURIComponent(profileId)}/assign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agents, groups }),
  })
    .then((response) => {
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      return response.json();
    })
    .then(() => {
      alert('Assignment updated.');
      loadBaselines();
    })
    .catch((error) => {
      alert(`Unable to save assignment: ${error.message}`);
    });
}

function handleApplyBaseline(event) {
  const button = event.currentTarget;
  const profileId = button.getAttribute('data-apply');
  if (!profileId) {
    return;
  }

  authFetch(`/firewall/baseline/${encodeURIComponent(profileId)}/apply`, {
    method: 'POST',
  })
    .then((response) => {
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      return response.json();
    })
    .then((payload) => {
      alert(payload.message ?? 'Baseline push requested.');
    })
    .catch((error) => {
      alert(`Unable to push baseline: ${error.message}`);
    });
}
