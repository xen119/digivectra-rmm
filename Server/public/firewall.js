const authFetch = (input, init = {}) => fetch(input, { credentials: 'same-origin', ...init });

const params = new URLSearchParams(window.location.search);
const agentId = params.get('agent');
const agentName = params.get('name') ?? 'agent';

const heroSubtitle = document.getElementById('heroSubtitle');
const statusMessage = document.getElementById('statusMessage');
const refreshButton = document.getElementById('refreshButton');
const profileBadges = document.getElementById('profileBadges');
const profileDetail = document.getElementById('profileDetail');
const rulesSummary = document.getElementById('rulesSummary');
const inboundBody = document.getElementById('inboundRulesBody');
const outboundBody = document.getElementById('outboundRulesBody');
const inboundCount = document.getElementById('inboundCount');
const outboundCount = document.getElementById('outboundCount');

const ruleNameInput = document.getElementById('ruleName');
const ruleDirectionInput = document.getElementById('ruleDirection');
const ruleActionInput = document.getElementById('ruleAction');
const ruleProtocolInput = document.getElementById('ruleProtocol');
const ruleLocalPortsInput = document.getElementById('ruleLocalPorts');
const ruleRemotePortsInput = document.getElementById('ruleRemotePorts');
const ruleApplicationInput = document.getElementById('ruleApplication');
const ruleAddButton = document.getElementById('ruleAddButton');

if (!agentId) {
  heroSubtitle.textContent = 'Agent identifier missing. Use ?agent=<id>&name=<friendly name>';
  statusMessage.textContent = 'Agent ID required.';
  statusMessage.style.color = '#fecdd3';
} else {
  heroSubtitle.textContent = `Managing firewall for ${agentName}`;
  refreshButton?.addEventListener('click', () => loadFirewall(true));
    ruleAddButton?.addEventListener('click', handleAddRule);
    if (ruleAddButton) {
      ruleAddButton.innerHTML = `<span class="button-icon">➕</span>`;
      ruleAddButton.setAttribute('aria-label', 'Add rule');
    }
  loadFirewall();
}

async function loadFirewall(force = false) {
  if (!agentId) {
    return;
  }

  setStatus('Refreshing firewall data.');
  profileDetail.textContent = '';
  profileBadges.innerHTML = '<div class="placeholder">Loading profile states.</div>';
  rulesSummary.textContent = 'Loading rules.';
  inboundBody.innerHTML = '<tr><td class="placeholder" colspan="7">Loading...</td></tr>';
  outboundBody.innerHTML = '<tr><td class="placeholder" colspan="7">Loading...</td></tr>';

  try {
    const response = await authFetch(`/firewall/${encodeURIComponent(agentId)}/rules`, { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`Server returned ${response.status}`);
    }

    const payload = await response.json();
    renderProfiles(payload.profiles, payload.firewallEnabled);
    renderRules(payload.rules);
    renderSummary(payload.rules, payload.defaultInboundAction, payload.defaultOutboundAction);
    setStatus(`Last refreshed ${new Date().toLocaleString()}`);
  } catch (error) {
    showError(`Unable to load firewall data: ${error.message}`);
  }
}

function renderProfiles(profiles, enabledBlock) {
  if (!profileBadges) {
    return;
  }

  if (!Array.isArray(profiles) || !profiles.length) {
    profileBadges.innerHTML = '<div class="placeholder">Profile data unavailable.</div>';
    return;
  }

  profileBadges.innerHTML = '';
  profiles.forEach((profile) => {
    const badge = document.createElement('button');
    badge.type = 'button';
    const isEnabled = Boolean(enabledBlock?.[profile.key]);
    badge.className = `badge ${isEnabled ? 'active' : ''}`;
    badge.textContent = `${profile.name}: ${isEnabled ? 'On' : 'Off'}`;
    badge.addEventListener('click', () => toggleProfile(profile.key, !isEnabled, profile.name));
    profileBadges.appendChild(badge);
  });

  profileDetail.textContent = enabledBlock
    ? `Domain: ${formatState(enabledBlock.domain)} · Private: ${formatState(enabledBlock.private)} · Public: ${formatState(enabledBlock.public)}`
    : 'Profile detail unavailable.';
}

function renderSummary(rules, inbound, outbound) {
  const total = Array.isArray(rules) ? rules.length : 0;
  const enabled = Array.isArray(rules) ? rules.filter((rule) => Boolean(rule.enabled)).length : 0;
  rulesSummary.textContent = `Rules: ${total} total, ${enabled} enabled · Inbound default: ${formatAction(inbound)} · Outbound default: ${formatAction(outbound)}`;
}

function renderRules(rules) {
  const parsedRules = Array.isArray(rules) ? rules : [];
  const inboundRules = parsedRules.filter((rule) => parseDirection(rule.direction) === 'inbound');
  const outboundRules = parsedRules.filter((rule) => parseDirection(rule.direction) === 'outbound');

  populateRuleTable(inboundBody, inboundRules);
  populateRuleTable(outboundBody, outboundRules);
  inboundCount.textContent = `${inboundRules.length} rules`;
  outboundCount.textContent = `${outboundRules.length} rules`;
}

function populateRuleTable(container, rules) {
  if (!container) {
    return;
  }

  if (!rules.length) {
    container.innerHTML = '<tr><td class="placeholder" colspan="7">No rules.</td></tr>';
    return;
  }

  container.innerHTML = '';
  rules.forEach((rule) => {
    const row = document.createElement('tr');
    const ports = [];
    if (rule.localPorts) ports.push(`Local: ${rule.localPorts}`);
    if (rule.remotePorts) ports.push(`Remote: ${rule.remotePorts}`);

    const actionCell = document.createElement('td');
    actionCell.textContent = formatAction(rule.action);

    row.innerHTML = `
      <td>${rule.name}</td>
      <td></td>
      <td>${actionCell.textContent}</td>
      <td>${formatProtocol(rule.protocol)}</td>
      <td>${ports.join('<br>') || 'Any'}</td>
      <td class="actions-row"></td>
    `;

    const toggleCell = row.querySelector('td:nth-child(2)');
    const actionsCell = row.querySelector('.actions-row');

    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = `toggle-button ${rule.enabled ? 'enabled' : 'disabled'}`;
    const icon = rule.enabled ? '⏸' : '▶';
    toggle.innerHTML = `<span class="button-icon">${icon}</span>`;
    toggle.setAttribute('aria-label', rule.enabled ? 'Disable rule' : 'Enable rule');
    toggle.addEventListener('click', () => toggleRule(rule.name, !rule.enabled));
    toggleCell?.appendChild(toggle);

    const deleteBtn = document.createElement('button');
    deleteBtn.type = 'button';
    deleteBtn.className = 'btn delete';
    deleteBtn.innerHTML = `<span class="button-icon">🗑️</span>`;
    deleteBtn.setAttribute('aria-label', `Delete ${rule.name}`);
    deleteBtn.addEventListener('click', () => deleteRule(rule.name));
    actionsCell?.appendChild(deleteBtn);

    container.appendChild(row);
  });
}

function handleAddRule() {
  const name = ruleNameInput.value.trim();
  if (!name) {
    showError('Rule name is required.');
    return;
  }

  const payload = {
    name,
    direction: ruleDirectionInput.value === 'inbound' ? 'inbound' : 'outbound',
    action: ruleActionInput.value === 'allow' ? 'allow' : 'block',
    protocol: ruleProtocolInput.value,
    localPorts: ruleLocalPortsInput.value.trim(),
    remotePorts: ruleRemotePortsInput.value.trim(),
    application: ruleApplicationInput.value.trim(),
  };

  setStatus('Adding new rule…');
  authFetch(`/firewall/${encodeURIComponent(agentId)}/rule/add`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
    .then((response) => {
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      return response.json();
    })
    .then((result) => {
      setStatus(result.message || 'Rule added.');
      clearRuleForm();
      loadFirewall();
    })
    .catch((error) => {
      showError(`Unable to add rule: ${error.message}`);
    });
}

function clearRuleForm() {
  ruleNameInput.value = '';
  ruleLocalPortsInput.value = '';
  ruleRemotePortsInput.value = '';
  ruleApplicationInput.value = '';
}

function deleteRule(name) {
  if (!name) {
    return;
  }

  setStatus(`Deleting ${name}…`);
  authFetch(`/firewall/${encodeURIComponent(agentId)}/rule/delete`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ruleName: name }),
  })
    .then((response) => {
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      return response.json();
    })
    .then((payload) => {
      setStatus(payload.message || 'Rule removal requested.');
      loadFirewall();
    })
    .catch((error) => {
      showError(`Unable to remove rule: ${error.message}`);
    });
}

function formatState(value) {
  return value ? 'On' : value === false ? 'Off' : 'Unknown';
}

function formatAction(value) {
  switch (value) {
    case 0:
      return 'Block';
    case 1:
      return 'Allow';
    default:
      return typeof value === 'string'
        ? `${value.charAt(0).toUpperCase()}${value.slice(1)}`
        : 'Unknown';
  }
}

function formatProtocol(value) {
  switch (value) {
    case 6:
      return 'TCP';
    case 17:
      return 'UDP';
    case 256:
    case 'any':
      return 'Any';
    case 'tcp':
      return 'TCP';
    case 'udp':
      return 'UDP';
    default:
      return typeof value === 'number' ? `Protocol ${value}` : 'Unknown';
  }
}

function toggleRule(name, targetState) {
  if (!name) {
    return;
  }

  setStatus(`Updating rule ${name}.`);
  authFetch(`/firewall/${encodeURIComponent(agentId)}/rule/action`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ruleName: name, enabled: targetState }),
  })
    .then((response) => {
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      return response.json();
    })
    .then((payload) => {
      setStatus(payload.message || 'Rule update queued.');
      loadFirewall();
    })
    .catch((error) => {
      showError(`Unable to update rule: ${error.message}`);
    });
}

function toggleProfile(key, targetState, displayName) {
  setStatus(`${displayName} profile ${targetState ? 'enabling' : 'disabling'}.`);
  authFetch(`/firewall/${encodeURIComponent(agentId)}/state`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ profile: key, enabled: targetState }),
  })
    .then((response) => {
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      return response.json();
    })
    .then((payload) => {
      setStatus(payload.message || 'Firewall updated.');
      loadFirewall();
    })
    .catch((error) => {
      showError(`Firewall update failed: ${error.message}`);
    });
}

function setStatus(message) {
  if (statusMessage) {
    statusMessage.textContent = message;
    statusMessage.style.color = '#94a3b8';
  }
}

function showError(message) {
  if (statusMessage) {
    statusMessage.textContent = message;
    statusMessage.style.color = '#fecdd3';
  }
  inboundBody.innerHTML = '<tr><td class="placeholder" colspan="7">Error loading rules.</td></tr>';
  outboundBody.innerHTML = '<tr><td class="placeholder" colspan="7">Error loading rules.</td></tr>';
  profileBadges.innerHTML = '<div class="placeholder">Profile data unavailable.</div>';
  rulesSummary.textContent = 'Unable to render firewall rules.';
}

function parseDirection(value) {
  if (typeof value === 'number') {
    return value === 2 ? 'outbound' : 'inbound';
  }

  const normalized = String(value ?? '').trim().toLowerCase();
  if (normalized.includes('out')) {
    return 'outbound';
  }

  return 'inbound';
}
