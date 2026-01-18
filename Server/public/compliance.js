const complianceStatusMessage = document.getElementById('complianceStatusMessage');
const complianceSummary = document.getElementById('complianceSummary');
const complianceTableBody = document.getElementById('complianceTableBody');
const refreshButton = document.getElementById('refreshCompliance');
const authFetch = (input, init = {}) => fetch(input, { credentials: 'same-origin', ...init });

let profileOptions = [];
let profilesById = new Map();

async function loadCompliance() {
  showStatus('Loading compliance configuration...', 'info');
  try {
    const profileResp = await authFetch('/compliance/profiles', { cache: 'no-store' });
    if (!profileResp.ok) {
      throw new Error('Unable to fetch profiles');
    }
    const profilePayload = await profileResp.json();
    profileOptions = Array.isArray(profilePayload.profiles) ? profilePayload.profiles : [];
    profilesById = new Map(profileOptions.map((profile) => [profile.id, profile]));
  } catch (error) {
    showStatus('Unable to load compliance profiles.', 'error');
    console.error(error);
    return;
  }

  try {
    const devicesResp = await authFetch('/compliance/devices', { cache: 'no-store' });
    if (!devicesResp.ok) {
      throw new Error('Unable to fetch device compliance');
    }
    const devicesPayload = await devicesResp.json();
    const statuses = Array.isArray(devicesPayload.statuses) ? devicesPayload.statuses : [];
    renderSummary(statuses);
    renderTable(statuses);
    showStatus('Compliance data refreshed.', 'success');
  } catch (error) {
    showStatus('Unable to load compliance statuses.', 'error');
    console.error(error);
  }
}

function renderSummary(statuses) {
  const scored = statuses.filter((entry) => typeof entry.score === 'number');
  const average = scored.length
    ? `${(scored.reduce((sum, item) => sum + (item.score ?? 0), 0) / scored.length).toFixed(1)}%`
    : 'N/A';
  const below = scored.filter((entry) => (entry.score ?? 0) < 80).length;
  const missing = statuses.filter((entry) => entry.score === null || entry.score === undefined).length;
  if (!complianceSummary) {
    return;
  }
  complianceSummary.innerHTML = `
    <div class="summary-card">
      <strong>${average}</strong>
      <span>Average score</span>
    </div>
    <div class="summary-card">
      <strong>${below}</strong>
      <span>Agents below target</span>
    </div>
    <div class="summary-card">
      <strong>${missing}</strong>
      <span>Missing evaluations</span>
    </div>
  `;
}

function renderTable(statuses) {
  if (!complianceTableBody) {
    return;
  }
  complianceTableBody.innerHTML = '';
  if (!statuses.length) {
    complianceTableBody.innerHTML = '<tr><td colspan="6">No compliance data available.</td></tr>';
    return;
  }

  statuses.forEach((status) => {
    const row = document.createElement('tr');

    const agentCell = document.createElement('td');
    agentCell.innerHTML = `
      <strong>${status.agentName ?? status.agentId}</strong>
      <div class="row-label">${status.agentId} · ${status.agentStatus}</div>
    `;
    row.appendChild(agentCell);

    const profileCell = document.createElement('td');
    profileCell.textContent = status.profileLabel ?? profilesById.get(status.profileId ?? '')?.label ?? 'Unknown';
    row.appendChild(profileCell);

    const scoreCell = document.createElement('td');
    const scoreValue = typeof status.score === 'number' ? `${status.score.toFixed(1)}%` : 'N/A';
    const pill = document.createElement('span');
    let tierClass = 'low';
    if (typeof status.score === 'number') {
      if (status.score >= 90) tierClass = 'high';
      else if (status.score >= 70) tierClass = 'medium';
    }
    pill.className = `score-pill ${tierClass}`;
    pill.textContent = scoreValue;
    scoreCell.appendChild(pill);
    row.appendChild(scoreCell);

    const evaluatedCell = document.createElement('td');
    evaluatedCell.textContent = status.evaluatedAt
      ? new Date(status.evaluatedAt).toLocaleString()
      : 'Not evaluated';
    row.appendChild(evaluatedCell);

    const assignCell = document.createElement('td');
    const assignSelect = document.createElement('select');
    assignSelect.className = 'assign-select';
    assignSelect.dataset.agentId = status.agentId ?? '';
    const defaultOption = document.createElement('option');
    defaultOption.value = '';
    defaultOption.textContent = 'Default profile';
    assignSelect.appendChild(defaultOption);
    profileOptions.forEach((entry) => {
      const option = document.createElement('option');
      option.value = entry.id ?? '';
      option.textContent = entry.label;
      assignSelect.appendChild(option);
    });
    assignSelect.value = status.assignedProfileId ?? '';
    assignSelect.addEventListener('change', () => {
      const selected = assignSelect.value || null;
      updateAssignment(status.agentId, selected);
    });
    assignCell.appendChild(assignSelect);
    row.appendChild(assignCell);

    const detailsCell = document.createElement('td');
    const details = document.createElement('details');
    const summary = document.createElement('summary');
    const failCount = (status.results ?? []).filter((item) => item.status === 'fail').length;
    summary.textContent = `Failed rules: ${failCount} · ${status.profileLabel}`;
    details.appendChild(summary);

    const ruleGrid = document.createElement('div');
    ruleGrid.className = 'rule-grid';
    (status.results ?? []).forEach((result) => {
      const badge = document.createElement('span');
      badge.className = `rule-chip ${result.status}`;
      badge.textContent = `${result.ruleId} (${result.status.replace('_', ' ')})`;
      ruleGrid.appendChild(badge);
    });
    if (!ruleGrid.childNodes.length) {
      const placeholder = document.createElement('span');
      placeholder.className = 'row-label';
      placeholder.textContent = 'No rules evaluated yet.';
      ruleGrid.appendChild(placeholder);
    }
    details.appendChild(ruleGrid);
    detailsCell.appendChild(details);
    row.appendChild(detailsCell);

    complianceTableBody.appendChild(row);
  });
}

function showStatus(message, variant = 'info') {
  if (!complianceStatusMessage) {
    return;
  }
  complianceStatusMessage.textContent = message;
  complianceStatusMessage.classList.remove('success', 'error');
  if (variant === 'success') {
    complianceStatusMessage.classList.add('success');
  } else if (variant === 'error') {
    complianceStatusMessage.classList.add('error');
  }
}

async function updateAssignment(agentId, profileId) {
  if (!agentId) {
    return;
  }
  try {
    showStatus('Saving profile assignment...', 'info');
    refreshButton?.setAttribute('disabled', 'true');
    const payload = { agentId, profileId };
    const response = await authFetch('/compliance/assignments', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new Error('Unable to save assignment');
    }
    showStatus('Assignment saved. Triggering reevaluation...', 'success');
    await triggerRun(agentId);
  } catch (error) {
    console.error(error);
    showStatus('Assignment update failed.', 'error');
  } finally {
    refreshButton?.removeAttribute('disabled');
  }
}

async function triggerRun(agentId = null) {
  try {
    showStatus(agentId ? 'Triggering compliance run for agent...' : 'Triggering compliance run for all agents...', 'info');
    refreshButton?.setAttribute('disabled', 'true');
    const response = await authFetch('/compliance/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(agentId ? { agentId } : {}),
    });
    if (!response.ok) {
      throw new Error('Unable to trigger compliance run');
    }
    await loadCompliance();
  } catch (error) {
    console.error(error);
    showStatus('Compliance run request failed.', 'error');
  } finally {
    refreshButton?.removeAttribute('disabled');
  }
}

refreshButton?.addEventListener('click', () => triggerRun());
loadCompliance();
setInterval(loadCompliance, 60_000);
