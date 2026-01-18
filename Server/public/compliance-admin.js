const profilesTabList = document.getElementById('profilesTabList');
const profilesTabPanels = document.getElementById('profilesTabPanels');
const statusEl = document.getElementById('adminStatus');
const reloadBtn = document.getElementById('reloadProfiles');
const saveBtn = document.getElementById('saveProfiles');
const exportBtn = document.getElementById('exportProfiles');
const importInput = document.getElementById('importProfiles');
const authFetch = (input, init = {}) => fetch(input, { credentials: 'same-origin', ...init });

let currentProfilesData = { defaultProfileId: null, profiles: [] };
let availableScripts = [];
let activeProfileId = null;

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

async function loadProfiles() {
  setStatus('Loading compliance profiles...');
  toggleButtons(true);
  await loadRemediationScripts();
  try {
    const response = await authFetch('/compliance/profiles', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const payload = await response.json();
    currentProfilesData = {
      defaultProfileId: payload.defaultProfileId ?? null,
      profiles: Array.isArray(payload.profiles) ? payload.profiles : [],
    };
    renderProfileTabs(currentProfilesData);
    setStatus('Profiles loaded.', 'success');
  } catch (error) {
    console.error(error);
    setStatus('Unable to load profiles.', 'error');
  } finally {
    toggleButtons(false);
  }
}

async function saveProfiles() {
  if (!currentProfilesData) {
    return;
  }
  setStatus('Saving compliance profiles...');
  toggleButtons(true);
  try {
    const response = await authFetch('/compliance/profiles', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(currentProfilesData),
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(text || `HTTP ${response.status}`);
    }
    setStatus('Profiles saved.', 'success');
  } catch (error) {
    console.error(error);
    setStatus('Unable to save profiles.', 'error');
  } finally {
    toggleButtons(false);
  }
}

async function loadRemediationScripts() {
  try {
    const response = await authFetch('/scripts', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const scripts = await response.json();
    availableScripts = Array.isArray(scripts) ? scripts : [];
  } catch (error) {
    console.error(error);
    availableScripts = [];
  }
}

function renderProfileTabs(data) {
  if (!profilesTabList || !profilesTabPanels) {
    return;
  }
  const profiles = Array.isArray(data.profiles) ? data.profiles : [];
  profilesTabList.innerHTML = '';
  profilesTabPanels.innerHTML = '';

  if (!profiles.length) {
    profilesTabList.innerHTML = '<span class="tab-placeholder">No profiles defined.</span>';
    profilesTabPanels.innerHTML = '<p class="tab-placeholder">Define a profile to manage its rules.</p>';
    activeProfileId = null;
    return;
  }

  const normalizeLabel = (profile) => profile.label ?? profile.id ?? 'Untitled profile';
  const initialId = activeProfileId && profiles.some((profile) => profile.id === activeProfileId)
    ? activeProfileId
    : data.defaultProfileId ?? profiles[0]?.id ?? null;

  profiles.forEach((profile, index) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'tab-button';
    const label = normalizeLabel(profile);
    button.dataset.profileId = profile.id ?? `profile-${index}`;
    button.setAttribute('role', 'tab');
    button.id = `tab-${button.dataset.profileId}`;
    button.setAttribute('aria-controls', `panel-${button.dataset.profileId}`);
    button.addEventListener('click', () => setActiveTab(button.dataset.profileId));
    button.appendChild(document.createTextNode(label));
    if (data.defaultProfileId === profile.id) {
      const defaultBadge = document.createElement('span');
      defaultBadge.className = 'tab-default';
      defaultBadge.textContent = 'default';
      button.appendChild(defaultBadge);
    }
    if (!profile.rules?.length) {
      button.title = 'No rules defined';
    }
    profilesTabList.appendChild(button);

    const panel = document.createElement('section');
    panel.dataset.profileId = button.dataset.profileId;
    panel.id = `panel-${button.dataset.profileId}`;
    panel.setAttribute('role', 'tabpanel');
    panel.setAttribute('aria-labelledby', button.id);

    const heading = document.createElement('div');
    heading.className = 'profile-heading';
    const nameEl = document.createElement('h2');
    nameEl.textContent = label;
    heading.appendChild(nameEl);
    if (profile.description) {
      const descEl = document.createElement('p');
      descEl.textContent = profile.description;
      heading.appendChild(descEl);
    }
    if (typeof profile.weight === 'number') {
      const meta = document.createElement('p');
      meta.className = 'profile-meta';
      meta.textContent = `Profile weight: ${profile.weight}`;
      heading.appendChild(meta);
    }
    panel.appendChild(heading);

    const tableWrapper = document.createElement('div');
    tableWrapper.className = 'table-wrapper';
    const table = document.createElement('table');
    table.innerHTML = `
      <thead>
        <tr>
          <th>Rule ID</th>
          <th>Description</th>
          <th>Type</th>
          <th>Operation</th>
          <th>Weight</th>
          <th>Remediation</th>
          <th>Mappings</th>
        </tr>
      </thead>
    `;
    const tbody = document.createElement('tbody');
    const rules = Array.isArray(profile.rules) ? profile.rules : [];
    if (!rules.length) {
      const emptyRow = document.createElement('tr');
      const emptyCell = document.createElement('td');
      emptyCell.colSpan = 7;
      emptyCell.textContent = 'No rules defined for this profile.';
      emptyRow.appendChild(emptyCell);
      tbody.appendChild(emptyRow);
    } else {
      rules.forEach((rule) => {
        const row = document.createElement('tr');
        const idCell = document.createElement('td');
        idCell.textContent = rule.id ?? '-';
        row.appendChild(idCell);

        const descCell = document.createElement('td');
        descCell.textContent = rule.description ?? '-';
        row.appendChild(descCell);

        const typeCell = document.createElement('td');
        typeCell.textContent = rule.type ?? '-';
        row.appendChild(typeCell);

        const opCell = document.createElement('td');
        opCell.textContent = rule.operation ?? '-';
        row.appendChild(opCell);

        const weightCell = document.createElement('td');
        weightCell.textContent = typeof rule.weight === 'number' ? rule.weight : '-';
        row.appendChild(weightCell);

        const remediationCell = document.createElement('td');
        const select = document.createElement('select');
        select.className = 'remediation-select';
        const placeholder = document.createElement('option');
        placeholder.value = '';
        placeholder.textContent = '— none —';
        select.appendChild(placeholder);
        availableScripts.forEach((script) => {
          const option = document.createElement('option');
          option.value = script.name;
          option.textContent = script.description
            ? `${script.name} – ${script.description}`
            : script.name;
          option.title = script.description ?? '';
          select.appendChild(option);
        });
        select.value = rule.remediationScript ?? '';
        select.addEventListener('change', () => {
          rule.remediationScript = select.value || null;
          setStatus('Remediation script selected. Save to persist changes.', 'info');
        });
        remediationCell.appendChild(select);
        row.appendChild(remediationCell);

        const mapCell = document.createElement('td');
        if (!Array.isArray(rule.mappings) || !rule.mappings.length) {
          mapCell.textContent = '-';
        } else {
          const list = document.createElement('div');
          list.className = 'mapping-list';
          rule.mappings.forEach((mapping) => {
            const pill = document.createElement('span');
            pill.className = 'mapping-pill';
            pill.textContent = `${mapping.standard}:${mapping.id}`;
            list.appendChild(pill);
          });
          mapCell.appendChild(list);
        }
        row.appendChild(mapCell);

        tbody.appendChild(row);
      });
    }
    table.appendChild(tbody);
    tableWrapper.appendChild(table);
    panel.appendChild(tableWrapper);
    profilesTabPanels.appendChild(panel);
  });

  if (initialId) {
    setActiveTab(initialId);
  }
}

function setActiveTab(profileId) {
  if (!profilesTabList || !profilesTabPanels || !profileId) {
    return;
  }
  activeProfileId = profileId;
  profilesTabList.querySelectorAll('.tab-button').forEach((button) => {
    const isActive = button.dataset.profileId === profileId;
    button.classList.toggle('active', isActive);
    button.setAttribute('aria-selected', isActive ? 'true' : 'false');
  });
  profilesTabPanels.querySelectorAll('[role="tabpanel"]').forEach((panel) => {
    panel.hidden = panel.dataset.profileId !== profileId;
  });
}

function downloadProfiles() {
  if (!currentProfilesData) {
    return;
  }
  try {
    const blob = new Blob([JSON.stringify(currentProfilesData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'compliance-profiles.json';
    anchor.click();
    URL.revokeObjectURL(url);
    setStatus('JSON exported.', 'success');
  } catch (error) {
    console.error(error);
    setStatus('Unable to export JSON.', 'error');
  }
}

function handleImport(event) {
  const file = event.target.files?.[0];
  if (!file) {
    return;
  }
  const reader = new FileReader();
  reader.onload = (loadEvent) => {
    try {
      const parsed = JSON.parse(loadEvent.target.result);
      currentProfilesData = {
        defaultProfileId: parsed.defaultProfileId ?? null,
        profiles: Array.isArray(parsed.profiles) ? parsed.profiles : [],
      };
      activeProfileId = null;
      renderProfileTabs(currentProfilesData);
      setStatus('JSON imported. Save to apply.', 'success');
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

function toggleButtons(loading) {
  if (reloadBtn) reloadBtn.disabled = loading;
  if (saveBtn) saveBtn.disabled = loading;
  if (exportBtn) exportBtn.disabled = loading;
}

reloadBtn?.addEventListener('click', loadProfiles);
saveBtn?.addEventListener('click', saveProfiles);
exportBtn?.addEventListener('click', downloadProfiles);
importInput?.addEventListener('change', handleImport);
loadProfiles();
