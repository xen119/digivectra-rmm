const params = new URLSearchParams(window.location.search);
const agentId = params.get('agent');
const agentHeading = document.getElementById('agentHeading');
const statusEl = document.getElementById('status');
const categoriesEl = document.getElementById('categories');
const countEl = document.getElementById('updateCount');
const labelEl = document.getElementById('updateLabel');
const refreshButton = document.getElementById('refreshButton');
const installButton = document.getElementById('installButton');
const logEl = document.getElementById('log');
const installedList = document.getElementById('installedList');
const installedCountEl = document.getElementById('installedCount');
const managedAlert = document.getElementById('managedAlert');
const KB_REGEX = /\bKB\d+\b/i;
const UNINSTALL_BLACKLIST = [
  'security intelligence update',
  'definition update',
  'defender update',
  'definitions update',
  'msrt',
  'definition',
];
const INSTALLED_CATEGORY_ORDER = [
  'Security Updates',
  'Definition Updates',
  'Cumulative Updates',
  'Driver Updates',
  'Feature Updates',
  'Optional Updates',
  'Other Updates',
];
const CATEGORY_PURPOSES = {
  'Security Updates': 'Vulnerability fixes',
  'Definition Updates': 'Malware protection',
  'Cumulative Updates': 'All fixes combined',
  'Driver Updates': 'Hardware support',
  'Feature Updates': 'New Windows versions',
  'Optional Updates': 'Previews & extras',
  'Other Updates': 'Miscellaneous updates',
};
const authFetch = (input, init) => fetch(input, { credentials: 'same-origin', ...init });

let summaryData = null;
let updatesManagedByPolicy = false;

refreshButton?.addEventListener('click', () => loadSummary(true));
installButton?.addEventListener('click', () => installSelectedUpdates());

if (!agentId || !agentHeading) {
  statusEl.textContent = 'Agent identifier missing.';
  refreshButton.disabled = true;
  if (installButton) installButton.disabled = true;
} else {
  initialize();
}

async function initialize() {
  await fetchAgentName();
  await loadSummary();
}

async function fetchAgentName() {
  try {
    const response = await authFetch('/clients', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error('Failed to fetch agent list');
    }

    const agents = await response.json();
    const agent = Array.isArray(agents) ? agents.find((entry) => entry.id === agentId) : null;
    if (agent && agentHeading) {
      agentHeading.textContent = `Updates for ${agent.name}`;
    }
  } catch (error) {
    console.error(error);
  }
}

async function loadSummary(force = false) {
  if (!agentId) {
    return;
  }

  setStatus(force ? 'Refreshing update information...' : 'Loading update information...');

  try {
    if (force) {
      const refreshResponse = await authFetch(`/updates/${agentId}/refresh`, { method: 'POST' });
      if (!refreshResponse.ok) {
        throw new Error('Failed to refresh updates');
      }
    }

    const response = await authFetch(`/updates/${agentId}/data`, { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    summaryData = payload?.summary ?? null;
    renderSummary(summaryData);
    } catch (error) {
      console.error(error);
      setStatus(`Failed to load updates (${error.message}).`);
      categoriesEl.innerHTML = '';
      renderInstalledUpdates([]);
      if (installButton) {
        installButton.disabled = true;
      }
    }
}

function renderSummary(summary) {
  const total = typeof summary?.totalCount === 'number' ? summary.totalCount : 0;
  countEl.textContent = String(total);
  countEl.className = `update-count ${total === 0 ? 'count-ok' : 'count-alert'}`;
  labelEl.textContent = total === 0 ? 'No pending updates' : `${total} pending update${total === 1 ? '' : 's'}`;
  setStatus(total === 0 ? 'System is up to date.' : 'Select updates to install.');

  updatesManagedByPolicy = Boolean(summary?.managedByPolicy);
  updateManagedAlert();

  const installedUpdates = Array.isArray(summary?.installedUpdates) ? summary.installedUpdates : [];

  categoriesEl.innerHTML = '';
  if (!summary?.categories?.length) {
    const fallback = document.createElement('p');
    fallback.textContent = 'No update information is currently available.';
    fallback.className = 'empty';
    categoriesEl.appendChild(fallback);
    updateInstallButtonState();
    renderInstalledUpdates(installedUpdates);
    return;
  }

  summary.categories.forEach((category) => {
    categoriesEl.appendChild(createCategoryCard(category));
  });

  updateInstallButtonState();
  renderInstalledUpdates(installedUpdates);
}

function createCategoryCard(category) {
  const card = document.createElement('section');
  card.className = 'category-card';

  const header = document.createElement('div');
  header.className = 'category-header';
  header.innerHTML = `<div><strong>${category.name}</strong><p>${category.purpose}</p></div>`;

  const selectButton = document.createElement('button');
  selectButton.type = 'button';
  selectButton.className = 'select-all';
  selectButton.textContent = 'Select all';
  selectButton.addEventListener('click', () => {
    card.querySelectorAll('input[data-update-id]').forEach((checkbox) => {
      checkbox.checked = true;
    });
    updateInstallButtonState();
  });

  header.appendChild(selectButton);
  card.appendChild(header);

  const list = document.createElement('div');
  list.className = 'category-list';

  if (!Array.isArray(category.updates) || category.updates.length === 0) {
    const empty = document.createElement('p');
    empty.textContent = 'No updates in this category.';
    empty.className = 'empty';
    list.appendChild(empty);
  } else {
    category.updates.forEach((update) => {
      const row = document.createElement('label');
      row.className = 'update-row';

      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.dataset.updateId = update.id;
      checkbox.addEventListener('change', updateInstallButtonState);

      const detail = document.createElement('div');
      detail.className = 'update-content';
      detail.innerHTML = `<strong>${update.title}</strong>${update.description ? `<p>${update.description}</p>` : ''}${
        Array.isArray(update.kbArticleIDs) && update.kbArticleIDs.length
          ? `<small>KB: ${update.kbArticleIDs.join(', ')}</small>`
          : ''
      }`;

      row.appendChild(checkbox);
      row.appendChild(detail);
      list.appendChild(row);
    });
  }

  card.appendChild(list);
  return card;
}

function updateInstallButtonState() {
  if (!installButton) {
    return;
  }

  const selected = categoriesEl.querySelectorAll('input[data-update-id]:checked');
  installButton.disabled = selected.length === 0;
}

async function installSelectedUpdates() {
  if (!agentId || !summaryData) {
    return;
  }

  const selectedIds = Array.from(categoriesEl.querySelectorAll('input[data-update-id]:checked'))
    .map((checkbox) => checkbox.dataset.updateId)
    .filter(Boolean);

  if (selectedIds.length === 0) {
    return;
  }

  installButton.disabled = true;
  setStatus('Sending install request...');

  try {
    const response = await authFetch(`/updates/${agentId}/install`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: selectedIds }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    logMessage(`Install request submitted for ${selectedIds.length} update(s).`);
    await loadSummary(true);
  } catch (error) {
    console.error(error);
    setStatus(`Install request failed (${error.message}).`);
  } finally {
    installButton.disabled = false;
  }
}

function setStatus(text) {
  if (!statusEl) {
    return;
  }

  statusEl.textContent = text ?? '';
}

function logMessage(message) {
  if (!logEl) {
    return;
  }

  const entry = document.createElement('div');
  entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
  logEl.appendChild(entry);
  logEl.scrollTop = logEl.scrollHeight;
}

function renderInstalledUpdates(list) {
  if (!installedList) {
    return;
  }

  installedList.innerHTML = '';
  const entries = Array.isArray(list) ? list : [];
  if (installedCountEl) {
    installedCountEl.textContent = String(entries.length);
  }

  if (entries.length === 0) {
    const empty = document.createElement('p');
    empty.textContent = 'No recently installed updates are available.';
    empty.className = 'empty';
    installedList.appendChild(empty);
    return;
  }

  const grouped = new Map();
  entries.forEach((update) => {
    const category = categorizeInstalledUpdate(update);
    if (!grouped.has(category)) {
      grouped.set(category, []);
    }
    grouped.get(category).push(update);
  });

  const orderedCategories = [];
  INSTALLED_CATEGORY_ORDER.forEach((category) => {
    if (grouped.has(category)) {
      orderedCategories.push(category);
      grouped.delete(category);
    }
  });
  const remaining = Array.from(grouped.keys()).sort((a, b) => a.localeCompare(b));
  orderedCategories.push(...remaining);

  orderedCategories.forEach((categoryName) => {
    const updates = grouped.get(categoryName) ?? [];
    if (!updates.length) {
      return;
    }
    installedList.appendChild(createInstalledCategoryCard(categoryName, updates));
  });
}

function categorizeInstalledUpdate(update) {
  const candidates = Array.isArray(update?.categories) && update.categories.length
    ? update.categories
    : ['Other Updates'];
  for (const raw of candidates) {
    const normalized = normalizeCategory(raw);
    if (normalized) {
      return normalized;
    }
  }

  return 'Other Updates';
}

function normalizeCategory(name) {
  if (!name) {
    return null;
  }

  const lower = name.toLowerCase();
  for (const canonical of INSTALLED_CATEGORY_ORDER) {
    if (lower.includes(canonical.toLowerCase())) {
      return canonical;
    }
  }

  return name;
}

function createInstalledCategoryCard(categoryName, updates) {
  const card = document.createElement('section');
  card.className = 'installed-category-card';

  const header = document.createElement('div');
  header.className = 'installed-category-header';
  const title = document.createElement('div');
  const strong = document.createElement('strong');
  strong.textContent = `${categoryName}`;
  title.appendChild(strong);
  const purpose = document.createElement('p');
  const note = CATEGORY_PURPOSES[categoryName];
  purpose.textContent = note ?? 'Installed updates';
  purpose.className = 'installed-note';
  title.appendChild(purpose);
  header.appendChild(title);
  const count = document.createElement('span');
  count.className = 'installed-category-count';
  count.textContent = String(updates.length);
  header.appendChild(count);
  card.appendChild(header);

  const list = document.createElement('div');
  list.className = 'installed-category-list';
  updates.forEach((update) => list.appendChild(createInstalledEntry(update)));
  card.appendChild(list);
  return card;
}

function createInstalledEntry(update) {
  const entryEl = document.createElement('article');
  entryEl.className = 'installed-entry';

  const header = document.createElement('div');
  header.className = 'installed-entry-header';

  const titleEl = document.createElement('strong');
  titleEl.textContent = update?.title ?? 'Unnamed update';

  const dateEl = document.createElement('span');
  dateEl.className = 'installed-date';
  dateEl.textContent = formatInstalledDate(update?.installedOn);

  header.appendChild(titleEl);
  header.appendChild(dateEl);
  entryEl.appendChild(header);

  if (update?.description) {
    const description = document.createElement('p');
    description.textContent = update.description;
    entryEl.appendChild(description);
  }

  if (Array.isArray(update?.kbArticleIDs) && update.kbArticleIDs.length) {
    const kb = document.createElement('small');
    kb.textContent = `KB: ${update.kbArticleIDs.join(', ')}`;
    entryEl.appendChild(kb);
  }

  if (update?.resultCode) {
    const result = document.createElement('small');
    result.className = 'installed-result';
    result.textContent = `Result: ${update.resultCode}`;
    entryEl.appendChild(result);
  }

  const uninstallKb = findKbIdentifier(update);
  if (uninstallKb && shouldOfferUninstall(update)) {
    const actions = document.createElement('div');
    actions.className = 'installed-actions';
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'installed-uninstall';
    button.textContent = 'Uninstall';
    button.addEventListener('click', async () => {
      if (button.disabled) {
        return;
      }

      button.disabled = true;
      try {
        await requestUpdateUninstall(uninstallKb);
        button.textContent = 'Requested';
      } catch (error) {
        console.error(error);
        setStatus(`Uninstall request failed (${error.message}).`);
        button.disabled = false;
      }
    });
    actions.appendChild(button);
    entryEl.appendChild(actions);
  }

  return entryEl;
}

function formatInstalledDate(value) {
  if (!value) {
    return 'Unknown date';
  }

  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) {
    return 'Unknown date';
  }

  return date.toLocaleString();
}

function findKbIdentifier(update) {
  if (Array.isArray(update?.kbArticleIDs)) {
    for (const kb of update.kbArticleIDs) {
      const normalized = typeof kb === 'string' ? kb.trim() : '';
      if (KB_REGEX.test(normalized)) {
        return normalized.toUpperCase();
      }
    }
  }

  if (typeof update?.title === 'string') {
    const match = KB_REGEX.exec(update.title);
    if (match) {
      return match[0].toUpperCase();
    }
  }

  return null;
}

function shouldOfferUninstall(update) {
  if (updatesManagedByPolicy) {
    return false;
  }

  if (typeof update?.title !== 'string') {
    return true;
  }

  const lower = update.title.toLowerCase();
  return !UNINSTALL_BLACKLIST.some((token) => lower.includes(token));
}

async function requestUpdateUninstall(kbArticleId) {
  if (!agentId) {
    throw new Error('Agent identifier missing.');
  }

  setStatus(`Sending uninstall request for ${kbArticleId}...`);
  const response = await authFetch(`/updates/${agentId}/uninstall`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kbArticleId }),
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  logMessage(`Uninstall request submitted for ${kbArticleId}.`);
  setStatus(`Uninstall requested for ${kbArticleId}.`);
}

function updateManagedAlert() {
  if (!managedAlert) {
    return;
  }

  if (updatesManagedByPolicy) {
    managedAlert.removeAttribute('hidden');
  } else {
    managedAlert.setAttribute('hidden', '');
  }
}
