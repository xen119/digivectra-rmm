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

let summaryData = null;

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
    const response = await fetch('/clients', { cache: 'no-store' });
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
      const refreshResponse = await fetch(`/updates/${agentId}/refresh`, { method: 'POST' });
      if (!refreshResponse.ok) {
        throw new Error('Failed to refresh updates');
      }
    }

    const response = await fetch(`/updates/${agentId}/data`, { cache: 'no-store' });
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

  categoriesEl.innerHTML = '';
  if (!summary?.categories?.length) {
    const fallback = document.createElement('p');
    fallback.textContent = 'No update information is currently available.';
    fallback.className = 'empty';
    categoriesEl.appendChild(fallback);
    updateInstallButtonState();
    return;
  }

  summary.categories.forEach((category) => {
    categoriesEl.appendChild(createCategoryCard(category));
  });

  updateInstallButtonState();
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
    const response = await fetch(`/updates/${agentId}/install`, {
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
