const params = new URLSearchParams(window.location.search);
const agentId = params.get('agent');
const agentName = params.get('name');
const baseAgentLabel = agentName?.trim() || (agentId ? `Agent ${agentId}` : 'Unknown agent');
const agentLabel = document.getElementById('agentLabel');
const statusMessage = document.getElementById('statusMessage');
const filterInput = document.getElementById('filterInput');
const sourceFilter = document.getElementById('sourceFilter');
const pageSizeSelect = document.getElementById('pageSizeSelect');
const refreshButton = document.getElementById('refreshButton');
const tableBody = document.getElementById('softwareTableBody');
const paginationInfo = document.getElementById('paginationInfo');
const prevPage = document.getElementById('prevPage');
const nextPage = document.getElementById('nextPage');
let currentPage = 1;
let totalItems = 0;
let isLoading = false;
let filterTimeout;

if (agentLabel) {
  agentLabel.textContent = baseAgentLabel;
}

function setStatus(text, error = false) {
  if (!statusMessage) {
    return;
  }
  statusMessage.textContent = text;
  statusMessage.dataset.error = error ? 'true' : 'false';
}

function buildQuery(pageSizeValue) {
  const search = filterInput?.value?.trim() ?? '';
  const sourceValue = sourceFilter?.value ?? 'all';
  const query = new URLSearchParams();
  query.set('page', currentPage.toString());
  query.set('pageSize', pageSizeValue.toString());
  if (search.length > 0) {
    query.set('filter', search);
  }

  if (sourceValue !== 'all') {
    query.set('source', sourceValue);
  }

  return query.toString();
}

function renderTable(entries) {
  if (!tableBody) {
    return;
  }

  tableBody.innerHTML = '';
  if (entries.length === 0) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.setAttribute('colspan', '7');
    cell.className = 'empty';
    cell.textContent = 'No software entries found.';
    row.appendChild(cell);
    tableBody.appendChild(row);
    return;
  }

  entries.forEach((entry) => {
    const row = document.createElement('tr');

    const addCell = (value, fullValue) => {
      const cell = document.createElement('td');
      cell.textContent = value;
      if (fullValue) {
        cell.title = fullValue;
      }
      return cell;
    };

    row.appendChild(addCell(entry.name || 'Unnamed'));
    row.appendChild(addCell(entry.version || '—'));
    row.appendChild(addCell(entry.publisher || '—'));
    row.appendChild(addCell(entry.source || '—'));
    row.appendChild(addCell(entry.installDate || '—'));
    row.appendChild(addCell(entry.installLocation || '—', entry.installLocation));

    const manageCell = document.createElement('td');
    manageCell.className = 'manage-cell';
    const uninstallButton = document.createElement('button');
    uninstallButton.type = 'button';
    uninstallButton.className = 'uninstall-btn';
    uninstallButton.textContent = 'Uninstall';
    const hasCommand = Boolean(entry.uninstallCommand || entry.packageFullName);
    uninstallButton.disabled = !hasCommand;
    if (hasCommand) {
      uninstallButton.addEventListener('click', () => handleUninstall(entry));
    }

    manageCell.appendChild(uninstallButton);
    row.appendChild(manageCell);
    tableBody.appendChild(row);
  });
}

function updatePagination(pageSizeValue) {
  if (!paginationInfo) {
    return;
  }

  const pageCount = Math.max(Math.ceil(totalItems / pageSizeValue), 1);
  const first = totalItems === 0 ? 0 : (currentPage - 1) * pageSizeValue + 1;
  const last = Math.min(currentPage * pageSizeValue, totalItems);
  paginationInfo.textContent = totalItems === 0
    ? 'No entries.'
    : `Page ${currentPage} of ${pageCount} (${totalItems} total)`;

  if (prevPage) {
    prevPage.disabled = currentPage <= 1 || pageCount === 1;
  }
  if (nextPage) {
    nextPage.disabled = currentPage >= pageCount;
  }
}

async function loadSoftware() {
  if (!agentId) {
    setStatus('Agent id missing.', true);
    return;
  }

  if (isLoading) {
    return;
  }

  isLoading = true;
  const pageSizeValue = Number(pageSizeSelect?.value ?? '25') || 25;
  setStatus('Loading software list...');

  try {
    const response = await fetch(`/software/${encodeURIComponent(agentId)}/list?${buildQuery(pageSizeValue)}`, {
      credentials: 'same-origin',
    });

    const bodyText = await response.text();
    let payload;
    try {
      payload = bodyText ? JSON.parse(bodyText) : {};
    } catch (error) {
      payload = {};
    }

    if (!response.ok) {
      throw new Error(payload?.message || `Server returned ${response.status}`);
    }

    const entries = Array.isArray(payload.entries) ? payload.entries : [];
    totalItems = typeof payload.total === 'number' ? payload.total : entries.length;
    renderTable(entries);
    updatePagination(pageSizeValue);

    if (totalItems === 0) {
      setStatus('No software entries match the filter.');
    } else {
      const first = (currentPage - 1) * pageSizeValue + 1;
      const last = Math.min(currentPage * pageSizeValue, totalItems);
      setStatus(`Showing ${first}-${last} of ${totalItems} entries.`);
    }

    if (payload?.retrievedAt) {
      const timestamp = new Date(payload.retrievedAt);
      if (!Number.isNaN(timestamp.getTime()) && agentLabel) {
        agentLabel.textContent = `${baseAgentLabel} · Last refreshed ${timestamp.toLocaleString()}`;
      }
    } else if (agentLabel) {
      agentLabel.textContent = baseAgentLabel;
    }
  } catch (error) {
    console.error(error);
    setStatus(error.message ? error.message : 'Failed to load software list.', true);
    renderTable([]);
    updatePagination(pageSizeValue);
  } finally {
    isLoading = false;
  }
}

async function handleUninstall(entry) {
  if (!entry?.name) {
    return;
  }

  if (!confirm(`Request uninstall for ${entry.name}?`)) {
    return;
  }

  const isStore = typeof entry.source === 'string' && entry.source.toLowerCase().includes('store');
  const payload = {
    softwareId: entry.id || entry.name,
    source: isStore ? 'appx' : 'registry',
    productCode: entry.productCode,
  };

  if (!isStore && entry.uninstallCommand) {
    payload.uninstallCommand = entry.uninstallCommand;
  }

  if (isStore && entry.packageFullName) {
    payload.packageFullName = entry.packageFullName;
  }

  setStatus(`Requesting uninstall for ${entry.name}...`);

  try {
    const response = await fetch(`/software/${encodeURIComponent(agentId)}/uninstall`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    const text = await response.text();
    let result;
    try {
      result = text ? JSON.parse(text) : {};
    } catch (error) {
      result = {};
    }

    if (!response.ok || !result.success) {
      throw new Error(result?.message || `Server returned ${response.status}`);
    }

    setStatus(result.message || 'Uninstall requested.');
    await loadSoftware();
  } catch (error) {
    console.error(error);
    setStatus(error.message ? error.message : 'Failed to request uninstall.', true);
  }
}

function initControls() {
  refreshButton?.addEventListener('click', () => {
    currentPage = 1;
    loadSoftware();
  });

  pageSizeSelect?.addEventListener('change', () => {
    currentPage = 1;
    loadSoftware();
  });

  sourceFilter?.addEventListener('change', () => {
    currentPage = 1;
    loadSoftware();
  });

  filterInput?.addEventListener('input', () => {
    clearTimeout(filterTimeout);
    filterTimeout = setTimeout(() => {
      currentPage = 1;
      loadSoftware();
    }, 400);
  });

  prevPage?.addEventListener('click', () => {
    if (currentPage > 1) {
      currentPage -= 1;
      loadSoftware();
    }
  });

  nextPage?.addEventListener('click', () => {
    const pageSizeValue = Number(pageSizeSelect?.value ?? '25') || 25;
    const pageCount = Math.max(Math.ceil(totalItems / pageSizeValue), 1);
    if (currentPage < pageCount) {
      currentPage += 1;
      loadSoftware();
    }
  });
}

initControls();
loadSoftware();
