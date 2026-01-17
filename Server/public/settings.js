const statusEl = document.getElementById('statusMessage');
const listEl = document.getElementById('settingsList');
const authFetch = (input, init = {}) => fetch(input, { credentials: 'same-origin', ...init });

function showStatus(message, variant = 'info') {
  if (statusEl) {
    statusEl.textContent = message;
    statusEl.classList.remove('error', 'success');
    if (variant === 'error') {
      statusEl.classList.add('error');
    } else if (variant === 'success') {
      statusEl.classList.add('success');
    }
  }
}

function renderItems(items) {
  if (!listEl) {
    return;
  }

  listEl.innerHTML = '';
  if (!items.length) {
    listEl.textContent = 'No navigation entries found.';
    return;
  }

  for (const item of items) {
    const row = document.createElement('div');
    row.className = 'setting-row';

    const copy = document.createElement('div');
    copy.className = 'setting-copy';

    const title = document.createElement('strong');
    title.textContent = item.label ?? 'Unnamed entry';
    copy.appendChild(title);

    if (item.description) {
      const detail = document.createElement('small');
      detail.textContent = item.description;
      copy.appendChild(detail);
    }

    const toggle = document.createElement('input');
    toggle.type = 'checkbox';
    toggle.className = 'setting-toggle';
    toggle.checked = Boolean(item.visible);
    toggle.dataset.navId = item.id;
    toggle.addEventListener('change', () => {
      handleToggle(item.id, toggle.checked, item.label ?? 'entry', toggle);
    });

    row.appendChild(copy);
    row.appendChild(toggle);
    listEl.appendChild(row);
  }
}

async function handleToggle(id, visible, label, toggle) {
  if (!id) {
    return;
  }

  toggle.disabled = true;
  showStatus(`Saving ${label}...`);

  try {
    const response = await authFetch('/settings/navigation', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ items: [{ id, visible }] }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    showStatus(`${label} saved.`, 'success');
  } catch (error) {
    console.error('Unable to save navigation setting', error);
    showStatus('Unable to save settings. Try again.', 'error');
    toggle.checked = !visible;
  } finally {
    toggle.disabled = false;
  }
}

async function loadSettings() {
  showStatus('Loading navigation settings...');
  try {
    const response = await authFetch('/settings/navigation', { cache: 'no-store' });

    if (response.status === 401) {
      window.location.href = '/login.html';
      return;
    }

    if (response.status === 403) {
      showStatus('Access denied. Contact an administrator.', 'error');
      return;
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    renderItems(Array.isArray(data.items) ? data.items : []);
    showStatus('Navigation settings loaded.', 'success');
  } catch (error) {
    console.error('Unable to load navigation settings', error);
    showStatus('Unable to load navigation settings.', 'error');
  }
}

loadSettings();
