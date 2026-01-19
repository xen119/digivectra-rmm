const DEFAULT_GROUP = 'Ungrouped';
const statusEl = document.getElementById('groupStatus');
const listEl = document.getElementById('groupList');
const form = document.getElementById('newGroupForm');
const nameInput = document.getElementById('newGroupName');
const authFetch = (input, init = {}) => fetch(input, { credentials: 'same-origin', ...init });

if (form) {
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const value = nameInput.value.trim();
    if (!value) {
      showStatus('Enter a valid name first.', 'error');
      return;
    }
    createGroup(value);
  });
}

function showStatus(message, variant = 'info') {
  if (!statusEl) {
    return;
  }
  statusEl.textContent = message;
  statusEl.classList.remove('error', 'success');
  if (variant === 'error') {
    statusEl.classList.add('error');
  } else if (variant === 'success') {
    statusEl.classList.add('success');
  }
}

async function createGroup(name) {
  if (!name) {
    return;
  }
  form?.querySelector('button')?.setAttribute('disabled', 'true');
  showStatus('Creating group...');
  try {
    const response = await authFetch('/groups', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(text || `HTTP ${response.status}`);
    }
    nameInput.value = '';
    showStatus('Group created.', 'success');
    await loadGroups();
  } catch (error) {
    console.error('Unable to create group', error);
    showStatus('Unable to create group. Try again.', 'error');
  } finally {
    form?.querySelector('button')?.removeAttribute('disabled');
  }
}

async function deleteGroup(name) {
  if (!name || name === DEFAULT_GROUP) {
    return;
  }
  const confirmed = window.confirm(`Delete the "${name}" group? Agents assigned to it will move to ${DEFAULT_GROUP}.`);
  if (!confirmed) {
    return;
  }
  showStatus(`Removing ${name}...`);
  try {
    const response = await authFetch('/groups', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(text || `HTTP ${response.status}`);
    }
    showStatus('Group removed.', 'success');
    await loadGroups();
  } catch (error) {
    console.error('Unable to delete group', error);
    showStatus('Unable to remove group. Try again.', 'error');
  }
}

function renderGroups(groups, counts) {
  if (!listEl) {
    return;
  }
  listEl.innerHTML = '';
  if (!groups.length) {
    listEl.textContent = 'No groups configured yet.';
    return;
  }
  groups.forEach((group) => {
    const row = document.createElement('div');
    row.className = 'group-row';

    const meta = document.createElement('div');
    meta.className = 'group-meta';
    const title = document.createElement('strong');
    title.textContent = group;
    const count = document.createElement('small');
    const agents = counts.get(group) ?? 0;
    count.textContent = `${agents} agent${agents === 1 ? '' : 's'}`;
    meta.appendChild(title);
    meta.appendChild(count);

    const actions = document.createElement('div');
    actions.className = 'group-actions';
    if (group !== DEFAULT_GROUP) {
      const deleteButton = document.createElement('button');
      deleteButton.type = 'button';
      deleteButton.className = 'secondary';
      deleteButton.textContent = 'Delete';
      deleteButton.addEventListener('click', () => deleteGroup(group));
      actions.appendChild(deleteButton);
    } else {
      const badge = document.createElement('span');
      badge.textContent = 'Default';
      badge.style.fontSize = '0.85rem';
      badge.style.color = '#94a3b8';
      actions.appendChild(badge);
    }

    row.appendChild(meta);
    row.appendChild(actions);
    listEl.appendChild(row);
  });
}

async function loadGroups() {
  showStatus('Loading groups...');
  try {
    const [groupsResponse, clientsResponse] = await Promise.all([
      authFetch('/groups', { cache: 'no-store' }),
      authFetch('/clients', { cache: 'no-store' }),
    ]);
    if (!groupsResponse.ok || !clientsResponse.ok) {
      throw new Error('Failed to load data');
    }
    const groupData = await groupsResponse.json();
    const clients = await clientsResponse.json();
    const groupList = Array.isArray(groupData.groups) ? groupData.groups : [];
    const counts = clients.reduce((acc, client) => {
      const groupName = client.group ?? DEFAULT_GROUP;
      acc.set(groupName, (acc.get(groupName) ?? 0) + 1);
      return acc;
    }, new Map());
    renderGroups(groupList, counts);
    showStatus('Groups loaded.', 'success');
  } catch (error) {
    console.error('Unable to load groups', error);
    showStatus('Unable to load groups. Try again.', 'error');
  }
}

loadGroups();
