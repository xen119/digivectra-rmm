const authFetch = (input, init = {}) => fetch(input, { credentials: 'same-origin', ...init });
const userListEl = document.getElementById('userList');
const userForm = document.getElementById('userForm');
const userMessageEl = document.getElementById('userMessage');
const tenantSelectGroup = document.getElementById('tenantSelectGroup');
const userTenantSelect = document.getElementById('userTenant');

let isGlobalUser = false;
let currentTenantId = '';
let selectedTenantId = '';

function renderUsers(users = []) {
  if (!userListEl) {
    return;
  }

  if (!users.length) {
    userListEl.innerHTML = '<p class="subtitle">No users configured yet.</p>';
    return;
  }

  const rows = users.map((user) => `
    <tr>
      <td><strong>${user.username}</strong></td>
      <td>${user.role}</td>
      <td>${user.tenantId ?? 'default'}</td>
      <td>${user.totpSecret}</td>
      <td>${user.createdAt ? new Date(user.createdAt).toLocaleString() : '—'}</td>
      <td><span class="pill">${user.role}</span></td>
    </tr>
  `);

  userListEl.innerHTML = `
    <table>
      <thead>
    <tr>
      <th>Username</th>
      <th>Role</th>
      <th>Tenant</th>
      <th>TOTP secret</th>
      <th>Created at</th>
      <th>Status</th>
    </tr>
      </thead>
      <tbody>
        ${rows.join('')}
      </tbody>
    </table>
  `;
}

async function loadUsers() {
  if (userListEl) {
    userListEl.innerHTML = '<p class="subtitle">Loading user list…</p>';
  }

  try {
    const params = new URLSearchParams();
    const effectiveTenant = isGlobalUser
      ? (selectedTenantId || currentTenantId) 
      : (currentTenantId || selectedTenantId);
    if (isGlobalUser && effectiveTenant) {
      params.set('tenantId', effectiveTenant);
    }
    const query = params.toString() ? `?${params.toString()}` : '';

    const response = await authFetch(`/users${query}`, { cache: 'no-store' });
    if (!response.ok) {
      const text = await response.text().catch(() => '');
      const message = text || `HTTP ${response.status}`;
      throw new Error(message);
    }

    const payload = await response.json();
    renderUsers(payload.users ?? []);
    showUserMessage('');
  } catch (error) {
    console.error('Failed to load users', error);
    if (userListEl) {
      userListEl.innerHTML = '<p class="subtitle">Unable to load users.</p>';
    }
    showUserMessage(`Unable to load users: ${error.message}`, 'error');
  }
}

function showUserMessage(text, type = '') {
  if (!userMessageEl) {
    return;
  }

  userMessageEl.textContent = text;
  userMessageEl.className = `message ${type}`;
}

async function populateTenantOptions() {
  if (!userTenantSelect) {
    return;
  }

  try {
    const response = await authFetch('/tenants', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    const tenants = Array.isArray(payload.tenants) ? payload.tenants : [];
    userTenantSelect.innerHTML = '';
    tenants.forEach((tenant) => {
      if (!tenant?.id) {
        return;
      }
      const option = document.createElement('option');
      option.value = tenant.id;
      option.textContent = tenant.name ? `${tenant.name} (${tenant.id})` : tenant.id;
      userTenantSelect.appendChild(option);
    });
  } catch (error) {
    console.error('Unable to load tenants', error);
  }
}

async function initializeTenantSelector() {
  if (!tenantSelectGroup) {
    return;
  }

  try {
    const response = await authFetch('/tenants/current', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    isGlobalUser = Boolean(payload?.isGlobal);
    currentTenantId = payload?.tenant?.id ?? '';
    selectedTenantId = selectedTenantId || currentTenantId;

    if (isGlobalUser) {
      tenantSelectGroup.classList.remove('hidden');
      await populateTenantOptions();
      if (userTenantSelect) {
        userTenantSelect.value = currentTenantId || '';
      }
    } else {
      tenantSelectGroup.classList.add('hidden');
    }
  } catch (error) {
    console.error('Unable to initialize tenant selector', error);
    tenantSelectGroup.classList.add('hidden');
  }
}

userForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!userForm) {
    return;
  }

  const formData = new FormData(userForm);
  const payload = {
    username: formData.get('username'),
    password: formData.get('password'),
    role: formData.get('role'),
    totp: formData.get('totp'),
  };
  if (isGlobalUser && userTenantSelect?.value) {
    payload.tenantId = userTenantSelect.value;
  }

  try {
    const response = await authFetch('/users', {
      method: 'POST',
      body: JSON.stringify(payload),
      headers: { 'Content-Type': 'application/json' },
    });

    if (!response.ok) {
      const errorPayload = await response.json().catch(() => null);
      let text = await response.text().catch(() => '');
      const message = errorPayload?.message ?? (text || `HTTP ${response.status}`);
      throw new Error(message);
    }

    const data = await response.json();
    showUserMessage(`Created ${data.username} (${data.role}).`, 'success');
    userForm.reset();
    loadUsers();
  } catch (error) {
    console.error('Failed to create user', error);
    showUserMessage(error.message ?? 'Unable to create user.', 'error');
  }
});

(async function init() {
  await initializeTenantSelector();
  await loadUsers();
})();

if (userTenantSelect) {
  userTenantSelect.addEventListener('change', () => {
    selectedTenantId = userTenantSelect.value || '';
    loadUsers();
  });
}
