const authFetch = (input, init = {}) => fetch(input, { credentials: 'same-origin', ...init });
const userListEl = document.getElementById('userList');
const userForm = document.getElementById('userForm');
const userMessageEl = document.getElementById('userMessage');

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
    const response = await authFetch('/users', { cache: 'no-store' });
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

  try {
    const response = await authFetch('/users', {
      method: 'POST',
      body: JSON.stringify(payload),
      headers: { 'Content-Type': 'application/json' },
    });

    if (!response.ok) {
      const errorPayload = await response.json().catch(() => null);
      let text = await response.text().catch(() => '');
      const message = errorPayload?.message ?? text || `HTTP ${response.status}`;
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

loadUsers();
