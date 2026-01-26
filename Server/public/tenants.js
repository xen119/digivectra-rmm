const authFetch = (input, init = {}) => fetch(input, { credentials: 'same-origin', ...init });
const tenantStatus = document.getElementById('tenantStatus');
const tenantListWrapper = document.getElementById('tenantListWrapper');
const tenantForm = document.getElementById('tenantForm');
const tenantIdInput = document.getElementById('tenantIdInput');
const tenantNameInput = document.getElementById('tenantNameInput');
const tenantDescriptionInput = document.getElementById('tenantDescriptionInput');
const tenantDomainsInput = document.getElementById('tenantDomainsInput');

function escapeHtml(value) {
  return (value ?? '').toString()
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderTenants(tenants) {
  if (!Array.isArray(tenants) || !tenants.length) {
    tenantListWrapper.innerHTML = '<p>No tenants configured yet.</p>';
    return;
  }

  const rows = tenants.map((tenant) => {
    const domainList = Array.isArray(tenant.domains) ? tenant.domains.join(', ') : '';
    return `
      <tr data-tenant-id="${escapeHtml(tenant.id)}">
        <td><strong>${escapeHtml(tenant.id)}</strong></td>
        <td><input data-field="name" type="text" value="${escapeHtml(tenant.name)}" /></td>
        <td><textarea data-field="description" rows="2">${escapeHtml(tenant.description)}</textarea></td>
        <td><input data-field="domains" type="text" value="${escapeHtml(domainList)}" /></td>
        <td class="tenant-actions">
          <button class="nav-button primary tenant-save" data-tenant="${escapeHtml(tenant.id)}">Save</button>
          ${tenant.id !== 'default' ? `<button class="nav-button tenant-delete" data-tenant="${escapeHtml(tenant.id)}">Delete</button>` : ''}
        </td>
      </tr>`;
  }).join('');

  tenantListWrapper.innerHTML = `
    <table class="tenants-table">
      <thead>
        <tr>
          <th>ID</th>
          <th>Name</th>
          <th>Description</th>
          <th>Domains</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;

  document.querySelectorAll('.tenant-save').forEach((button) => {
    button.addEventListener('click', () => {
      const tenantId = button.dataset.tenant;
      if (!tenantId) {
        return;
      }
      updateTenant(tenantId);
    });
  });

  document.querySelectorAll('.tenant-delete').forEach((button) => {
    button.addEventListener('click', () => {
      const tenantId = button.dataset.tenant;
      if (!tenantId) {
        return;
      }
      deleteTenant(tenantId);
    });
  });
}

function setStatus(message, error = false) {
  if (tenantStatus) {
    tenantStatus.textContent = message;
    tenantStatus.style.color = error ? '#f87171' : '#f8bd0a';
  }
}

async function loadTenants() {
  setStatus('Loading tenants...');
  try {
    const response = await authFetch('/tenants', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const payload = await response.json();
    renderTenants(Array.isArray(payload.tenants) ? payload.tenants : []);
    setStatus('');
  } catch (error) {
    console.error('Unable to load tenants', error);
    setStatus('Failed to load tenants', true);
  }
}

async function createTenant(event) {
  event.preventDefault();
  const id = (tenantIdInput.value ?? '').trim();
  if (!id) {
    setStatus('Tenant ID is required', true);
    return;
  }
  const payload = {
    id,
    name: (tenantNameInput.value ?? '').trim(),
    description: (tenantDescriptionInput.value ?? '').trim(),
    domains: (tenantDomainsInput.value ?? '').trim(),
  };

  setStatus('Creating tenant...');
  try {
    const response = await authFetch('/tenants', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (response.status === 409) {
      setStatus('Tenant already exists', true);
      return;
    }
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    tenantForm.reset();
    await loadTenants();
    setStatus('Tenant created.');
  } catch (error) {
    console.error('Failed to create tenant', error);
    setStatus('Unable to create tenant', true);
  }
}

async function updateTenant(id) {
  const row = document.querySelector(`tr[data-tenant-id="${id}"]`);
  if (!row) {
    return;
  }

  const name = row.querySelector('[data-field="name"]')?.value.trim() ?? '';
  const description = row.querySelector('[data-field="description"]')?.value.trim() ?? '';
  const domains = row.querySelector('[data-field="domains"]')?.value ?? '';
  if (!name && !description && !domains) {
    setStatus('Provide a value to update', true);
    return;
  }

  setStatus(`Updating ${id}...`);
  try {
    const response = await authFetch(`/tenants/${encodeURIComponent(id)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, description, domains }),
    });
    if (!response.ok) {
      if (response.status === 404) {
        setStatus('Tenant no longer exists', true);
        await loadTenants();
        return;
      }
      throw new Error(`HTTP ${response.status}`);
    }
    await loadTenants();
    setStatus(`Updated ${id}`);
  } catch (error) {
    console.error('Failed to update tenant', error);
    setStatus('Unable to update tenant', true);
  }
}

async function deleteTenant(id) {
  if (!confirm(`Delete tenant ${id}? This cannot be undone.`)) {
    return;
  }

  setStatus(`Removing ${id}...`);
  try {
    const response = await authFetch(`/tenants/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (response.status === 400) {
      setStatus('Default tenant cannot be removed', true);
      return;
    }
    if (!response.ok) {
      if (response.status === 404) {
        setStatus('Tenant no longer exists', true);
        await loadTenants();
        return;
      }
      throw new Error(`HTTP ${response.status}`);
    }
    await loadTenants();
    setStatus(`Deleted ${id}`);
  } catch (error) {
    console.error('Unable to delete tenant', error);
    setStatus('Failed to delete tenant', true);
  }
}

tenantForm?.addEventListener('submit', createTenant);
loadTenants();
