const statusEl = document.getElementById('statusMessage');
const listEl = document.getElementById('settingsList');
const generalStatusEl = document.getElementById('generalStatusMessage');
const screenConsentToggle = document.getElementById('screenConsentToggle');
const tabButtons = document.querySelectorAll('[data-tab-target]');
const tabPanels = document.querySelectorAll('[data-tab-panel]');
const aiStatusEl = document.getElementById('aiStatusMessage');
const aiApiKeyInput = document.getElementById('aiApiKey');
const aiSystemPromptInput = document.getElementById('aiSystemPrompt');
const aiSaveButton = document.getElementById('aiSaveButton');
const aiClearKeyButton = document.getElementById('aiClearKeyButton');
const TAB_STORAGE_KEY = 'settings.activeTab';
const authFetch = (input, init = {}) => fetch(input, { credentials: 'same-origin', ...init });

if (screenConsentToggle) {
  screenConsentToggle.addEventListener('change', () => {
    handleScreenConsentToggle(screenConsentToggle.checked);
  });
}

if (aiSaveButton) {
  aiSaveButton.addEventListener('click', handleAiSave);
}

if (aiClearKeyButton) {
  aiClearKeyButton.addEventListener('click', handleAiClearKey);
}

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

function showGeneralStatus(message, variant = 'info') {
  if (!generalStatusEl) {
    return;
  }

  generalStatusEl.textContent = message;
  generalStatusEl.classList.remove('error', 'success');
  if (variant === 'error') {
    generalStatusEl.classList.add('error');
  } else if (variant === 'success') {
    generalStatusEl.classList.add('success');
  }
}

async function handleScreenConsentToggle(enabled) {
  if (!generalStatusEl || !screenConsentToggle) {
    return;
  }

  screenConsentToggle.disabled = true;
  showGeneralStatus('Saving general settings...');

  try {
    const response = await authFetch('/settings/general', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ screenConsentRequired: enabled }),
    });

    if (response.status === 401) {
      window.location.href = '/login.html';
      return;
    }

    if (response.status === 403) {
      showGeneralStatus('Access denied. Contact an administrator.', 'error');
      return;
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    screenConsentToggle.checked = Boolean(data.screenConsentRequired);
    showGeneralStatus('General settings updated.', 'success');
  } catch (error) {
    console.error('Unable to update general settings', error);
    showGeneralStatus('Unable to update settings. Try again.', 'error');
    screenConsentToggle.checked = !enabled;
  } finally {
    screenConsentToggle.disabled = false;
  }
}

async function loadGeneralSettings() {
  if (!generalStatusEl || !screenConsentToggle) {
    return;
  }

  screenConsentToggle.disabled = true;
  showGeneralStatus('Loading general settings...');

  try {
    const response = await authFetch('/settings/general', { cache: 'no-store' });

    if (response.status === 401) {
      window.location.href = '/login.html';
      return;
    }

    if (response.status === 403) {
      showGeneralStatus('Access denied. Contact an administrator.', 'error');
      return;
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    screenConsentToggle.checked = Boolean(data.screenConsentRequired);
    showGeneralStatus('General settings loaded.', 'success');
  } catch (error) {
    console.error('Unable to load general settings', error);
    showGeneralStatus('Unable to load general settings.', 'error');
  } finally {
    screenConsentToggle.disabled = false;
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

function showAiStatus(message, variant = 'info') {
  if (!aiStatusEl) {
    return;
  }

  aiStatusEl.textContent = message;
  aiStatusEl.classList.remove('error', 'success');
  if (variant === 'error') {
    aiStatusEl.classList.add('error');
  } else if (variant === 'success') {
    aiStatusEl.classList.add('success');
  }
}

async function loadAiSettings() {
  if (!aiStatusEl || !aiSystemPromptInput) {
    return;
  }

  showAiStatus('Loading AI settings...');
  try {
    const response = await authFetch('/settings/ai', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    aiSystemPromptInput.value = typeof data.systemPrompt === 'string' ? data.systemPrompt : '';
    showAiStatus(data.apiKeyConfigured ? 'AI key configured.' : 'Enter an OpenAI API key to enable the agent.');
  } catch (error) {
    console.error('Unable to load AI settings', error);
    showAiStatus('Unable to load AI settings.', 'error');
  }
}

async function handleAiSave() {
  if (!aiSaveButton || !aiSystemPromptInput) {
    return;
  }

  aiSaveButton.disabled = true;
  showAiStatus('Saving AI settings...');
  const payload = {
    systemPrompt: aiSystemPromptInput.value ?? '',
  };
  const apiKeyValue = aiApiKeyInput?.value?.trim();
  if (apiKeyValue) {
    payload.apiKey = apiKeyValue;
  }

  try {
    const response = await authFetch('/settings/ai', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    if (aiApiKeyInput) {
      aiApiKeyInput.value = '';
    }
    showAiStatus('AI settings saved.', 'success');
    await loadAiSettings();
  } catch (error) {
    console.error('Unable to save AI settings', error);
    showAiStatus('Unable to save AI settings.', 'error');
  } finally {
    aiSaveButton.disabled = false;
  }
}

async function handleAiClearKey() {
  if (!aiClearKeyButton) {
    return;
  }

  aiClearKeyButton.disabled = true;
  showAiStatus('Clearing stored API key...');
  const payload = {
    systemPrompt: aiSystemPromptInput?.value ?? '',
    apiKey: '',
  };

  try {
    const response = await authFetch('/settings/ai', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    if (aiApiKeyInput) {
      aiApiKeyInput.value = '';
    }
    showAiStatus('Stored API key cleared.', 'success');
    await loadAiSettings();
  } catch (error) {
    console.error('Unable to clear API key', error);
    showAiStatus('Unable to clear API key.', 'error');
  } finally {
    aiClearKeyButton.disabled = false;
  }
}

loadSettings();
loadGeneralSettings();
loadAiSettings();
configureTabs();

function configureTabs() {
  if (!tabButtons.length || !tabPanels.length) {
    return;
  }

  tabButtons.forEach((button) => {
    button.addEventListener('click', () => {
      const target = button.dataset.tabTarget;
      if (target) {
        setActiveTab(target);
      }
    });
  });

  const initialTab = localStorage.getItem(TAB_STORAGE_KEY) ?? 'general';
  setActiveTab(initialTab);
}

function setActiveTab(tabKey) {
  const panels = Array.from(tabPanels);
  const buttons = Array.from(tabButtons);
  const availableTabs = panels.map((panel) => panel.dataset.tabPanel);
  const targetKey = availableTabs.includes(tabKey) ? tabKey : 'navigation';

  buttons.forEach((button) => {
    const isActive = button.dataset.tabTarget === targetKey;
    button.classList.toggle('active', isActive);
    button.setAttribute('aria-selected', isActive ? 'true' : 'false');
  });

  panels.forEach((panel) => {
    const isActive = panel.dataset.tabPanel === targetKey;
    panel.classList.toggle('active', isActive);
    if (isActive) {
      panel.removeAttribute('hidden');
    } else {
      panel.setAttribute('hidden', '');
    }
  });

  localStorage.setItem(TAB_STORAGE_KEY, targetKey);
}
