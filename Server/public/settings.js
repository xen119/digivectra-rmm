const statusEl = document.getElementById('statusMessage');
const listEl = document.getElementById('settingsList');
const generalStatusEl = document.getElementById('generalStatusMessage');
const screenConsentToggle = document.getElementById('screenConsentToggle');
const autoAiChatToggle = document.getElementById('autoAiChatToggle');
const tabButtons = document.querySelectorAll('[data-tab-target]');
const tabPanels = document.querySelectorAll('[data-tab-panel]');
const aiStatusEl = document.getElementById('aiStatusMessage');
const aiApiKeyInput = document.getElementById('aiApiKey');
const aiSystemPromptInput = document.getElementById('aiSystemPrompt');
const aiSaveButton = document.getElementById('aiSaveButton');
const aiClearKeyButton = document.getElementById('aiClearKeyButton');
const techDirectStatusEl = document.getElementById('techDirectStatusMessage');
const techDirectApiKeyInput = document.getElementById('techDirectApiKey');
const techDirectApiSecretInput = document.getElementById('techDirectApiSecret');
const techDirectSaveButton = document.getElementById('techDirectSaveButton');
const techDirectClearButton = document.getElementById('techDirectClearButton');
const snmpStatusEl = document.getElementById('snmpStatusMessage');
const snmpV1PortInput = document.getElementById('snmpV1Port');
const snmpV1CommunityInput = document.getElementById('snmpV1Community');
const snmpV1ResolveInput = document.getElementById('snmpV1Resolve');
const snmpV2PortInput = document.getElementById('snmpV2Port');
const snmpV2CommunityInput = document.getElementById('snmpV2Community');
const snmpV2ResolveInput = document.getElementById('snmpV2Resolve');
const snmpV3PortInput = document.getElementById('snmpV3Port');
const snmpV3UsernameInput = document.getElementById('snmpV3Username');
const snmpV3AuthProtocolInput = document.getElementById('snmpV3AuthProtocol');
const snmpV3AuthPasswordInput = document.getElementById('snmpV3AuthPassword');
const snmpV3PrivProtocolInput = document.getElementById('snmpV3PrivProtocol');
const snmpV3PrivPasswordInput = document.getElementById('snmpV3PrivPassword');
const snmpV3ResolveInput = document.getElementById('snmpV3Resolve');
const snmpSaveButton = document.getElementById('snmpSaveButton');
const snmpDefaultVersionSelect = document.getElementById('snmpDefaultVersion');
const snmpV3ModeSelect = document.getElementById('snmpV3Mode');
const snmpV3AuthFields = document.getElementById('snmpV3AuthFields');
const snmpV3PrivFields = document.getElementById('snmpV3PrivFields');
const TAB_STORAGE_KEY = 'settings.activeTab';
const MIN_SNMP_PORT = 1;
const MAX_SNMP_PORT = 65535;
const authFetch = (input, init = {}) => fetch(input, { credentials: 'same-origin', ...init });

function parseSnmpPort(value, fallback) {
  const parsed = Number(value);
  if (Number.isInteger(parsed) && parsed >= MIN_SNMP_PORT && parsed <= MAX_SNMP_PORT) {
    return parsed;
  }

  return fallback;
}

if (screenConsentToggle) {
  screenConsentToggle.addEventListener('change', () => {
    handleScreenConsentToggle(screenConsentToggle.checked);
  });
}

if (autoAiChatToggle) {
  autoAiChatToggle.addEventListener('change', () => {
    handleAutoAiChatToggle(autoAiChatToggle.checked);
  });
}

if (aiSaveButton) {
  aiSaveButton.addEventListener('click', handleAiSave);
}

if (aiClearKeyButton) {
  aiClearKeyButton.addEventListener('click', handleAiClearKey);
}

if (techDirectSaveButton) {
  techDirectSaveButton.addEventListener('click', handleTechDirectSave);
}

if (techDirectClearButton) {
  techDirectClearButton.addEventListener('click', handleTechDirectClear);
}

if (snmpSaveButton) {
  snmpSaveButton.addEventListener('click', handleSnmpSave);
}

if (snmpV3ModeSelect) {
  snmpV3ModeSelect.addEventListener('change', () => {
    updateSnmpV3FieldVisibility(snmpV3ModeSelect.value);
  });
  updateSnmpV3FieldVisibility(snmpV3ModeSelect.value);
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

function showTechDirectStatus(message, variant = 'info') {
  if (!techDirectStatusEl) {
    return;
  }

  techDirectStatusEl.textContent = message;
  techDirectStatusEl.classList.remove('error', 'success');
  if (variant === 'error') {
    techDirectStatusEl.classList.add('error');
  } else if (variant === 'success') {
    techDirectStatusEl.classList.add('success');
  }
}

function showSnmpStatus(message, variant = 'info') {
  if (!snmpStatusEl) {
    return;
  }

  snmpStatusEl.textContent = message;
  snmpStatusEl.classList.remove('error', 'success');
  if (variant === 'error') {
    snmpStatusEl.classList.add('error');
  } else if (variant === 'success') {
    snmpStatusEl.classList.add('success');
  }
}

function populateSnmpFields(snmp, defaultVersion = 'v3') {
  const v1 = (snmp && typeof snmp.v1 === 'object' && snmp.v1 !== null) ? snmp.v1 : {};
  const v2 = (snmp && typeof snmp.v2c === 'object' && snmp.v2c !== null) ? snmp.v2c : {};
  const v3 = (snmp && typeof snmp.v3 === 'object' && snmp.v3 !== null) ? snmp.v3 : {};

  if (snmpV1PortInput) {
    snmpV1PortInput.value = (v1.port ?? 161).toString();
  }
  if (snmpV1CommunityInput) {
    snmpV1CommunityInput.value = v1.community ?? 'public';
  }
  if (snmpV1ResolveInput) {
    snmpV1ResolveInput.checked = Boolean(v1.resolveNamesOnly);
  }

  if (snmpV2PortInput) {
    snmpV2PortInput.value = (v2.port ?? 161).toString();
  }
  if (snmpV2CommunityInput) {
    snmpV2CommunityInput.value = v2.community ?? 'public';
  }
  if (snmpV2ResolveInput) {
    snmpV2ResolveInput.checked = Boolean(v2.resolveNamesOnly);
  }

  if (snmpV3PortInput) {
    snmpV3PortInput.value = (v3.port ?? 161).toString();
  }
  if (snmpV3UsernameInput) {
    snmpV3UsernameInput.value = v3.username ?? '';
  }
  if (snmpV3AuthProtocolInput) {
    snmpV3AuthProtocolInput.value = v3.authProtocol ?? 'SHA1';
  }
  if (snmpV3AuthPasswordInput) {
    snmpV3AuthPasswordInput.value = v3.authPassword ?? '';
  }
  if (snmpV3PrivProtocolInput) {
    snmpV3PrivProtocolInput.value = v3.privProtocol ?? 'AES';
  }
  if (snmpV3PrivPasswordInput) {
    snmpV3PrivPasswordInput.value = v3.privPassword ?? '';
  }
  if (snmpV3ResolveInput) {
    snmpV3ResolveInput.checked = Boolean(v3.resolveNamesOnly);
  }

  if (snmpDefaultVersionSelect) {
    snmpDefaultVersionSelect.value = typeof defaultVersion === 'string' ? defaultVersion : 'v3';
  }

  const v3Mode = determineSnmpV3Mode(v3);
  if (snmpV3ModeSelect) {
    snmpV3ModeSelect.value = v3Mode;
  }
  updateSnmpV3FieldVisibility(v3Mode);
}

function determineSnmpV3Mode(v3 = {}) {
  if (!v3 || typeof v3 !== 'object') {
    return 'no-auth';
  }

  const authPassword = typeof v3.authPassword === 'string' ? v3.authPassword.trim() : '';
  const privPassword = typeof v3.privPassword === 'string' ? v3.privPassword.trim() : '';
  const hasAuth = authPassword.length > 0;
  const hasPriv = privPassword.length > 0;

  if (hasPriv) {
    return 'auth-priv';
  }

  if (hasAuth) {
    return 'auth';
  }

  return 'no-auth';
}

function updateSnmpV3FieldVisibility(mode) {
  const showAuth = mode === 'auth' || mode === 'auth-priv';
  const showPriv = mode === 'auth-priv';

  if (snmpV3AuthFields) {
    snmpV3AuthFields.style.display = showAuth ? 'flex' : 'none';
  }

  if (snmpV3PrivFields) {
    snmpV3PrivFields.style.display = showPriv ? 'flex' : 'none';
  }
}

function collectSnmpPayload() {
  return {
    v1: {
      port: parseSnmpPort(snmpV1PortInput?.value, 161),
      community: (snmpV1CommunityInput?.value ?? '').trim(),
      resolveNamesOnly: Boolean(snmpV1ResolveInput?.checked),
    },
    v2c: {
      port: parseSnmpPort(snmpV2PortInput?.value, 161),
      community: (snmpV2CommunityInput?.value ?? '').trim(),
      resolveNamesOnly: Boolean(snmpV2ResolveInput?.checked),
    },
    v3: {
      port: parseSnmpPort(snmpV3PortInput?.value, 161),
      username: (snmpV3UsernameInput?.value ?? '').trim(),
      authProtocol: snmpV3AuthProtocolInput?.value ?? 'SHA1',
      authPassword: snmpV3AuthPasswordInput?.value ?? '',
      privProtocol: snmpV3PrivProtocolInput?.value ?? 'AES',
      privPassword: snmpV3PrivPasswordInput?.value ?? '',
      resolveNamesOnly: Boolean(snmpV3ResolveInput?.checked),
    },
  };
}

async function handleSnmpSave() {
  if (!snmpSaveButton) {
    return;
  }

  snmpSaveButton.disabled = true;
  showSnmpStatus('Saving SNMP defaults...');

  try {
    const payload = {
      snmp: collectSnmpPayload(),
      snmpVersion: (snmpDefaultVersionSelect?.value ?? 'v3').toLowerCase(),
    };
    const response = await authFetch('/settings/general', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (response.status === 401) {
      window.location.href = '/login.html';
      return;
    }

    if (response.status === 403) {
      showSnmpStatus('Access denied. Contact an administrator.', 'error');
      return;
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    populateSnmpFields(data.snmp ?? {}, data.snmpVersion);
    showSnmpStatus('SNMP defaults saved.', 'success');
  } catch (error) {
    console.error('Unable to save SNMP settings', error);
    showSnmpStatus('Unable to save SNMP settings.', 'error');
  } finally {
    snmpSaveButton.disabled = false;
  }
}

function updateTechDirectStatus(configured) {
  if (!techDirectStatusEl) {
    return;
  }

  if (configured) {
    showTechDirectStatus('TechDirect credentials configured.', 'success');
  } else {
    showTechDirectStatus('Enter TechDirect API credentials to display Dell warranty info.');
  }
}

async function handleScreenConsentToggle(enabled) {
  if (!screenConsentToggle) {
    return;
  }
  await updateGeneralSettings({ screenConsentRequired: enabled }, screenConsentToggle, !enabled);
}

async function handleAutoAiChatToggle(enabled) {
  if (!autoAiChatToggle) {
    return;
  }
  await updateGeneralSettings({ autoRespondToAgentChat: enabled }, autoAiChatToggle, !enabled);
}

async function handleTechDirectSave() {
  if (!techDirectSaveButton) {
    return;
  }

  const apiKeyValue = techDirectApiKeyInput?.value?.trim() ?? '';
  const apiSecretValue = techDirectApiSecretInput?.value?.trim() ?? '';
  if (!apiKeyValue || !apiSecretValue) {
    showTechDirectStatus('Provide both API key and secret before saving.', 'error');
    return;
  }

  techDirectSaveButton.disabled = true;
  if (techDirectClearButton) {
    techDirectClearButton.disabled = true;
  }
  showTechDirectStatus('Saving TechDirect credentials...');

  try {
    const response = await authFetch('/settings/general', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        techDirectApiKey: apiKeyValue,
        techDirectApiSecret: apiSecretValue,
      }),
    });

    if (response.status === 401) {
      window.location.href = '/login.html';
      return;
    }

    if (response.status === 403) {
      showTechDirectStatus('Access denied. Contact an administrator.', 'error');
      return;
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    if (techDirectApiKeyInput) {
      techDirectApiKeyInput.value = '';
    }
    if (techDirectApiSecretInput) {
      techDirectApiSecretInput.value = '';
    }
    showTechDirectStatus('TechDirect credentials saved.', 'success');
    updateTechDirectStatus(Boolean(data.techDirectConfigured));
  } catch (error) {
    console.error('Unable to save TechDirect credentials', error);
    showTechDirectStatus('Unable to save TechDirect credentials.', 'error');
  } finally {
    techDirectSaveButton.disabled = false;
    if (techDirectClearButton) {
      techDirectClearButton.disabled = false;
    }
  }
}

async function handleTechDirectClear() {
  if (!techDirectClearButton) {
    return;
  }

  techDirectClearButton.disabled = true;
  if (techDirectSaveButton) {
    techDirectSaveButton.disabled = true;
  }
  showTechDirectStatus('Clearing stored credentials...');

  try {
    const response = await authFetch('/settings/general', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        techDirectApiKey: '',
        techDirectApiSecret: '',
      }),
    });

    if (response.status === 401) {
      window.location.href = '/login.html';
      return;
    }

    if (response.status === 403) {
      showTechDirectStatus('Access denied. Contact an administrator.', 'error');
      return;
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    showTechDirectStatus('Stored TechDirect credentials cleared.', 'success');
    updateTechDirectStatus(Boolean(data.techDirectConfigured));
  } catch (error) {
    console.error('Unable to clear TechDirect credentials', error);
    showTechDirectStatus('Unable to clear TechDirect credentials.', 'error');
  } finally {
    techDirectClearButton.disabled = false;
    if (techDirectSaveButton) {
      techDirectSaveButton.disabled = false;
    }
  }
}

async function updateGeneralSettings(payload, toggleEl, fallbackValue) {
  if (!toggleEl) {
    return;
  }

  toggleEl.disabled = true;
  showGeneralStatus('Saving general settings...');

  try {
    const response = await authFetch('/settings/general', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
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
    if (screenConsentToggle) {
      screenConsentToggle.checked = Boolean(data.screenConsentRequired);
    }
    if (autoAiChatToggle) {
      autoAiChatToggle.checked = Boolean(data.autoRespondToAgentChat);
    }
    showGeneralStatus('General settings updated.', 'success');
  } catch (error) {
    console.error('Unable to update general settings', error);
    showGeneralStatus('Unable to update settings. Try again.', 'error');
    toggleEl.checked = fallbackValue;
  } finally {
    toggleEl.disabled = false;
  }
}

async function loadGeneralSettings() {
  if (!generalStatusEl || !screenConsentToggle) {
    return;
  }

  if (techDirectStatusEl) {
    showTechDirectStatus('Loading TechDirect settings...');
  }

  const toggles = [screenConsentToggle, autoAiChatToggle].filter(Boolean);
  toggles.forEach((toggle) => {
    toggle.disabled = true;
  });
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
    if (autoAiChatToggle) {
      autoAiChatToggle.checked = Boolean(data.autoRespondToAgentChat);
    }
    updateTechDirectStatus(Boolean(data.techDirectConfigured));
    populateSnmpFields(data.snmp ?? {}, data.snmpVersion);
    showSnmpStatus('SNMP defaults loaded.', 'success');
    showGeneralStatus('General settings loaded.', 'success');
  } catch (error) {
    console.error('Unable to load general settings', error);
    showGeneralStatus('Unable to load general settings.', 'error');
    showTechDirectStatus('Unable to load TechDirect settings.', 'error');
    showSnmpStatus('Unable to load SNMP settings.', 'error');
  } finally {
    toggles.forEach((toggle) => {
      toggle.disabled = false;
    });
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
