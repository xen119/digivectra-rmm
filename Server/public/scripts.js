const scriptForm = document.getElementById('scriptForm');
const scriptList = document.getElementById('scriptList');
const agentSelect = document.getElementById('agentSelect');
const scriptLog = document.getElementById('scriptLog');

const authFetch = (input, init = {}) => fetch(input, { credentials: 'same-origin', ...init });

document.addEventListener('DOMContentLoaded', () => {
  scriptForm?.addEventListener('submit', handleScriptSubmit);
  refreshScripts();
  refreshAgents();
  startEventStream();
});

async function refreshScripts() {
  try {
    const response = await authFetch('/scripts', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const scripts = await response.json();
    renderScriptList(scripts);
  } catch (error) {
    log('error', `Unable to load scripts: ${error.message}`);
  }
}

function renderScriptList(scripts) {
  if (!scriptList) {
    return;
  }

  if (!Array.isArray(scripts) || scripts.length === 0) {
    scriptList.innerHTML = '<div class="script-item">No scripts available.</div>';
    return;
  }

  scriptList.innerHTML = '';
  scripts.forEach((script) => {
    const item = document.createElement('div');
    item.className = 'script-item';
    item.innerHTML = `<strong>${script.name}</strong>
      <div>${script.description ?? 'No description'}</div>
      <div class="badge">${script.language.toUpperCase()}</div>
      <p style="margin:0.5rem 0 0;">File: ${script.file}</p>`;

    const actions = document.createElement('div');
    actions.className = 'script-actions';
    const viewButton = document.createElement('button');
    viewButton.type = 'button';
    viewButton.className = 'secondary';
    viewButton.textContent = 'View content';
    viewButton.addEventListener('click', () => viewScriptContent(script.name));

    const runButton = document.createElement('button');
    runButton.type = 'button';
    runButton.textContent = 'Run on selected agents';
    runButton.addEventListener('click', () => runScript(script.name));

    actions.appendChild(viewButton);
    actions.appendChild(runButton);
    item.appendChild(actions);
    scriptList.appendChild(item);
  });
}

async function viewScriptContent(scriptName) {
  try {
    const response = await authFetch(`/scripts/${encodeURIComponent(scriptName)}/content`, { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const payload = await response.json();
    const message = `
Script: ${payload.name}
---------------
${payload.content}
`;
    log('info', message);
  } catch (error) {
    log('error', `Unable to load ${scriptName}: ${error.message}`);
  }
}

async function runScript(scriptName) {
  if (!agentSelect) {
    return;
  }

  const selected = Array.from(agentSelect.selectedOptions).map((opt) => opt.value);
  if (selected.length === 0) {
    log('error', 'Pick at least one agent before running a script.');
    return;
  }

  try {
    const response = await authFetch('/scripts/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scriptName, agentIds: selected }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const result = await response.json();
    log('info', `Script ${scriptName} scheduled for ${result.triggered.length} agent(s). Missing: ${result.missing.length}`);
  } catch (error) {
    log('error', `Run failed: ${error.message}`);
  }
}

async function handleScriptSubmit(event) {
  event.preventDefault();
  const name = document.getElementById('scriptName')?.value.trim();
  const description = document.getElementById('scriptDescription')?.value.trim();
  const language = document.getElementById('scriptLanguage')?.value;
  const content = document.getElementById('scriptContent')?.value ?? '';

  if (!name || !content) {
    log('error', 'Script name and content are required.');
    return;
  }

  try {
    const response = await authFetch('/scripts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, description, language, content }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    log('info', `Script ${name} saved.`);
    scriptForm.reset();
    await refreshScripts();
  } catch (error) {
    log('error', `Save failed: ${error.message}`);
  }
}

async function refreshAgents() {
  if (!agentSelect) {
    return;
  }

  try {
    const response = await authFetch('/clients', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error('Failed to load agents.');
    }

    const agents = await response.json();
    agentSelect.innerHTML = '';
    agents.forEach((agent) => {
      const option = document.createElement('option');
      option.value = agent.id;
      option.textContent = `${agent.name} (${agent.group ?? 'Ungrouped'})`;
      agentSelect.appendChild(option);
    });
  } catch (error) {
    log('error', error.message);
  }
}

function log(level, message) {
  if (!scriptLog) {
    return;
  }

  const entry = document.createElement('div');
  entry.className = 'log-entry';
  entry.innerHTML = `<strong>${level.toUpperCase()}</strong> - ${message.replace(/\n/g, '<br/>')}`;
  scriptLog.prepend(entry);
  while (scriptLog.childNodes.length > 60) {
    scriptLog.removeChild(scriptLog.lastChild);
  }
}

function startEventStream() {
  const source = new EventSource('/monitoring/events');
  source.addEventListener('script-run', (event) => {
    const payload = JSON.parse(event.data);
    log('event', `Script run requested: ${payload.scriptName} for ${payload.agentIds?.length ?? 0} agent(s).`);
  });
  source.addEventListener('remediation-result', (event) => {
    const payload = JSON.parse(event.data);
    log('info', `Script ${payload.scriptName} finished on ${payload.agentName}: ${payload.message}`);
  });
  source.onerror = () => {
    source.close();
    setTimeout(startEventStream, 5000);
  };
}
