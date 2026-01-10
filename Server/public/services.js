const params = new URLSearchParams(window.location.search);
const agentId = params.get('agent');
const agentName = params.get('name');

const agentHeader = document.getElementById('agentInfo');
const refreshButton = document.getElementById('refreshButton');
const statusText = document.getElementById('statusText');
const serviceTableBody = document.getElementById('serviceTableBody');

function setStatus(message, isError = false) {
  if (!statusText) {
    return;
  }
  statusText.textContent = message;
  statusText.style.color = isError ? '#f87171' : '#94a3b8';
}

function setAgentHeader(text) {
  if (!agentHeader) {
    return;
  }
  agentHeader.textContent = text;
}

async function loadServices() {
  if (!agentId) {
    setStatus('Agent id missing.', true);
    renderServices([]);
    return;
  }

  setAgentHeader(agentName ? `${agentName} (${agentId})` : `Agent ${agentId}`);
  setStatus('Loading services...');

  try {
    const response = await fetch(`/agent/${encodeURIComponent(agentId)}/services`, {
      credentials: 'same-origin',
    });

    if (!response.ok) {
      throw new Error(`Server returned ${response.status}`);
    }

    const payload = await response.json();
    renderServices(Array.isArray(payload.services) ? payload.services : []);
    setStatus(`Last refreshed ${new Date().toLocaleTimeString()}`);
  } catch (error) {
    console.error(error);
    setStatus('Failed to load services.', true);
    renderServices([]);
  }
}

function renderServices(services) {
  if (!serviceTableBody) {
    return;
  }

  serviceTableBody.innerHTML = '';

  if (!services.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.className = 'empty';
    cell.setAttribute('colspan', '5');
    cell.textContent = 'No services reported.';
    row.appendChild(cell);
    serviceTableBody.appendChild(row);
    return;
  }

  services.forEach((service) => {
    const row = document.createElement('tr');

    const nameCell = document.createElement('td');
    nameCell.textContent = service.name ?? '';
    row.appendChild(nameCell);

    const displayCell = document.createElement('td');
    displayCell.textContent = service.displayName ?? '';
    row.appendChild(displayCell);

    const statusCell = document.createElement('td');
    const status = (service.status ?? 'Unknown').toLowerCase();
    const statusPill = document.createElement('span');
    statusPill.className = `status-pill ${status}`;
    statusPill.textContent = status.charAt(0).toUpperCase() + status.slice(1);
    statusCell.appendChild(statusPill);
    row.appendChild(statusCell);

    const startCell = document.createElement('td');
    startCell.textContent = service.startType ?? '-';
    row.appendChild(startCell);

    const actionCell = document.createElement('td');
    actionCell.appendChild(createActionButtons(service));
    row.appendChild(actionCell);

    serviceTableBody.appendChild(row);
  });
}

function createActionButtons(service) {
  const wrapper = document.createElement('div');
  wrapper.className = 'actions';

  const startBtn = document.createElement('button');
  startBtn.type = 'button';
  startBtn.className = 'start';
  startBtn.textContent = 'Start';
  startBtn.disabled = (service.status ?? '').toLowerCase() === 'running';
  startBtn.addEventListener('click', () => executeAction(service, 'start', startBtn));

  const stopBtn = document.createElement('button');
  stopBtn.type = 'button';
  stopBtn.className = 'stop';
  stopBtn.textContent = 'Stop';
  stopBtn.disabled = (service.status ?? '').toLowerCase() === 'stopped';
  stopBtn.addEventListener('click', () => executeAction(service, 'stop', stopBtn));

  const restartBtn = document.createElement('button');
  restartBtn.type = 'button';
  restartBtn.className = 'restart';
  restartBtn.textContent = 'Restart';
  restartBtn.disabled = false;
  restartBtn.addEventListener('click', () => executeAction(service, 'restart', restartBtn));

  wrapper.appendChild(startBtn);
  wrapper.appendChild(stopBtn);
  wrapper.appendChild(restartBtn);
  return wrapper;
}

async function executeAction(service, action, button) {
  if (!agentId || !service.name) {
    return;
  }

  button.disabled = true;
  setStatus(`${action.charAt(0).toUpperCase() + action.slice(1)} requested...`);

  try {
    const response = await fetch(`/agent/${encodeURIComponent(agentId)}/service/${encodeURIComponent(service.name)}/action`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action }),
    });

    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload?.message || `Server returned ${response.status}`);
    }

    setStatus(payload?.message ?? 'Action completed');
    await loadServices();
  } catch (error) {
    console.error(error);
    setStatus(error.message ?? 'Action failed', true);
  } finally {
    button.disabled = false;
  }
}

refreshButton?.addEventListener('click', () => loadServices());
loadServices();
