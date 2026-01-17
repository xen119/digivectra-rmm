const fs = require('fs');
const https = require('https');
const path = require('path');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const { authenticator } = require('otplib');
const WebSocket = require('ws');
const archiver = require('archiver');

const CERT_DIR = path.join(__dirname, 'certs');
const PORT = process.env.PORT ? Number(process.env.PORT) : 8443;
const USERS_CONFIG_PATH = path.join(__dirname, 'config', 'users.json');
const AGENT_DOWNLOAD_DIR = process.env.AGENT_DOWNLOAD_DIR
  ? path.resolve(process.env.AGENT_DOWNLOAD_DIR)
  : path.join(__dirname, '..', 'AgentPublished');
const AGENT_BUILD_FALLBACK_DIR = path.join(__dirname, '..', 'Agent', 'bin', 'Debug', 'net8.0-windows');

const certPath = path.join(CERT_DIR, 'server.crt');
const keyPath = path.join(CERT_DIR, 'server.key');

if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
  console.error('TLS certificate not found.');
  console.error(`Place server.crt and server.key in ${CERT_DIR}`);
  process.exit(1);
}

const PUBLIC_DIR = path.join(__dirname, 'public');
const server = https.createServer({
  cert: fs.readFileSync(certPath),
  key: fs.readFileSync(keyPath),
});

const DEFAULT_GROUP = 'Ungrouped';
const DATA_DIR = path.join(__dirname, 'data');
const MONITORING_CONFIG_PATH = path.join(DATA_DIR, 'monitoring.json');
const FIREWALL_BASELINE_PATH = path.join(DATA_DIR, 'firewall-baseline.json');
const NAVIGATION_CONFIG_PATH = path.join(DATA_DIR, 'navigation.json');
const GROUPS_CONFIG_PATH = path.join(DATA_DIR, 'groups.json');
const AGENT_GROUP_ASSIGNMENTS_PATH = path.join(DATA_DIR, 'agent-groups.json');
const VULNERABILITY_CONFIG_PATH = path.join(__dirname, 'config', 'vulnerability.json');
const VULNERABILITY_STORE_PATH = path.join(DATA_DIR, 'vulnerabilities.json');
const clients = new Map(); // socket -> info
const agents = new Map(); // id -> info (persist offline)
const clientsById = new Map(); // id -> { socket, info }
const shellStreams = new Map(); // id -> response
const screenSessions = new Map(); // sessionId -> session data
const groups = loadGroups();
const agentGroupAssignments = loadAgentGroupAssignments(groups);
const screenLists = new Map(); // agentId -> { screens, updatedAt }
const screenListRequests = new Map(); // agentId -> { resolvers: [], timer }
const FILE_REQUEST_TIMEOUT_MS = 120_000;
const FILE_UPLOAD_CHUNK_BYTES = 256 * 1024;
const fileRequests = new Map(); // requestId -> { kind, agentId, resolve, reject, timer }
const SOFTWARE_REQUEST_TIMEOUT_MS = 60_000;
const softwareRequests = new Map(); // requestId -> { agentId, resolve, reject, timer }
const SERVICE_REQUEST_TIMEOUT_MS = 60_000;
const serviceRequests = new Map();
const patchApprovals = new Map(); // `${agentId}:${updateId}` -> { approvedAt }
const patchSchedules = new Map(); // scheduleId -> schedule data
const PATCH_SCHEDULE_TICK_MS = 5_000;
const PATCH_SCHEDULE_RETRY_MS = 15_000;
const patchHistory = [];
const PATCH_HISTORY_LIMIT = 200;
const PATCH_CATEGORY_ORDER = [
  'Security Updates',
  'Feature Updates',
  'Driver Updates',
  'Definition Updates',
  'Optional Updates',
  'Out-of-Band Updates',
  'Servicing Stack Updates',
  'Cumulative Updates',
  'Other Updates',
];
const MIN_SCREEN_SCALE = 0.35;
const MAX_SCREEN_SCALE = 1.0;
const DEFAULT_SCREEN_SCALE = 0.75;
const chatListeners = new Map(); // agentId -> Set<ServerResponse>
const chatHistories = new Map(); // agentId -> [{ sessionId, text, direction, agentName, timestamp }]
const chatNotificationCounts = new Map();
const CHAT_HISTORY_LIMIT = 200;
const agentChatLastTimestamp = new Map();
const SCREEN_LIST_TTL_MS = 60_000;
const SCREEN_LIST_TIMEOUT_MS = 5_000;
const NAVIGATION_ITEMS = [
  {
    id: 'monitoring',
    label: 'Monitoring',
    href: 'monitoring.html',
    description: 'View active monitoring profiles, metrics, and alerts.',
  },
  {
    id: 'system-health',
    label: 'System Health',
    href: 'system-health.html',
    description: 'Review overall system health and diagnostics.',
  },
  {
    id: 'firewall-baseline',
    label: 'Firewall Baseline',
    href: 'firewall-baseline.html',
    description: 'Track baseline firewall policies and deviations.',
  },
  {
    id: 'vulnerabilities',
    label: 'Vulnerabilities',
    href: 'vulnerabilities.html',
    description: 'Browse the vulnerability catalog and CVE details.',
  },
  {
    id: 'patches',
    label: 'Patch Management',
    href: 'patches.html',
    description: 'Approve, schedule, and monitor Windows updates.',
  },
  {
    id: 'software-management',
    label: 'Software Inventory',
    href: 'software-management.html',
    description: 'Inspect software inventory, approvals, and actions.',
  },
  {
    id: 'scripts',
    label: 'Scripts',
    href: 'scripts.html',
    description: 'Upload and execute remediation scripts.',
  },
  {
    id: 'scheduler',
    label: 'Scheduler',
    href: 'scheduler.html',
    description: 'Create recurring automation or patch campaigns.',
  },
  {
    id: 'users',
    label: 'Users',
    href: 'users.html',
    description: 'Manage dashboard users, roles, and access.',
  },
];
const SESSION_TTL_MS = 30 * 60_1000;
const SSO_SECRET = process.env.SSO_SECRET ?? 'CHANGE_ME-SSO-KEY';
const SSO_WINDOW_MS = 5 * 60_1000;
const REMEDIATION_DIR = path.join(__dirname, 'scripts', 'remediation');
const SOFTWARE_UNINSTALL_INTERVAL_MS = 60 * 60_1000;
const softwareApprovals = new Map(); // softwareId -> { state: 'approved'|'rejected'|'pending' }
const softwareUninstallQueue = new Map(); // softwareId -> { pending: Set<agentId>, lastAttempt: Map<agentId, timestamp> }
const softwareUninstallLog = [];
const SOFTWARE_UNINSTALL_LOG_LIMIT = 200;
const SERVICE_ACTION_TIMEOUT_MS = 30_000;
const serviceActionRequests = new Map();
const FIREWALL_REQUEST_TIMEOUT_MS = 30_000;
const firewallRequests = new Map();
const EVENT_STATS_TIMEOUT_MS = 30_000;
const EVENT_ENTRIES_TIMEOUT_MS = 30_000;
const eventStatsRequests = new Map();
const eventEntriesRequests = new Map();
const agentEventStatsCache = new Map();

let USERS_CONFIG = loadUsersConfig();
const monitoringEvents = new Set();
const monitoringConfig = loadMonitoringConfig();
const firewallBaselines = loadFirewallBaselines();
const vulnerabilityConfig = loadVulnerabilityConfig();
const vulnerabilityStore = loadVulnerabilityStore();
const monitoringHistory = [];
const MONITORING_HISTORY_LIMIT = 100;
const agentMetrics = new Map(); // agentId -> [{ timestamp, cpuPercent?, ramPercent? }]
const alertStates = new Map(); // `${agentId}:${profileId}:${ruleId}` -> boolean
const agentAlertStatus = new Map(); // agentId -> boolean
const agentProfileStatus = new Map(); // agentId -> Map<profileId, boolean>
const sessions = new Map();
const roleWeight = { viewer: 0, operator: 1, admin: 2 };
const assetVulnerabilityCache = new Map();
const vulnerabilityIngestionTimers = [];
const navigationVisibility = loadNavigationVisibility();

server.on('request', async (req, res) => {
  const requestedUrl = new URL(req.url ?? '/', `https://${req.headers.host ?? 'localhost'}`);
  const pathname = requestedUrl.pathname;

  if (pathname.startsWith('/auth/')) {
    handleAuthRoute(req, res, pathname, requestedUrl);
    return;
  }

  const chatReadMatch = pathname.match(/^\/chat\/([^/]+)\/read$/);
  if (chatReadMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const agentId = chatReadMatch[1];
    clearChatNotification(agentId);
    res.writeHead(204);
    res.end();
    return;
  }

  if (pathname === '/login.html' || pathname === '/login.js') {
    serveStaticAsset(req, res, pathname);
    return;
  }

  const session = getSessionFromRequest(req);
  if (!session) {
    respondUnauthorized(req, res);
    return;
  }

  req.userSession = session;

  if (pathname === '/clients' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    const payload = Array.from(agents.values()).map((info) => ({
      id: info.id,
      name: info.name,
      os: info.os,
      platform: info.platform,
      connectedAt: info.connectedAt,
      remoteAddress: info.remoteAddress,
      group: info.group ?? DEFAULT_GROUP,
      specs: info.specs ?? null,
      updatesSummary: info.updatesSummary ?? null,
      bsodSummary: info.bsodSummary ?? null,
      processSnapshot: info.processSnapshot ?? null,
      status: info.status ?? 'offline',
      lastSeen: info.lastSeen ?? null,
      loggedInUser: info.loggedInUser ?? null,
      pendingReboot: info.pendingReboot ?? false,
      monitoringEnabled: shouldMonitorAgent(info),
      monitoringAlert: agentAlertStatus.get(info.id) ?? false,
      monitoringProfiles: getAgentMonitoringProfiles(info),
      softwareSummary: info.softwareSummary ?? null,
      features: Array.isArray(info.features) ? info.features : [],
      bitlockerStatus: info.bitlockerStatus ?? null,
      avStatus: info.avStatus ?? null,
      chatNotifications: chatNotificationCounts.get(info.id) ?? 0,
    }));
    return res.end(JSON.stringify(payload));
  }

  if (pathname === '/groups' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ groups: Array.from(groups).sort() }));
    return;
  }

  if (pathname === '/groups' && req.method === 'POST') {
    collectBody(req, (body) => {
      try {
        const { name } = JSON.parse(body);
        const normalized = normalizeGroupName(name);
        if (!normalized) {
          res.writeHead(400);
          return res.end('Invalid group name');
        }

        groups.add(normalized);
        persistGroups();
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ name: normalized }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  if (pathname === '/groups/assign' && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }
    collectBody(req, (body) => {
      try {
        const { agentId, group } = JSON.parse(body);
        const entry = clientsById.get(agentId);
        if (!entry) {
          res.writeHead(404);
          return res.end('Agent not found');
        }

        const normalized = normalizeGroupName(group);
        const assignedGroup = assignAgentToGroup(agentId, normalized);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ group: assignedGroup }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const usersGetMatch = pathname === '/users' && req.method === 'GET';
  if (usersGetMatch) {
    if (!ensureRole(req, res, 'admin')) {
      return;
    }

    const payload = USERS_CONFIG.map((entry) => ({
      username: entry.username,
      role: entry.role,
      totpSecret: entry.totpSecret,
      createdAt: entry.createdAt ?? null,
    }));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ users: payload }));
    return;
  }

  const usersCreateMatch = pathname === '/users' && req.method === 'POST';
  if (usersCreateMatch) {
    if (!ensureRole(req, res, 'admin')) {
      return;
    }

    collectBody(req, async (body) => {
      try {
        const data = JSON.parse(body);
        const username = (data.username ?? '').toString().trim();
        const password = (data.password ?? '').toString();
        const role = (data.role ?? 'viewer').toString().trim();
        const totpSecret = (data.totp ?? authenticator.generateSecret()).toString().trim();
        if (!username || !password || !role) {
          res.writeHead(400);
          return res.end('Username, password and role are required');
        }

        if (USERS_CONFIG.some((entry) => entry.username === username)) {
          res.writeHead(409);
          return res.end('Username already exists');
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const newUser = {
          username,
          role,
          passwordHash,
          totpSecret,
          createdAt: Date.now(),
        };
        USERS_CONFIG.push(newUser);
        persistUsersConfig();

        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          username: newUser.username,
          role: newUser.role,
          totpSecret: newUser.totpSecret,
          createdAt: newUser.createdAt,
        }));
      } catch (error) {
        console.error('Unable to create user', error);
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const navigationSettingsMatch = pathname === '/settings/navigation';
  if (navigationSettingsMatch && req.method === 'GET') {
    if (!ensureRole(req, res, 'admin')) {
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ items: getNavigationPayload() }));
    return;
  }

  if (navigationSettingsMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'admin')) {
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const updates = Array.isArray(payload.items) ? payload.items : [];
        updateNavigationVisibility(updates);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ items: getNavigationPayload() }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const agentDownloadMatch = pathname === '/agent/download' && req.method === 'GET';
  if (agentDownloadMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const agentDir = resolveAgentPackageDir();
    if (!agentDir) {
      res.writeHead(500);
      res.end('Agent package directory not found. Publish the agent first.');
      return;
    }

    const forwardedProto = req.headers['x-forwarded-proto'];
    const protocol = forwardedProto
      ? String(forwardedProto).split(',')[0].trim()
      : (req.socket.encrypted || req.connection?.encrypted ? 'https' : 'http');
    const wssScheme = protocol === 'https' ? 'wss' : 'ws';
    const hostHeader = req.headers.host ?? `localhost:${PORT}`;
    const endpoint = `${wssScheme}://${hostHeader}`;
    const archive = archiver('zip', { zlib: { level: 9 } });
    const fileName = `rmm-agent-${Date.now()}.zip`;
    res.writeHead(200, {
      'Content-Type': 'application/zip',
      'Content-Disposition': `attachment; filename="${fileName}"`,
    });

    archive.on('error', (error) => {
      console.error('Agent download creation failed', error);
      if (!res.headersSent) {
        res.writeHead(500);
        res.end('Unable to create agent package.');
      } else {
        res.destroy(error);
      }
    });

    archive.pipe(res);
    archive.directory(agentDir, false);
    const launcherLines = [
      '@echo off',
      'setlocal',
      'cd /d "%~dp0"',
      `dotnet Agent.dll ${endpoint}`,
      'endlocal',
    ];
    archive.append(launcherLines.join('\r\n'), { name: 'run-agent.bat' });
    archive.append(JSON.stringify({ endpoint, dashboard: `${protocol}://${hostHeader}` }, null, 2), { name: 'server.json' });
    archive.finalize();
    return;
  }

  const shellStreamMatch = pathname.match(/^\/shell\/([^/]+)$/);
  if (shellStreamMatch && req.method === 'GET') {
    const agentId = shellStreamMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    });
    res.write(': connected\n\n');

    shellStreams.set(agentId, res);
    res.on('close', () => {
      shellStreams.delete(agentId);
      sendControl(entry.socket, 'stop-shell');
    });

    sendControl(entry.socket, 'start-shell');
    return;
  }

  const shellInputMatch = pathname.match(/^\/shell\/([^/]+)\/input$/);
  if (shellInputMatch && req.method === 'POST') {
    const agentId = shellInputMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    collectBody(req, (body) => {
      sendControl(entry.socket, 'shell-input', { input: body });
      res.writeHead(204);
      res.end();
    });

    return;
  }

  const screenListMatch = pathname.match(/^\/screen\/([^/]+)\/screens$/);
  if (screenListMatch && req.method === 'GET') {
    const agentId = screenListMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    const cached = screenLists.get(agentId);
    if (cached && Date.now() - cached.updatedAt < SCREEN_LIST_TTL_MS) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ screens: cached.screens }));
      return;
    }

    requestScreenList(agentId, entry.socket)
      .then((screens) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ screens }));
      })
      .catch(() => {
        res.writeHead(504);
        res.end('Failed to retrieve screen list');
      });

    return;
  }

  const screenOfferMatch = pathname.match(/^\/screen\/([^/]+)\/offer$/);
  if (screenOfferMatch && req.method === 'GET') {
    const sessionId = screenOfferMatch[1];
    const session = screenSessions.get(sessionId);
    if (!session) {
      console.warn(`Offer requested for unknown session ${sessionId}`);
      res.writeHead(404);
      return res.end('Session not found');
    }

    console.log(`Offer requested for session ${sessionId} (agent ${session.agentName}) - ready=${Boolean(session.offer)}`);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    const payloadBase = {
      sessionId,
      agentId: session.agentId,
      agentName: session.agentName,
    };

    if (!session.offer) {
      return res.end(JSON.stringify({ ...payloadBase, ready: false }));
    }

    res.end(JSON.stringify({ ...payloadBase, ...session.offer, ready: true }));
    return;
  }

  const screenEventsMatch = pathname.match(/^\/screen\/([^/]+)\/events$/);
  if (screenEventsMatch && req.method === 'GET') {
    const sessionId = screenEventsMatch[1];
    const session = screenSessions.get(sessionId);
    if (!session) {
      res.writeHead(404);
      return res.end('Session not found');
    }

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    });
    res.write(': connected\n\n');
    session.sseClients.add(res);

    console.log(`Screen events client added for session ${sessionId} (agent ${session.agentName})`);
    sendScreenEvent(session, 'status', {
      sessionId,
      agentId: session.agentId,
      agentName: session.agentName,
      state: session.offer ? 'offer-ready' : 'waiting-offer',
      screenId: session.screenId,
      screenName: getScreenName(session.agentId, session.screenId),
    });

    res.on('close', () => {
      session.sseClients.delete(res);
      console.log(`Screen events disconnected for session ${sessionId}`);
      sendControl(session.socket, 'stop-screen', { sessionId });
      screenSessions.delete(sessionId);
    });

    if (session.offer) {
      sendScreenEvent(session, 'offer', session.offer);
    }

    for (const candidate of session.agentCandidates) {
      sendScreenEvent(session, 'candidate', candidate);
    }

    return;
  }

  const screenRequestMatch = pathname === '/screen/request' && req.method === 'POST';
  if (screenRequestMatch) {
    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const agentId = payload.agentId;
        const requestedScreenId = typeof payload.screenId === 'string' && payload.screenId.trim()
          ? payload.screenId.trim()
          : null;
        console.log(`Received screen request for agent ${agentId}`);
        const entry = clientsById.get(agentId);
        if (!entry) {
          res.writeHead(404);
          return res.end('Agent not found');
        }

        const requestedScale = extractScale(payload?.scale);
        const sessionId = uuidv4();
        screenSessions.set(sessionId, {
          agentId,
          socket: entry.socket,
          agentName: entry.info.name,
          sseClients: new Set(),
          offer: null,
          agentCandidates: [],
          screenId: requestedScreenId,
          scale: requestedScale,
        });

        console.log(`Sending start-screen to agent ${agentId} for session ${sessionId}`);
        sendControl(entry.socket, 'start-screen', { sessionId, screenId: requestedScreenId, scale: requestedScale });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ sessionId }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const chatEventsMatch = pathname.match(/^\/chat\/([^/]+)\/events$/);
  if (chatEventsMatch && req.method === 'GET') {
    const agentId = chatEventsMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      res.end('Agent not found');
      return;
    }

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    });
    res.write(': connected\n\n');

    addChatListener(agentId, res);
    flushChatHistory(agentId, res);
    res.on('close', () => {
      removeChatListener(agentId, res);
    });

    return;
  }

  const chatMessageMatch = pathname.match(/^\/chat\/([^/]+)\/message$/);
  if (chatMessageMatch && req.method === 'POST') {
    const agentId = chatMessageMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      res.end('Agent not found');
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const text = typeof payload?.text === 'string' ? payload.text.trim() : '';
        if (!text) {
          res.writeHead(400);
          res.end('Message text is required');
          return;
        }

        const sessionId = uuidv4();
        const sessionUser = req.userSession?.user?.username ?? 'server';
        const sessionRole = req.userSession?.user?.role ?? 'user';
        const chatEvent = {
          sessionId,
          agentId,
          agentName: entry.info.name,
          direction: 'server',
          text,
          timestamp: new Date().toISOString(),
          user: sessionUser,
          role: sessionRole,
        };

        recordChatHistory(agentId, chatEvent);
        dispatchChatEvent(agentId, chatEvent);
        sendControl(entry.socket, 'chat-request', { sessionId, text, user: sessionUser, role: sessionRole });

        res.writeHead(202, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ sessionId }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const updatesDataMatch = pathname.match(/^\/updates\/([^/]+)\/data$/);
  if (updatesDataMatch && req.method === 'GET') {
    const agentId = updatesDataMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ summary: entry.info.updatesSummary ?? null }));
    return;
  }

  const updatesRefreshMatch = pathname.match(/^\/updates\/([^/]+)\/refresh$/);
  if (updatesRefreshMatch && req.method === 'POST') {
    const agentId = updatesRefreshMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    sendControl(entry.socket, 'request-updates');
    res.writeHead(202);
    res.end();
    return;
  }

  const updatesInstallMatch = pathname.match(/^\/updates\/([^/]+)\/install$/);
  if (updatesInstallMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }
    const agentId = updatesInstallMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        if (!Array.isArray(payload?.ids)) {
          res.writeHead(400);
          return res.end('Invalid request');
        }

        const ids = payload.ids
          .filter((entryId) => typeof entryId === 'string' && entryId.trim())
          .map((entryId) => entryId.trim());

        if (ids.length === 0) {
          res.writeHead(400);
          return res.end('No updates selected');
        }

        console.log(`Installing ${ids.length} updates on agent ${agentId}`);
        sendControl(entry.socket, 'install-updates', { ids });
        res.writeHead(202);
        res.end();
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid JSON');
      }
    });

    return;
  }

  const patchesMatch = pathname === '/patches' && req.method === 'GET';
  if (patchesMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    const patches = buildPatchCatalog();
    res.end(JSON.stringify({
      patches,
      summary: buildPatchSummary(patches),
    }));
    return;
  }

  const patchSchedulesMatch = pathname === '/patches/schedules' && req.method === 'GET';
  if (patchSchedulesMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ schedules: serializeSchedules(Array.from(patchSchedules.values())) }));
    return;
  }

  const patchApproveMatch = pathname === '/patches/approve' && req.method === 'POST';
  if (patchApproveMatch) {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const agentId = typeof payload?.agentId === 'string' ? payload.agentId.trim() : '';
        const updateId = typeof payload?.updateId === 'string' ? payload.updateId.trim() : '';
        if (!agentId || !updateId) {
          res.writeHead(400);
          return res.end('Agent and update ID required');
        }

        const entry = agents.get(agentId);
        if (!entry) {
          res.writeHead(404);
          return res.end('Agent not found');
        }

        const approved = payload?.approved !== false;
        const key = `${agentId}:${updateId}`;
        if (approved) {
          patchApprovals.set(key, { approvedAt: Date.now() });
        } else {
          patchApprovals.delete(key);
        }

        res.writeHead(204);
        res.end();
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const patchScheduleMatch = pathname === '/patches/schedule' && req.method === 'POST';
  if (patchScheduleMatch) {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const patchIds = Array.isArray(payload?.patchIds)
          ? payload.patchIds.filter((entry) => typeof entry === 'string' && entry.trim()).map((entry) => entry.trim())
          : [];
        const agentIds = Array.isArray(payload?.agentIds)
          ? payload.agentIds.filter((entry) => typeof entry === 'string' && entry.trim()).map((entry) => entry.trim())
          : [];

        if (patchIds.length === 0) {
          res.writeHead(400);
          return res.end('At least one patch must be selected');
        }

        const runAtValue = payload?.runAt;
        let runAt = typeof runAtValue === 'number' ? runAtValue : Date.parse(runAtValue ?? '');
        if (Number.isNaN(runAt)) {
          runAt = Date.now();
        }
        if (runAt < Date.now()) {
          runAt = Date.now();
        }

        const repeatMsValue = Number(payload?.repeatMs);
        const repeatMs = Number.isFinite(repeatMsValue) && repeatMsValue > 0 ? repeatMsValue : 0;

        const missingApprovals = [];
        if (agentIds.length > 0) {
          for (const agentId of agentIds) {
            for (const patchId of patchIds) {
              if (!isPatchApproved(agentId, patchId)) {
                missingApprovals.push({ agentId, patchId });
              }
            }
          }

          if (missingApprovals.length > 0) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({
              error: 'All agents must approve the selected patches before scheduling',
              missing: missingApprovals,
            }));
          }
        }

        const schedule = {
          id: uuidv4(),
          name: typeof payload?.name === 'string' && payload.name.trim()
            ? payload.name.trim()
            : `Patch run ${new Date().toISOString()}`,
          patchIds,
          agentIds,
          category: typeof payload?.category === 'string' && payload.category.trim()
            ? payload.category.trim()
            : null,
          dynamic: agentIds.length === 0,
          runAt,
          repeatMs,
          nextRun: runAt,
          lastRun: null,
          createdAt: Date.now(),
          pendingAgents: new Set(agentIds),
        };

        patchSchedules.set(schedule.id, schedule);
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(serializeSchedule(schedule)));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const clientActionMatch = pathname.match(/^\/clients\/([^/]+)\/action$/);
  if (clientActionMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const agentId = clientActionMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const action = typeof payload?.action === 'string' ? payload.action.trim() : '';
        if (!action) {
          res.writeHead(400);
          return res.end('Action required');
        }

        sendControl(entry.socket, 'invoke-action', { action });
        logPatchEvent({
          timestamp: new Date().toISOString(),
          type: 'action',
          agentId,
          action,
          scheduleId: payload?.scheduleId ?? null,
        });
        res.writeHead(202);
        res.end();
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid JSON');
      }
    });

    return;
  }

  const deleteScheduleMatch = pathname.match(/^\/patches\/schedules\/([^/]+)$/);
  if (deleteScheduleMatch && req.method === 'DELETE') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const scheduleId = deleteScheduleMatch[1];
    if (patchSchedules.has(scheduleId)) {
      patchSchedules.delete(scheduleId);
      logPatchEvent({
        timestamp: new Date().toISOString(),
        type: 'schedule-deleted',
        scheduleId,
      });
      res.writeHead(204);
      return res.end();
    }

    res.writeHead(404);
    res.end('Schedule not found');
    return;
  }

  const historyMatch = pathname === '/patches/history' && req.method === 'GET';
  if (historyMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ history: patchHistory.slice() }));
    return;
  }

  const bsodDataMatch = pathname.match(/^\/bsod\/([^/]+)\/data$/);
  if (bsodDataMatch && req.method === 'GET') {
    const agentId = bsodDataMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ summary: entry.info.bsodSummary ?? null }));
    return;
  }

  const bsodRefreshMatch = pathname.match(/^\/bsod\/([^/]+)\/refresh$/);
  if (bsodRefreshMatch && req.method === 'POST') {
    const agentId = bsodRefreshMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    sendControl(entry.socket, 'request-bsod');
    res.writeHead(202);
    res.end();
    return;
  }

  const processDataMatch = pathname.match(/^\/processes\/([^/]+)\/data$/);
  if (processDataMatch && req.method === 'GET') {
    const agentId = processDataMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ snapshot: entry.info.processSnapshot ?? null }));
    return;
  }

  const processRefreshMatch = pathname.match(/^\/processes\/([^/]+)\/refresh$/);
  if (processRefreshMatch && req.method === 'POST') {
    const agentId = processRefreshMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    sendControl(entry.socket, 'list-processes');
    res.writeHead(202);
    res.end();
    return;
  }

  const processKillMatch = pathname.match(/^\/processes\/([^/]+)\/kill$/);
  if (processKillMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }
    const agentId = processKillMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const pid = Number(payload?.processId);
        if (!Number.isInteger(pid) || pid <= 0) {
          res.writeHead(400);
          return res.end('Invalid process id');
        }

        sendControl(entry.socket, 'kill-process', { processId: pid });
        res.writeHead(202);
        res.end();
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid JSON');
      }
    });

    return;
  }

  if (pathname === '/monitoring/events' && req.method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    });
    res.write(': connected\n\n');
    monitoringEvents.add(res);
    res.on('close', () => monitoringEvents.delete(res));
    return;
  }

  if (pathname === '/monitoring/events/history' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    const queryAgentId = requestedUrl.searchParams.get('agentId')?.trim();
    const queryProfileId = requestedUrl.searchParams.get('profileId')?.trim();
    const limitParam = parseInt(requestedUrl.searchParams.get('limit') ?? '', 10);
    const limit = Number.isNaN(limitParam) || limitParam <= 0 ? 200 : limitParam;
    let entries = monitoringHistory;
    if (queryAgentId) {
      entries = entries.filter((entry) => entry.payload?.agentId === queryAgentId);
    }
    if (queryProfileId) {
      entries = entries.filter((entry) => entry.payload?.profileId === queryProfileId);
    }
    res.end(JSON.stringify(entries.slice(-limit)));
    return;
  }

  if (pathname === '/monitoring/profiles' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(monitoringConfig.monitoringProfiles));
    return;
  }

  if (pathname === '/monitoring/profiles' && req.method === 'POST') {
    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const name = typeof payload?.name === 'string' ? payload.name.trim() : '';
        if (!name) {
          res.writeHead(400);
          return res.end('Profile name required');
        }

        const profile = {
          id: uuidv4(),
          name,
          description: typeof payload?.description === 'string' ? payload.description.trim() : '',
          alertProfileId: typeof payload?.alertProfileId === 'string' ? payload.alertProfileId.trim() : null,
          assignedAgents: [],
          assignedGroups: [],
          rules: [],
        };

        const rules = Array.isArray(payload?.rules) ? payload.rules : [payload?.rule].filter(Boolean);
        for (const entry of rules) {
          if (entry?.metric && typeof entry?.threshold === 'number') {
            profile.rules.push({
              id: uuidv4(),
              metric: entry.metric,
              threshold: entry.threshold,
              windowSeconds: typeof entry?.windowSeconds === 'number' ? entry.windowSeconds : 30,
              comparison: entry?.comparison || 'gte',
            });
          }
        }

        if (profile.rules.length === 0) {
          res.writeHead(400);
          return res.end('At least one rule is required');
        }

        monitoringConfig.monitoringProfiles.push(profile);
        saveMonitoringConfig();
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(profile));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const profileAssignMatch = pathname.match(/^\/monitoring\/profiles\/([^/]+)\/assign$/);
  if (profileAssignMatch && req.method === 'POST') {
    const profileId = profileAssignMatch[1];
    const profile = monitoringConfig.monitoringProfiles.find((entry) => entry.id === profileId);
    if (!profile) {
      res.writeHead(404);
      return res.end('Profile not found');
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const targetType = payload?.targetType;
        const rawTargetId = typeof payload?.targetId === 'string' ? payload.targetId.trim() : '';
        const targetId = targetType === 'group' ? normalizeGroupName(rawTargetId) : rawTargetId;
        if (!targetType || !targetId) {
          res.writeHead(400);
          return res.end('Invalid assignment');
        }

        if (targetType === 'agent') {
          if (!profile.assignedAgents.includes(targetId)) {
            profile.assignedAgents.push(targetId);
          }
          notifyAgentMonitoring(targetId);
        } else if (targetType === 'group') {
          if (!profile.assignedGroups.includes(targetId)) {
            profile.assignedGroups.push(targetId);
          }
          notifyGroupMonitoring(targetId);
        } else {
          res.writeHead(400);
          return res.end('Unknown target type');
        }

        saveMonitoringConfig();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(profile));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

  return;
}

  const profileDeleteMatch = pathname.match(/^\/monitoring\/profiles\/([^/]+)$/);
  if (profileDeleteMatch && req.method === 'DELETE') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const profileId = profileDeleteMatch[1];
    const index = monitoringConfig.monitoringProfiles.findIndex((entry) => entry.id === profileId);
    if (index === -1) {
      res.writeHead(404);
      return res.end('Profile not found');
    }

    const [removed] = monitoringConfig.monitoringProfiles.splice(index, 1);
    clearMonitoringProfileState(profileId);
    saveMonitoringConfig();

    const affectedAgents = new Set(removed.assignedAgents ?? []);
    for (const entry of clientsById.values()) {
      const groupName = entry.info.group ?? DEFAULT_GROUP;
      if ((removed.assignedGroups ?? []).includes(groupName)) {
        affectedAgents.add(entry.info.id);
      }
    }
    for (const agentId of affectedAgents) {
      notifyAgentMonitoring(agentId);
    }

    res.writeHead(204);
    return res.end();
  }

  if (pathname === '/alert-profiles' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(monitoringConfig.alertProfiles));
    return;
  }

  if (pathname === '/alert-profiles' && req.method === 'POST') {
    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const name = typeof payload?.name === 'string' ? payload.name.trim() : '';
        if (!name) {
          res.writeHead(400);
          return res.end('Alert profile name required');
        }

        const profile = {
          id: uuidv4(),
          name,
          emails: Array.isArray(payload?.emails) ? payload.emails.filter((email) => typeof email === 'string' && email.trim()) : [],
          dashboard: Boolean(payload?.dashboard),
          remediationScript: typeof payload?.remediationScript === 'string' ? payload.remediationScript.trim() : null,
        };

        monitoringConfig.alertProfiles.push(profile);
        saveMonitoringConfig();
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(profile));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  if (profileAssignMatch && req.method === 'DELETE') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const profileId = profileAssignMatch[1];
    const profile = monitoringConfig.monitoringProfiles.find((entry) => entry.id === profileId);
    if (!profile) {
      res.writeHead(404);
      return res.end('Profile not found');
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const targetType = payload?.targetType;
        const rawTargetId = typeof payload?.targetId === 'string' ? payload.targetId.trim() : '';
        const targetId = targetType === 'group' ? normalizeGroupName(rawTargetId) : rawTargetId;
        if (!targetType || !targetId) {
          res.writeHead(400);
          return res.end('Invalid assignment');
        }

        if (targetType === 'agent') {
          profile.assignedAgents = (profile.assignedAgents ?? []).filter((id) => id !== targetId);
          notifyAgentMonitoring(targetId);
        } else if (targetType === 'group') {
          profile.assignedGroups = (profile.assignedGroups ?? []).filter((id) => id !== targetId);
          notifyGroupMonitoring(targetId);
        } else {
          res.writeHead(400);
          return res.end('Unknown target type');
        }

        saveMonitoringConfig();
        res.writeHead(204);
        res.end();
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  if (pathname === '/remediation/scripts' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(monitoringConfig.remediationScripts));
    return;
  }

  if (pathname === '/scripts' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(monitoringConfig.remediationScripts));
    return;
  }

  const scriptContentMatch = pathname.match(/^\/scripts\/([^/]+)\/content$/);
  if (scriptContentMatch && req.method === 'GET') {
    const scriptName = scriptContentMatch[1];
    const script = getScriptByName(scriptName);
    if (!script) {
      res.writeHead(404);
      return res.end('Script not found');
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ name: script.name, content: readScriptContent(script) }));
    return;
  }

  if (pathname === '/scripts' && req.method === 'POST') {
    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const name = typeof payload?.name === 'string' ? payload.name.trim() : '';
        const description = typeof payload?.description === 'string' ? payload.description.trim() : '';
        const language = typeof payload?.language === 'string' ? payload.language.toLowerCase() : 'powershell';
        const content = typeof payload?.content === 'string' ? payload.content : '';

        if (!name || !content) {
          res.writeHead(400);
          return res.end('Name and content are required');
        }

        if (getScriptByName(name)) {
          res.writeHead(409);
          return res.end('Script name already exists');
        }

        ensureRemediationDirectory();
        const fileName = sanitizeScriptFileName(name, language);
        fs.writeFileSync(path.join(REMEDIATION_DIR, fileName), content, 'utf-8');

        const scriptEntry = {
          name,
          description,
          language,
          file: fileName,
        };

        monitoringConfig.remediationScripts.push(scriptEntry);
        saveMonitoringConfig();
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(scriptEntry));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  if (pathname === '/scripts/run' && req.method === 'POST') {
    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const scriptName = typeof payload?.scriptName === 'string' ? payload.scriptName.trim() : '';
        const agentIds = Array.isArray(payload?.agentIds) ? payload.agentIds : [];

        const script = getScriptByName(scriptName);
        if (!script || agentIds.length === 0) {
          res.writeHead(400);
          return res.end('Script name and agent list are required');
        }

        const missing = [];
        const triggered = [];
        for (const agentId of agentIds) {
          const entry = clientsById.get(agentId);
          if (!entry) {
            missing.push(agentId);
            continue;
          }

          runRemediation(entry.info, entry.socket, script.name, {
            type: 'script-run',
            metric: script.language,
            message: `Manual run of ${script.name}`,
          });
          triggered.push(agentId);
        }

        sendMonitoringEvent('script-run', {
          type: 'script-run',
          scriptName: script.name,
          agentIds: triggered,
          timestamp: new Date().toISOString(),
        });

        res.writeHead(202, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ triggered, missing }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const fileListMatch = pathname.match(/^\/files\/([^/]+)\/list$/);
  if (fileListMatch && req.method === 'GET') {
    const agentId = fileListMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    const requestedPath = requestedUrl.searchParams.get('path') ?? '';
    requestAgentFileList(entry, requestedPath)
      .then((result) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
      })
      .catch((error) => {
        console.error('File list request failed', error);
        res.writeHead(504);
        res.end('File list request timed out');
      });

    return;
  }

  const fileDownloadMatch = pathname.match(/^\/files\/([^/]+)\/download$/);
  if (fileDownloadMatch && req.method === 'GET') {
    const agentId = fileDownloadMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    const requestedPath = requestedUrl.searchParams.get('path');
    if (!requestedPath) {
      res.writeHead(400);
      return res.end('Path is required');
    }

    requestAgentFileDownload(entry, requestedPath)
      .then((result) => {
        if (!result || typeof result.data !== 'string' || !result.name) {
          res.writeHead(502);
          return res.end('Invalid download response');
        }

        const buffer = Buffer.from(result.data, 'base64');
        res.writeHead(200, {
          'Content-Type': 'application/octet-stream',
          'Content-Disposition': `attachment; filename="${encodeURIComponent(result.name)}"`,
        });
        res.end(buffer);
      })
      .catch((error) => {
        console.error('File download failed', error);
        res.writeHead(504);
        res.end('File download timed out');
      });

    return;
  }

  const fileUploadMatch = pathname.match(/^\/files\/([^/]+)\/upload$/);
  if (fileUploadMatch && req.method === 'POST') {
    const agentId = fileUploadMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const destinationPath = typeof payload?.path === 'string' ? payload.path.trim() : '';
        const data = typeof payload?.data === 'string' ? payload.data.trim() : '';
        if (!destinationPath || !data) {
          res.writeHead(400);
          return res.end('Path and data are required');
        }

        requestAgentFileUpload(entry, destinationPath, data)
          .then((response) => {
            res.writeHead(response.success ? 202 : 400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              success: response.success,
              message: response.message ?? '',
            }));
          })
          .catch((error) => {
            console.error('File upload failed', error);
            res.writeHead(400);
            res.end('Upload request timed out');
          });
      } catch (error) {
        console.error('File upload failed', error);
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const softwareListMatch = pathname.match(/^\/software\/([^/]+)\/list$/);
  if (softwareListMatch && req.method === 'GET') {
    const agentId = softwareListMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    const filterText = (requestedUrl.searchParams.get('filter') ?? '').trim().toLowerCase();
    const sourceFilter = (requestedUrl.searchParams.get('source') ?? '').trim().toLowerCase();
    const pageValue = Number(requestedUrl.searchParams.get('page') ?? '1');
    const sizeValue = Number(requestedUrl.searchParams.get('pageSize') ?? '25');
    const page = Math.max(Math.floor(pageValue) || 1, 1);
    const pageSize = Math.min(Math.max(Math.floor(sizeValue) || 25, 5), 200);

        requestAgentSoftwareList(entry)
          .then((result) => {
            const allEntries = Array.isArray(result.entries) ? result.entries : [];
        const filtered = allEntries.filter((item) => {
          if (!filterText) {
            return true;
          }
          const haystack = `${item.name ?? ''} ${item.version ?? ''} ${item.publisher ?? ''} ${item.source ?? ''}`.toLowerCase();
          return haystack.includes(filterText);
        }).filter((item) => {
          if (!sourceFilter) {
            return true;
          }
          return (item.source ?? '').toLowerCase().includes(sourceFilter);
        });

        filtered.sort((a, b) => (a.name ?? '').localeCompare(b.name ?? '', 'en', { sensitivity: 'base' }));
        const total = filtered.length;
        const offset = (page - 1) * pageSize;
        const paged = filtered.slice(offset, offset + pageSize);

        res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              agentId,
              total,
              page,
              pageSize,
              entries: paged,
              retrievedAt: result.retrievedAt,
            }));
          })
      .catch((error) => {
        console.error('Software list request failed', error);
        res.writeHead(504);
        res.end('Software request timed out');
      });
    return;
  }

  const softwareUninstallMatch = pathname.match(/^\/software\/([^/]+)\/uninstall$/);
  if (softwareUninstallMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const agentId = softwareUninstallMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const softwareId = typeof payload?.softwareId === 'string' ? payload.softwareId.trim() : '';
        if (!softwareId) {
          res.writeHead(400);
          return res.end('softwareId is required');
        }

        const requestId = uuidv4();
        sendControl(entry.socket, 'uninstall-software', {
          requestId,
          softwareId,
          source: typeof payload?.source === 'string' ? payload.source : 'registry',
          uninstallCommand: typeof payload?.uninstallCommand === 'string' ? payload.uninstallCommand : null,
          packageFullName: typeof payload?.packageFullName === 'string' ? payload.packageFullName : null,
          productCode: typeof payload?.productCode === 'string' ? payload.productCode : null,
        });

        res.writeHead(202, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ requestId, success: true, message: 'Uninstall requested.' }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const softwareInventoryMatch = pathname === '/software' && req.method === 'GET';
  if (softwareInventoryMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    try {
      await refreshSoftwareEntriesFromAgents();
    } catch (error) {
      console.warn('Software inventory refresh failed', error);
    }

    const snapshot = buildSoftwareCatalog();
    const pendingUninstalls = Array.from(softwareUninstallQueue.values()).reduce((sum, queue) => sum + queue.pending.size, 0);

    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      software: snapshot.list,
      summary: {
        totalSoftware: snapshot.list.length,
        totalAgents: snapshot.agentCount,
        rejectedPairs: snapshot.rejectedPairs,
        pendingUninstalls,
      },
    }));
  }

  const softwareApprovalMatch = pathname === '/software/approval' && req.method === 'POST';
  if (softwareApprovalMatch) {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    collectBody(req, async (body) => {
      try {
        const payload = JSON.parse(body);
        const softwareId = (payload?.softwareId ?? '').toString().trim();
        const action = (payload?.action ?? '').toString().trim().toLowerCase();
        if (!softwareId || (action !== 'approve' && action !== 'reject')) {
          res.writeHead(400);
          return res.end('softwareId and valid action are required');
        }

        const state = action === 'reject' ? 'rejected' : 'approved';
        softwareApprovals.set(softwareId, { state });
        if (state === 'rejected') {
          queueRejectedSoftwareNow(softwareId);
        } else {
          softwareUninstallQueue.delete(softwareId);
        }

        res.writeHead(204);
        res.end();
      } catch (error) {
        console.error('Software approval failed', error);
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const softwareLogsMatch = pathname === '/software/logs' && req.method === 'GET';
  if (softwareLogsMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ logs: softwareUninstallLog.slice(0, SOFTWARE_UNINSTALL_LOG_LIMIT) }));
    return;
  }

  const ruleLibraryMatch = pathname === '/firewall/rule-library' && req.method === 'GET';
  if (ruleLibraryMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const requestedAgentId = requestedUrl.searchParams.get('agent');
    let entry = requestedAgentId ? clientsById.get(requestedAgentId) : null;
    if (!entry) {
      entry = Array.from(clientsById.values()).find((client) => client.socket.readyState === WebSocket.OPEN) ?? null;
    }

    if (!entry || entry.socket.readyState !== WebSocket.OPEN) {
      res.writeHead(404);
      res.end('Agent not found');
      return;
    }

    requestAgentFirewallRules(entry)
      .then((payload) => {
        const rules = Array.isArray(payload.rules) ? payload.rules : [];
        const unique = new Map();
        for (const rule of rules) {
          if (!rule?.name) {
            continue;
          }
          if (!unique.has(rule.name)) {
            unique.set(rule.name, { name: rule.name, enabled: Boolean(rule.enabled) });
          }
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          agentId: entry.info.id,
          agentName: entry.info.name,
          rules: Array.from(unique.values()),
        }));
      })
      .catch((error) => {
        console.error('Rule library request failed', error);
        res.writeHead(504, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unable to load rule library' }));
      });

    return;
  }

  const firewallRulesMatch = pathname.match(/^\/firewall\/([^/]+)\/rules$/);
  if (firewallRulesMatch && req.method === 'GET') {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const agentId = firewallRulesMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry || entry.socket.readyState !== WebSocket.OPEN) {
      res.writeHead(404);
      res.end('Agent not found');
      return;
    }

    try {
      const result = await requestAgentFirewallRules(entry);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        firewallEnabled: result.firewallEnabled ?? null,
        profiles: result.profiles ?? null,
        defaultInboundAction: result.defaultInboundAction ?? null,
        defaultOutboundAction: result.defaultOutboundAction ?? null,
        rules: Array.isArray(result.rules) ? result.rules : [],
      }));
    } catch (error) {
      console.error('Firewall rules request failed', error);
      const message = typeof error?.message === 'string' ? error.message : '';
      if (message.includes('unsupported')) {
        res.writeHead(501, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Firewall unsupported' }));
      } else {
        res.writeHead(504, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Firewall request timed out' }));
      }
    }

    return;
  }

  const firewallRuleActionMatch = pathname.match(/^\/firewall\/([^/]+)\/rule\/action$/);
  if (firewallRuleActionMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const agentId = firewallRuleActionMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry || entry.socket.readyState !== WebSocket.OPEN) {
      res.writeHead(404);
      res.end('Agent not found');
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const ruleName = typeof payload?.ruleName === 'string' ? payload.ruleName.trim() : '';
        const enabled = payload?.enabled === true;
        if (!ruleName) {
          res.writeHead(400);
          return res.end('ruleName is required');
        }

        if (entry.socket.readyState !== WebSocket.OPEN) {
          res.writeHead(503, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Agent offline' }));
          return;
        }

        requestAgentFirewallAction(entry, { type: 'rule', ruleName, enabled })
          .then((result) => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              success: Boolean(result.success),
              message: result.message ?? 'Rule update requested',
            }));
          })
        .catch((error) => {
          console.error('Firewall rule update failed', error);
          const message = typeof error?.message === 'string' ? error.message : '';
          if (message.includes('unsupported')) {
            res.writeHead(501, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Firewall unsupported' }));
          } else {
            res.writeHead(504, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Firewall request timed out' }));
          }
        });
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const firewallRuleAddMatch = pathname.match(/^\/firewall\/([^/]+)\/rule\/add$/);
  if (firewallRuleAddMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const agentId = firewallRuleAddMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry || entry.socket.readyState !== WebSocket.OPEN) {
      res.writeHead(404);
      res.end('Agent not found');
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const ruleName = typeof payload?.name === 'string' ? payload.name.trim() : '';
        const direction = payload?.direction === 'outbound' ? 'outbound' : 'inbound';
        const action = payload?.action === 'block' ? 'block' : 'allow';
        const protocol = typeof payload?.protocol === 'string' ? payload.protocol : 'any';
        const localPorts = typeof payload?.localPorts === 'string' ? payload.localPorts : '';
        const remotePorts = typeof payload?.remotePorts === 'string' ? payload.remotePorts : '';
        const application = typeof payload?.application === 'string' ? payload.application : '';

        if (!ruleName) {
          res.writeHead(400);
          return res.end('Rule name is required');
        }

        requestAgentFirewallAction(entry, {
          type: 'add-rule',
          ruleName,
          direction,
          action,
          protocol,
          localPorts,
          remotePorts,
          applicationName: application,
        })
          .then((result) => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              success: Boolean(result.success),
              message: result.message ?? 'Rule add requested',
            }));
          })
          .catch((error) => {
            console.error('Firewall rule add failed', error);
            const message = typeof error?.message === 'string' ? error.message : '';
            if (message.includes('unsupported')) {
              res.writeHead(501, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Firewall unsupported' }));
            } else {
              res.writeHead(504, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Firewall request timed out' }));
            }
          });
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const firewallRuleDeleteMatch = pathname.match(/^\/firewall\/([^/]+)\/rule\/delete$/);
  if (firewallRuleDeleteMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const agentId = firewallRuleDeleteMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry || entry.socket.readyState !== WebSocket.OPEN) {
      res.writeHead(404);
      res.end('Agent not found');
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const ruleName = typeof payload?.ruleName === 'string' ? payload.ruleName.trim() : '';
        if (!ruleName) {
          res.writeHead(400);
          return res.end('Rule name is required');
        }

        requestAgentFirewallAction(entry, {
          type: 'delete-rule',
          ruleName,
        })
          .then((result) => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              success: Boolean(result.success),
              message: result.message ?? 'Rule removal requested',
            }));
          })
          .catch((error) => {
            console.error('Firewall rule removal failed', error);
            const message = typeof error?.message === 'string' ? error.message : '';
            if (message.includes('unsupported')) {
              res.writeHead(501, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Firewall unsupported' }));
            } else {
              res.writeHead(504, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Firewall request timed out' }));
            }
          });
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }
  const firewallStateMatch = pathname.match(/^\/firewall\/([^/]+)\/state$/);
  if (firewallStateMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const agentId = firewallStateMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry || entry.socket.readyState !== WebSocket.OPEN) {
      res.writeHead(404);
      res.end('Agent not found');
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const profile = typeof payload?.profile === 'string' ? payload.profile.toLowerCase() : 'all';
        const enabled = payload?.enabled === true;
        if (entry.socket.readyState !== WebSocket.OPEN) {
          res.writeHead(503, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Agent offline' }));
          return;
        }

        requestAgentFirewallAction(entry, { type: 'state', profile, enabled })
          .then((result) => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              success: Boolean(result.success),
              message: result.message ?? 'Firewall state updated',
            }));
          })
            .catch((error) => {
              console.error('Firewall state update failed', error);
              const message = typeof error?.message === 'string' ? error.message : '';
              if (message.includes('unsupported')) {
                res.writeHead(501, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Firewall unsupported' }));
              } else {
                res.writeHead(504, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Firewall request timed out' }));
              }
            });
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

  return;
}

  const baselineListMatch = pathname === '/firewall/baseline' && req.method === 'GET';
  if (baselineListMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ profiles: firewallBaselines }));
    return;
  }

  const baselineCreateMatch = pathname === '/firewall/baseline' && req.method === 'POST';
  if (baselineCreateMatch) {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const name = (payload?.name ?? '').toString().trim();
        const description = (payload?.description ?? '').toString().trim();
        const rules = Array.isArray(payload?.rules)
          ? payload.rules.map((rule) => ({
            ruleName: (rule?.ruleName ?? '').toString().trim(),
            enabled: Boolean(rule?.enabled),
          })).filter((rule) => rule.ruleName)
          : [];

        if (!name) {
          res.writeHead(400);
          return res.end('Profile name is required');
        }

        const profile = {
          id: uuidv4(),
          name,
          description,
          rules,
          assignedAgents: [],
          assignedGroups: [],
          createdAt: new Date().toISOString(),
        };
        firewallBaselines.push(profile);
        persistFirewallBaselines();

        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(profile));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const baselineAssignMatch = pathname.match(/^\/firewall\/baseline\/([^/]+)\/assign$/);
  if (baselineAssignMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const profileId = baselineAssignMatch[1];
    const profile = firewallBaselines.find((entry) => entry.id === profileId);
    if (!profile) {
      res.writeHead(404);
      return res.end('Baseline not found');
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        const agents = Array.isArray(payload?.agents) ? payload.agents : [];
        const groups = Array.isArray(payload?.groups) ? payload.groups : [];
        profile.assignedAgents = Array.from(new Set(agents.filter((id) => typeof id === 'string' && id.trim())));
        profile.assignedGroups = Array.from(new Set(groups.filter((name) => typeof name === 'string' && name.trim())));
        persistFirewallBaselines();

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, profile }));
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid request');
      }
    });

    return;
  }

  const baselineApplyMatch = pathname.match(/^\/firewall\/baseline\/([^/]+)\/apply$/);
  if (baselineApplyMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const profileId = baselineApplyMatch[1];
    const profile = firewallBaselines.find((entry) => entry.id === profileId);
    if (!profile) {
      res.writeHead(404);
      return res.end('Baseline not found');
    }

    const targetAgentIds = getBaselineTargetAgentIds(profile);
    const agentEntries = targetAgentIds
      .map((agentId) => clientsById.get(agentId))
      .filter((entry) => entry && entry.socket.readyState === WebSocket.OPEN);

    if (!agentEntries.length) {
      res.writeHead(400);
      return res.end('No connected agents available for this profile');
    }

    const applyPromises = [];
    for (const entry of agentEntries) {
      for (const rule of profile.rules) {
        if (!rule.ruleName) {
          continue;
        }

        applyPromises.push(
          requestAgentFirewallAction(entry, {
            type: 'rule',
            ruleName: rule.ruleName,
            enabled: Boolean(rule.enabled),
          }).catch(() => null),
        );
      }
    }

    Promise.allSettled(applyPromises)
      .then(() => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          message: 'Baseline push requested',
          targetCount: agentEntries.length,
        }));
      })
      .catch(() => {
        res.writeHead(500);
        res.end('Unable to dispatch baseline');
      });

    return;
  }

  const vulnerabilityStatusMatch = pathname === '/vulnerabilities/status' && req.method === 'GET';
  if (vulnerabilityStatusMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(getVulnerabilityStatus()));
    return;
  }

  const vulnerabilityQueryMatch = pathname === '/vulnerabilities' && req.method === 'GET';
  if (vulnerabilityQueryMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const query = requestedUrl.searchParams.get('q')?.trim().toLowerCase() ?? '';
    const limit = Number(requestedUrl.searchParams.get('limit')) || 50;
    const results = searchVulnerabilities(query, limit);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ total: results.total, items: results.items }));
    return;
  }

  const vulnerabilityAssetMatch = pathname.match(/^\/vulnerabilities\/asset\/([^/]+)$/);
  if (vulnerabilityAssetMatch && req.method === 'GET') {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const agentId = vulnerabilityAssetMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      res.end('Agent not found');
      return;
    }

    const results = evaluateAssetVulnerabilities(entry.info);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ agentId, total: results.length, vulnerabilities: results }));
    return;
  }

  const systemHealthMatch = pathname === '/system-health/agents' && req.method === 'GET';
  if (systemHealthMatch) {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const agentInfos = Array.from(agents.values());
    const statsPromises = agentInfos.map(async (info) => {
      const clientEntry = clientsById.get(info.id);
      if (clientEntry?.socket?.readyState === WebSocket.OPEN) {
        try {
          const result = await requestAgentEventStats(clientEntry);
          const record = {
            stats: typeof result.stats === 'object' && result.stats !== null ? result.stats : {},
            since: typeof result.since === 'string' ? result.since : new Date().toISOString(),
            retrievedAt: new Date().toISOString(),
          };
          agentEventStatsCache.set(info.id, record);
          return formatSystemHealthPayload(info, record.stats, record.since, record.retrievedAt, { source: 'live' });
        } catch (error) {
          const cache = agentEventStatsCache.get(info.id);
          return formatSystemHealthPayload(info, cache?.stats ?? null, cache?.since ?? null, cache?.retrievedAt ?? null, {
            offline: true,
            error: error?.message ?? 'Event stats request failed',
          });
        }
      }

      const cache = agentEventStatsCache.get(info.id);
      return formatSystemHealthPayload(info, cache?.stats ?? null, cache?.since ?? null, cache?.retrievedAt ?? null, { offline: true });
    });

    try {
      const payload = await Promise.all(statsPromises);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        agents: payload,
        summary: {
          totalAgents: agentInfos.length,
          retrievedAt: new Date().toISOString(),
        },
      }));
    } catch (error) {
      console.error('System health stats failed', error);
      res.writeHead(500);
      res.end('Unable to gather event log stats');
    }

    return;
  }

  const systemHealthAgentMatch = pathname.match(/^\/system-health\/agent\/([^/]+)$/);
  if (systemHealthAgentMatch && req.method === 'GET') {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const agentId = systemHealthAgentMatch[1];
    const agentInfo = agents.get(agentId) ?? clientsById.get(agentId)?.info ?? null;
    const clientEntry = clientsById.get(agentId);
    let record = agentEventStatsCache.get(agentId);
    let offline = true;
    let errorMessage = null;

    if (clientEntry?.socket?.readyState === WebSocket.OPEN) {
      try {
        const result = await requestAgentEventStats(clientEntry);
        record = {
          stats: typeof result.stats === 'object' && result.stats !== null ? result.stats : {},
          since: typeof result.since === 'string' ? result.since : new Date().toISOString(),
          retrievedAt: new Date().toISOString(),
        };
        agentEventStatsCache.set(agentId, record);
        offline = false;
      } catch (error) {
        offline = true;
        errorMessage = error?.message ?? 'Event stats request failed';
      }
    }

    if (!record) {
      record = {
        stats: null,
        since: null,
        retrievedAt: null,
      };
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      agentId,
      name: agentInfo?.name ?? agentId,
      os: agentInfo?.os ?? agentInfo?.platform ?? 'unknown',
      platform: agentInfo?.platform ?? null,
      status: agentInfo?.status ?? (clientEntry ? 'online' : 'offline'),
      loggedInUser: agentInfo?.loggedInUser ?? null,
      group: agentInfo?.group ?? DEFAULT_GROUP,
      pendingReboot: Boolean(agentInfo?.pendingReboot),
      eventStats: record.stats,
      since: record.since,
      retrievedAt: record.retrievedAt,
      offline,
      error: errorMessage,
    }));

    return;
  }

  const systemHealthEntriesMatch = pathname.match(/^\/system-health\/([^/]+)\/entries$/);
  if (systemHealthEntriesMatch && req.method === 'GET') {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const agentId = systemHealthEntriesMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry || entry.socket.readyState !== WebSocket.OPEN) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Agent unavailable' }));
      return;
    }

    const requestedLevel = (requestedUrl.searchParams.get('level') ?? '').trim();
    const level = requestedLevel || 'Information';

    try {
      const result = await requestAgentEventEntries(entry, level);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        agentId,
        level: result.level ?? level,
        entries: Array.isArray(result.entries) ? result.entries : [],
        retrievedAt: new Date().toISOString(),
      }));
    } catch (error) {
      res.writeHead(504, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: error?.message ?? 'Event entries request timed out' }));
    }

    return;
  }

  const agentServicesMatch = pathname.match(/^\/agent\/([^/]+)\/services$/);
  if (agentServicesMatch && req.method === 'GET') {
    if (!ensureRole(req, res, 'viewer')) {
      return;
    }

    const agentId = agentServicesMatch[1];
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    requestAgentServiceList(entry)
      .then((services) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ services }));
      })
      .catch(() => {
        res.writeHead(504);
        res.end('Unable to retrieve services');
      });

    return;
  }

  const agentServiceActionMatch = pathname.match(/^\/agent\/([^/]+)\/service\/([^/]+)\/action$/);
  if (agentServiceActionMatch && req.method === 'POST') {
    if (!ensureRole(req, res, 'operator')) {
      return;
    }

    const agentId = agentServiceActionMatch[1];
    const serviceName = decodeURIComponent(agentServiceActionMatch[2]);
    const entry = clientsById.get(agentId);
    if (!entry) {
      res.writeHead(404);
      return res.end('Agent not found');
    }

    collectBody(req, async (body) => {
      try {
        const payload = JSON.parse(body);
        const action = (payload?.action ?? '').toString().trim().toLowerCase();
        if (!['start', 'stop', 'restart'].includes(action)) {
          res.writeHead(400);
          return res.end('Invalid action');
        }

        const result = await performServiceAction(entry, serviceName, action);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: Boolean(result.success),
          message: result.message ?? 'Action completed',
        }));
      } catch (error) {
        console.error('Service action failed', error);
        res.writeHead(500);
        res.end('Service action failed');
      }
    });

    return;
  }

  const screenAnswerMatch = pathname.match(/^\/screen\/([^/]+)\/answer$/);
  if (screenAnswerMatch && req.method === 'POST') {
    const sessionId = screenAnswerMatch[1];
    const session = screenSessions.get(sessionId);
    if (!session) {
      res.writeHead(404);
      return res.end('Session not found');
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        sendControl(session.socket, 'screen-answer', {
          sessionId,
          sdp: payload.sdp,
          sdpType: payload.type,
        });
        res.writeHead(204);
        res.end();
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid SDP');
      }
    });

    return;
  }

  const screenCandidateMatch = pathname.match(/^\/screen\/([^/]+)\/candidate$/);
  if (screenCandidateMatch && req.method === 'POST') {
    const sessionId = screenCandidateMatch[1];
    const session = screenSessions.get(sessionId);
    if (!session) {
      res.writeHead(404);
      return res.end('Session not found');
    }

    collectBody(req, (body) => {
      try {
        const payload = JSON.parse(body);
        sendControl(session.socket, 'screen-candidate', {
          sessionId,
          candidate: payload.candidate,
          sdpMid: payload.sdpMid,
          sdpMLineIndex: payload.sdpMLineIndex,
        });
        res.writeHead(204);
        res.end();
      } catch (error) {
        res.writeHead(400);
        res.end('Invalid candidate');
      }
    });

    return;
  }

  const screenStopMatch = pathname.match(/^\/screen\/([^/]+)\/stop$/);
  if (screenStopMatch && req.method === 'POST') {
    const sessionId = screenStopMatch[1];
    const session = screenSessions.get(sessionId);
    if (!session) {
      res.writeHead(404);
      return res.end('Session not found');
    }

    sendControl(session.socket, 'stop-screen', { sessionId });
    screenSessions.delete(sessionId);
    res.writeHead(204);
    res.end();
    return;
  }

  const filePath = pathname === '/' ? '/index.html' : pathname;
  const resolved = path.join(PUBLIC_DIR, decodeURIComponent(filePath));
  if (!resolved.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }

  fs.readFile(resolved, (error, data) => {
    if (error) {
      res.writeHead(404);
      return res.end('Not found');
    }

    const ext = path.extname(resolved);
    const mime = ext === '.js' ? 'application/javascript' : 'text/html';
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  });
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (socket, request) => {
  const remote = request.socket.remoteAddress ?? 'unknown';
  const id = uuidv4();
  let info = {
    id,
    name: `unnamed (${remote})`,
    remoteAddress: remote,
    connectedAt: new Date().toISOString(),
    os: 'unknown',
    platform: 'unknown',
    group: DEFAULT_GROUP,
    status: 'online',
    lastSeen: null,
    specs: null,
    updatesSummary: null,
    bsodSummary: null,
    processSnapshot: null,
    loggedInUser: 'Unknown',
    pendingReboot: false,
    softwareSummary: null,
      features: [],
      bitlockerStatus: null,
      avStatus: null,
  };

  {
    const storedGroup = agentGroupAssignments.get(info.id);
    if (storedGroup) {
      info.group = storedGroup;
      groups.add(storedGroup);
    }
  }

  clients.set(socket, info);
  agents.set(id, info);
  clientsById.set(id, { socket, info });

  console.log(`Client connected from ${remote}`);
  socket.send('Welcome to the secure WebSocket server!');

  socket.on('message', (data) => {
    const payload = data.toString();
    console.log(`Received: ${payload}`);

    try {
      const parsed = JSON.parse(payload);
      if (parsed?.type === 'hello' && typeof parsed.name === 'string' && parsed.name.trim()) {
        const requestedId = typeof parsed.agentId === 'string' && parsed.agentId.trim()
          ? parsed.agentId.trim()
          : info.id;
        if (requestedId !== info.id) {
          clientsById.delete(info.id);
          agents.delete(info.id);
          const existing = agents.get(requestedId);
          if (existing) {
            info = existing;
          } else {
            info = { ...info, id: requestedId };
          }
          const assignedGroup = agentGroupAssignments.get(requestedId);
          if (assignedGroup) {
            info.group = assignedGroup;
            groups.add(assignedGroup);
          } else if (!info.group) {
            info.group = DEFAULT_GROUP;
          }
          agents.set(requestedId, info);
        }

      info.name = parsed.name.trim();
      if (typeof parsed.os === 'string' && parsed.os.trim()) {
        info.os = parsed.os.trim();
        evaluateAssetVulnerabilities(info);
      }
      if (typeof parsed.platform === 'string' && parsed.platform.trim()) {
        info.platform = parsed.platform.trim();
      }
      if (typeof parsed.loggedInUser === 'string' && parsed.loggedInUser.trim()) {
        info.loggedInUser = parsed.loggedInUser.trim();
      }
      if (parsed.specs != null) {
        info.specs = parsed.specs;
      }
      if (Array.isArray(parsed.features)) {
        info.features = parsed.features.filter((item) => typeof item === 'string' && item.trim()).map((item) => item.trim());
      }

      info.bitlockerStatus = normalizeBitlockerStatus(parsed.bitlockerStatus);
      info.avStatus = normalizeAvStatus(parsed.avStatus);
      if (typeof parsed.pendingReboot === 'boolean') {
        info.pendingReboot = parsed.pendingReboot;
      }
        info.status = 'online';
        info.lastSeen = null;
        console.log(`Identified client as ${info.name}`);
        clients.set(socket, info);
        clientsById.set(info.id, { socket, info });
        notifyMonitoringState({ socket, info });
      } else if (parsed?.type === 'shell-output') {
        emitShellOutput(info.id, parsed);
      } else if (parsed?.type === 'screen-offer') {
        const session = screenSessions.get(parsed.sessionId);
        if (session) {
          session.offer = {
            sdp: parsed.sdp,
            sdpType: parsed.sdpType,
          };
          console.log(`Stored screen offer for ${parsed.sessionId} (agent ${session.agentName})`);
          sendScreenEvent(session, 'offer', {
            sessionId: parsed.sessionId,
            agentId: session.agentId,
            agentName: session.agentName,
            ...session.offer,
            screenId: session.screenId,
            screenName: getScreenName(session.agentId, session.screenId),
          });
          sendScreenEvent(session, 'status', {
            sessionId: parsed.sessionId,
            agentId: session.agentId,
            agentName: session.agentName,
            state: 'offer-ready',
            screenId: session.screenId,
            screenName: getScreenName(session.agentId, session.screenId),
          });
        }
      } else if (parsed?.type === 'screen-candidate') {
        const session = screenSessions.get(parsed.sessionId);
        if (session) {
          const candidate = {
            candidate: parsed.candidate,
            sdpMid: parsed.sdpMid,
            sdpMLineIndex: parsed.sdpMLineIndex,
          };
          session.agentCandidates.push(candidate);
          console.log(`Stored screen candidate for ${parsed.sessionId}`);
          sendScreenEvent(session, 'candidate', {
            sessionId: parsed.sessionId,
            agentId: session.agentId,
            agentName: session.agentName,
            ...candidate,
          });
        }
      } else if (parsed?.type === 'screen-error') {
        const session = screenSessions.get(parsed.sessionId);
        if (session) {
          console.log(`Screen error from agent ${session.agentName}: ${parsed.message}`);
          sendScreenEvent(session, 'error', {
            sessionId: parsed.sessionId,
            agentId: session.agentId,
            agentName: session.agentName,
            message: parsed.message,
          });
        }
      } else if (parsed?.type === 'updates-summary') {
      info.updatesSummary = parsed.summary ?? null;
      if (typeof parsed.pendingReboot === 'boolean') {
        info.pendingReboot = parsed.pendingReboot;
      }
      } else if (parsed?.type === 'bsod-summary') {
        info.bsodSummary = parsed.summary ?? null;
      } else if (parsed?.type === 'update-install-result') {
        console.log(`Update install result from ${info.name}: success=${parsed.success}, message="${parsed.message}", rebootRequired=${parsed.rebootRequired}`);
        info.pendingReboot = Boolean(parsed.rebootRequired);
        const scheduleId = typeof parsed.scheduleId === 'string' && parsed.scheduleId.trim()
          ? parsed.scheduleId.trim()
          : null;
        if (scheduleId) {
          const schedule = patchSchedules.get(scheduleId);
          logPatchEvent({
            timestamp: new Date().toISOString(),
            type: 'result',
            scheduleId,
            scheduleName: schedule?.name ?? null,
            agentId: info.id,
            success: Boolean(parsed.success),
            message: parsed.message ?? '',
            rebootRequired: Boolean(parsed.rebootRequired),
            patchIds: schedule?.patchIds ?? [],
          });
        }
        } else if (parsed?.type === 'process-list') {
          info.processSnapshot = parsed.snapshot ?? null;
        } else if (parsed?.type === 'process-kill-result') {
        console.log(`Process kill result from ${info.name}: pid=${parsed.processId}, success=${parsed.success}, message=${parsed.message ?? 'n/a'}`);
      } else if (parsed?.type === 'file-list' && typeof parsed.requestId === 'string') {
        const pending = completeFileRequest(parsed.requestId);
        if (pending) {
          pending.resolve(parsed);
        }
      } else if (parsed?.type === 'file-download-result' && typeof parsed.requestId === 'string') {
        const pending = completeFileRequest(parsed.requestId);
        if (pending) {
          pending.resolve(parsed);
        }
      } else if (parsed?.type === 'file-upload-result' && typeof parsed.requestId === 'string') {
        const pending = completeFileRequest(parsed.requestId);
        if (pending) {
          pending.resolve(parsed);
        }
    } else if (parsed?.type === 'software-list' && typeof parsed.requestId === 'string') {
      const pending = completeSoftwareRequest(parsed.requestId);
      if (pending) {
        const entries = Array.isArray(parsed.entries) ? parsed.entries : [];
        const retrievedAt = typeof parsed.retrievedAt === 'string' ? parsed.retrievedAt : new Date().toISOString();
        pending.resolve({ entries, retrievedAt });
        info.softwareSummary = {
          totalCount: entries.length,
          lastUpdated: retrievedAt,
        };
      }
      } else if (parsed?.type === 'service-list' && typeof parsed.requestId === 'string') {
        const pending = completeServiceRequest(parsed.requestId);
        if (pending) {
          pending.resolve(Array.isArray(parsed.services) ? parsed.services : []);
        }
      } else if (parsed?.type === 'service-action-result' && typeof parsed.requestId === 'string') {
        const pending = completeServiceActionRequest(parsed.requestId);
        if (pending) {
          pending.resolve({
            success: Boolean(parsed.success),
            message: parsed.message ?? '',
            serviceName: parsed.serviceName ?? '',
            action: parsed.action ?? '',
          });
        }
      } else if (parsed?.type === 'firewall-rules' && typeof parsed.requestId === 'string') {
        const pending = completeFirewallRequest(parsed.requestId);
        if (pending && pending.kind === 'rules') {
          pending.resolve(parsed);
        }
      } else if (parsed?.type === 'firewall-action-result' && typeof parsed.requestId === 'string') {
        const pending = completeFirewallRequest(parsed.requestId);
        if (pending && pending.kind === 'action') {
          pending.resolve(parsed);
        }
      } else if (parsed?.type === 'event-stats' && typeof parsed.requestId === 'string') {
        const pending = completeEventStatsRequest(parsed.requestId);
        if (pending) {
          const stats = typeof parsed.stats === 'object' && parsed.stats !== null ? parsed.stats : {};
          const since = typeof parsed.since === 'string' ? parsed.since : new Date().toISOString();
          const record = {
            stats,
            since,
            retrievedAt: new Date().toISOString(),
          };
          agentEventStatsCache.set(info.id, record);
          pending.resolve({
            stats: record.stats,
            since: record.since,
            retrievedAt: record.retrievedAt,
          });
        }
      } else if (parsed?.type === 'event-entries' && typeof parsed.requestId === 'string') {
        const pending = completeEventEntriesRequest(parsed.requestId);
        if (pending) {
          const entries = Array.isArray(parsed.entries) ? parsed.entries : [];
          pending.resolve({
            entries,
            level: typeof parsed.level === 'string' ? parsed.level : 'Information',
          });
        }
      } else if (parsed?.type === 'chat-response') {
        const text = typeof parsed.text === 'string' ? parsed.text.trim() : '';
        if (text.length > 0) {
          const chatEvent = {
            sessionId: typeof parsed.sessionId === 'string' && parsed.sessionId.trim()
              ? parsed.sessionId.trim()
              : uuidv4(),
            agentId: info.id,
            agentName: info.name,
            direction: 'agent',
            text,
            timestamp: new Date().toISOString(),
            user: info.loggedInUser ?? info.name,
            role: 'agent',
          };

          recordChatHistory(info.id, chatEvent);
          dispatchChatEvent(info.id, chatEvent);
        }
        } else if (parsed?.type === 'software-operation-result') {
          handleSoftwareOperationResult(info, parsed);
        } else if (parsed?.type === 'action-result') {
          logPatchEvent({
            timestamp: new Date().toISOString(),
            type: 'result',
            agentId: info.id,
            action: parsed.action ?? null,
            scheduleId: parsed.scheduleId ?? null,
            success: Boolean(parsed.success),
            message: parsed.message ?? '',
          });
        } else if (parsed?.type === 'screen-list' && Array.isArray(parsed.screens)) {
        const normalized = parsed.screens.map((screen, index) => ({
          id: typeof screen.id === 'string' && screen.id.trim() ? screen.id.trim() : `display-${index + 1}`,
          name: typeof screen.name === 'string' && screen.name.trim() ? screen.name.trim() : `Display ${index + 1}`,
          width: typeof screen.width === 'number' ? screen.width : null,
          height: typeof screen.height === 'number' ? screen.height : null,
          x: typeof screen.x === 'number' ? screen.x : null,
          y: typeof screen.y === 'number' ? screen.y : null,
          primary: Boolean(screen.primary),
        }));

        screenLists.set(info.id, { screens: normalized, updatedAt: Date.now() });
        fulfillScreenListRequest(info.id, normalized);
      } else if (parsed?.type === 'monitoring-metrics') {
        handleMonitoringMetrics(info, socket, parsed);
      } else if (parsed?.type === 'remediation-result') {
        sendMonitoringEvent('remediation-result', {
          type: 'remediation-result',
          agentId: info.id,
          agentName: info.name,
          requestId: parsed.requestId,
          success: Boolean(parsed.success),
          message: parsed.message ?? '',
          scriptName: parsed.scriptName ?? '',
          timestamp: new Date().toISOString(),
        });
      }
    } catch (error) {
      // ignore invalid JSON and continue echoing
    }

    socket.send(`Echo: ${payload}`);
  });

  socket.on('close', () => {
    info.status = 'offline';
    info.lastSeen = new Date().toISOString();
    clients.delete(socket);
    clientsById.delete(id);
    shellStreams.delete(id);
    screenLists.delete(id);
    cancelScreenListRequest(id, new Error('agent disconnected'));
    agentProfileStatus.delete(id);
    for (const [requestId, request] of softwareRequests) {
      if (request.agentId === id) {
        clearTimeout(request.timer);
        request.reject(new Error('Agent disconnected'));
        softwareRequests.delete(requestId);
      }
    }
    for (const [requestId, request] of eventStatsRequests) {
      if (request.agentId === id) {
        clearTimeout(request.timer);
        request.reject(new Error('Agent disconnected'));
        eventStatsRequests.delete(requestId);
      }
    }
    for (const [requestId, request] of eventEntriesRequests) {
      if (request.agentId === id) {
        clearTimeout(request.timer);
        request.reject(new Error('Agent disconnected'));
        eventEntriesRequests.delete(requestId);
      }
    }
    for (const [requestId, request] of firewallRequests) {
      if (request.agentId === id) {
        clearTimeout(request.timer);
        request.reject(new Error('Agent disconnected'));
        firewallRequests.delete(requestId);
      }
    }
    for (const [sessionId, session] of screenSessions) {
      if (session.agentId === id) {
        sendScreenEvent(session, 'closed', { reason: 'agent disconnected' });
        screenSessions.delete(sessionId);
      }
    }
    console.log(`Client disconnected: ${info.name}`);
  });
});

server.listen(PORT, () => {
  console.log(`HTTPS server listening on https://localhost:${PORT}`);
  console.log(`WebSocket endpoint available at wss://localhost:${PORT}`);
  console.log('Agent dashboard available via the root path');
  startVulnerabilityIngestion();
});

function sendControl(socket, type, additional = {}) {
  if (socket.readyState !== WebSocket.OPEN) {
    console.log(`Cannot send ${type}; socket state ${socket.readyState}`);
    return;
  }

  const message = JSON.stringify({ type, ...additional });
  console.log(`sendControl ${type} -> ${message}`);
  socket.send(message);
}

function emitShellOutput(agentId, data) {
  const stream = shellStreams.get(agentId);
  if (!stream) {
    return;
  }

  const payload = {
    output: data.output,
    stream: data.stream,
    timestamp: new Date().toISOString(),
  };

  stream.write('event: shell\n');
  stream.write(`data: ${JSON.stringify(payload)}\n\n`);
}

function collectBody(req, callback) {
  let body = '';
  req.on('data', (chunk) => {
    body += chunk;
  });
  req.on('end', () => {
    callback(body);
  });
}

function sendScreenEvent(session, eventName, data) {
  const payload = JSON.stringify(data);
  console.log(`dispatching ${eventName} for ${session.agentId}`);
  for (const res of session.sseClients) {
    res.write(`event: ${eventName}\n`);
    res.write(`data: ${payload}\n\n`);
  }
}

function isPatchApproved(agentId, updateId) {
  if (!agentId || !updateId) {
    return false;
  }

  return patchApprovals.has(`${agentId}:${updateId}`);
}

function buildPatchCatalog() {
  const catalog = new Map();

  for (const info of agents.values()) {
    const summary = info.updatesSummary;
    if (!summary?.categories?.length) {
      continue;
    }

    for (const category of summary.categories) {
      const updates = Array.isArray(category.updates) ? category.updates : [];
      for (const update of updates) {
        const updateId = typeof update?.id === 'string' && update.id.trim() ? update.id.trim() : '';
        if (!updateId) {
          continue;
        }

        let entry = catalog.get(updateId);
        if (!entry) {
          entry = {
            id: updateId,
            title: update.title ?? 'Unnamed update',
            description: update.description ?? '',
            categories: new Map(),
            kbArticleIDs: new Set(),
            agents: new Map(),
          };
          catalog.set(updateId, entry);
        }

        if (category?.name) {
          entry.categories.set(category.name, category.purpose ?? '');
        }

        if (Array.isArray(update.kbArticleIDs)) {
          for (const kb of update.kbArticleIDs) {
            if (typeof kb === 'string' && kb.trim()) {
              entry.kbArticleIDs.add(kb.trim());
            }
          }
        }

        const agentKey = info.id ?? '';
        if (!agentKey) {
          continue;
        }

        let agentRecord = entry.agents.get(agentKey);
        if (!agentRecord) {
          agentRecord = {
            agentId: agentKey,
            agentName: info.name ?? agentKey,
            status: info.status ?? 'offline',
            group: info.group ?? DEFAULT_GROUP,
            approved: false,
            pendingReboot: Boolean(info.pendingReboot),
          };
          entry.agents.set(agentKey, agentRecord);
        }

        agentRecord.status = info.status ?? 'offline';
        agentRecord.pendingReboot = Boolean(info.pendingReboot);
        agentRecord.group = info.group ?? DEFAULT_GROUP;
        agentRecord.approved = isPatchApproved(agentKey, updateId);
      }
    }
  }

  return Array.from(catalog.values()).map((entry) => ({
    id: entry.id,
    title: entry.title,
    description: entry.description,
    categories: Array.from(entry.categories.entries()).map(([name, purpose]) => ({ name, purpose })),
    kbArticleIDs: Array.from(entry.kbArticleIDs),
    agents: Array.from(entry.agents.values()),
    primaryCategory: selectPrimaryCategory(entry.categories),
  }));
}

function buildPatchSummary(patches) {
  const agentIds = new Set();
  let approvedCount = 0;
  let pendingCount = 0;
  let rebootCount = 0;
  for (const patch of patches) {
    for (const agent of patch.agents) {
      agentIds.add(agent.agentId);
      if (agent.approved) {
        approvedCount += 1;
      } else {
        pendingCount += 1;
      }
      if (agent.pendingReboot) {
        rebootCount += 1;
      }
    }
  }

  return {
    totalPatches: patches.length,
    totalAgents: agentIds.size,
    approvedPairs: approvedCount,
    pendingApprovals: pendingCount,
    pendingReboots: rebootCount,
  };
}

function collectApprovedAgentsForPatches(patchIds) {
  const patchSet = new Set(patchIds);
  const targets = new Map();
  for (const key of patchApprovals.keys()) {
    const separator = key.indexOf(':');
    if (separator === -1) {
      continue;
    }

    const agentId = key.slice(0, separator);
    const updateId = key.slice(separator + 1);
    if (!patchSet.has(updateId)) {
      continue;
    }

    const updates = targets.get(agentId) ?? new Set();
    updates.add(updateId);
    targets.set(agentId, updates);
  }
  return targets;
}

function getSoftwareCatalogKey(software) {
  if (!software) {
    return 'unknown';
  }

  const idPart = typeof software.id === 'string' && software.id.trim();
  if (idPart) {
    return idPart.trim();
  }

  const namePart = (software.name ?? '').toString().trim() || 'unknown';
  const versionPart = (software.version ?? '').toString().trim();
  const publisherPart = (software.publisher ?? '').toString().trim();
  return `${namePart}::${versionPart}::${publisherPart}`;
}

function getSoftwareState(softwareId) {
  const record = softwareApprovals.get(softwareId);
  return record?.state ?? 'pending';
}

function buildSoftwareCatalog() {
  const catalog = new Map();
  const agentSet = new Set();
  for (const { info } of clientsById.values()) {
    const agentId = info.id;
    if (!agentId) {
      continue;
    }

    agentSet.add(agentId);
    const entries = Array.isArray(info.softwareEntries) ? info.softwareEntries : [];
    entries.forEach((softwareItem) => {
      const softwareId = softwareItem.__catalogId ?? getSoftwareCatalogKey(softwareItem);
      softwareItem.__catalogId = softwareId;
      let record = catalog.get(softwareId);
      if (!record) {
        record = {
          id: softwareId,
          name: softwareItem.name ?? 'Unknown',
          version: softwareItem.version ?? '',
          publisher: softwareItem.publisher ?? '',
          source: softwareItem.source ?? '',
          agents: new Map(),
        };
        catalog.set(softwareId, record);
      }

      record.agents.set(agentId, {
        agentId,
        agentName: info.name ?? agentId,
        status: info.status ?? 'offline',
        source: softwareItem.source ?? '',
        version: softwareItem.version ?? '',
        publisher: softwareItem.publisher ?? '',
        installDate: softwareItem.installDate ?? '',
        location: softwareItem.location ?? '',
        uninstallCommand: softwareItem.uninstallCommand ?? '',
        packageFullName: softwareItem.packageFullName ?? '',
        productCode: softwareItem.productCode ?? '',
        softwareId: softwareId,
      });
    });
  }

  const list = Array.from(catalog.values()).map((entry) => {
    const status = getSoftwareState(entry.id);
    return {
      id: entry.id,
      name: entry.name,
      version: entry.version,
      publisher: entry.publisher,
      source: entry.source,
      status,
      agents: Array.from(entry.agents.values()),
      agentCount: entry.agents.size,
    };
  });

  updateSoftwareUninstallQueue(list);
  return {
    list,
    agentCount: agentSet.size,
    rejectedPairs: list.reduce((total, software) => {
      if (software.status === 'rejected') {
        return total + software.agentCount;
      }
      return total;
    }, 0),
  };
}

function updateSoftwareUninstallQueue(softwareList) {
  const rejectedSet = new Set();

  softwareList.forEach((software) => {
    if (software.status !== 'rejected') {
      softwareUninstallQueue.delete(software.id);
      return;
    }

    rejectedSet.add(software.id);
    let queue = softwareUninstallQueue.get(software.id);
    if (!queue) {
      queue = { pending: new Set(), lastAttempt: new Map() };
    }

    const currentAgents = new Set();
    software.agents.forEach((agent) => {
      queue.pending.add(agent.agentId);
      currentAgents.add(agent.agentId);
    });

    for (const agentId of Array.from(queue.pending)) {
      if (!currentAgents.has(agentId)) {
        queue.pending.delete(agentId);
      }
    }

    if (queue.pending.size === 0) {
      return softwareUninstallQueue.delete(software.id);
    }

    softwareUninstallQueue.set(software.id, queue);
  });

  for (const softwareId of Array.from(softwareUninstallQueue.keys())) {
    if (!rejectedSet.has(softwareId)) {
      softwareUninstallQueue.delete(softwareId);
    }
  }
}

async function refreshSoftwareEntriesFromAgents() {
  const clients = Array.from(clientsById.values());
  await Promise.allSettled(clients.map(async (entry) => {
    if (entry.socket.readyState !== WebSocket.OPEN) {
      return;
    }

    try {
      const result = await requestAgentSoftwareList(entry);
      const normalized = Array.isArray(result.entries)
        ? result.entries.map((item) => {
            const clone = { ...item };
            clone.__catalogId = getSoftwareCatalogKey(clone);
            return clone;
          })
        : [];
      entry.info.softwareEntries = normalized;
      entry.info.softwareRetrievedAt = result.retrievedAt;
      evaluateAssetVulnerabilities(entry.info);
    } catch (error) {
      console.warn('Software refresh failed for', entry.info.id, error);
    }
  }));
}

function logSoftwareEvent(entry) {
  softwareUninstallLog.unshift(entry);
  if (softwareUninstallLog.length > SOFTWARE_UNINSTALL_LOG_LIMIT) {
    softwareUninstallLog.pop();
  }
}

function handleSoftwareOperationResult(info, parsed) {
  const softwareId = parsed.softwareId;
  if (!softwareId) {
    return;
  }

  const queue = softwareUninstallQueue.get(softwareId);
  if (!queue) {
    return;
  }

  if (parsed.success) {
    queue.pending.delete(info.id);
    queue.lastAttempt.delete(info.id);
    logSoftwareEvent({
      timestamp: new Date().toISOString(),
      type: 'uninstall-success',
      softwareId,
      agentId: info.id,
      agentName: info.name,
      softwareName: parsed.softwareName ?? '',
      message: parsed.message ?? 'Uninstall completed',
    });
  } else {
    queue.lastAttempt.set(info.id, Date.now());
    logSoftwareEvent({
      timestamp: new Date().toISOString(),
      type: 'uninstall-failure',
      softwareId,
      agentId: info.id,
      agentName: info.name,
      softwareName: parsed.softwareName ?? '',
      message: parsed.message ?? 'Uninstall failed',
    });
  }

  if (!queue.pending.size) {
    softwareUninstallQueue.delete(softwareId);
  } else {
    // ensure we attempt again soon
    setTimeout(processSoftwareUninstalls, 5_000);
  }
}

function findAgentSoftwareEntry(info, softwareId) {
  const entries = Array.isArray(info.softwareEntries) ? info.softwareEntries : [];
  return entries.find((item) => (item.__catalogId ?? getSoftwareCatalogKey(item)) === softwareId) ?? null;
}

function queueRejectedSoftwareNow(softwareId) {
  const queue = softwareUninstallQueue.get(softwareId) ?? { pending: new Set(), lastAttempt: new Map() };
  queue.pending.clear();
  for (const { info } of clientsById.values()) {
    const softwareEntry = findAgentSoftwareEntry(info, softwareId);
    if (softwareEntry && info.id) {
      queue.pending.add(info.id);
    }
  }

  if (!queue.pending.size) {
    return softwareUninstallQueue.delete(softwareId);
  }

  softwareUninstallQueue.set(softwareId, queue);
  processSoftwareUninstalls();
}

  function processSoftwareUninstalls() {
  if (!softwareUninstallQueue.size) {
    return;
  }

  for (const [softwareId, queue] of Array.from(softwareUninstallQueue.entries())) {
    if (!queue.pending.size) {
      softwareUninstallQueue.delete(softwareId);
      continue;
    }

    for (const agentId of Array.from(queue.pending)) {
      const entry = clientsById.get(agentId);
      if (!entry || entry.socket.readyState !== WebSocket.OPEN) {
        continue;
      }

        const softwareEntry = findAgentSoftwareEntry(entry.info, softwareId);
        if (!softwareEntry) {
          queue.pending.delete(agentId);
          continue;
        }

        const hasPackageFullName = typeof softwareEntry.packageFullName === 'string' && softwareEntry.packageFullName.trim().length > 0;
        const hasUninstallCommand = typeof softwareEntry.uninstallCommand === 'string' && softwareEntry.uninstallCommand.trim().length > 0;
        const hasProductCode = typeof softwareEntry.productCode === 'string' && softwareEntry.productCode.trim().length > 0;

        if (!hasPackageFullName && !hasUninstallCommand && !hasProductCode) {
          queue.pending.delete(agentId);
          logSoftwareEvent({
            timestamp: new Date().toISOString(),
            type: 'uninstall-failure',
            softwareId,
            agentId,
            agentName: entry.info.name,
            softwareName: softwareEntry.name ?? '',
            message: 'No uninstall payload available (missing appx name, command, and product code).',
          });
          continue;
        }

        const requestId = uuidv4();
        const payload = {
          requestId,
          softwareId,
          source: hasPackageFullName ? 'appx' : 'registry',
          uninstallCommand: hasUninstallCommand ? softwareEntry.uninstallCommand?.trim() ?? null : null,
          packageFullName: hasPackageFullName ? softwareEntry.packageFullName?.trim() ?? null : null,
          productCode: hasProductCode ? softwareEntry.productCode?.trim() ?? null : null,
        };

        sendControl(entry.socket, 'uninstall-software', payload);
        logSoftwareEvent({
          timestamp: new Date().toISOString(),
          type: 'uninstall-attempt',
          softwareId,
          agentId,
          agentName: entry.info.name,
          softwareName: softwareEntry.name ?? '',
          message: 'Automatic uninstall requested',
        });
    }

    if (queue.pending.size === 0) {
      softwareUninstallQueue.delete(softwareId);
    }
  }
}

function resolveAgentPackageDir() {
  if (fs.existsSync(AGENT_DOWNLOAD_DIR)) {
    return AGENT_DOWNLOAD_DIR;
  }

  if (fs.existsSync(AGENT_BUILD_FALLBACK_DIR)) {
    return AGENT_BUILD_FALLBACK_DIR;
  }

  return null;
}

function selectPrimaryCategory(categoryMap) {
  for (const canonical of PATCH_CATEGORY_ORDER) {
    if (categoryMap.has(canonical)) {
      return { name: canonical, purpose: categoryMap.get(canonical) ?? '' };
    }
  }

  for (const [name, purpose] of categoryMap.entries()) {
    return { name, purpose: purpose ?? '' };
  }

  return null;
}

function serializeSchedule(schedule) {
  return {
    id: schedule.id,
    name: schedule.name,
    patchIds: schedule.patchIds,
    agentIds: Array.isArray(schedule.agentIds) ? schedule.agentIds : [],
    category: schedule.category ?? null,
    dynamic: Boolean(schedule.dynamic ?? (!Array.isArray(schedule.agentIds) || schedule.agentIds.length === 0)),
    createdAt: schedule.createdAt,
    nextRun: schedule.nextRun,
    lastRun: schedule.lastRun,
    repeatMs: schedule.repeatMs > 0 ? schedule.repeatMs : null,
    pendingAgents: Array.from(schedule.pendingAgents),
  };
}

function serializeSchedules(schedules) {
  return schedules.map((schedule) => serializeSchedule(schedule));
}

function logPatchEvent(entry) {
  patchHistory.unshift(entry);
  if (patchHistory.length > PATCH_HISTORY_LIMIT) {
    patchHistory.pop();
  }
}

function processPatchSchedules() {
  const now = Date.now();
  for (const schedule of Array.from(patchSchedules.values())) {
    if (schedule.nextRun > now) {
      continue;
    }

    const isDynamic = Boolean(schedule.dynamic || !Array.isArray(schedule.agentIds) || !schedule.agentIds.length);
    const targetEntries = [];

    if (isDynamic) {
      const dynamicTargets = collectApprovedAgentsForPatches(schedule.patchIds);
      dynamicTargets.forEach((patchSet, agentId) => {
        targetEntries.push({
          agentId,
          patchIds: Array.from(patchSet),
        });
      });
    } else {
      const referenceIds = schedule.repeatMs > 0
        ? schedule.agentIds
        : Array.from(schedule.pendingAgents);
      referenceIds.forEach((agentId) => {
        targetEntries.push({
          agentId,
          patchIds: schedule.patchIds.slice(),
        });
      });
    }

    if (!targetEntries.length) {
      schedule.nextRun = now + PATCH_SCHEDULE_RETRY_MS;
      continue;
    }

    let delivered = false;
    for (const target of targetEntries) {
      const entry = clientsById.get(target.agentId);
      if (!entry || entry.socket.readyState !== WebSocket.OPEN) {
        continue;
      }

      const filteredIds = Array.from(new Set(target.patchIds)).filter(Boolean);
      if (!filteredIds.length) {
        continue;
      }

      console.log(`Triggering patch schedule ${schedule.name} (${schedule.id}) for agent ${target.agentId}`);
      sendControl(entry.socket, 'install-updates', { ids: filteredIds, scheduleId: schedule.id });
      logPatchEvent({
        timestamp: new Date().toISOString(),
        type: 'dispatch',
        scheduleId: schedule.id,
        scheduleName: schedule.name,
        agentId: target.agentId,
        patchIds: filteredIds,
      });
      delivered = true;
      if (!isDynamic && schedule.repeatMs === 0) {
        schedule.pendingAgents.delete(target.agentId);
      }
    }

    schedule.lastRun = now;
    if (schedule.repeatMs > 0) {
      if (!isDynamic) {
        schedule.pendingAgents = new Set(schedule.agentIds);
      }
      schedule.nextRun = now + schedule.repeatMs;
      continue;
    }

    if (isDynamic) {
      patchSchedules.delete(schedule.id);
      continue;
    }

    if (schedule.pendingAgents.size === 0) {
      patchSchedules.delete(schedule.id);
      continue;
    }

    schedule.nextRun = now + PATCH_SCHEDULE_RETRY_MS;
    if (!delivered) {
      console.log(`Patch schedule ${schedule.name} waiting for offline targets`);
    }
  }
}

setInterval(processPatchSchedules, PATCH_SCHEDULE_TICK_MS);
setInterval(processSoftwareUninstalls, SOFTWARE_UNINSTALL_INTERVAL_MS);

function addChatListener(agentId, res) {
  const listeners = chatListeners.get(agentId) ?? new Set();
  listeners.add(res);
  chatListeners.set(agentId, listeners);
}

function removeChatListener(agentId, res) {
  const listeners = chatListeners.get(agentId);
  if (!listeners) {
    return;
  }

  listeners.delete(res);
  if (listeners.size === 0) {
    chatListeners.delete(agentId);
  } else {
    chatListeners.set(agentId, listeners);
  }
}

function flushChatHistory(agentId, res) {
  const history = chatHistories.get(agentId) ?? [];
  for (const entry of history) {
    writeChatEvent(res, entry);
  }
}

function dispatchChatEvent(agentId, payload) {
  const listeners = chatListeners.get(agentId);
  if (!listeners || listeners.size === 0) {
    return;
  }

  const data = JSON.stringify(payload);
  for (const res of listeners) {
    res.write('event: chat\n');
    res.write(`data: ${data}\n\n`);
  }
}

function recordChatHistory(agentId, payload) {
  const history = chatHistories.get(agentId) ?? [];
  history.push({ ...payload });
  if (history.length > CHAT_HISTORY_LIMIT) {
    history.shift();
  }
  chatHistories.set(agentId, history);
  if (payload.direction === 'agent') {
    const messageTimestamp = Number.isFinite(Date.parse(payload.timestamp ?? '')) && payload.timestamp
      ? Date.parse(payload.timestamp ?? '')
      : Date.now();
    const previousTimestamp = agentChatLastTimestamp.get(agentId) ?? 0;
    if (messageTimestamp > previousTimestamp) {
      agentChatLastTimestamp.set(agentId, messageTimestamp);
      incrementChatNotification(agentId, messageTimestamp);
    }
  }
}

function writeChatEvent(res, payload) {
  res.write('event: chat\n');
  res.write(`data: ${JSON.stringify(payload)}\n\n`);
}

function normalizeGroupName(value) {
  if (typeof value !== 'string') {
    return DEFAULT_GROUP;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : DEFAULT_GROUP;
}

function assignAgentToGroup(agentId, groupName) {
  const entry = clientsById.get(agentId);
  if (!entry) {
    return DEFAULT_GROUP;
  }

  const normalized = normalizeGroupName(groupName);
  entry.info.group = normalized;
  const alreadyKnown = groups.has(normalized);
  groups.add(normalized);
  if (!alreadyKnown) {
    persistGroups();
  }
  agentGroupAssignments.set(agentId, normalized);
  persistAgentGroupAssignments();
  return normalized;
}

function extractScale(raw) {
  let scale = DEFAULT_SCREEN_SCALE;
  if (typeof raw === 'number') {
    scale = raw;
  } else if (typeof raw === 'string') {
    const parsed = parseFloat(raw);
    if (!Number.isNaN(parsed)) {
      scale = parsed;
    }
  }

  return clampScreenScale(scale);
}

function clampScreenScale(value) {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return DEFAULT_SCREEN_SCALE;
  }

  return Math.min(Math.max(value, MIN_SCREEN_SCALE), MAX_SCREEN_SCALE);
}

function requestScreenList(agentId, socket) {
  return new Promise((resolve, reject) => {
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      reject(new Error('Agent unavailable'));
      return;
    }

    const existing = screenListRequests.get(agentId);
    if (existing) {
      existing.resolvers.push({ resolve, reject });
      return;
    }

    const resolvers = [{ resolve, reject }];
    const timer = setTimeout(() => {
      screenListRequests.delete(agentId);
      for (const entry of resolvers) {
        entry.reject(new Error('Screen list request timed out'));
      }
    }, SCREEN_LIST_TIMEOUT_MS);

    screenListRequests.set(agentId, { resolvers, timer });
    sendControl(socket, 'get-screen-list');
  });
}

function fulfillScreenListRequest(agentId, screens) {
  const pending = screenListRequests.get(agentId);
  if (!pending) {
    return;
  }

  clearTimeout(pending.timer);
  screenListRequests.delete(agentId);
  for (const entry of pending.resolvers) {
    entry.resolve(screens);
  }
}

function cancelScreenListRequest(agentId, reason) {
  const pending = screenListRequests.get(agentId);
  if (!pending) {
    return;
  }

  clearTimeout(pending.timer);
  screenListRequests.delete(agentId);
  for (const entry of pending.resolvers) {
    entry.reject(reason);
  }
}

function requestAgentFileList(entry, requestedPath) {
  return new Promise((resolve, reject) => {
    const requestId = enqueueFileRequest('list', entry.info.id, resolve, reject);
    sendControl(entry.socket, 'list-files', { requestId, path: requestedPath ?? '' });
  });
}

function requestAgentFileDownload(entry, requestedPath) {
  return new Promise((resolve, reject) => {
    const requestId = enqueueFileRequest('download', entry.info.id, resolve, reject);
    sendControl(entry.socket, 'download-file', { requestId, path: requestedPath });
  });
}

function requestAgentFileUpload(entry, destinationPath, base64Data) {
  return new Promise((resolve, reject) => {
    const requestId = enqueueFileRequest('upload', entry.info.id, resolve, reject);
    const buffer = Buffer.from(base64Data, 'base64');
    const chunkCount = buffer.length === 0
      ? 1
      : Math.ceil(buffer.length / FILE_UPLOAD_CHUNK_BYTES);

    for (let index = 0; index < chunkCount; index += 1) {
      const start = index * FILE_UPLOAD_CHUNK_BYTES;
      const end = Math.min(buffer.length, start + FILE_UPLOAD_CHUNK_BYTES);
      const chunk = buffer.slice(start, end);

      sendControl(entry.socket, 'upload-file-chunk', {
        requestId,
        path: destinationPath,
        chunkIndex: index,
        totalChunks: chunkCount,
        data: chunk.toString('base64'),
      });
    }

    sendControl(entry.socket, 'upload-file-complete', {
      requestId,
      path: destinationPath,
    });
  });
}

function requestAgentSoftwareList(entry) {
  return new Promise((resolve, reject) => {
    const requestId = enqueueSoftwareRequest(entry.info.id, resolve, reject);
    sendControl(entry.socket, 'list-software', { requestId });
  });
}

function enqueueFileRequest(kind, agentId, resolve, reject) {
  const requestId = uuidv4();
  const timer = setTimeout(() => {
    fileRequests.delete(requestId);
    reject(new Error('File request timed out'));
  }, FILE_REQUEST_TIMEOUT_MS);

  fileRequests.set(requestId, { kind, agentId, resolve, reject, timer });
  return requestId;
}

function completeFileRequest(requestId) {
  const entry = fileRequests.get(requestId);
  if (!entry) {
    return null;
  }

  clearTimeout(entry.timer);
  fileRequests.delete(requestId);
  return entry;
}

  function enqueueSoftwareRequest(agentId, resolve, reject) {
    const requestId = uuidv4();
    const timer = setTimeout(() => {
      softwareRequests.delete(requestId);
      reject(new Error('Software request timed out'));
    }, SOFTWARE_REQUEST_TIMEOUT_MS);

    softwareRequests.set(requestId, { agentId, resolve, reject, timer });
    return requestId;
  }

  function completeSoftwareRequest(requestId) {
    const entry = softwareRequests.get(requestId);
    if (!entry) {
      return null;
    }

  clearTimeout(entry.timer);
  softwareRequests.delete(requestId);
    return entry;
  }

  function enqueueServiceRequest(agentId, resolve, reject) {
    const requestId = uuidv4();
    const timer = setTimeout(() => {
      serviceRequests.delete(requestId);
      reject(new Error('Service request timed out'));
    }, SERVICE_REQUEST_TIMEOUT_MS);

    serviceRequests.set(requestId, { agentId, resolve, reject, timer });
    return requestId;
  }

  function completeServiceRequest(requestId) {
    const entry = serviceRequests.get(requestId);
    if (!entry) {
      return null;
    }

    clearTimeout(entry.timer);
    serviceRequests.delete(requestId);
    return entry;
  }

function enqueueServiceActionRequest(requestId, resolve, reject) {
  const timer = setTimeout(() => {
    serviceActionRequests.delete(requestId);
    reject(new Error('Service action timed out'));
  }, SERVICE_ACTION_TIMEOUT_MS);

    serviceActionRequests.set(requestId, { resolve, reject, timer });
  }

function completeServiceActionRequest(requestId) {
  const entry = serviceActionRequests.get(requestId);
  if (!entry) {
    return null;
  }

  clearTimeout(entry.timer);
  serviceActionRequests.delete(requestId);
  return entry;
}

function enqueueFirewallRequest(agentId, kind, resolve, reject) {
  const requestId = uuidv4();
  const timer = setTimeout(() => {
    firewallRequests.delete(requestId);
    reject(new Error('Firewall request timed out'));
  }, FIREWALL_REQUEST_TIMEOUT_MS);

  firewallRequests.set(requestId, { agentId, kind, resolve, reject, timer });
  return requestId;
}

function completeFirewallRequest(requestId) {
  const entry = firewallRequests.get(requestId);
  if (!entry) {
    return null;
  }

  clearTimeout(entry.timer);
  firewallRequests.delete(requestId);
  return entry;
}

function requestAgentEventStats(entry) {
  return new Promise((resolve, reject) => {
    const requestId = enqueueEventStatsRequest(entry.info.id, resolve, reject);
    sendControl(entry.socket, 'request-event-stats', { requestId });
  });
}

function requestAgentEventEntries(entry, level) {
  return new Promise((resolve, reject) => {
    const normalized = typeof level === 'string' && level.trim()
      ? `${level.charAt(0).toUpperCase()}${level.slice(1).toLowerCase()}`
      : 'Information';
    const requestId = enqueueEventEntriesRequest(entry.info.id, resolve, reject);
    sendControl(entry.socket, 'request-event-entries', { requestId, level: normalized });
  });
}

function enqueueEventStatsRequest(agentId, resolve, reject) {
  const requestId = uuidv4();
  const timer = setTimeout(() => {
    eventStatsRequests.delete(requestId);
    reject(new Error('Event stats request timed out'));
  }, EVENT_STATS_TIMEOUT_MS);

  eventStatsRequests.set(requestId, { agentId, resolve, reject, timer });
  return requestId;
}

function completeEventStatsRequest(requestId) {
  const entry = eventStatsRequests.get(requestId);
  if (!entry) {
    return null;
  }

  clearTimeout(entry.timer);
  eventStatsRequests.delete(requestId);
  return entry;
}

function enqueueEventEntriesRequest(agentId, resolve, reject) {
  const requestId = uuidv4();
  const timer = setTimeout(() => {
    eventEntriesRequests.delete(requestId);
    reject(new Error('Event entries request timed out'));
  }, EVENT_ENTRIES_TIMEOUT_MS);

  eventEntriesRequests.set(requestId, { agentId, resolve, reject, timer });
  return requestId;
}

function completeEventEntriesRequest(requestId) {
  const entry = eventEntriesRequests.get(requestId);
  if (!entry) {
    return null;
  }

  clearTimeout(entry.timer);
  eventEntriesRequests.delete(requestId);
  return entry;
}

function formatSystemHealthPayload(info, stats, since, retrievedAt, options = {}) {
  const agentId = info?.id ?? '';
  const status = info?.status ?? (clientsById.has(agentId) ? 'online' : 'offline');
  return {
    agentId,
    name: info?.name ?? agentId,
    status,
    os: info?.os ?? info?.platform ?? 'unknown',
    platform: info?.platform ?? null,
    group: info?.group ?? DEFAULT_GROUP,
    loggedInUser: info?.loggedInUser ?? null,
    pendingReboot: Boolean(info?.pendingReboot),
    lastSeen: info?.lastSeen ?? null,
    eventStats: stats ?? null,
    since: since ?? null,
    retrievedAt: retrievedAt ?? null,
    error: options.error ?? null,
    source: options.source ?? 'cache',
    offline: Boolean(options.offline) || status !== 'online',
  };
}

function handleAuthRoute(req, res, pathname, requestedUrl) {
  if (req.method === 'POST' && pathname === '/auth/login') {
    return handleLogin(req, res);
  }

  if (pathname === '/auth/logout') {
    const session = getSessionFromRequest(req);
    if (session) {
      sessions.delete(session.id);
    }

    clearSessionCookie(res);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ success: true }));
  }

  if (pathname === '/auth/me' && req.method === 'GET') {
    const session = getSessionFromRequest(req);
    if (!session) {
      res.writeHead(401);
      return res.end('Unauthorized');
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ username: session.user.username, role: session.user.role }));
  }

  if (pathname === '/auth/sso') {
    return handleSso(req, res, requestedUrl);
  }

  res.writeHead(404);
  res.end('Not found');
}

function handleLogin(req, res) {
  collectBody(req, async (body) => {
    try {
      const data = JSON.parse(body.toString());
      const username = data.username?.toString().trim();
      const password = data.password?.toString();
      const totp = data.totp?.toString();
      if (!username || !password || !totp) {
        throw new Error('Missing credentials.');
      }

      const user = USERS_CONFIG.find((entry) => entry.username === username);
      if (!user) {
        throw new Error('Invalid credentials.');
      }

      const match = await bcrypt.compare(password, user.passwordHash);
      if (!match || !authenticator.check(totp, user.totpSecret)) {
        throw new Error('Invalid credentials.');
      }

      const session = createSession(user);
      setSessionCookie(res, session.id);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ username: user.username, role: user.role }));
    } catch (error) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: error.message }));
    }
  });
}

function handleSso(req, res, requestedUrl) {
  const username = requestedUrl.searchParams.get('username') ?? '';
  const timestamp = Number(requestedUrl.searchParams.get('ts'));
  const signature = requestedUrl.searchParams.get('sig');

  if (!username || !signature || Number.isNaN(timestamp)) {
    res.writeHead(400);
    return res.end('Invalid SSO request.');
  }

  if (Math.abs(Date.now() - timestamp) > SSO_WINDOW_MS) {
    res.writeHead(400);
    return res.end('SSO request expired.');
  }

  const expected = crypto.createHmac('sha256', SSO_SECRET).update(`${username}:${timestamp}`).digest('hex');
  if (expected !== signature) {
    res.writeHead(401);
    return res.end('Invalid SSO signature.');
  }

  const user = USERS_CONFIG.find((entry) => entry.username === username);
  if (!user) {
    res.writeHead(401);
    return res.end('Unknown user.');
  }

  const session = createSession(user);
  setSessionCookie(res, session.id);
  res.writeHead(302, { Location: '/' });
  res.end();
}

function serveStaticAsset(req, res, pathname) {
  const filePath = pathname === '/login.html' ? '/login.html' : '/login.js';
  const resolved = path.join(PUBLIC_DIR, filePath);
  if (!resolved.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }

  fs.readFile(resolved, (error, data) => {
    if (error) {
      res.writeHead(404);
      return res.end('Not found');
    }

    const ext = path.extname(resolved);
    const mime = ext === '.js' ? 'application/javascript' : 'text/html';
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  });
}

function setSessionCookie(res, sessionId) {
  const maxAge = Math.floor(SESSION_TTL_MS / 1000);
  res.setHeader('Set-Cookie', `rmm-session=${sessionId}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`);
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'rmm-session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0');
}

function parseCookies(header) {
  if (!header) {
    return {};
  }

  return header.split(';').reduce((acc, cookie) => {
    const [key, ...valueParts] = cookie.split('=');
    if (!key) {
      return acc;
    }

    acc[key.trim()] = decodeURIComponent(valueParts.join('=').trim());
    return acc;
  }, {});
}

function getSessionFromRequest(req) {
  const cookies = parseCookies(req.headers.cookie);
  const sessionId = cookies['rmm-session'];
  if (!sessionId) {
    return null;
  }

  const session = sessions.get(sessionId);
  if (!session) {
    return null;
  }

  if (session.expires < Date.now()) {
    sessions.delete(sessionId);
    return null;
  }

  session.expires = Date.now() + SESSION_TTL_MS;
  return session;
}

function agentSupports(info, feature) {
  if (!info || !feature) {
    return false;
  }

  const features = Array.isArray(info.features) ? info.features : [];
  return features.includes(feature);
}

function createSession(user) {
  const id = uuidv4();
  const session = { id, user, expires: Date.now() + SESSION_TTL_MS };
  sessions.set(id, session);
  return session;
}

function respondUnauthorized(req, res) {
  const acceptHeader = req.headers.accept ?? '';
  if (acceptHeader.includes('text/html')) {
    res.writeHead(302, { Location: '/login.html' });
    res.end();
    return;
  }

  res.writeHead(401);
  res.end('Unauthorized');
}

function ensureRole(req, res, minRole) {
  const session = req.userSession;
  if (!session) {
    respondUnauthorized(req, res);
    return false;
  }

  const weight = roleWeight[session.user.role] ?? 0;
  if (weight < roleWeight[minRole]) {
    res.writeHead(403);
    res.end('Forbidden');
    return false;
  }

  return true;
}

function loadUsersConfig() {
  try {
    const raw = fs.readFileSync(USERS_CONFIG_PATH, 'utf-8');
    return JSON.parse(raw);
  } catch (error) {
    console.error('Failed to load users config', error);
    return [];
  }
}

function requestAgentServiceList(entry) {
  return new Promise((resolve, reject) => {
    const requestId = enqueueServiceRequest(entry.info.id, resolve, reject);
    sendControl(entry.socket, 'list-services', { requestId });
  });
}

function requestAgentFirewallRules(entry) {
  if (!agentSupports(entry.info, 'firewall')) {
    return Promise.reject(new Error('Firewall feature unsupported by this agent'));
  }

  return new Promise((resolve, reject) => {
    const requestId = enqueueFirewallRequest(entry.info.id, 'rules', resolve, reject);
    sendControl(entry.socket, 'list-firewall', { requestId });
  });
}

function requestAgentFirewallAction(entry, payload) {
  if (!agentSupports(entry.info, 'firewall')) {
    return Promise.reject(new Error('Firewall feature unsupported by this agent'));
  }

  return new Promise((resolve, reject) => {
    const requestId = enqueueFirewallRequest(entry.info.id, 'action', resolve, reject);
    sendControl(entry.socket, 'firewall-action', { requestId, ...payload });
  });
}

function performServiceAction(entry, serviceName, action) {
  return new Promise((resolve, reject) => {
    const requestId = uuidv4();
    enqueueServiceActionRequest(requestId, resolve, reject);
    sendControl(entry.socket, 'manage-service', {
      requestId,
      serviceName,
      action,
    });
  });
}

function persistUsersConfig() {
  try {
    fs.writeFileSync(USERS_CONFIG_PATH, JSON.stringify(USERS_CONFIG, null, 2), 'utf-8');
    return true;
  } catch (error) {
    console.error('Failed to save users config', error);
    return false;
  }
}

function getScreenName(agentId, screenId) {
  if (!screenId) {
    return null;
  }

  const stored = screenLists.get(agentId);
  return stored?.screens.find((screen) => screen.id === screenId)?.name ?? null;
}

function getAssignedProfiles(info) {
  if (!info) {
    return [];
  }

  const group = info.group ?? DEFAULT_GROUP;
  return monitoringConfig.monitoringProfiles.filter((profile) => {
    const agents = Array.isArray(profile.assignedAgents) ? profile.assignedAgents : [];
    const groups = Array.isArray(profile.assignedGroups) ? profile.assignedGroups : [];
    return agents.includes(info.id) || groups.includes(group);
  });
}

function getAgentMonitoringProfiles(info) {
  const profiles = getAssignedProfiles(info);
  if (!info || !info.id) {
    return profiles.map((profile) => ({
      id: profile.id,
      name: profile.name,
      alert: false,
      metrics: getRequiredMetricsForProfiles([profile]),
    }));
  }

  const statusMap = agentProfileStatus.get(info.id) ?? new Map();
  return profiles.map((profile) => ({
    id: profile.id,
    name: profile.name,
    alert: statusMap.get(profile.id) ?? false,
    metrics: getRequiredMetricsForProfiles([profile]),
  }));
}

function shouldMonitorAgent(info) {
  return getAssignedProfiles(info).length > 0;
}

function normalizeBitlockerStatus(payload) {
  if (!payload || typeof payload !== 'object') {
    return null;
  }

  const protectionStatus = typeof payload.protectionStatus === 'string' && payload.protectionStatus.trim()
    ? payload.protectionStatus.trim()
    : null;
  const lockStatus = typeof payload.lockStatus === 'string' && payload.lockStatus.trim()
    ? payload.lockStatus.trim()
    : null;

  if (!protectionStatus && !lockStatus) {
    return null;
  }

  const volume = typeof payload.volume === 'string' && payload.volume.trim()
    ? payload.volume.trim()
    : 'Unknown';

  let percentage = null;
  if (typeof payload.percentageEncrypted === 'number' && Number.isFinite(payload.percentageEncrypted)) {
    percentage = clampPercentage(payload.percentageEncrypted);
  } else if (typeof payload.percentageEncrypted === 'string') {
    const parsed = Number(payload.percentageEncrypted);
    if (Number.isFinite(parsed)) {
      percentage = clampPercentage(parsed);
    }
  }

  const keyProtectors = Array.isArray(payload.keyProtectors)
    ? payload.keyProtectors
      .filter((entry) => typeof entry === 'string' && entry.trim())
      .map((entry) => entry.trim())
    : [];

  return {
    volume,
    protectionStatus: protectionStatus ?? 'Unknown',
    lockStatus: lockStatus ?? 'Unknown',
    percentageEncrypted: Number.isFinite(percentage) ? percentage : null,
    keyProtectors,
  };
}

function normalizeAvStatus(payload) {
  if (!payload || typeof payload !== 'object') {
    return null;
  }

  const name = typeof payload.name === 'string' && payload.name.trim()
    ? payload.name.trim()
    : 'Unknown AV';
  const status = typeof payload.status === 'string' && payload.status.trim()
    ? payload.status.trim()
    : 'Unknown';
  const definition = typeof payload.definition === 'string' && payload.definition.trim()
    ? payload.definition.trim()
    : 'Definition status unknown';
  const productState = Number.isFinite(payload.ProductState)
    ? Number(payload.ProductState)
    : 0;

  return { name, status, definition, productState };
}

function clampPercentage(value) {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return null;
  }

  if (value < 0) {
    return 0;
  }

  if (value > 100) {
    return 100;
  }

  return value;
}

function notifyMonitoringState(entry) {
  if (!entry || !entry.socket || !entry.info) {
    return;
  }

  const profiles = getAssignedProfiles(entry.info);
  const enabled = profiles.length > 0;
  const metrics = getRequiredMetricsForProfiles(profiles);
  sendControl(entry.socket, 'monitoring-status', {
    enabled,
    profiles: profiles.map((profile) => profile.id),
    metrics,
  });
}

function notifyAgentMonitoring(agentId) {
  const entry = clientsById.get(agentId);
  if (!entry) {
    return;
  }

  notifyMonitoringState(entry);
}

function notifyGroupMonitoring(groupName) {
  for (const entry of clientsById.values()) {
    if ((entry.info.group ?? DEFAULT_GROUP) === groupName) {
      notifyMonitoringState(entry);
    }
  }
}

function ensureDataDirectory() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function loadGroups() {
  ensureDataDirectory();
  let stored = [];
  try {
    if (fs.existsSync(GROUPS_CONFIG_PATH)) {
      let raw = fs.readFileSync(GROUPS_CONFIG_PATH, 'utf-8');
      if (raw.charCodeAt(0) === 0xfeff) {
        raw = raw.slice(1);
      }
      stored = JSON.parse(raw);
    }
  } catch (error) {
    console.error('Failed to load group config', error);
  }

  const set = new Set([DEFAULT_GROUP]);
  if (Array.isArray(stored)) {
    for (const candidate of stored) {
      const normalized = normalizeGroupName(candidate);
      if (normalized) {
        set.add(normalized);
      }
    }
  }

  persistGroups(set);
  return set;
}

function persistGroups(set = groups) {
  try {
    ensureDataDirectory();
    const payload = Array.from(set).sort();
    fs.writeFileSync(GROUPS_CONFIG_PATH, JSON.stringify(payload, null, 2), 'utf-8');
    return true;
  } catch (error) {
    console.error('Failed to persist group config', error);
    return false;
  }
}

function loadAgentGroupAssignments(groupsSet) {
  ensureDataDirectory();
  let stored = {};
  try {
    if (fs.existsSync(AGENT_GROUP_ASSIGNMENTS_PATH)) {
      let raw = fs.readFileSync(AGENT_GROUP_ASSIGNMENTS_PATH, 'utf-8');
      if (raw.charCodeAt(0) === 0xfeff) {
        raw = raw.slice(1);
      }
      stored = JSON.parse(raw);
    }
  } catch (error) {
    console.error('Failed to load agent group assignments', error);
  }

  const map = new Map();
  if (stored && typeof stored === 'object' && !Array.isArray(stored)) {
    for (const [agentId, value] of Object.entries(stored)) {
      if (!agentId) {
        continue;
      }
      const normalized = normalizeGroupName(value);
      map.set(agentId, normalized);
      if (groupsSet && normalized) {
        groupsSet.add(normalized);
      }
    }
  }

  persistAgentGroupAssignments(map);
  return map;
}

function persistAgentGroupAssignments(map = agentGroupAssignments) {
  try {
    ensureDataDirectory();
    const payload = {};
    for (const [agentId, groupName] of map) {
      if (!agentId || !groupName) {
        continue;
      }
      payload[agentId] = groupName;
    }
    fs.writeFileSync(AGENT_GROUP_ASSIGNMENTS_PATH, JSON.stringify(payload, null, 2), 'utf-8');
    return true;
  } catch (error) {
    console.error('Failed to persist agent group assignments', error);
    return false;
  }
}

function ensureRemediationDirectory() {
  if (!fs.existsSync(REMEDIATION_DIR)) {
    fs.mkdirSync(REMEDIATION_DIR, { recursive: true });
  }
}

function loadNavigationVisibility() {
  ensureDataDirectory();
  let stored = [];
  try {
    if (fs.existsSync(NAVIGATION_CONFIG_PATH)) {
      let raw = fs.readFileSync(NAVIGATION_CONFIG_PATH, 'utf-8');
      if (raw.charCodeAt(0) === 0xfeff) {
        raw = raw.slice(1);
      }
      stored = JSON.parse(raw);
    }
  } catch (error) {
    console.error('Failed to load navigation config', error);
  }

  const map = new Map();
  for (const item of NAVIGATION_ITEMS) {
    const entry = Array.isArray(stored)
      ? stored.find((candidate) => candidate.id === item.id)
      : null;
    const visible = entry && typeof entry.visible === 'boolean' ? entry.visible : true;
    map.set(item.id, visible);
  }

  persistNavigationVisibility(map);
  return map;
}

function persistNavigationVisibility(map) {
  try {
    ensureDataDirectory();
    const payload = NAVIGATION_ITEMS.map((item) => ({
      id: item.id,
      visible: map.get(item.id) ?? true,
    }));
    fs.writeFileSync(NAVIGATION_CONFIG_PATH, JSON.stringify(payload, null, 2), 'utf-8');
    return true;
  } catch (error) {
    console.error('Failed to persist navigation config', error);
    return false;
  }
}

function getNavigationPayload() {
  return NAVIGATION_ITEMS.map((item) => ({
    id: item.id,
    label: item.label,
    href: item.href,
    description: item.description,
    visible: navigationVisibility.get(item.id) ?? true,
  }));
}

function updateNavigationVisibility(entries) {
  if (!Array.isArray(entries)) {
    return false;
  }

  let mutated = false;
  for (const entry of entries) {
    const id = (entry?.id ?? '').toString();
    if (!id) {
      continue;
    }

    const known = NAVIGATION_ITEMS.find((item) => item.id === id);
    if (!known) {
      continue;
    }

    const visible = typeof entry.visible === 'boolean' ? entry.visible : null;
    if (visible === null) {
      continue;
    }

    const current = navigationVisibility.get(id) ?? true;
    if (current === visible) {
      continue;
    }

    navigationVisibility.set(id, visible);
    mutated = true;
  }

  if (mutated) {
    persistNavigationVisibility(navigationVisibility);
  }

  return mutated;
}

function loadMonitoringConfig() {
  ensureDataDirectory();
  try {
    if (fs.existsSync(MONITORING_CONFIG_PATH)) {
      let raw = fs.readFileSync(MONITORING_CONFIG_PATH, 'utf-8');
      if (raw.charCodeAt(0) === 0xfeff) {
        raw = raw.slice(1);
      }
      return JSON.parse(raw);
    }
  } catch (error) {
    console.error('Failed to load monitoring config', error);
  }

  const defaultConfig = {
    monitoringProfiles: [],
    alertProfiles: [],
    remediationScripts: [],
  };
  fs.writeFileSync(MONITORING_CONFIG_PATH, JSON.stringify(defaultConfig, null, 2));
  return defaultConfig;
}

function ensureConfigDirectory() {
  const configDir = path.join(__dirname, 'config');
  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, { recursive: true });
  }
}

const DEFAULT_VULNERABILITY_CONFIG = {
  nvdApiKey: '',
  ingestionMinutes: {
    nvd: 1440,
    kev: 1440,
    epss: 60,
  },
  epssThreshold: 0.4,
  ignoredCves: [],
};

function loadVulnerabilityConfig() {
  ensureConfigDirectory();
  try {
    if (fs.existsSync(VULNERABILITY_CONFIG_PATH)) {
      let raw = fs.readFileSync(VULNERABILITY_CONFIG_PATH, 'utf-8');
      if (raw.charCodeAt(0) === 0xfeff) {
        raw = raw.slice(1);
      }
      return JSON.parse(raw);
    }
  } catch (error) {
    console.error('Failed to load vulnerability config', error);
  }

  fs.writeFileSync(VULNERABILITY_CONFIG_PATH, JSON.stringify(DEFAULT_VULNERABILITY_CONFIG, null, 2));
  return { ...DEFAULT_VULNERABILITY_CONFIG };
}

function persistVulnerabilityConfig() {
  try {
    ensureConfigDirectory();
    fs.writeFileSync(VULNERABILITY_CONFIG_PATH, JSON.stringify(vulnerabilityConfig, null, 2));
    return true;
  } catch (error) {
    console.error('Failed to persist vulnerability config', error);
    return false;
  }
}

function loadVulnerabilityStore() {
  ensureDataDirectory();
  try {
    if (fs.existsSync(VULNERABILITY_STORE_PATH)) {
      let raw = fs.readFileSync(VULNERABILITY_STORE_PATH, 'utf-8');
      if (raw.charCodeAt(0) === 0xfeff) {
        raw = raw.slice(1);
      }
      return new Map(JSON.parse(raw));
    }
  } catch (error) {
    console.error('Failed to load vulnerability store', error);
  }

  const store = new Map();
  persistVulnerabilityStore(store);
  return store;
}

function persistVulnerabilityStore(store = vulnerabilityStore) {
  try {
    ensureDataDirectory();
    fs.writeFileSync(VULNERABILITY_STORE_PATH, JSON.stringify(Array.from(store.entries())), 'utf-8');
    return true;
  } catch (error) {
    console.error('Failed to persist vulnerability store', error);
    return false;
  }
}

const NVD_ENDPOINT = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const KEV_ENDPOINT = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_ENDPOINT = 'https://api.first.org/data/v1/epss';

function startVulnerabilityIngestion() {
  scheduleIngestion('nvd', vulnerabilityConfig.ingestionMinutes.nvd ?? 1440, ingestNvdFeed);
  scheduleIngestion('kev', vulnerabilityConfig.ingestionMinutes.kev ?? 1440, ingestKevCatalog);
  scheduleIngestion('epss', vulnerabilityConfig.ingestionMinutes.epss ?? 60, ingestEpssScores);
}

function scheduleIngestion(name, minutes, fn) {
  if (!minutes || minutes <= 0) {
    return;
  }
  async function runner() {
    try {
      await fn();
    } catch (error) {
      console.error(`Vulnerability ingestion (${name}) failed`, error);
    }
    vulnerabilityIngestionTimers.push(setTimeout(runner, minutes * 60 * 1000));
  }
  runner();
}

async function ingestNvdFeed() {
  const url = `${NVD_ENDPOINT}?resultsPerPage=2000`;
  const headers = {};
  if (vulnerabilityConfig.nvdApiKey) {
    headers['API-Key'] = vulnerabilityConfig.nvdApiKey;
  }
  const data = await fetchJson(url, { headers });
  const items = data?.vulnerabilities ?? data?.result?.vulnerabilities ?? [];
  for (const item of items) {
    const entry = normalizeNvdItem(item);
    if (entry) {
      applyNormalizedVulnerability(entry, 'nvd');
    }
  }
  persistVulnerabilityStore();

  vulnerabilityConfig.lastNvdIngest = new Date().toISOString();
  persistVulnerabilityConfig();
}

async function ingestKevCatalog() {
  const data = await fetchJson(KEV_ENDPOINT, { cache: 'no-store' });
  const entries = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
  for (const vuln of entries) {
    if (!vuln?.cveID) {
      continue;
    }
    applyNormalizedVulnerability({
      cveId: vuln.cveID.trim(),
      description: vuln?.vulnerabilityName ?? '',
      kev: true,
      sources: { kev: true },
      lastUpdated: vuln?.dateAdded ?? new Date().toISOString(),
    }, 'kev');
  }
  persistVulnerabilityStore();

  vulnerabilityConfig.lastKevIngest = new Date().toISOString();
  persistVulnerabilityConfig();
}

async function ingestEpssScores() {
  const data = await fetchJson(EPSS_ENDPOINT, { cache: 'no-store' });
  const entries = Array.isArray(data?.data) ? data.data : [];
  for (const item of entries) {
    const cveId = item?.cve;
    const probability = Number(item?.probability);
    if (!cveId) {
      continue;
    }
    applyNormalizedVulnerability({
      cveId: cveId.trim(),
      epss: Number.isFinite(probability) ? probability : 0,
      sources: { epss: true },
      lastUpdated: item?.timestamp ?? new Date().toISOString(),
    }, 'epss');
  }
  persistVulnerabilityStore();

  vulnerabilityConfig.lastEpssIngest = new Date().toISOString();
  persistVulnerabilityConfig();
}

function applyNormalizedVulnerability(entry, source) {
  const existing = vulnerabilityStore.get(entry.cveId) ?? {
    cveId: entry.cveId,
    described: '',
    cvss: entry.cvss ?? 0,
    cpes: [],
    kev: false,
    epss: null,
    sources: {},
    lastUpdated: entry.lastUpdated ?? new Date().toISOString(),
  };
  const merged = {
    ...existing,
    ...entry,
    cvss: entry.cvss ?? existing.cvss,
    cpes: Array.from(new Set([...(entry.cpes ?? existing.cpes ?? [])])),
    kbArticleIDs: Array.from(
      new Set([
        ...((entry.kbArticleIDs ?? existing.kbArticleIDs ?? []) ?? []),
      ]),
    ),
    kev: existing.kev || Boolean(entry.kev),
    epss: entry.epss ?? existing.epss,
    lastUpdated: entry.lastUpdated ?? existing.lastUpdated,
    sources: { ...existing.sources, ...(entry.sources ?? {}), [source]: true },
  };
  vulnerabilityStore.set(entry.cveId, merged);
}

function normalizeNvdItem(item) {
  const cveId = item?.cve?.cveDataMeta?.id || item?.cve?.CVE_data_meta?.ID;
  if (!cveId) {
    return null;
  }
  const description = item?.cve?.description?.description_data?.[0]?.value ?? item?.cve?.CVE_data_meta?.description ?? '';
  const impact = item?.impact?.baseMetricV3?.cvssV3 ?? item?.impact?.baseMetricV2;
  const cvss = impact?.baseScore ?? null;
  const cpes = extractCpesFromItem(item);
  const kbArticleIDs = extractKbArticles(item);
  return {
    cveId: cveId.trim(),
    description,
    cvss: Number.isFinite(cvss) ? cvss : null,
    vectors: impact?.vectorString ?? null,
    cpes,
    kbArticleIDs,
    lastUpdated: item?.lastModifiedDate ?? new Date().toISOString(),
    sources: { nvd: true },
  };
}

function extractCpesFromItem(item) {
  const nodes = item?.configurations?.nodes ?? [];
  const collected = new Set();
  for (const node of nodes) {
    const cpeMatches = node?.cpeMatch ?? [];
    for (const match of cpeMatches) {
      if (match?.cpe23Uri) {
        collected.add(match.cpe23Uri);
      }
    }
  }
  return Array.from(collected);
}

function extractKbArticles(item) {
  const references = item?.cve?.references?.reference_data ?? [];
  const collected = new Set();
  for (const entry of references) {
    const url = entry?.url ?? '';
    const match = url.match(/KB\d+/i);
    if (match) {
      collected.add(match[0].toUpperCase());
    }
  }
  return Array.from(collected);
}

function gatherAppliedPatches(info) {
  const applied = new Set();
  const summary = info.updatesSummary;
  if (!summary?.categories) {
    return applied;
  }

  for (const category of summary.categories) {
    const updates = Array.isArray(category.updates) ? category.updates : [];
    for (const update of updates) {
      const kbs = Array.isArray(update?.kbArticleIDs) ? update.kbArticleIDs : [];
      for (const kb of kbs) {
        if (typeof kb === 'string' && kb.trim()) {
          applied.add(kb.trim().toUpperCase());
        }
      }
    }
  }

  return applied;
}

async function fetchJson(url, options = {}) {
  const res = await globalThis.fetch(url, options);
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} ${res.statusText}`);
  }
  return res.json();
}

function computeAssetFingerprint(info) {
  const hash = crypto.createHash('sha256');
  hash.update(info.id ?? '');
  hash.update(info.os ?? '');
  hash.update(JSON.stringify(info.specs ?? {}));
  const software = Array.isArray(info.softwareEntries) ? info.softwareEntries : [];
  const sortedSoftware = software
    .map((item) => `${normalizeToken(item.publisher ?? '')}:${normalizeToken(item.name ?? '')}:${item.version ?? ''}`)
    .sort()
    .join('|');
  hash.update(sortedSoftware);
  const updates = info.updatesSummary ?? {};
  hash.update(JSON.stringify(updates));
  return hash.digest('hex');
}

function normalizeToken(value) {
  return (value ?? '').toString().toLowerCase().replace(/[^a-z0-9]+/g, '');
}

function gatherSoftwareIdentifiers(info) {
  const entries = Array.isArray(info.softwareEntries) ? info.softwareEntries : [];
  return entries.map((item) => ({
    name: normalizeToken(item.name ?? ''),
    vendor: normalizeToken(item.publisher ?? ''),
    version: (item.version ?? '').toString(),
    original: item,
  }));
}

function evaluateAssetVulnerabilities(info) {
  if (!info?.id) {
    return [];
  }

  const fingerprint = computeAssetFingerprint(info);
  const cached = assetVulnerabilityCache.get(info.id);
  if (cached && cached.fingerprint === fingerprint) {
    return cached.results;
  }

  const softwareIdentifiers = gatherSoftwareIdentifiers(info);
  const osDescriptor = {
    raw: info.os ?? info.platform ?? '',
    normalized: normalizeToken(info.os ?? info.platform ?? ''),
  };
  const appliedPatches = gatherAppliedPatches(info);

  const matches = [];
  for (const entry of vulnerabilityStore.values()) {
    if (vulnerabilityConfig.ignoredCves?.includes(entry.cveId)) {
      continue;
    }

    const match = matchVulnerabilityToAsset(entry, osDescriptor, softwareIdentifiers, appliedPatches);
    if (!match) {
      continue;
    }

    const patchState = match.patchInfo?.patched ? 'vulnerable_but_patched' : 'vulnerable_unpatched';
    const priorityScore = computePriority(entry, patchState);
    matches.push({
      cveId: entry.cveId,
      description: entry.description,
      cvss: entry.cvss,
      severity: categorizeSeverity(entry.cvss),
      kev: Boolean(entry.kev),
      epss: entry.epss,
      component: match.component,
      componentType: match.type,
      matchedCpe: match.cpe,
      state: patchState,
      fixedBy: match.patchInfo?.fixedBy ?? [],
      explanation: match.explanation,
      updatedAt: new Date().toISOString(),
      priorityScore,
      priority:
        priorityScore >= 10
          ? 'urgent'
          : priorityScore >= 7
            ? 'high'
            : priorityScore >= 4
              ? 'medium'
              : match.patchInfo?.patched
                ? 'patched'
                : 'low',
    });
  }

  assetVulnerabilityCache.set(info.id, { fingerprint, results: matches });
  return matches;
}

function categorizeSeverity(cvss) {
  if (cvss >= 9) return 'Critical';
  if (cvss >= 7) return 'High';
  if (cvss >= 4) return 'Medium';
  if (cvss > 0) return 'Low';
  return 'Info';
}

function matchVulnerabilityToAsset(entry, osDescriptor, softwareIdentifiers, appliedPatches) {
  const cpes = Array.isArray(entry.cpes) ? entry.cpes : [];
  for (const raw of cpes) {
    const parsed = parseCpe(raw);
    if (!parsed) {
      continue;
    }

    const stateInfo = {
      fixedBy: Array.isArray(entry.kbArticleIDs) ? entry.kbArticleIDs : [],
      patched: false,
    };
    if (stateInfo.fixedBy.some((kb) => appliedPatches.has(kb))) {
      stateInfo.patched = true;
    }

    if (parsed.part === 'o' && matchesOsCpe(parsed, osDescriptor)) {
      return {
        component: osDescriptor.raw || 'Windows',
        type: 'os',
        cpe: raw,
        explanation: `OS matches ${parsed.vendor}:${parsed.product}`,
        patchInfo: stateInfo,
      };
    }

    if (parsed.part === 'a') {
      const matchedSoftware = matchesSoftwareCpe(parsed, softwareIdentifiers);
      if (matchedSoftware) {
        return {
          component: matchedSoftware.original.name || matchedSoftware.original.softwareId || 'Unknown software',
          type: 'software',
          cpe: raw,
          explanation: `Software ${matchedSoftware.original.name} matches ${parsed.vendor}:${parsed.product}`,
          patchInfo: stateInfo,
        };
      }
    }
  }

  return null;
}

function matchesOsCpe(parsed, osDescriptor) {
  const vendorMatch = normalizeToken(parsed.vendor).includes('microsoft');
  const productMatch = normalizeToken(parsed.product).includes('windows');
  return vendorMatch && productMatch && osDescriptor.normalized.includes('windows');
}

function matchesSoftwareCpe(parsed, softwareIdentifiers) {
  const vendor = normalizeToken(parsed.vendor);
  const product = normalizeToken(parsed.product);
  const version = (parsed.version ?? '').toString();

  for (const identifier of softwareIdentifiers) {
    if (vendor && identifier.vendor && !identifier.vendor.includes(vendor)) {
      continue;
    }
    if (product && identifier.name && !identifier.name.includes(product)) {
      continue;
    }

    if (version && identifier.version && identifier.version !== version) {
      continue;
    }

    return identifier;
  }

  return null;
}

function computePriority(entry, patchState) {
  let score = entry?.cvss ?? 0;
  if (entry?.kev) {
    score += 2;
  }
  if (entry?.epss >= (vulnerabilityConfig.epssThreshold ?? 0.4)) {
    score += 1;
  }
  if (patchState === 'vulnerable_but_patched') {
    score -= 4;
  }
  return Math.max(0, score);
}

function parseCpe(cpe) {
  if (typeof cpe !== 'string') {
    return null;
  }
  const parts = cpe.split(':');
  if (parts.length < 6) {
    return null;
  }
  return {
    part: parts[2],
    vendor: parts[3],
    product: parts[4],
    version: parts[5],
  };
}

function getVulnerabilityStatus() {
  const total = vulnerabilityStore.size;
  return {
    total,
    lastNvdIngest: vulnerabilityConfig.lastNvdIngest ?? null,
    lastKevIngest: vulnerabilityConfig.lastKevIngest ?? null,
    lastEpssIngest: vulnerabilityConfig.lastEpssIngest ?? null,
    storedAt: new Date().toISOString(),
  };
}

function searchVulnerabilities(query, limit = 50) {
  const normalized = String(query ?? '').trim().toLowerCase();
  const matches = [];
  for (const entry of vulnerabilityStore.values()) {
    if (
      !normalized
      || entry.cveId.toLowerCase().includes(normalized)
      || entry.description?.toLowerCase().includes(normalized)
    ) {
      matches.push({
        cveId: entry.cveId,
        description: entry.description,
        cvss: entry.cvss,
        cpes: entry.cpes,
        kev: entry.kev,
        epss: entry.epss,
        sources: entry.sources,
      });
      if (matches.length >= limit) {
        break;
      }
    }
  }
  return { total: matches.length, items: matches };
}

function loadFirewallBaselines() {
  ensureDataDirectory();
  try {
    if (fs.existsSync(FIREWALL_BASELINE_PATH)) {
      let raw = fs.readFileSync(FIREWALL_BASELINE_PATH, 'utf-8');
      if (raw.charCodeAt(0) === 0xfeff) {
        raw = raw.slice(1);
      }
      return JSON.parse(raw);
    }
  } catch (error) {
    console.error('Failed to load firewall baseline config', error);
  }

  const defaultProfiles = [];
  fs.writeFileSync(FIREWALL_BASELINE_PATH, JSON.stringify(defaultProfiles, null, 2));
  return defaultProfiles;
}

function persistFirewallBaselines() {
  try {
    ensureDataDirectory();
    fs.writeFileSync(FIREWALL_BASELINE_PATH, JSON.stringify(firewallBaselines, null, 2));
    return true;
  } catch (error) {
    console.error('Failed to persist firewall baseline config', error);
    return false;
  }
}

function getScriptByName(name) {
  if (!name) {
    return null;
  }

  return monitoringConfig.remediationScripts.find((entry) => entry.name === name) ?? null;
}

function sanitizeScriptFileName(value, language) {
  const extension = language === 'python' ? '.py' : '.ps1';
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
  return `${normalized || 'script'}${extension}`;
}

function readScriptContent(entry) {
  try {
    const filePath = path.join(REMEDIATION_DIR, entry.file);
    return fs.readFileSync(filePath, 'utf-8');
  } catch (error) {
    return '';
  }
}

function saveMonitoringConfig() {
  ensureDataDirectory();
  fs.writeFileSync(MONITORING_CONFIG_PATH, JSON.stringify(monitoringConfig, null, 2));
}

function handleMonitoringMetrics(info, socket, payload) {
  if (!payload?.metrics || typeof payload.metrics !== 'object') {
    return;
  }

  const entry = {
    timestamp: Date.now(),
    cpuPercent: typeof payload.metrics.cpuPercent === 'number' ? payload.metrics.cpuPercent : null,
    ramPercent: typeof payload.metrics.ramPercent === 'number' ? payload.metrics.ramPercent : null,
    diskUsagePercent: typeof payload.metrics.diskUsagePercent === 'number' ? payload.metrics.diskUsagePercent : null,
    diskPerformancePercent: typeof payload.metrics.diskPerformancePercent === 'number' ? payload.metrics.diskPerformancePercent : null,
    networkKbSec: typeof payload.metrics.networkKbSec === 'number' ? payload.metrics.networkKbSec : null,
  };

  const history = agentMetrics.get(info.id) ?? [];
  history.push(entry);
  while (history.length > 120) {
    history.shift();
  }

  agentMetrics.set(info.id, history);
  evaluateMonitoringProfiles(info, history, socket);
}

function evaluateMonitoringProfiles(info, history, socket) {
  const now = Date.now();
  const profileTriggers = new Map();

  for (const profile of monitoringConfig.monitoringProfiles) {
    if (!canProfileMonitor(profile, info)) {
      continue;
    }

    let profileTriggered = false;
    for (const rule of profile.rules) {
      const metricKey = mapMetricToProperty(rule.metric);
      if (!metricKey) {
        continue;
      }

      const windowMs = Math.max((rule.windowSeconds ?? 30) * 1000, 1000);
      const threshold = typeof rule.threshold === 'number' ? rule.threshold : null;
      if (threshold === null) {
        continue;
      }

      const since = now - windowMs;
      const samples = history.filter((entry) => entry.timestamp >= since && typeof entry[metricKey] === 'number');
      if (samples.length === 0) {
        continue;
      }

      const average = samples.reduce((sum, entry) => sum + (entry[metricKey] ?? 0), 0) / samples.length;
      const comparison = (rule.comparison ?? 'gte').toLowerCase();
      const triggered = comparison === 'gt' ? average > threshold : average >= threshold;
      const key = `${info.id}:${profile.id}:${rule.id}`;
      const previouslyTriggered = alertStates.get(key) ?? false;

      if (triggered && !previouslyTriggered) {
        alertStates.set(key, true);
        triggerAlert(info, socket, profile, rule, average);
      } else if (!triggered && previouslyTriggered) {
        alertStates.set(key, false);
      }

      profileTriggered = profileTriggered || triggered;
    }

    profileTriggers.set(profile.id, profileTriggered);
  }

  for (const [profileId, triggered] of profileTriggers.entries()) {
    const profile = monitoringConfig.monitoringProfiles.find((entry) => entry.id === profileId);
    if (profile) {
      updateAgentProfileStatus(info, profile, triggered);
    }
  }

  const overallTriggered = Array.from(agentProfileStatus.get(info.id) ?? new Map()).some((value) => value);
  updateAgentAlertStatus(info, overallTriggered);
}

function canProfileMonitor(profile, info) {
  if (profile.assignedAgents && profile.assignedAgents.includes(info.id)) {
    return true;
  }

  const group = info.group ?? DEFAULT_GROUP;
  if (profile.assignedGroups && profile.assignedGroups.includes(group)) {
    return true;
  }

  return false;
}

function mapMetricToProperty(metric) {
  switch ((metric ?? '').toLowerCase()) {
    case 'cpu':
      return 'cpuPercent';
    case 'ram':
    case 'memory':
      return 'ramPercent';
    case 'disk-usage':
      return 'diskUsagePercent';
    case 'disk-performance':
      return 'diskPerformancePercent';
    case 'network':
      return 'networkKbSec';
    default:
      return null;
  }
}

function getRequiredMetricsForProfiles(profiles) {
  if (!Array.isArray(profiles)) {
    return [];
  }

  const metrics = new Set();
  for (const profile of profiles) {
    if (!profile || !Array.isArray(profile.rules)) {
      continue;
    }

    for (const rule of profile.rules) {
      const property = mapMetricToProperty(rule.metric);
      if (property === 'cpuPercent') {
        metrics.add('cpu');
      } else if (property === 'ramPercent') {
        metrics.add('ram');
      } else if (property === 'diskUsagePercent') {
        metrics.add('disk-usage');
      } else if (property === 'diskPerformancePercent') {
        metrics.add('disk-performance');
      } else if (property === 'networkKbSec') {
        metrics.add('network');
      }
    }
  }

  return Array.from(metrics);
}

function triggerAlert(info, socket, profile, rule, value) {
  const alertProfile = monitoringConfig.alertProfiles.find((entry) => entry.id === profile.alertProfileId) ?? null;
  const eventPayload = {
    type: 'alert',
    agentId: info.id,
    agentName: info.name,
    profileId: profile.id,
    profileName: profile.name,
    ruleId: rule.id,
    metric: rule.metric,
    threshold: rule.threshold,
    value,
    timestamp: new Date().toISOString(),
    alertProfileId: alertProfile?.id ?? null,
    emails: alertProfile?.emails ?? [],
    dashboard: Boolean(alertProfile?.dashboard),
  };

  console.log(`Alert triggered for ${info.name}: ${rule.metric} = ${value.toFixed(1)} (${rule.threshold})`);
  sendMonitoringEvent('alert', eventPayload);
  if (alertProfile?.emails?.length > 0) {
    console.log(`Stub email: sending alert to ${alertProfile.emails.join(', ')}`);
  }

  if (alertProfile?.remediationScript) {
    runRemediation(info, socket, alertProfile.remediationScript, eventPayload);
  }
}

function runRemediation(info, socket, scriptName, eventPayload) {
  const script = monitoringConfig.remediationScripts.find((entry) => entry.name === scriptName);
  if (!script) {
    console.warn(`Remediation script ${scriptName} not found`);
    return;
  }

  const scriptPath = path.join(REMEDIATION_DIR, script.file);
  let content = '';
  try {
    content = fs.readFileSync(scriptPath, 'utf-8');
  } catch (error) {
    console.warn(`Unable to load remediation script ${script.file}: ${error.message}`);
    return;
  }

  const requestId = uuidv4();
  sendControl(socket, 'run-remediation', {
    requestId,
    scriptName: script.name,
    language: script.language,
    content,
  });
  sendMonitoringEvent('remediation-request', {
    type: 'remediation-request',
    agentId: info.id,
    agentName: info.name,
    scriptName: script.name,
    requestId,
    timestamp: new Date().toISOString(),
    originalEvent: eventPayload,
  });
}

function sendMonitoringEvent(eventName, payload) {
  monitoringHistory.push({
    eventName,
    payload: JSON.parse(JSON.stringify(payload)),
  });
  while (monitoringHistory.length > MONITORING_HISTORY_LIMIT) {
    monitoringHistory.shift();
  }

  const data = JSON.stringify(payload);
  for (const res of monitoringEvents) {
    res.write(`event: ${eventName}\n`);
    res.write(`data: ${data}\n\n`);
  }
}

function incrementChatNotification(agentId, messageTimestamp) {
  if (!agentId) {
    return;
  }

  const count = (chatNotificationCounts.get(agentId) ?? 0) + 1;
  chatNotificationCounts.set(agentId, count);
  sendMonitoringEvent('chat-notification', {
    agentId,
    count,
    timestamp: Date.now(),
    messageTimestamp: Number.isFinite(messageTimestamp) ? messageTimestamp : Date.now(),
  });
}

function clearChatNotification(agentId) {
  if (!agentId) {
    return;
  }

  chatNotificationCounts.delete(agentId);
  sendMonitoringEvent('chat-notification', { agentId, count: 0, timestamp: Date.now() });
}

function hasActiveAlertForAgent(agentId) {
  if (!agentId) {
    return false;
  }

  const prefix = `${agentId}:`;
  for (const [key, value] of alertStates) {
    if (value && key.startsWith(prefix)) {
      return true;
    }
  }

  return false;
}

function updateAgentProfileStatus(info, profile, triggered) {
  if (!info || !info.id || !profile) {
    return;
  }

  const agentId = info.id;
  let profileMap = agentProfileStatus.get(agentId);
  if (!profileMap) {
    profileMap = new Map();
    agentProfileStatus.set(agentId, profileMap);
  }

  const previous = profileMap.get(profile.id) ?? false;
  if (previous === triggered) {
    return;
  }

  profileMap.set(profile.id, Boolean(triggered));

  sendMonitoringEvent('monitoring-state', {
    agentId,
    agentName: info.name ?? 'Unknown agent',
    profileId: profile.id,
    profileName: profile.name,
    triggered: Boolean(triggered),
    status: triggered ? 'triggered' : 'resolved',
    monitoringEnabled: shouldMonitorAgent(info),
    metrics: getRequiredMetricsForProfiles([profile]),
    timestamp: new Date().toISOString(),
  });
}

function updateAgentAlertStatus(info, triggered) {
  if (!info || !info.id) {
    return;
  }

  const normalized = Boolean(triggered);
  const previous = agentAlertStatus.get(info.id) ?? false;
  if (previous === normalized) {
    return;
  }

  agentAlertStatus.set(info.id, normalized);
  sendMonitoringEvent('monitoring-state', {
    agentId: info.id,
    agentName: info.name ?? 'Unknown agent',
    triggered: normalized,
    monitoringEnabled: shouldMonitorAgent(info),
    status: normalized ? 'triggered' : 'resolved',
    metrics: getRequiredMetricsForProfiles(getAssignedProfiles(info)),
    timestamp: new Date().toISOString(),
  });
}

function getBaselineTargetAgentIds(profile) {
  if (!profile) {
    return [];
  }

  const ids = new Set(Array.isArray(profile.assignedAgents) ? profile.assignedAgents : []);
  const groups = Array.isArray(profile.assignedGroups) ? profile.assignedGroups : [];
  for (const entry of clientsById.values()) {
    const group = entry.info.group ?? DEFAULT_GROUP;
    if (groups.includes(group)) {
      ids.add(entry.info.id);
    }
  }

  return Array.from(ids).filter((value) => typeof value === 'string' && value);
}

function clearMonitoringProfileState(profileId) {
  if (!profileId) {
    return;
  }

  for (const profileMap of agentProfileStatus.values()) {
    profileMap.delete(profileId);
  }

  for (const key of Array.from(alertStates.keys())) {
    const [, id] = key.split(':');
    if (id === profileId) {
      alertStates.delete(key);
    }
  }

  for (const agentId of clientsById.keys()) {
    const entry = clientsById.get(agentId);
    if (entry) {
      updateAgentAlertStatus(entry.info, hasActiveAlertForAgent(agentId));
    }
  }
}
