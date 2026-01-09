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
const clients = new Map(); // socket -> info
const agents = new Map(); // id -> info (persist offline)
const clientsById = new Map(); // id -> { socket, info }
const shellStreams = new Map(); // id -> response
const screenSessions = new Map(); // sessionId -> session data
const groups = new Set([DEFAULT_GROUP]);
const screenLists = new Map(); // agentId -> { screens, updatedAt }
const screenListRequests = new Map(); // agentId -> { resolvers: [], timer }
const FILE_REQUEST_TIMEOUT_MS = 120_000;
const FILE_UPLOAD_CHUNK_BYTES = 256 * 1024;
const fileRequests = new Map(); // requestId -> { kind, agentId, resolve, reject, timer }
const SOFTWARE_REQUEST_TIMEOUT_MS = 60_000;
const softwareRequests = new Map(); // requestId -> { agentId, resolve, reject, timer }
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
const CHAT_HISTORY_LIMIT = 200;
const SCREEN_LIST_TTL_MS = 60_000;
const SCREEN_LIST_TIMEOUT_MS = 5_000;
const DATA_DIR = path.join(__dirname, 'data');
const MONITORING_CONFIG_PATH = path.join(DATA_DIR, 'monitoring.json');
const SESSION_TTL_MS = 30 * 60_1000;
const SSO_SECRET = process.env.SSO_SECRET ?? 'CHANGE_ME-SSO-KEY';
const SSO_WINDOW_MS = 5 * 60_1000;
const REMEDIATION_DIR = path.join(__dirname, 'scripts', 'remediation');

const USERS_CONFIG = loadUsersConfig();
const monitoringEvents = new Set();
const monitoringConfig = loadMonitoringConfig();
const monitoringHistory = [];
const MONITORING_HISTORY_LIMIT = 100;
const agentMetrics = new Map(); // agentId -> [{ timestamp, cpuPercent?, ramPercent? }]
const alertStates = new Map(); // `${agentId}:${profileId}:${ruleId}` -> boolean
const agentAlertStatus = new Map(); // agentId -> boolean
const agentProfileStatus = new Map(); // agentId -> Map<profileId, boolean>
const sessions = new Map();
const roleWeight = { viewer: 0, operator: 1, admin: 2 };

server.on('request', (req, res) => {
  const requestedUrl = new URL(req.url ?? '/', `https://${req.headers.host ?? 'localhost'}`);
  const pathname = requestedUrl.pathname;

  if (pathname.startsWith('/auth/')) {
    handleAuthRoute(req, res, pathname, requestedUrl);
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
  };

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
          agents.set(requestedId, info);
        }

        info.name = parsed.name.trim();
        if (typeof parsed.os === 'string' && parsed.os.trim()) {
          info.os = parsed.os.trim();
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
          console.log(`Software operation result from ${info.name}: ${parsed.softwareId ?? 'n/a'} ${parsed.operation ?? 'operation'} success=${parsed.success ? 'yes' : 'no'} message="${parsed.message ?? ''}"`);
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
  groups.add(normalized);
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
    const configPath = path.join(__dirname, 'config', 'users.json');
    const raw = fs.readFileSync(configPath, 'utf-8');
    return JSON.parse(raw);
  } catch (error) {
    console.error('Failed to load users config', error);
    return [];
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

function ensureRemediationDirectory() {
  if (!fs.existsSync(REMEDIATION_DIR)) {
    fs.mkdirSync(REMEDIATION_DIR, { recursive: true });
  }
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
