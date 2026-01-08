const fs = require('fs');
const https = require('https');
const path = require('path');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const { authenticator } = require('otplib');
const WebSocket = require('ws');

const CERT_DIR = path.join(__dirname, 'certs');
const PORT = process.env.PORT ? Number(process.env.PORT) : 8443;

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
const MIN_SCREEN_SCALE = 0.35;
const MAX_SCREEN_SCALE = 1.0;
const DEFAULT_SCREEN_SCALE = 0.75;
const chatListeners = new Map(); // agentId -> Set<ServerResponse>
const chatHistories = new Map(); // agentId -> [{ sessionId, text, direction, agentName, timestamp }]
const CHAT_HISTORY_LIMIT = 200;
const SCREEN_LIST_TTL_MS = 60_000;
const SCREEN_LIST_TIMEOUT_MS = 5_000;
const SESSION_TTL_MS = 30 * 60_1000;
const SSO_SECRET = process.env.SSO_SECRET ?? 'CHANGE_ME-SSO-KEY';
const SSO_WINDOW_MS = 5 * 60_1000;

const USERS_CONFIG = loadUsersConfig();
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
      } else if (parsed?.type === 'process-list') {
        info.processSnapshot = parsed.snapshot ?? null;
      } else if (parsed?.type === 'process-kill-result') {
        console.log(`Process kill result from ${info.name}: pid=${parsed.processId}, success=${parsed.success}, message=${parsed.message ?? 'n/a'}`);
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
