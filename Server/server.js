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

    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });

    req.on('end', () => {
      sendControl(entry.socket, 'shell-input', { input: body });
      res.writeHead(204);
      res.end();
    });

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
    return;
  }

  const message = JSON.stringify({ type, ...additional });
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
