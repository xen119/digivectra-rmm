require('dotenv').config();

const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const axios = require('axios');
const https = require('https');

const RMM_BASE_URL = (process.env.RMM_BASE_URL ?? 'https://localhost:8443').replace(/\/$/, '');
const PORT = Number(process.env.PORT) || 4020;
const TIMEOUT = Number(process.env.RMM_REQUEST_TIMEOUT_MS) || 20000;
const ACCEPT_SELF_SIGNED = process.env.RMM_ALLOW_SELF_SIGNED === 'true';

const httpsAgent = new https.Agent({ rejectUnauthorized: !ACCEPT_SELF_SIGNED });
const rmmClient = axios.create({
  baseURL: RMM_BASE_URL,
  timeout: TIMEOUT,
  httpsAgent,
});

const app = express();
app.use(cors({ origin: process.env.MCP_CORS_ORIGIN ?? '*' }));
app.use(morgan('tiny'));
app.use(express.json({ limit: '512kb' }));

function buildRmmHeaders(req) {
  const headers = {
    Accept: 'application/json',
  };

  const sessionHint = req.get('x-rmm-session');
  const authHeader = req.get('authorization');
  const cookieHeader = req.get('cookie');

  if (sessionHint) {
    headers.Cookie = `rmm-session=${sessionHint.trim()}`;
  } else if (authHeader && authHeader.toLowerCase().startsWith('bearer ')) {
    const token = authHeader.slice(7).trim();
    if (token) {
      headers.Cookie = `rmm-session=${token}`;
    }
  } else if (cookieHeader) {
    headers.Cookie = cookieHeader;
  }

  const forwarded = req.get('x-forwarded-for');
  if (forwarded) {
    headers['X-Forwarded-For'] = forwarded;
  }

  return headers;
}

async function rmmRequest(req, method, path, options = {}) {
  const config = {
    method,
    url: path,
    headers: buildRmmHeaders(req),
    params: options.params ?? {},
    data: options.data ?? null,
  };

  const response = await rmmClient.request(config);
  return response;
}

function handleProxyError(error, res) {
  if (error?.response) {
    const { status, data } = error.response;
    res.status(status).json({
      error: 'RMM request failed',
      status,
      details: data,
    });
  } else {
    res.status(502).json({
      error: 'Unable to reach RMM backend',
      message: error.message,
    });
  }
}

app.get('/', (req, res) => {
  res.json({
    service: 'RMM MCP adapter',
    target: RMM_BASE_URL,
    allowSelfSigned: ACCEPT_SELF_SIGNED,
  });
});

app.get('/mcp/status', (req, res) => {
  res.json({
    ready: true,
    target: RMM_BASE_URL,
    timeoutMs: TIMEOUT,
    proxyCookie: !!buildRmmHeaders(req).Cookie,
  });
});

app.get('/mcp/agents', async (req, res) => {
  try {
    const response = await rmmRequest(req, 'get', '/clients');
    res.status(response.status).json({ agents: response.data });
  } catch (error) {
    handleProxyError(error, res);
  }
});

app.get('/mcp/agents/:agentId', async (req, res) => {
  try {
    const response = await rmmRequest(req, 'get', `/system-health/agent/${encodeURIComponent(req.params.agentId)}`);
    res.status(response.status).json(response.data);
  } catch (error) {
    handleProxyError(error, res);
  }
});

app.post('/mcp/agents/:agentId/chat', async (req, res) => {
  if (!req.body?.text) {
    return res.status(400).json({ error: 'text is required' });
  }
  try {
    const response = await rmmRequest(req, 'post', `/chat/${encodeURIComponent(req.params.agentId)}/message`, {
      data: { text: req.body.text },
    });
    res.status(response.status).json(response.data);
  } catch (error) {
    handleProxyError(error, res);
  }
});

app.post('/mcp/agents/:agentId/shell', async (req, res) => {
  const payload = req.body ?? {};
  if (!payload.input) {
    return res.status(400).json({ error: 'input is required' });
  }
  try {
    const response = await rmmRequest(req, 'post', `/shell/${encodeURIComponent(req.params.agentId)}/input`, {
      data: payload.input,
    });
    res.status(response.status).json(response.data);
  } catch (error) {
    handleProxyError(error, res);
  }
});

app.get('/mcp/vulnerabilities/status', async (req, res) => {
  try {
    const response = await rmmRequest(req, 'get', '/vulnerabilities/status');
    res.status(response.status).json(response.data);
  } catch (error) {
    handleProxyError(error, res);
  }
});

app.get('/mcp/vulnerabilities', async (req, res) => {
  try {
    const response = await rmmRequest(req, 'get', '/vulnerabilities', {
      params: {
        q: req.query.q,
        limit: req.query.limit,
      },
    });
    res.status(response.status).json(response.data);
  } catch (error) {
    handleProxyError(error, res);
  }
});

app.listen(PORT, () => {
  console.log(`MCP server listening on http://localhost:${PORT}`);
  console.log(`Proxying RMM APIs to ${RMM_BASE_URL}`);
});
