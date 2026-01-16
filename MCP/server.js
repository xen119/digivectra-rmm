require('dotenv').config();

const express = require('express');
const cors = require('cors');
const https = require('https');
const axios = require('axios');
const Ajv = require('ajv');
const { randomUUID } = require('crypto');

const { version: packageVersion } = require('./package.json');

const PORT = Number(process.env.PORT) || 4020;
const RMM_BASE_URL = (process.env.RMM_BASE_URL ?? 'https://localhost:8443').replace(/\/$/, '');
const TIMEOUT = Number(process.env.RMM_REQUEST_TIMEOUT_MS) || 20000;
const ACCEPT_SELF_SIGNED = process.env.RMM_ALLOW_SELF_SIGNED === 'true';
const MCP_CORS_ORIGIN = process.env.MCP_CORS_ORIGIN ?? '*';
const SERVER_NAME = process.env.MCP_SERVER_NAME ?? 'RMM MCP Server';
const SERVER_VERSION = process.env.MCP_SERVER_VERSION ?? packageVersion ?? '0.0.1';

const httpsAgent = new https.Agent({ rejectUnauthorized: !ACCEPT_SELF_SIGNED });

const rmmClient = axios.create({
  baseURL: RMM_BASE_URL,
  timeout: TIMEOUT,
  httpsAgent,
});

const app = express();
app.use(cors({ origin: MCP_CORS_ORIGIN }));
app.use(express.json({ limit: '512kb' }));
app.disable('x-powered-by');

const ajv = new Ajv({ allErrors: true, strict: false });

const sseClients = new Set();

function buildRmmHeaders(req) {
  const headers = { Accept: 'application/json' };
  const sessionHint = req.get('x-rmm-session');
  const authorization = req.get('authorization');
  const cookieHeader = req.get('cookie');

  if (sessionHint) {
    headers.Cookie = `rmm-session=${sessionHint.trim()}`;
  } else if (authorization && authorization.toLowerCase().startsWith('bearer ')) {
    const token = authorization.slice(7).trim();
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
    timeout: TIMEOUT,
  };

  return rmmClient.request(config);
}

function cleanSseClients() {
  for (const client of Array.from(sseClients)) {
    if (client.res.writableEnded || client.res.destroyed) {
      sseClients.delete(client);
    }
  }
}

function broadcastMessage(payload) {
  cleanSseClients();
  const body = JSON.stringify(payload);
  const frame = `event: message\ndata: ${body}\n\n`;

  for (const client of sseClients) {
    try {
      console.debug('SSE → message', client.id, payload?.id, body.slice(0, 200));
      client.res.write(frame);
    } catch (error) {
      console.error('Failed to write SSE message', error);
      sseClients.delete(client);
    }
  }
}

function streamSsePayload(id, payload) {
  console.debug('Streaming payload', { id, payloadKeys: Object.keys(payload) });
  broadcastMessage({
    jsonrpc: '2.0',
    id,
    ...payload,
  });
}

function broadcastDone() {
  cleanSseClients();
  const frame = 'event: done\ndata: {}\n\n';
  console.debug('SSE → done', sseClients.size);

  for (const client of sseClients) {
    try {
      client.res.write(frame);
    } catch (error) {
      console.error('Failed to write SSE done event', error);
      sseClients.delete(client);
    }
  }
}

function registerSseClient(req, res) {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();
  res.write(':\n\n');

  const client = { id: randomUUID(), res };
  sseClients.add(client);
  console.info('SSE client connected', client.id, `total:${sseClients.size}`);

  req.on('close', () => {
    sseClients.delete(client);
    console.info('SSE client disconnected', client.id, `remaining:${sseClients.size}`);
  });
}

function isValidId(value) {
  return value === null || typeof value === 'string' || typeof value === 'number';
}

function normalizeToolContent(item) {
  if (!item || typeof item !== 'object') {
    throw new Error('Each content entry must be an object');
  }

  if (item.type === 'text') {
    if (typeof item.text !== 'string') {
      throw new Error('text content must include a string `text` property');
    }
    return { type: 'text', text: item.text };
  }

  if (item.type === 'json') {
    if (item.data === undefined || item.data === null || typeof item.data !== 'object') {
      throw new Error('json content must include a non-null `data` object');
    }
    return { type: 'json', data: item.data };
  }

  throw new Error(`Unsupported content type: ${String(item.type)}`);
}

function normalizeCallToolResult(payload) {
  if (!payload || typeof payload !== 'object') {
    throw new Error('Tool result must be an object');
  }

  if (!Array.isArray(payload.content)) {
    throw new Error('Tool result must include a `content` array');
  }

  const normalizedContent = payload.content.map(normalizeToolContent);
  const { content, ...rest } = payload;
  return { ...rest, content: normalizedContent };
}

class StreamSession {
  constructor(requestId) {
    this.requestId = requestId;
    this.completed = false;
  }

  send(payload) {
    if (this.completed) return;
    const normalized = normalizeCallToolResult(payload);
    broadcastMessage({
      jsonrpc: '2.0',
      id: this.requestId,
      result: normalized,
    });
  }

  sendError(errorObject) {
    if (this.completed) return;
    broadcastMessage({
      jsonrpc: '2.0',
      id: this.requestId,
      error: errorObject,
    });
  }

  complete() {
    if (this.completed) return;
    this.completed = true;
    broadcastDone();
  }
}

function toJsonRpcError(error, code = -32000) {
  const message = error?.message ?? 'Internal server error';
  const payload = { code, message };

  if (axios.isAxiosError(error)) {
    payload.data = {
      status: error.response?.status,
      statusText: error.response?.statusText,
      details: error.response?.data,
    };
  }

  return payload;
}

function respondJsonRpc(res, id, result) {
  res.json({
    jsonrpc: '2.0',
    id,
    result,
  });
}

function respondJsonRpcError(res, id, error) {
  res.json({
    jsonrpc: '2.0',
    id,
    error,
  });
}

const toolRegistry = new Map();

function registerTool({ name, description, inputSchema, handler }) {
  if (toolRegistry.has(name)) {
    throw new Error(`Tool ${name} is already registered`);
  }

  const validate = ajv.compile(inputSchema);
  toolRegistry.set(name, {
    name,
    description,
    inputSchema,
    handler,
    validate,
  });
}

const noInputSchema = { type: 'object', properties: {}, additionalProperties: false };
const agentIdSchema = {
  type: 'object',
  properties: { agentId: { type: 'string', minLength: 1 } },
  required: ['agentId'],
  additionalProperties: false,
};
const agentChatSchema = {
  type: 'object',
  properties: {
    agentId: { type: 'string', minLength: 1 },
    text: { type: 'string', minLength: 1 },
  },
  required: ['agentId', 'text'],
  additionalProperties: false,
};
const agentShellSchema = {
  type: 'object',
  properties: {
    agentId: { type: 'string', minLength: 1 },
    input: { type: 'string', minLength: 1 },
  },
  required: ['agentId', 'input'],
  additionalProperties: false,
};
const vulnerabilitiesSearchSchema = {
  type: 'object',
  properties: {
    q: { type: 'string', minLength: 1 },
    limit: { type: 'integer', minimum: 1, maximum: 200 },
  },
  additionalProperties: false,
};

registerTool({
  name: 'rmm.status.overview',
  description: 'Report proxy status, backend target, and session hints.',
  inputSchema: noInputSchema,
  handler: async ({ request }) => ({
    content: [
      {
        type: 'json',
        data: {
          server: {
            name: SERVER_NAME,
            version: SERVER_VERSION,
          },
          target: RMM_BASE_URL,
          timeoutMs: TIMEOUT,
          allowSelfSigned: ACCEPT_SELF_SIGNED,
          sessionProvided: Boolean(buildRmmHeaders(request).Cookie),
          timestamp: new Date().toISOString(),
        },
      },
    ],
  }),
});

registerTool({
  name: 'rmm.agents.list',
  description: 'List every agent known to the RMM dashboard.',
  inputSchema: noInputSchema,
  handler: async ({ request }) => {
    const response = await rmmRequest(request, 'get', '/clients');
    return {
      content: [
        {
          type: 'json',
          data: { agents: response.data },
        },
      ],
    };
  },
});

registerTool({
  name: 'rmm.agents.health',
  description: 'Get the aggregated system-health/agents payload.',
  inputSchema: noInputSchema,
  handler: async ({ request }) => {
    const response = await rmmRequest(request, 'get', '/system-health/agents');
    return {
      content: [
        {
          type: 'json',
          data: response.data,
        },
      ],
    };
  },
});

registerTool({
  name: 'rmm.agent.details',
  description: 'Fetch detailed health for a single agent.',
  inputSchema: agentIdSchema,
  handler: async ({ request, input }) => {
    const response = await rmmRequest(
      request,
      'get',
      `/system-health/agent/${encodeURIComponent(input.agentId)}`,
    );
    return {
      content: [
        {
          type: 'json',
          data: response.data,
        },
      ],
    };
  },
});

registerTool({
  name: 'rmm.agent.chat',
  description: 'Relay a chat message to the dashboard agent.',
  inputSchema: agentChatSchema,
  handler: async ({ request, input }) => {
    const text = input.text.trim();
    if (!text) {
      throw new Error('text cannot be empty');
    }

    const response = await rmmRequest(
      request,
      'post',
      `/chat/${encodeURIComponent(input.agentId)}/message`,
      { data: { text } },
    );

    return {
      content: [
        {
          type: 'text',
          text: 'Chat message queued for delivery.',
        },
        {
          type: 'json',
          data: response.data,
        },
      ],
    };
  },
});

registerTool({
  name: 'rmm.agent.shell',
  description: 'Send shell input to an agent.',
  inputSchema: agentShellSchema,
  handler: async ({ request, input }) => {
    const response = await rmmRequest(
      request,
      'post',
      `/shell/${encodeURIComponent(input.agentId)}/input`,
      { data: input.input },
    );

    return {
      content: [
        {
          type: 'text',
          text: 'Shell input submitted.',
        },
        {
          type: 'json',
          data: response.data,
        },
      ],
    };
  },
});

registerTool({
  name: 'rmm.vulnerabilities.status',
  description: 'Report ingestion progress for vulnerability data.',
  inputSchema: noInputSchema,
  handler: async ({ request }) => {
    const response = await rmmRequest(request, 'get', '/vulnerabilities/status');
    return {
      content: [
        {
          type: 'json',
          data: response.data,
        },
      ],
    };
  },
});

registerTool({
  name: 'rmm.vulnerabilities.search',
  description: 'Search the vulnerability store with optional filters.',
  inputSchema: vulnerabilitiesSearchSchema,
  handler: async ({ request, input }) => {
    const params = {};
    if (input.q) {
      params.q = input.q;
    }
    if (input.limit) {
      params.limit = input.limit;
    }

    const response = await rmmRequest(request, 'get', '/vulnerabilities', { params });
    return {
      content: [
        {
          type: 'json',
          data: response.data,
        },
      ],
    };
  },
});

function executeToolCall(toolEntry, input, requestId, req) {
  console.info('Executing tool', toolEntry.name, requestId, input);
  const session = new StreamSession(requestId);

  toolEntry
    .handler({ input, request: req, stream: session, rmmRequest })
    .then((result) => {
      session.send(result);
    })
    .catch((error) => {
      console.error('Tool execution failed', error);
      session.sendError(toJsonRpcError(error));
    })
    .finally(() => {
      session.complete();
    });
}

let shuttingDown = false;

function startShutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  console.info('Shutdown requested, closing SSE streams.');
  broadcastDone();
  for (const client of Array.from(sseClients)) {
    try {
      client.res.end();
    } catch (error) {
      console.error('Failed to close SSE client', error);
    }
  }
  process.exit(0);
}

function validateJsonRpcEnvelope(body) {
  if (!body || typeof body !== 'object') {
    console.warn('Invalid JSON-RPC body', body);
    return { error: { code: -32600, message: 'Request must be a JSON object' } };
  }

  if (body.jsonrpc !== '2.0') {
    console.warn('Invalid jsonrpc version', body.jsonrpc, body);
    return { error: { code: -32600, message: 'jsonrpc must equal "2.0"' } };
  }

  if (!body.method || typeof body.method !== 'string') {
    console.warn('Missing method', body);
    return { error: { code: -32600, message: 'method is required' } };
  }

  if (!Object.prototype.hasOwnProperty.call(body, 'id')) {
    console.warn('Missing id', body);
    return { error: { code: -32600, message: 'id is required' } };
  }

  if (!isValidId(body.id)) {
    console.warn('Invalid id type', body.id);
    return { error: { code: -32600, message: 'id must be string, number, or null' } };
  }

  return { value: body };
}

app.get('/mcp/stream', (req, res) => {
  registerSseClient(req, res);
});

app.get('/mcp', (req, res) => {
  const acceptsEventStream = String(req.headers.accept ?? '').includes('text/event-stream');
  if (acceptsEventStream) {
    registerSseClient(req, res);
    return;
  }
  res.status(405).json({
    jsonrpc: '2.0',
    error: { code: -32600, message: 'POST /mcp must be used for JSON-RPC requests' },
  });
});

app.post('/mcp', (req, res) => {
  const validation = validateJsonRpcEnvelope(req.body);
  if (validation.error) {
    console.warn('JSON-RPC validation failed', validation.error, req.body);
    return respondJsonRpcError(res, req.body?.id ?? null, validation.error);
  }

  const { id, method, params } = validation.value;
  console.debug('JSON-RPC request', { id, method, params: Object.keys(params ?? {}) });

  switch (method) {
    case 'initialize':
      return respondJsonRpc(res, id, {
        capabilities: {
          tools: { streaming: true },
        },
        serverInfo: {
          name: SERVER_NAME,
          version: SERVER_VERSION,
        },
      });

    case 'initialized':
      return respondJsonRpc(res, id, {});

    case 'tools/list': {
      const tools = Array.from(toolRegistry.values()).map((entry) => ({
        name: entry.name,
        description: entry.description,
        inputSchema: entry.inputSchema,
      }));
      return respondJsonRpc(res, id, { tools });
    }

    case 'tools/call': {
      const toolName = params?.name;
      const toolArgs = params?.arguments ?? {};

      if (typeof toolName !== 'string' || !toolRegistry.has(toolName)) {
        return respondJsonRpcError(res, id, {
          code: -32601,
          message: `Unknown tool: ${toolName}`,
        });
      }

      const toolEntry = toolRegistry.get(toolName);
      if (!toolEntry.validate(toolArgs)) {
        return respondJsonRpcError(res, id, {
          code: -32602,
          message: 'Invalid tool arguments',
          data: toolEntry.validate.errors,
        });
      }

      respondJsonRpc(res, id, { status: 'accepted', streaming: true });
      executeToolCall(toolEntry, toolArgs, id, req);
      return undefined;
    }

    case 'shutdown':
      respondJsonRpc(res, id, { status: 'accepted', streaming: true });
      broadcastDone();
      res.once('finish', () => startShutdown());
      return undefined;

    default:
      return respondJsonRpcError(res, id, {
        code: -32601,
        message: `Unknown method ${method}`,
      });
  }
});

app.listen(PORT, () => {
  console.info(`MCP server listening on http://localhost:${PORT}`);
});
