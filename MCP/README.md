# MCP AI Adapter for RMM

This lightweight service exposes AI-friendly HTTP endpoints that proxy the most useful RMM APIs (agents, shell, chat, vulnerabilities, and health) while handling session cookies for you. It is deliberately simple so it can be plugged into autop-run platforms that need a consistent REST contract.

## Getting started

1. `cd MCP`
2. `npm install`
3. Create a `.env` file (optional) to override defaults:
   ```env
   PORT=4020
   RMM_BASE_URL=https://localhost:8443
   RMM_ALLOW_SELF_SIGNED=true
   RMM_REQUEST_TIMEOUT_MS=20000
   MCP_CORS_ORIGIN=*
   ```
4. `npm start`

The server listens on `http://localhost:4020` (adjustable with `PORT`) and proxies to the RMM dashboard behind `RMM_BASE_URL`.

## Authentication

- Provide the dashboard session cookie to MCP via one of:
  * `Authorization: Bearer <rmm-session-token>` (MCP sends `rmm-session=<token>` to RMM).
  * `X-RMM-SESSION: <rmm-session-token>`
  * `Cookie: rmm-session=<token>`
- `RMM_ALLOW_SELF_SIGNED=true` relaxes TLS so the MCP adapter can talk to the default dev server.

## Exposed endpoints

| Endpoint | Method | Description |
| --- | --- | --- |
| `/` | GET | Returns the MCP service status and target configuration. |
| `/mcp/status` | GET | Returns service-ready metadata and whether a session was supplied. |
| `/mcp/agents` | GET | Returns the complete `/clients` list from the RMM server. |
| `/mcp/agents/{agentId}` | GET | Returns the `/system-health/agent/{agentId}` payload for detailed health. |
| `/mcp/agents/{agentId}/chat` | POST | Body `{ text }`. Relays to `/chat/{agentId}/message`. |
| `/mcp/agents/{agentId}/shell` | POST | Body `{ input }`. Sends typed shell input (proxy to `/shell/{agentId}/input`). |
| `/mcp/vulnerabilities/status` | GET | Returns ingestion counts/timestamps from `/vulnerabilities/status`. |
| `/mcp/vulnerabilities` | GET | Proxy for `/vulnerabilities`, supports `q` and `limit` query params. |

All responses mirror the shape of the proxied RMM payload for easier consumption by AI runners.

## Examples

Retrieve agents with the session cookie:

```bash
curl -H "X-RMM-SESSION: $RMM_TOKEN" http://localhost:4020/mcp/agents
```

Send a chat message:

```bash
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer $RMM_TOKEN" \
  -d '{"text":"AI assistant requesting an update"}' \
  http://localhost:4020/mcp/agents/<agent-id>/chat
```

Trigger shell input:

```bash
curl -X POST -H "Content-Type: application/json" -H "X-RMM-SESSION: $RMM_TOKEN" \
  -d '{"input":"whoami\n"}' http://localhost:4020/mcp/agents/<agent-id>/shell
```

## Extension ideas

- Add `/mcp/patches`, `/mcp/software`, or `/mcp/firewall` endpoints if the AI workflow needs them.
- Cache `/clients` output to avoid hitting the dashboard too often.
- Expose an SSE endpoint if the AI agent needs to monitor `/monitoring/events`.

Keep this README in sync with `MCP/server.js` whenever you expand the proxy surface.
