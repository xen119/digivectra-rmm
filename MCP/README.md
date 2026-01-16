# MCP AI Adapter for RMM

This service exposes the RMM dashboard through the **Model Context Protocol (MCP)** HTTP transport so it can be consumed directly by n8n or any other MCP-compatible client. The implementation strictly follows the JSON-RPC + Server-Sent Events (SSE) transport that n8n expects: all control messages travel through `POST /mcp`, while every tool response streams through `GET /mcp/stream`.

## Getting started
1. `cd MCP`
2. `npm install`
3. Create a `.env` file (optional) that overrides the defaults listed below.
4. `npm start`

## Environment
| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `4020` | HTTP port for both JSON-RPC and SSE listeners. |
| `RMM_BASE_URL` | `https://localhost:8443` | Target RMM dashboard URL (no trailing slash). |
| `RMM_ALLOW_SELF_SIGNED` | `false` | Set to `true` to skip TLS validation for RMM. |
| `RMM_REQUEST_TIMEOUT_MS` | `20000` | Millisecond timeout for proxied RMM calls. |
| `MCP_CORS_ORIGIN` | `*` | CORS origin for the MCP HTTP endpoint. |
| `MCP_SERVER_NAME` | `RMM MCP Server` | Name advertised to MCP clients. |
| `MCP_SERVER_VERSION` | package version | Version reported to MCP clients. |

### Authentication
Supply the RMM session cookie in one of three ways:
* `Authorization: Bearer <rmm-session-token>`
* `X-RMM-SESSION: <rmm-session-token>`
* `Cookie: rmm-session=<token>`

The adapter forwards whichever value is present to the dashboard when making proxied requests.

## Transport contract
Only two endpoints exist:

### `POST /mcp`
Handles every JSON-RPC request. Supported methods:

* `initialize`: returns server capabilities (`tools.streaming: true`) and `serverInfo`.
* `initialized`: acknowledges the MCP handshake.
* `tools/list`: returns the tool catalog with `name`, `description`, and `inputSchema` fields.
* `tools/call`: starts a tool execution; `params.name` selects a tool and `params.arguments` must follow the schema from `tools/list`. The HTTP response is an immediate acknowledgement (`{ status: "accepted", streaming: true }`); the actual result is streamed over SSE.
* `shutdown`: sends an empty result and then shuts down the server after `done` is emitted.

JSON-RPC responses always use `jsonrpc: "2.0"` and echo the `id` from the request. Invalid requests or validation failures return a JSON-RPC error object with the appropriate code (`-32600`, `-32601`, `-32602`, `-32000`, etc.).

### `GET /mcp/stream` (alternate for manual SSE)
Keeps an SSE connection alive for all streaming tool responses. Clients **must** send:

```
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive
Accept: text/event-stream
```

Every tool update is sent as:

```
event: message
data: {"jsonrpc":"2.0","id":<request-id>,"result":{...CallToolResult...}}

```

When a tool completes (successfully or with an error), the stream emits:

```
event: done
data: {}

```

Do **not** close the SSE connection without emitting `event: done`. Clients should keep the stream open while they issue `tools/call` requests so that every completion message can be delivered.

> **Tip:** HTTP Streamable clients like n8n will open the SSE connection at `GET /mcp` with `Accept: text/event-stream`—this endpoint mirrors `/mcp/stream` so you can keep a long-lived stream while calling tools over `POST /mcp`.

## Tool catalog

| Tool | Description | Input schema highlights |
| --- | --- | --- |
| `rmm.status.overview` | Reports proxy metadata, backend target, `timeoutMs`, and whether a session was supplied. | `{}` |
| `rmm.agents.list` | Returns the `/clients` array from the dashboard. | `{}` |
| `rmm.agents.health` | Retrieves `/system-health/agents`. | `{}` |
| `rmm.agent.details` | Returns `/system-health/agent/{agentId}`. | `{ agentId: string }` |
| `rmm.agent.chat` | Queues `/chat/{agentId}/message` with the provided `text`. | `{ agentId: string, text: string }` |
| `rmm.agent.shell` | Sends a raw shell payload to `/shell/{agentId}/input`. | `{ agentId: string, input: string }` |
| `rmm.vulnerabilities.status` | Mirrors `/vulnerabilities/status`. | `{}` |
| `rmm.vulnerabilities.search` | Proxies `/vulnerabilities` with optional `q` and `limit`. | `{ q?: string, limit?: number }` |

Every tool returns a `CallToolResult` with `content` entries limited to the two allowed output formats:

* `{ "type": "text", "text": "..." }`
* `{ "type": "json", "data": { ... } }`

If a tool is partially through its work or emitting intermediate updates, those partial items are streamed as `event: message` before the final `event: done` is sent.

## Example workflow

1. Open SSE connection (keep it alive while you interact with the server):

```bash
curl -N http://localhost:4020/mcp/stream
```

2. Send `initialize`:

```bash
curl -s -X POST http://localhost:4020/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
```

3. Request the tool catalog:

```bash
curl -s -X POST http://localhost:4020/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

4. Call a tool once the stream is open (example: list agents). The HTTP response acknowledges the request, and the tool result appears in the SSE stream.

```bash
curl -s -X POST http://localhost:4020/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"rmm.agents.list","arguments":{}}}'
```

Watch for the SSE `event: message` containing the `CallToolResult`, followed by `event: done`.

## Next steps

- Keep the SSE stream open before issuing every `tools/call` request so that partial and final results can be delivered.
- Update the tool catalog if you need to expose more RMM endpoints via MCP.
