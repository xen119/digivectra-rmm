# RMM HTTP & Real-Time API

This document describes every HTTP, SSE, and WebSocket entry point that exposes the features in this repository. The API is hosted by `Server/server.js` and is reachable from the dashboard at `https://<host>:8443` (default port `8443`). All client-side callers must log in first so the server can issue the `HttpOnly` cookie `rmm-session`.

## Authentication and roles

| Endpoint | Auth | Description |
| --- | --- | --- |
| `POST /auth/login` | None | JSON body `{ username, password, totp }`. Issues `rmm-session` cookie on success. | 
| `GET /auth/me` | `rmm-session` | Returns the authenticated username/role. |
| `GET /auth/logout` | `rmm-session` | Clears the cookie and invalidates the session. |
| `GET /auth/sso?username=&ts=&sig=` | None | Signs in `username` for five minutes with `SSO_SECRET` HMAC. Redirects back to `/`. |

Roles (viewer < operator < admin) gate the endpoints listed below. `ensureRole` enforces the minimum role.

## Common headers & cookies

- `Content-Type: application/json` for requests with bodies.
- The `rmm-session` cookie (set by login or SSO) must accompany every HTTP/SSE request.
- All endpoints return `401`/`403` when the session is missing/insufficient.

## Agent & group management

| Endpoint | Method | Required role | Description |
| --- | --- | --- | --- |
| `GET /clients` | GET | viewer | Lists every agent (offline + online snapshot). Includes group, OS, updates, software summary, alerts, and features array. |
| `GET /groups` | GET | viewer | Returns sorted group names (default `Ungrouped`). |
| `POST /groups` | POST | viewer | Body `{ name }`. Normalizes, stores, returns `{ name }`. |
| `POST /groups/assign` | POST | operator | Body `{ agentId, group }`. Assigns agent to normalized group. Returns `{ group }`. |
| `GET /users` | GET | admin | Returns configured dashboard users (`username`, `role`, `totpSecret`, `createdAt`). |
| `POST /users` | POST | admin | Body `{ username, password, role, totp? }`. Creates user, persists to `Server/config/users.json`. |
| `GET /agent/download` | GET | viewer | Packages `AgentPublished/` or fallback build into ZIP with `run-agent.bat` & `server.json`. |

## Chat endpoints

| Endpoint | Method | Role | Description |
| --- | --- | --- | --- |
| `POST /chat/{agentId}/read` | POST | viewer | Clears the agent's unread counter. |
| `GET /chat/{agentId}/events` | GET | viewer | SSE stream that emits `chat` events (`{ sessionId, agentId, text, direction, user, role, timestamp }`). |
| `POST /chat/{agentId}/message` | POST | viewer | Body `{ text }`. Queues `chat-request` control message to agent and returns `{ sessionId }`. | 

## Shell streaming

| Endpoint | Method | Role | Description |
| --- | --- | --- | --- |
| `GET /shell/{agentId}` | GET | viewer | SSE stream with `shell` events containing `{ output, stream, timestamp }`. Server sends `start-shell` and closes when client disconnects. |
| `POST /shell/{agentId}/input` | POST | viewer | Body raw text. Sends `shell-input` to agent, enabling remote command typing. |

## Screen sharing & remote control

| Endpoint | Method | Role | Description |
| --- | --- | --- | --- |
| `GET /screen/{agentId}/screens` | GET | viewer | Returns cached or freshly requested screen list: `{ screens: [ { id, name, width, height, x, y, primary } ] }`. |
| `POST /screen/{agentId}/start` | POST | viewer | Body `{ screenId?, scale? }`. Creates session, sends `start-screen` control, returns `{ sessionId }`. |
| `POST /screen/{sessionId}/answer` | POST | viewer | Agent sends SDP answer to this SSE/HTTP bridge. Body `{ sdp, type }`. |
| `POST /screen/{sessionId}/candidate` | POST | viewer | Relays additional WebRTC ICE candidates from dashboard to agent. |
| `POST /screen/{sessionId}/stop` | POST | viewer | Stops screen session, tells agent to close stream. |

### Screen SSE events

Subscribe to `/screen/{agentId}/events` (added to `screenSessions` when a session is created). Events emitted:
- `status`: indicates session state (`offer-ready`, `connected`, `closed`).
- `offer`: agent's SDP offer and metadata (`screenId`, `screenName`).
- `candidate`: agent ICE candidates.
- `error`: passes agent-reported errors.
- `closed`: emitted when the session closes (agent disconnect or `stop`).

## Updates & patching

| Endpoint | Method | Role | Description |
| --- | --- | --- | --- |
| `GET /updates/{agentId}/data` | GET | viewer | Returns `{ summary }` (per-agent Windows update summary). |
| `POST /updates/{agentId}/refresh` | POST | viewer | Queues `request-updates` on agent. |
| `POST /updates/{agentId}/install` | POST | operator | Body `{ ids: [updateId,...] }`. Sends `install-updates` to agent. |
| `GET /patches` | GET | viewer | Returns catalog from `buildPatchCatalog()` and summary stats. |
| `GET /patches/schedules` | GET | viewer | Lists active schedule metadata. |
| `POST /patches/approve` | POST | operator | Body `{ agentId, updateId, approved?: true|false }`. Stores approvals. |
| `POST /patches/schedule` | POST | operator | Body `{ name?, patchIds, agentIds?, runAt?, repeatMs?, category? }`. Creates a schedule (dynamic when `agentIds` omitted). |
| `DELETE /patches/schedules/{id}` | DELETE | operator | Drops a scheduled run. |
| `GET /patches/history` | GET | viewer | Returns the most recent 200 patch/log entries. |
| `POST /clients/{agentId}/action` | POST | operator | Body `{ action, scheduleId? }`. Sends `invoke-action`. Used by scheduler and remote buttons. |

## BSOD tracking

| Endpoint | Method | Role | Description |
| --- | --- | --- | --- |
| `GET /bsod/{agentId}/data` | GET | viewer | Returns `{ summary }` recorded for agent. |
| `POST /bsod/{agentId}/refresh` | POST | viewer | Triggers `request-bsod` and replies with `202`. |

## Process management

| Endpoint | Method | Role | Description |
| --- | --- | --- | --- |
| `GET /processes/{agentId}/data` | GET | viewer | Returns `{ snapshot }` containing CPU/RAM/disk/network percentages. |
| `POST /processes/{agentId}/refresh` | POST | viewer | Sends `list-processes`. |
| `POST /processes/{agentId}/kill` | POST | operator | Body `{ processId }`. Validates PID, forwards `kill-process`. |

## File operations

| Endpoint | Method | Role | Description |
| --- | --- | --- | --- |
| `GET /files/{agentId}/list?path=` | GET | viewer | Requests directory listing via `file-list`. Returns `{ entries, path, retrievedAt }`. |
| `GET /files/{agentId}/download?path=` | GET | viewer | Initiates `download-file`, streams back binary with `Content-Disposition`. |
| `POST /files/{agentId}/upload` | POST | viewer | Body `{ path, data }` (base64). Server splits into 256 KiB chunks and sends `upload-file-*` commands. Responds with `{ success, message }`. |

## Software inventory & remediations

| Endpoint | Method | Role | Description |
| --- | --- | --- | --- |
| `GET /software/{agentId}/list` | GET | viewer | Optional query `filter`, `source`, `page`, `pageSize`. Returns paged `_entries`. |
| `POST /software/{agentId}/uninstall` | POST | operator | Body `{ softwareId, source?, uninstallCommand?, packageFullName?, productCode? }`. Sends `uninstall-software`. Response includes `{ requestId }`. |
| `GET /software` | GET | viewer | Refreshes all agents and returns catalog + summary (totalSoftware/agents/rejected/pendingUninstalls). |
| `POST /software/approval` | POST | operator | Body `{ softwareId, action: 'approve'|'reject' }`. Records approval, queues rejects for uninstall. |
| `GET /software/logs` | GET | viewer | Returns `softwareUninstallLog` (limit 200). |

### Software automation queue

- Rejected software entries get queued per agent (`softwareUninstallQueue`), retried with exponential backoff; success/failure events are pushed to logs.

## Services

| Endpoint | Method | Role | Description |
| --- | --- | --- | --- |
| `GET /agent/{agentId}/services` | GET | viewer | Requests live service list (`list-services`). Returns `{ services }`. |
| `POST /agent/{agentId}/service/{serviceName}/action` | POST | operator | Body `{ action: 'start'|'stop'|'restart' }`. Sends `manage-service`. |

## Firewall management

| Endpoint | Method | Role | Description |
| --- | --- | --- | --- |
| `GET /firewall/rule-library` | GET | viewer | Queries first online agent for raw rule names (99 duplicates suppressed). |
| `GET /firewall/{agentId}/rules` | GET | viewer | Returns firewall status, default actions, and rule details from agent. |
| `POST /firewall/{agentId}/rule/action` | POST | operator | Body `{ ruleName, enabled }`. Enables/disables a rule. |
| `POST /firewall/{agentId}/rule/add` | POST | operator | Body `{ name, direction?, action?, protocol?, localPorts?, remotePorts?, application? }`. Adds a new rule. |
| `POST /firewall/{agentId}/rule/delete` | POST | operator | Body `{ ruleName }`. Removes an existing rule. |
| `POST /firewall/{agentId}/state` | POST | operator | Body `{ profile: 'public'|'private'|'domain'|'all', enabled: true|false }`. Toggles base firewall state. |
| `GET /firewall/baseline` | GET | viewer | Returns stored baselines. |
| `POST /firewall/baseline` | POST | operator | Body `{ name, description, rules: [ { ruleName, enabled } ] }`. Creates baseline template. |
| `POST /firewall/baseline/{id}/assign` | POST | operator | Body `{ agents: [...], groups: [...] }`. Assigns baseline to agents/groups. |
| `POST /firewall/baseline/{id}/apply` | POST | operator | Pushes baseline rules to every assigned online agent. |

## Monitoring & alerting

| Endpoint | Method | Role | Description |
| --- | --- | --- | --- |
| `GET /monitoring/events` | GET | viewer | SSE stream of events (`alert`, `remediation-request`, `remediation-result`, `monitoring-state`, `script-run`, `chat-notification`). |
| `GET /monitoring/events/history` | GET | viewer | Supports `agentId`, `profileId`, `limit`. Returns the last `N` events. |
| `GET /monitoring/profiles` | GET | viewer | Lists profiles with `rules`, `assignedAgents`, `assignedGroups`. |
| `POST /monitoring/profiles` | POST | viewer | Body `{ name, description?, alertProfileId?, rules: [ { metric, threshold, windowSeconds?, comparison? } ] }`. Creates profile with `id`/`rules` assigned. |
| `POST /monitoring/profiles/{id}/assign` | POST | viewer | Body `{ targetType: 'agent'|'group', targetId }`. Assigns profile; notifies matching agents. |
| `DELETE /monitoring/profiles/{id}` | DELETE | operator | Deletes profile and clears alert state. |
| `GET /alert-profiles` | GET | viewer | Lists alert outputs (email, dashboard, remediation script). |
| `POST /alert-profiles` | POST | viewer | Body `{ name, emails?, dashboard?, remediationScript? }`. Creates new alert profile. |

## Scripts & remediation

| Endpoint | Method | Role | Description |
| --- | --- | --- | --- |
| `GET /remediation/scripts` | GET | viewer | Same as `/scripts`; lists stored PowerShell/Python scripts. |
| `GET /scripts` | GET | viewer | Lists scripts defined in `monitoringConfig.remediationScripts`. |
| `GET /scripts/{name}/content` | GET | viewer | Returns `{ name, content }` for the requested script file. |
| `POST /scripts` | POST | viewer | Body `{ name, description?, language?, content }`. Persists script file under `scripts/remediation/`. |
| `POST /scripts/run` | POST | viewer | Body `{ scriptName, agentIds: [] }`. Sends `run-remediation` to each agent and emits `script-run` monitoring event. |

## Vulnerability data

| Endpoint | Method | Role | Description |
| --- | --- | --- | --- |
| `GET /vulnerabilities/status` | GET | viewer | Returns ingestion timestamps and store size (NVD/KEV/EPSS). |
| `GET /vulnerabilities?q=&limit=` | GET | viewer | Searches `vulnerabilityStore` by CVE/description (default limit 50). |
| `GET /vulnerabilities/asset/{agentId}` | GET | viewer | Evaluates vulnerabilities against an agent's collected inventory. |

## System health & event logs

| Endpoint | Method | Role | Description |
| --- | --- | --- | --- |
| `GET /system-health/agents` | GET | viewer | Gathers live event stats from every agent and caches results when unavailable. |
| `GET /system-health/agent/{agentId}` | GET | viewer | Single-agent health record + cached `agentEventStatsCache`. |
| `GET /system-health/{agentId}/entries?level=` | GET | viewer | Asks agent for Windows Event entries at the requested level. |

## SSE/streaming summary

- `/shell/{agentId}`, `/chat/{agentId}/events`, and `/monitoring/events` are SSE-only endpoints; respect the `text/event-stream` headers and reconnect logic.
- `/screen/{agentId}/start` spawns a WebRTC session that feeds additional SSE streams (status/offer/candidate/error/closed) via the `screenSessions` map.
- `GET /monitoring/events/history` and `GET /chat/{agentId}/events` can be polled if SSE is not convenient.

## WebSocket control channel (agent → server)

Agents and the dashboard connect to `wss://<host>:8443`. The server exposes the same API used by `sendControl(...)` in `Server/server.js`. Control messages carry JSON `{ type, ... }`.

| Type | Direction | Description |
| --- | --- | --- |
| `hello` | agent → server | Initial handshake with `{ agentId?, name, os?, platform?, loggedInUser?, specs?, features? }`. |
| `shell-output` | agent → server | Streams shell output to SSE consumers. |
| `start-shell` | server → agent | Tells agent to open interactive PowerShell. |
| `shell-input` | server → agent | Streams keystrokes entered from dashboard to agent console. |
| `start-screen` | server → agent | Initiates WebRTC offer with `{ sessionId, screenId, scale }`. |
| `screen-answer` | client → server → agent | Dashboard posts to `/screen/{sessionId}/answer`, server forwards agent's response. |
| `screen-candidate` | both | Handles ICE candidate relay through HTTP proxy endpoints. |
| `request-updates` / `install-updates` / `request-bsod` | server → agent | Triggers update scans, installs, or BSOD history retrieval. |
| `list-processes` / `kill-process` | server → agent | For process snapshots and termination. |
| `list-software` / `uninstall-software` | server → agent | Software inventory and uninstall requests. |
| `list-services` / `manage-service` | server → agent | Service enumeration and control. |
| `list-firewall` / `firewall-action` | server → agent | Firewall rules & actions, state changes. |
| `download-file` / `upload-file-*` | server → agent | Chunked file transfer helpers. |
| `request-event-stats` / `request-event-entries` | server → agent | System health data collectors. |
| `monitoring-status` | server → agent | Sends assigned monitoring profiles and metrics to the agent. |
| `monitoring-metrics` | agent → server | Agent feeds telemetry to evaluate alert rules. |
| `chat-request` / `chat-response` | both | Chat bridging between agent console and dashboard. |
| `screen-list` | agent → server | Provides multi-screen metadata for `/screen/{agentId}/screens`. |
| `action-result` / `update-install-result` / `software-operation-result` | agent → server | Status updates for patch, action, and software workflows. |
| `run-remediation` / `remediation-result` | server ↔ agent | Script execution requests and results. |

The server echoes every incoming message (`socket.send('Echo: ...')`) for debugging.

## Notes

- Monitoring profiles, alert profiles, firewall baselines, and remediation scripts are persisted under `Server/data` or `Server/scripts/remediation` for durability.
- The dashboard uses these endpoints exclusively; any API client can replicate actions by following the documented paths and payload shapes.
- When agent requests time out, the HTTP response returns `504` with an explanatory message.

By referencing `Server/server.js`, you can extend this API (e.g., add new `sendControl` types) and keep the documentation in sync.