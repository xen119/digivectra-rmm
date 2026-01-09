# RMM WebSocket Demo

This repository illustrates a simple HTTPS/WSS setup with a C# agent that connects to a JavaScript server.

## Agent

- Located in `Agent/`.
- A .NET 8 console app that connects to a `wss://` endpoint, echoes server messages, and lets you type outgoing payloads.
- Displays an RMM-branded tray icon so the console stays accessible while running in the background.
- Collects installed software listings (registry uninstall entries plus Microsoft Store packages) on demand and handles uninstall requests using the stored uninstall string or `Remove-AppxPackage`.
- Supports secure chat requests from the dashboard; a tray chat popup appears in the lower-right, showing the server user/role, timestamps and no redundant header, and you reply by typing `/chat <your response>` or using the popup.
- Incoming chat requests now pop up as a small window near the agent’s system tray so you always see the server user, and replies are sent with the local logged-in username.
- Screen sharing now captures at ~5 FPS with JPEG compression plus automatic resizing to keep bandwidth low, making the stream noticeably smoother.

## Server

- Located in `Server/`.
- Node.js HTTPS server (`server.js`) exposing a WSS endpoint backed by `ws`.
- TLS assets go into `Server/certs/server.crt` and `server.key` (instructions in `Server/certs/README.md`).
- Run `npm install` then `npm start` to launch; defaults to `wss://localhost:8443`.
- Access `https://localhost:8443` in a browser to see a dashboard of connected agents (the root path serves the GUI).
- Use the dashboard's **Stream shell** button to open a live PowerShell stream for any agent; the browser opens `shell.html` to display the output and send commands.
- Use **Stream screen** to open `screen.html` and negotiate a WebRTC connection; the agent user must click Yes/No in the popup consent dialog before frames are displayed. The dialog shows a 30 s countdown and automatically denies if no action is taken. Once the page shows the live image, click **Enable control** to forward mouse/keyboard events for remote interaction.  The button disables when the data channel closes.
- Inside the screen stream window there is now a resolution selector (High/Balanced/Low/Very Low) that requests a scaled feed from the agent before the session starts so you can choose the best trade-off between clarity and speed.
- Multi-screen support lets the UI fetch the agent’s monitor list, pick a display from the dropdown, and request that specific output before the stream starts.
- The dashboard now shows an OS icon for every agent so it is easy to see Windows, Linux, or macOS hosts.
- The dashboard tracks agent groups and connection status, so you can create named groups, assign agents to them, and see whether each host is online or when it last communicated.
- Each agent card now exposes a **Chat** button that opens `chat.html`; messages stream over SSE, you can send secure requests, and the agent replies by typing `/chat <response>` in the console (the page now shows timestamps and the user name of the sender).
- Each card also shows the agent’s logged-in user so you can tell whom you are talking to, and the chat window payload includes the dashboard user that initiated the request.
- Each agent card now exposes an updates badge (green if there are no outstanding Windows updates, red otherwise); clicking it opens `updates.html`, where updates are grouped by category/purpose, bulk-selectable, and installable via the agent.
- A **Patches** sidebar link launches `patches.html`, aggregating every pending Windows update across agents; the three tabs (approve/schedule/scheduled) now also let you trigger remote restart/shutdown/update+restart/shutdown commands per agent, log those intents plus their results, and reuse the log to confirm that reboot-required machines have been handled before scheduling the next wave.
- A **Manage tasks** button opens `processes.html`, letting you view per-process CPU/RAM/disk/network percentages and send kill requests.
- A **Files** button opens `files.html`, giving you a quick explorer for the selected agent so you can browse directories, download files, or upload content directly to a target path.
- A **Software** button opens `software.html`, showing paginated results for all registry-installed and Microsoft Store apps and sending uninstall requests (using whatever uninstall string or Appx package ID was collected) back to the agent.
- A **Monitoring** button opens `monitoring.html`, where you can define monitoring profiles (metric, threshold, window), map them to alert profiles (dashboard/email + optional remediation scripts), unassign agents/groups, delete outdated profiles, and watch a live alert/remediation log.
- The **Scheduler** view lets you select one or more agent/group targets, choose an interval (seconds/minutes/etc.), pick from stored scripts, and save recurring jobs for future automation or patch campaigns.
- A new **Scheduler** view (sidebar link) lets you sketch recurring script or patch jobs for future implementation and keeps a client-side list of the planned runs.
- From that page you can also delete obsolete monitoring profiles so agents stop collecting the associated metrics.
- A **BSODs** badge tracks Windows bug check counts; click it to open `bsod.html`, which lists timestamped events.

## Authentication

- Open `https://localhost:8443` in your browser. You will be redirected to the new login page (username/password + TOTP). The built-in users live at `Server/config/users.json`, e.g.:
  - `admin` (role `admin`, password `P@ssw0rd!`, TOTP secret `FF6TA63XLBDFQE2C`)
  - `operator` (role `operator`, password `Operate123`, TOTP secret `OFWF6AA5EYSU65Q4`)
  - `viewer` (role `viewer`, password `ViewOnly1`, TOTP secret `CRUVMZJLNBCE6YCX`)

- After successful login the server issues an HttpOnly session cookie. API and static assets load with `fetch(..., { credentials: 'same-origin' })` so embedded clients respect the same session. Click **Logout** in the dashboard header to clear the cookie and return to the login screen.
- RBAC is enforced: viewers can browse the dashboard, operators may run remote installs and terminate processes, and admins have full control.
- MFA is implemented via TOTP (use any authenticator app with the secret above when logging in).
- SSO is supported through a signed token handshake (`/auth/sso`). Use `Server/scripts/gen_sso_url.md` (and the `SSO_SECRET` environment variable your deployment uses) to craft a URL; the link stays valid for five minutes and automatically redirects back to `/` when the signature matches.
- BSOD totals appear on every card; clicking the new badge opens `bsod.html` to show each recorded blue screen with its timestamp.
- A **Manage tasks** button opens `processes.html`, letting you view per-process CPU/RAM/disk/network percentages and send kill requests directly from the browser.
- A **Files** button launches `files.html` for the selected agent so you can explore folders, download binaries, or push new files to a specific destination.
- A **Monitoring** button opens `monitoring.html`, where you can define monitoring and alert profiles, assign them to agents/groups, watch real-time alert streams, and optionally trigger remediation scripts that execute on the agent.
- A **Scripts** entry in the sidebar launches `scripts.html`, a central repository for uploading, viewing, and executing PowerShell or Python automation across multiple agents at once (with sample scripts stored under `Server/scripts/remediation/`).
- A **Users** entry in the sidebar opens `users.html`, where admins can list the configured dashboard users and quickly create new accounts (the zip download area already embeds the current `wss://` endpoint, so downloaded agents automatically point back to whichever domain you are hosting on).

## Running

1. Generate TLS certs for the server (OpenSSL example in `Server/certs/README.md`).
2. Start the server:
   ```bash
   cd Server
   npm install
   npm start
   ```
3. Start the agent normally:
   ```bash
   cd Agent
   dotnet run -r win-x64 -- wss://localhost:8443
   ```

Press Enter on an empty line in the agent to close the connection gracefully.

## Distributing the agent

The dashboard now exposes a **Download agent** button (top-right of `https://localhost:8443`). Clicking it packages whatever is in `AgentPublished/` (or, when that folder is empty, the default `Agent/bin/Debug/net8.0-windows` build) into a zip, injects a `run-agent.bat` launcher plus a `server.json` containing the current `wss://` endpoint, and streams that archive back to the browser. Because the endpoint is computed from the request’s host header and protocol, the downloaded agent always points to the domain or IP address you used when visiting the dashboard—even when you host the server on another domain.

Before clicking **Download agent**, publish your latest build:

```powershell
cd Agent
dotnet publish -c Release -r win-x64 --self-contained false -o ..\AgentPublished
```

If you store the published files somewhere else, set `AGENT_DOWNLOAD_DIR` before launching the server so `/agent/download` packages the right directory.

## Running the agent as SYSTEM

To ensure the agent always runs as `NT AUTHORITY\SYSTEM`:

1. Build/publish the agent for `win-x64`:
   ```powershell
   cd Agent
   dotnet publish -c Release -r win-x64 --self-contained false -o ../AgentPublished
   ```
2. Create a Windows service that runs the published binary under LocalSystem (adjust paths/names as needed):
   ```powershell
   sc.exe create RMMSystem binPath= "C:\Users\DavidNefdt\Desktop\Projects\RMM\AgentPublished\Agent.exe" start= auto obj= "LocalSystem"
   ```
3. Start the service:
   ```powershell
   sc.exe start RMMSystem
   ```
4. The service will now launch the agent with SYSTEM privileges and automatically reconnect to the configured WSS endpoint whenever the machine boots.

Use the Windows Services MMC (`services.msc`) or PowerShell to stop/remove the service when you no longer need the elevated agent.
