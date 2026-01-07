# RMM WebSocket Demo

This repository illustrates a simple HTTPS/WSS setup with a C# agent that connects to a JavaScript server.

## Agent

- Located in `Agent/`.
- A .NET 8 console app that connects to a `wss://` endpoint, echoes server messages, and lets you type outgoing payloads.
- Displays an RMM-branded tray icon so the console stays accessible while running in the background.

## Server

- Located in `Server/`.
- Node.js HTTPS server (`server.js`) exposing a WSS endpoint backed by `ws`.
- TLS assets go into `Server/certs/server.crt` and `server.key` (instructions in `Server/certs/README.md`).
- Run `npm install` then `npm start` to launch; defaults to `wss://localhost:8443`.
- Access `https://localhost:8443` in a browser to see a dashboard of connected agents (the root path serves the GUI).
- Use the dashboard's **Stream shell** button to open a live PowerShell stream for any agent; the browser opens `shell.html` to display the output and send commands.
- Use **Stream screen** to open `screen.html` and negotiate a WebRTC connection; the agent user must click Yes/No in the popup consent dialog before frames are displayed. The dialog shows a 30 s countdown and automatically denies if no action is taken. Once the page shows the live image, click **Enable control** to forward mouse/keyboard events for remote interaction.  The button disables when the data channel closes.
- Multi-screen support lets the UI fetch the agent’s monitor list, pick a display from the dropdown, and request that specific output before the stream starts.
- The dashboard now shows an OS icon for every agent so it is easy to see Windows, Linux, or macOS hosts.
- The dashboard tracks agent groups and connection status, so you can create named groups, assign agents to them, and see whether each host is online or when it last communicated.
- Each agent card now exposes an updates badge (green if there are no outstanding Windows updates, red otherwise); clicking it opens `updates.html`, where updates are grouped by category/purpose, bulk-selectable, and installable via the agent.

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
