# RMM WebSocket Demo

This repository illustrates a simple HTTPS/WSS setup with a C# agent that connects to a JavaScript server.

## Agent

- Located in `Agent/`.
- A .NET 8 console app that connects to a `wss://` endpoint, echoes server messages, and lets you type outgoing payloads.

## Server

- Located in `Server/`.
- Node.js HTTPS server (`server.js`) exposing a WSS endpoint backed by `ws`.
- TLS assets go into `Server/certs/server.crt` and `server.key` (instructions in `Server/certs/README.md`).
- Run `npm install` then `npm start` to launch; defaults to `wss://localhost:8443`.
- Access `https://localhost:8443` in a browser to see a dashboard of connected agents (the root path serves the GUI).
- Use the dashboard's **Stream shell** button to open a live PowerShell stream for any agent; the browser opens `shell.html` to display the output and send commands.

## Running

1. Generate TLS certs for the server (OpenSSL example in `Server/certs/README.md`).
2. Start the server:
   ```bash
   cd Server
   npm install
   npm start
   ```
3. Start the agent:
   ```bash
   cd Agent
   dotnet run -- wss://localhost:8443
   ```

Press Enter on an empty line in the agent to close the connection gracefully.
