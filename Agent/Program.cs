using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;
using Microsoft.MixedReality.WebRTC;

namespace Agent;

internal static class Program
{
    private static readonly SemaphoreSlim SendLock = new(1, 1);
    private static Process? shellProcess;
    private static CancellationTokenSource? shellCts;
    private static CancellationTokenSource? shellLinkedCts;
    private const int ScreenCaptureIntervalMs = 400;
    private static PeerConnection? screenPeerConnection;
    private static DataChannel? screenDataChannel;
    private static CancellationTokenSource? screenCaptureCts;
    private static Task? screenCaptureTask;
    private static string? screenSessionId;
    private static readonly TimeSpan ScreenOfferTimeout = TimeSpan.FromSeconds(10);
    private static Action? screenDataChannelStateHandler;
    private static readonly Dictionary<string, ushort> VirtualKeyMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Enter"] = 0x0D,
        ["Escape"] = 0x1B,
        ["Backspace"] = 0x08,
        ["Tab"] = 0x09,
        ["Delete"] = 0x2E,
        ["Insert"] = 0x2D,
        ["Home"] = 0x24,
        ["End"] = 0x23,
        ["PageUp"] = 0x21,
        ["PageDown"] = 0x22,
        ["ArrowLeft"] = 0x25,
        ["ArrowUp"] = 0x26,
        ["ArrowRight"] = 0x27,
        ["ArrowDown"] = 0x28,
        ["Space"] = 0x20,
        ["Shift"] = 0x10,
        ["Control"] = 0x11,
        ["Alt"] = 0x12,
        ["Meta"] = 0x5B
    };
    private const uint INPUT_MOUSE = 0;
    private const uint INPUT_KEYBOARD = 1;
    private const uint KEYEVENTF_KEYUP = 0x0002;
    private const uint KEYEVENTF_UNICODE = 0x0004;
    private const uint MOUSEEVENTF_MOVE = 0x0001;
    private const uint MOUSEEVENTF_ABSOLUTE = 0x8000;
    private const uint MOUSEEVENTF_LEFTDOWN = 0x0002;
    private const uint MOUSEEVENTF_LEFTUP = 0x0004;
    private const uint MOUSEEVENTF_RIGHTDOWN = 0x0008;
    private const uint MOUSEEVENTF_RIGHTUP = 0x0010;
    private const uint MOUSEEVENTF_MIDDLEDOWN = 0x0020;
    private const uint MOUSEEVENTF_MIDDLEUP = 0x0040;
    private const uint MOUSEEVENTF_WHEEL = 0x0800;

    private static async Task Main(string[] args)
    {
        var target = args.Length > 0 ? args[0] : "wss://localhost:8443";
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cts.Cancel();
        };

        using var socket = new ClientWebSocket();

        // Development convenience: allow self-signed certs. Remove this for production.
        socket.Options.RemoteCertificateValidationCallback = (_, _, _, _) => true;

        Console.WriteLine($"Connecting to {target} ...");
        await socket.ConnectAsync(new Uri(target), cts.Token);
        Console.WriteLine("Connected. Sending identity...");

        await SendAgentIdentityAsync(socket, cts.Token);
        Console.WriteLine("Type messages and press Enter. Send an empty line to close.");

        var receiveLoop = ReceiveAsync(socket, cts.Token);
        await SendAsync(socket, cts.Token);

        cts.Cancel();
        await receiveLoop;
        Console.WriteLine("Closed.");
    }

    private static async Task ReceiveAsync(ClientWebSocket socket, CancellationToken cancellationToken)
    {
        var buffer = new byte[4096];

        while (!cancellationToken.IsCancellationRequested)
        {
            var segment = new ArraySegment<byte>(buffer);
            using var messageBuffer = new MemoryStream();

            WebSocketReceiveResult? result;
            do
            {
                result = await socket.ReceiveAsync(segment, cancellationToken);

                if (result.MessageType == WebSocketMessageType.Close)
                {
                    await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Server requested close", cancellationToken);
                    return;
                }

                messageBuffer.Write(segment.Array!, segment.Offset, result.Count);
            } while (!result.EndOfMessage);

            var message = Encoding.UTF8.GetString(messageBuffer.ToArray());
            Console.WriteLine($"[server] {message}");
            await HandleServerMessageAsync(message, socket, cancellationToken);
        }
    }

    private static TaskCompletionSource<string?>? screenConsentTcs;

    private static async Task SendAsync(ClientWebSocket socket, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested && socket.State == WebSocketState.Open)
        {
            var line = Console.ReadLine();
            if (SubmitScreenConsentResponse(line))
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(line))
            {
                await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Client closing", cancellationToken);
                return;
            }

            await SendTextAsync(socket, line, cancellationToken);
        }
    }

    private static Task SendAgentIdentityAsync(ClientWebSocket socket, CancellationToken cancellationToken)
    {
        var identity = JsonSerializer.Serialize(new
        {
            type = "hello",
            name = Environment.MachineName
        });

        return SendTextAsync(socket, identity, cancellationToken);
    }

    private static async Task HandleServerMessageAsync(string payload, ClientWebSocket socket, CancellationToken cancellationToken)
    {
        JsonDocument? document = null;
        try
        {
            Console.WriteLine($"[server raw] {payload}");
            document = JsonDocument.Parse(payload);
            if (!document.RootElement.TryGetProperty("type", out var typeElement))
            {
                return;
            }

            var messageType = typeElement.GetString();
            switch (messageType)
            {
            case "start-shell":
                await StartShellSessionAsync(socket, cancellationToken);
                break;
            case "stop-shell":
                await StopShellSessionAsync();
                break;
            case "start-screen":
            {
                Console.WriteLine("Received start-screen request from server.");
                if (document.RootElement.TryGetProperty("sessionId", out var sessionIdElement))
                {
                    var sessionId = sessionIdElement.GetString();
                    if (!string.IsNullOrWhiteSpace(sessionId))
                    {
                        await StartScreenSessionAsync(socket, sessionId, cancellationToken);
                    }
                }

                break;
            }
            case "stop-screen":
                await StopScreenSessionAsync();
                break;
            case "screen-answer":
            {
                if (screenPeerConnection is null)
                {
                    break;
                }

                if (document.RootElement.TryGetProperty("sdp", out var sdpElement) &&
                    document.RootElement.TryGetProperty("sdpType", out var sdpTypeElement))
                {
                    var sdp = sdpElement.GetString();
                    var sdpType = sdpTypeElement.GetString();
                    if (!string.IsNullOrWhiteSpace(sdp) && !string.IsNullOrWhiteSpace(sdpType) &&
                        Enum.TryParse<SdpMessageType>(sdpType, true, out var parsedType))
                    {
                        var message = new SdpMessage
                        {
                            Type = parsedType,
                            Content = sdp
                        };
                        await screenPeerConnection.SetRemoteDescriptionAsync(message);
                    }
                }

                break;
            }
            case "screen-candidate":
            {
                if (screenPeerConnection is null)
                {
                    break;
                }

                if (document.RootElement.TryGetProperty("candidate", out var candidateElement) &&
                    document.RootElement.TryGetProperty("sdpMid", out var midElement) &&
                    document.RootElement.TryGetProperty("sdpMLineIndex", out var indexElement) &&
                    candidateElement.ValueKind == JsonValueKind.String &&
                    midElement.ValueKind == JsonValueKind.String &&
                    indexElement.TryGetInt32(out var index))
                {
                    var iceCandidate = new IceCandidate
                    {
                        Content = candidateElement.GetString() ?? string.Empty,
                        SdpMid = midElement.GetString(),
                        SdpMlineIndex = index
                    };
                    screenPeerConnection.AddIceCandidate(iceCandidate);
                }
            }
            break;
            case "shell-input":
                if (document.RootElement.TryGetProperty("input", out var inputElement) &&
                    inputElement.ValueKind == JsonValueKind.String)
                {
                    SendInput(inputElement.GetString());
                }

                break;
            }
        }
        catch (JsonException)
        {
            // Ignore messages that are not JSON control signals.
        }
        finally
        {
            document?.Dispose();
        }
    }

    private static async Task StartShellSessionAsync(ClientWebSocket socket, CancellationToken cancellationToken)
    {
        if (shellProcess != null && !shellProcess.HasExited)
        {
            await SendShellOutputAsync(socket, "Shell already running.\n", "stdout", cancellationToken);
            return;
        }

        shellCts?.Cancel();
        shellCts?.Dispose();
        shellCts = new CancellationTokenSource();
        shellLinkedCts?.Cancel();
        shellLinkedCts?.Dispose();
        shellLinkedCts = CancellationTokenSource.CreateLinkedTokenSource(shellCts.Token, cancellationToken);
        var readToken = GetShellReadToken();

        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoLogo -NoProfile -Command -",
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
                UseShellExecute = false,
                CreateNoWindow = true,
            },
            EnableRaisingEvents = true,
        };
        process.OutputDataReceived += async (_, e) =>
        {
            if (e.Data is not null)
            {
                await SendShellOutputSafeAsync(socket, e.Data + "\n", "stdout", readToken);
            }
        };

        process.ErrorDataReceived += async (_, e) =>
        {
            if (e.Data is not null)
            {
                await SendShellOutputSafeAsync(socket, e.Data + "\n", "stderr", readToken);
            }
        };

        process.Exited += async (_, _) =>
        {
            await SendShellOutputSafeAsync(socket, "Shell process exited.\n", "stdout", readToken);
            shellProcess = null;
        };

        shellProcess = process;
        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        await SendShellOutputAsync(socket, "PowerShell session started.\n", "stdout", cancellationToken);
    }

    private static async Task StopShellSessionAsync()
    {
        shellLinkedCts?.Cancel();
        shellLinkedCts?.Dispose();
        shellLinkedCts = null;
        shellCts?.Cancel();
        if (shellProcess is { HasExited: false })
        {
            try
            {
                shellProcess.Kill(true);
            }
            catch
            {
                // ignore kill failures.
            }

            try
            {
                await shellProcess.WaitForExitAsync();
            }
            catch
            {
                // ignore.
            }

            shellProcess = null;
        }
    }

    private static async Task StartScreenSessionAsync(ClientWebSocket socket, string sessionId, CancellationToken cancellationToken)
    {
        Console.WriteLine($"Starting screen session {sessionId}");
        if (!await RequestScreenConsentAsync())
        {
            await SendJsonAsync(socket, new { type = "screen-error", sessionId, message = "User declined screen share." }, cancellationToken);
            return;
        }

        screenSessionId = sessionId;

        async Task AbortScreenSessionAsync(string message)
        {
            Console.WriteLine(message);
            await SendJsonAsync(socket, new { type = "screen-error", sessionId, message }, cancellationToken);
            await StopScreenSessionAsync();
        }

        screenCaptureCts?.Cancel();
        screenCaptureCts?.Dispose();
        screenCaptureCts = new CancellationTokenSource();

        screenPeerConnection?.Close();
        screenPeerConnection?.Dispose();
        screenPeerConnection = new PeerConnection();

        var offerReadyTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        screenPeerConnection.IceCandidateReadytoSend += async (candidate) =>
        {
            var payload = new
            {
                type = "screen-candidate",
                sessionId,
                candidate = candidate.Content,
                sdpMid = candidate.SdpMid,
                sdpMLineIndex = candidate.SdpMlineIndex
            };

            try
            {
                Console.WriteLine($"Sending screen candidate ({payload.candidate?.Length ?? 0} chars) to server.");
                await SendJsonAsync(socket, payload, cancellationToken);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to send screen candidate: {ex.Message}");
            }
        };

        screenPeerConnection.LocalSdpReadytoSend += async (message) =>
        {
            var payload = new
            {
                type = "screen-offer",
                sessionId,
                sdpType = message.Type.ToString(),
                sdp = message.Content
            };

            try
            {
                Console.WriteLine($"Screen offer ready ({payload.sdp?.Length ?? 0} chars).");
                await SendJsonAsync(socket, payload, cancellationToken);
                offerReadyTcs.TrySetResult(true);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to send screen offer: {ex.Message}");
                offerReadyTcs.TrySetException(ex);
                await AbortScreenSessionAsync($"Failed to send screen offer: {ex.Message}");
            }
        };

        try
        {
            await screenPeerConnection.InitializeAsync(new PeerConnectionConfiguration
            {
                IceServers = { new IceServer { Urls = { "stun:stun.l.google.com:19302" } } }
            }, cancellationToken);
        }
        catch (Exception ex)
        {
            await AbortScreenSessionAsync($"Failed to initialize screen peer: {ex.Message}");
            return;
        }

        Console.WriteLine("InitializeAsync completed");

        try
        {
            screenDataChannel = await screenPeerConnection.AddDataChannelAsync("screen", true, true, cancellationToken);
        }
        catch (Exception ex)
        {
            await AbortScreenSessionAsync($"Failed to create screen data channel: {ex.Message}");
            return;
        }

        if (screenDataChannel is null)
        {
            await AbortScreenSessionAsync("Failed to create screen data channel.");
            return;
        }

        Console.WriteLine($"Data channel ready? {screenDataChannel.State}");

        screenDataChannelStateHandler = () =>
        {
            if (screenDataChannel is null)
            {
                return;
            }

            Console.WriteLine($"Screen data channel state: {screenDataChannel.State}");
        };
        screenDataChannel.StateChanged += screenDataChannelStateHandler;
        screenDataChannel.MessageReceived += OnScreenDataChannelMessageReceived;
        screenDataChannelStateHandler();

        try
        {
            Console.WriteLine("Creating screen offer...");
            var offerCreated = screenPeerConnection.CreateOffer();
            Console.WriteLine($"CreateOffer returned {offerCreated}");
            if (!offerCreated)
            {
                await AbortScreenSessionAsync("Failed to create offer.");
                return;
            }
        }
        catch (Exception ex)
        {
            await AbortScreenSessionAsync($"CreateOffer threw {ex.Message}");
            return;
        }

        try
        {
            var offerDelay = Task.Delay(ScreenOfferTimeout, cancellationToken);
            var offerCompleted = await Task.WhenAny(offerReadyTcs.Task, offerDelay);
            if (offerCompleted != offerReadyTcs.Task)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    return;
                }

                await AbortScreenSessionAsync("Timed out waiting for screen offer.");
                return;
            }

            if (offerReadyTcs.Task.IsFaulted)
            {
                var error = offerReadyTcs.Task.Exception?.GetBaseException().Message ?? "Unknown error generating the offer.";
                await AbortScreenSessionAsync($"Screen offer failed: {error}");
                return;
            }
        }
        catch (OperationCanceledException)
        {
            return;
        }

        screenCaptureTask = Task.Run(() => CaptureScreenLoopAsync(screenCaptureCts.Token), screenCaptureCts.Token);

        await SendShellOutputAsync(socket, "Screen sharing initialized.\n", "stdout", cancellationToken);
    }

    private static Task StopScreenSessionAsync()
    {
        screenCaptureCts?.Cancel();
        screenCaptureCts?.Dispose();
        screenCaptureCts = null;
        screenCaptureTask = null;

        if (screenDataChannel is not null && screenDataChannelStateHandler is not null)
        {
            screenDataChannel.StateChanged -= screenDataChannelStateHandler;
            screenDataChannelStateHandler = null;
        }

        if (screenDataChannel is not null)
        {
            screenDataChannel.MessageReceived -= OnScreenDataChannelMessageReceived;
        }

        screenDataChannel = null;

        screenPeerConnection?.Close();
        screenPeerConnection?.Dispose();
        screenPeerConnection = null;
        screenSessionId = null;
        return Task.CompletedTask;
    }

    private static async Task<bool> RequestScreenConsentAsync()
    {
        Console.WriteLine("Remote screen share requested. Type 'yes' to approve within 30 seconds.");
        screenConsentTcs?.TrySetResult(null);
        screenConsentTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);

        var timeoutTask = Task.Delay(TimeSpan.FromSeconds(30));
        var completed = await Task.WhenAny(screenConsentTcs.Task, timeoutTask);
        var response = completed == screenConsentTcs.Task ? await screenConsentTcs.Task : null;

        if (completed != screenConsentTcs.Task)
        {
            Console.WriteLine("Screen share request timed out.");
            screenConsentTcs = null;
            return false;
        }

        screenConsentTcs = null;
        var approved = string.Equals(response?.Trim(), "yes", StringComparison.OrdinalIgnoreCase);
        Console.WriteLine(approved ? "Screen share approved." : "Screen share denied.");
        return approved;
    }

    private static bool SubmitScreenConsentResponse(string? line)
    {
        if (screenConsentTcs is null)
        {
            return false;
        }

        screenConsentTcs.TrySetResult(line);
        return true;
    }

    private static async Task CaptureScreenLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var frame = CaptureScreenFrame();
                if (frame.Length > 0 && screenDataChannel is not null)
                {
                    var message = JsonSerializer.Serialize(new
                    {
                        type = "frame",
                        image = Convert.ToBase64String(frame)
                    });

                    try
                    {
                        var bytes = Encoding.UTF8.GetBytes(message);
                        screenDataChannel.SendMessage(bytes);
                    }
                    catch
                    {
                        // ignore send errors during shutdown
                    }
                }

                await Task.Delay(ScreenCaptureIntervalMs, cancellationToken);
            }
            catch (TaskCanceledException)
            {
                break;
            }
        }
    }

    private static byte[] CaptureScreenFrame()
    {
        var screenBounds = Screen.PrimaryScreen!.Bounds;
        using var bitmap = new Bitmap(screenBounds.Width, screenBounds.Height);
        using var g = Graphics.FromImage(bitmap);
        g.CopyFromScreen(screenBounds.Location, Point.Empty, screenBounds.Size);
        using var ms = new MemoryStream();
        bitmap.Save(ms, ImageFormat.Png);
        return ms.ToArray();
    }

    private static CancellationToken GetShellReadToken()
    {
        try
        {
            return shellLinkedCts?.Token ?? CancellationToken.None;
        }
        catch (ObjectDisposedException)
        {
            return CancellationToken.None;
        }
    }

    private static async Task SendShellOutputSafeAsync(ClientWebSocket socket, string output, string stream, CancellationToken cancellationToken)
    {
        try
        {
            await SendShellOutputAsync(socket, output, stream, cancellationToken);
        }
        catch (ObjectDisposedException)
        {
            // Ignore races where the token source was disposed while we were sending.
        }
    }

    private static void OnScreenDataChannelMessageReceived(byte[] data)
    {
        try
        {
            var text = Encoding.UTF8.GetString(data);
            HandleControlMessage(text);
        }
        catch (Exception)
        {
            // Ignore invalid control payloads.
        }
    }

    private static void HandleControlMessage(string payload)
    {
        try
        {
            using var document = JsonDocument.Parse(payload);
            var root = document.RootElement;
            if (!root.TryGetProperty("type", out var typeElement))
            {
                return;
            }

            var type = typeElement.GetString();
            if (string.Equals(type, "keyboard", StringComparison.OrdinalIgnoreCase))
            {
                HandleKeyboardMessage(root);
            }
            else if (string.Equals(type, "mouse", StringComparison.OrdinalIgnoreCase))
            {
                HandleMouseMessage(root);
            }
        }
        catch (JsonException)
        {
            // Ignore malformed control payloads.
        }
    }

    private static void HandleKeyboardMessage(JsonElement root)
    {
        if (!root.TryGetProperty("action", out var actionElement) ||
            !root.TryGetProperty("key", out var keyElement))
        {
            return;
        }

        var action = actionElement.GetString();
        var key = keyElement.GetString();
        if (string.IsNullOrWhiteSpace(action) || string.IsNullOrWhiteSpace(key))
        {
            return;
        }

        var keyDown = string.Equals(action, "down", StringComparison.OrdinalIgnoreCase);
        SendKeyboardInput(key, keyDown);
    }

    private static void HandleMouseMessage(JsonElement root)
    {
        if (!root.TryGetProperty("action", out var actionElement))
        {
            return;
        }

        var action = actionElement.GetString();
        if (action is null)
        {
            return;
        }

        if (string.Equals(action, "move", StringComparison.OrdinalIgnoreCase))
        {
            if (TryGetNormalizedCoordinates(root, out var x, out var y))
            {
                SendMouseMove(x, y);
            }

            return;
        }

        if (string.Equals(action, "wheel", StringComparison.OrdinalIgnoreCase))
        {
            if (root.TryGetProperty("delta", out var deltaElement))
            {
                SendMouseWheel(deltaElement.GetDouble());
            }

            return;
        }

        if (!TryGetNormalizedCoordinates(root, out var clickX, out var clickY))
        {
            return;
        }

        if (!root.TryGetProperty("button", out var buttonElement))
        {
            return;
        }

        var button = buttonElement.GetString();
        if (string.IsNullOrWhiteSpace(button))
        {
            return;
        }

        var isDown = string.Equals(action, "down", StringComparison.OrdinalIgnoreCase);
        SendMouseButton(button, isDown, clickX, clickY);
    }

    private static bool TryGetNormalizedCoordinates(JsonElement root, out int normalizedX, out int normalizedY)
    {
        normalizedX = normalizedY = 0;
        if (!root.TryGetProperty("x", out var xElement) || !root.TryGetProperty("y", out var yElement))
        {
            return false;
        }

        var xRatio = xElement.GetDouble();
        var yRatio = yElement.GetDouble();
        normalizedX = NormalizeToAbsolute(xRatio);
        normalizedY = NormalizeToAbsolute(yRatio);
        return true;
    }

    private static int NormalizeToAbsolute(double ratio)
    {
        var clamped = Math.Clamp(ratio, 0.0, 1.0);
        return (int)Math.Round(clamped * ushort.MaxValue);
    }

    private static void SendMouseMove(int normalizedX, int normalizedY)
    {
        SendMouseInput(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, normalizedX, normalizedY);
    }

    private static void SendMouseButton(string button, bool isDown, int normalizedX, int normalizedY)
    {
        uint flag = button.ToLowerInvariant() switch
        {
            "left" => isDown ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_LEFTUP,
            "right" => isDown ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_RIGHTUP,
            "middle" => isDown ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP,
            _ => 0
        };

        if (flag == 0)
        {
            return;
        }

        SendMouseInput(flag | MOUSEEVENTF_ABSOLUTE, normalizedX, normalizedY);
    }

    private static void SendMouseWheel(double delta)
    {
        var wheelDelta = (int)Math.Round(delta * 120);
        SendMouseInput(MOUSEEVENTF_WHEEL, 0, 0, (uint)wheelDelta);
    }

    private static void SendMouseInput(uint flags, int x, int y, uint data = 0)
    {
        var input = new INPUT
        {
            type = INPUT_MOUSE,
            U = new InputUnion
            {
                mi = new MOUSEINPUT
                {
                    dx = x,
                    dy = y,
                    mouseData = data,
                    dwFlags = flags,
                    time = 0,
                    dwExtraInfo = IntPtr.Zero
                }
            }
        };

        SendInput(1, new[] { input }, Marshal.SizeOf<INPUT>());
    }

    private static void SendKeyboardInput(string key, bool keyDown)
    {
        if (key.Length == 1)
        {
            SendUnicodeInput(key[0], keyDown);
            return;
        }

        if (VirtualKeyMap.TryGetValue(key, out var vk))
        {
            SendVirtualKey(vk, keyDown);
        }
    }

    private static void SendUnicodeInput(char character, bool keyDown)
    {
        var input = new INPUT
        {
            type = INPUT_KEYBOARD,
            U = new InputUnion
            {
                ki = new KEYBDINPUT
                {
                    wVk = 0,
                    wScan = character,
                    dwFlags = KEYEVENTF_UNICODE | (keyDown ? 0 : KEYEVENTF_KEYUP),
                    time = 0,
                    dwExtraInfo = IntPtr.Zero
                }
            }
        };

        SendInput(1, new[] { input }, Marshal.SizeOf<INPUT>());
    }

    private static void SendVirtualKey(ushort vk, bool keyDown)
    {
        var input = new INPUT
        {
            type = INPUT_KEYBOARD,
            U = new InputUnion
            {
                ki = new KEYBDINPUT
                {
                    wVk = vk,
                    wScan = 0,
                    dwFlags = keyDown ? 0 : KEYEVENTF_KEYUP,
                    time = 0,
                    dwExtraInfo = IntPtr.Zero
                }
            }
        };

        SendInput(1, new[] { input }, Marshal.SizeOf<INPUT>());
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

    [StructLayout(LayoutKind.Sequential)]
    private struct INPUT
    {
        public uint type;
        public InputUnion U;
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct InputUnion
    {
        [FieldOffset(0)] public MOUSEINPUT mi;
        [FieldOffset(0)] public KEYBDINPUT ki;
        [FieldOffset(0)] public HARDWAREINPUT hi;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MOUSEINPUT
    {
        public int dx;
        public int dy;
        public uint mouseData;
        public uint dwFlags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KEYBDINPUT
    {
        public ushort wVk;
        public ushort wScan;
        public uint dwFlags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct HARDWAREINPUT
    {
        public uint uMsg;
        public ushort wParamL;
        public ushort wParamH;
    }

    private static void SendInput(string? input)
    {
        if (string.IsNullOrEmpty(input) || shellProcess is not { HasExited: false })
        {
            return;
        }

        try
        {
            shellProcess.StandardInput.WriteLine(input);
            shellProcess.StandardInput.Flush();
        }
        catch
        {
            // ignore.
        }
    }

    private static async Task SendShellOutputAsync(ClientWebSocket socket, string output, string stream, CancellationToken cancellationToken)
    {
        var payload = new
        {
            type = "shell-output",
            stream,
            output,
        };

        await SendJsonAsync(socket, payload, cancellationToken);
    }

    private static async Task SendJsonAsync(ClientWebSocket socket, object payload, CancellationToken cancellationToken)
    {
        var text = JsonSerializer.Serialize(payload);
        await SendTextAsync(socket, text, cancellationToken);
    }

    private static async Task SendTextAsync(ClientWebSocket socket, string text, CancellationToken cancellationToken)
    {
        var data = Encoding.UTF8.GetBytes(text);
        var acquired = false;

        try
        {
            await SendLock.WaitAsync(cancellationToken);
            acquired = true;
        }
        catch (OperationCanceledException)
        {
            return;
        }

        try
        {
            if (socket.State == WebSocketState.Open)
            {
                await socket.SendAsync(data, WebSocketMessageType.Text, true, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Swallow cancellations triggered during shutdown.
        }
        finally
        {
            if (acquired)
            {
                SendLock.Release();
            }
        }
    }
}
