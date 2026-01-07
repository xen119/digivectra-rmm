using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
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
    private static string? selectedScreenId;
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
        TrayIconManager.Start();

        try
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
        finally
        {
            TrayIconManager.Stop();
        }
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

    private static async Task SendAsync(ClientWebSocket socket, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested && socket.State == WebSocketState.Open)
        {
            var line = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(line))
            {
                await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Client closing", cancellationToken);
                return;
            }

            await SendTextAsync(socket, line, cancellationToken);
        }
    }

    private const string AgentIdFile = "agent.id";
    private static string? agentId;
    private static DeviceSpecs? deviceSpecs;
    private static UpdateSummary? lastUpdateSummary;
    private static readonly string[] UpdateCategoryOrder = new[]
    {
        "Security Updates",
        "Feature Updates",
        "Driver Updates",
        "Definition Updates",
        "Optional Updates",
        "Out-of-Band Updates",
        "Servicing Stack Updates",
        "Cumulative Updates",
        "Other Updates",
    };
    private static readonly Dictionary<string, string> UpdateCategoryPurposes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Security Updates"] = "Vulnerability fixes",
        ["Feature Updates"] = "New Windows versions",
        ["Driver Updates"] = "Hardware support",
        ["Definition Updates"] = "Malware protection",
        ["Optional Updates"] = "Previews & extras",
        ["Out-of-Band Updates"] = "Emergency fixes",
        ["Servicing Stack Updates"] = "Update reliability",
        ["Cumulative Updates"] = "All fixes combined",
        ["Other Updates"] = "Miscellaneous updates",
    };

    private static async Task SendAgentIdentityAsync(ClientWebSocket socket, CancellationToken cancellationToken)
    {
        var identity = JsonSerializer.Serialize(new
        {
            type = "hello",
            name = Environment.MachineName,
            os = RuntimeInformation.OSDescription,
            platform = GetPlatformName(),
            agentId = GetAgentId(),
            specs = GetDeviceSpecs()
        });
        await SendTextAsync(socket, identity, cancellationToken);
        await SendAgentUpdateSummaryAsync(socket, cancellationToken);
    }

    private static string GetAgentId()
    {
        if (agentId is not null)
        {
            return agentId;
        }

        var path = Path.Combine(AppContext.BaseDirectory, AgentIdFile);
        try
        {
            if (File.Exists(path))
            {
                var existing = File.ReadAllText(path).Trim();
                if (!string.IsNullOrWhiteSpace(existing))
                {
                    agentId = existing;
                    return agentId;
                }
            }
        }
        catch
        {
            // ignore read failures
        }

        agentId = Guid.NewGuid().ToString("D");
        try
        {
            File.WriteAllText(path, agentId);
        }
        catch
        {
            // ignore write failures
        }

        return agentId;
    }

    private static string GetPlatformName()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return "Windows";
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return "Linux";
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return "macOS";
        }

        return "Unknown";
    }

    private static DeviceSpecs GetDeviceSpecs()
    {
        if (deviceSpecs is not null)
        {
            return deviceSpecs;
        }

        var specs = new DeviceSpecs();

        try
        {
            using var systemSearcher = new ManagementObjectSearcher("SELECT Manufacturer, Model FROM Win32_ComputerSystem");
            using var systemResults = systemSearcher.Get();
            foreach (ManagementBaseObject item in systemResults)
            {
                specs.Manufacturer = (item["Manufacturer"] as string)?.Trim();
                specs.Model = (item["Model"] as string)?.Trim();
                break;
            }
        }
        catch
        {
            // ignore
        }

        try
        {
            using var biosSearcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BIOS");
            using var biosResults = biosSearcher.Get();
            foreach (ManagementBaseObject item in biosResults)
            {
                specs.SerialNumber = (item["SerialNumber"] as string)?.Trim();
                break;
            }
        }
        catch
        {
            // ignore
        }

        try
        {
            using var cpuSearcher = new ManagementObjectSearcher("SELECT Name, NumberOfLogicalProcessors FROM Win32_Processor");
            using var cpuResults = cpuSearcher.Get();
            foreach (ManagementBaseObject item in cpuResults)
            {
                specs.CpuName = (item["Name"] as string)?.Trim();
                if (item["NumberOfLogicalProcessors"] is uint logical)
                {
                    specs.CpuCores = (int)logical;
                }

                break;
            }
        }
        catch
        {
            // ignore
        }

        try
        {
            using var memorySearcher = new ManagementObjectSearcher("SELECT TotalVisibleMemorySize, FreePhysicalMemory, Caption FROM Win32_OperatingSystem");
            using var memoryResults = memorySearcher.Get();
            foreach (ManagementBaseObject item in memoryResults)
            {
                if (item["TotalVisibleMemorySize"] is ulong totalKb)
                {
                    specs.TotalMemoryBytes = (long)totalKb * 1024;
                }

                if (item["FreePhysicalMemory"] is ulong freeKb)
                {
                    specs.AvailableMemoryBytes = (long)freeKb * 1024;
                }

                if (specs.Edition is null && item["Caption"] is string caption)
                {
                    specs.Edition = caption.Trim();
                }

                break;
            }
        }
        catch
        {
            // ignore
        }

        var drives = new List<StorageInfo>();
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady || drive.DriveType != DriveType.Fixed)
                {
                    continue;
                }

                drives.Add(new StorageInfo
                {
                    Name = drive.Name.TrimEnd('\\'),
                    TotalBytes = drive.TotalSize,
                    FreeBytes = drive.AvailableFreeSpace
                });
            }
        }
        catch
        {
            // ignore
        }

        specs.Storages = drives.ToArray();
        deviceSpecs = specs;
        return specs;
    }

    private static async Task SendAgentUpdateSummaryAsync(ClientWebSocket socket, CancellationToken cancellationToken, bool force = false)
    {
        if (!force && lastUpdateSummary is not null)
        {
            await SendJsonAsync(socket, new { type = "updates-summary", summary = lastUpdateSummary }, cancellationToken);
            return;
        }

        UpdateSummary summary;
        try
        {
            summary = await GetUpdateSummaryAsync();
        }
        catch (OperationCanceledException)
        {
            return;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to collect updates: {ex.Message}");
            summary = new UpdateSummary();
        }

        lastUpdateSummary = summary;
        await SendJsonAsync(socket, new { type = "updates-summary", summary }, cancellationToken);
    }

    private static Task<UpdateSummary> GetUpdateSummaryAsync()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return Task.FromResult(new UpdateSummary());
        }

        return Task.Run(() => CollectUpdateSummary());
    }

    private static UpdateSummary CollectUpdateSummary()
    {
        var sessionType = Type.GetTypeFromProgID("Microsoft.Update.Session");
        if (sessionType is null)
        {
            return new UpdateSummary();
        }

        object? sessionObj = Activator.CreateInstance(sessionType);
        if (sessionObj is null)
        {
            return new UpdateSummary();
        }

        dynamic session = sessionObj;

        dynamic searcher = session.CreateUpdateSearcher();
        if (searcher is null)
        {
            return new UpdateSummary();
        }
        dynamic results = searcher.Search("IsInstalled=0 and IsHidden=0");
        var entries = new List<UpdateEntry>();
        var categories = new Dictionary<string, List<UpdateEntry>>(StringComparer.OrdinalIgnoreCase);
        var seenIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (dynamic update in results.Updates)
        {
            string? updateId = (update?.Identity?.UpdateID as string)?.Trim();
            if (string.IsNullOrWhiteSpace(updateId))
            {
                continue;
            }

            var entry = new UpdateEntry
            {
                Id = updateId,
                Title = ((update?.Title as string)?.Trim()) ?? "Unnamed update",
                Description = (update?.Description as string)?.Trim(),
                KBArticleIDs = CollectKbArticles(update),
                Categories = ExtractCategoryNames(update)
            };

            if (!seenIds.Add(entry.Id))
            {
                continue;
            }

            entries.Add(entry);

            var targetCategories = entry.Categories.Length > 0 ? entry.Categories : new[] { "Other Updates" };
            foreach (var rawName in targetCategories)
            {
                var normalized = NormalizeCategoryName(rawName);
                if (!categories.TryGetValue(normalized, out var list))
                {
                    list = new List<UpdateEntry>();
                    categories[normalized] = list;
                }

                list.Add(entry);
            }
        }

        var ordered = new List<UpdateCategoryInfo>();
        foreach (var categoryName in UpdateCategoryOrder)
        {
            if (categories.TryGetValue(categoryName, out var list))
            {
                ordered.Add(new UpdateCategoryInfo
                {
                    Name = categoryName,
                    Purpose = GetCategoryPurpose(categoryName),
                    Updates = list.ToArray()
                });
                categories.Remove(categoryName);
            }
        }

        foreach (var remaining in categories)
        {
            ordered.Add(new UpdateCategoryInfo
            {
                Name = remaining.Key,
                Purpose = GetCategoryPurpose(remaining.Key),
                Updates = remaining.Value.ToArray()
            });
        }

        return new UpdateSummary
        {
            RetrievedAt = DateTime.UtcNow,
            TotalCount = entries.Count,
            Categories = ordered.ToArray()
        };
    }

    private static string[] CollectKbArticles(dynamic update)
    {
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (dynamic kb in update.KBArticleIDs)
            {
                if (kb is string kbText && !string.IsNullOrWhiteSpace(kbText))
                {
                    ids.Add(kbText.Trim());
                }
            }
        }
        catch
        {
            // ignore
        }

        return ids.ToArray();
    }

    private static string[] ExtractCategoryNames(dynamic update)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (dynamic category in update.Categories)
            {
                if (category?.Name is string name && !string.IsNullOrWhiteSpace(name))
                {
                    names.Add(name.Trim());
                }
            }
        }
        catch
        {
            // ignore
        }

        return names.ToArray();
    }

    private static string NormalizeCategoryName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return "Other Updates";
        }

        foreach (var canonical in UpdateCategoryOrder)
        {
            if (name.Equals(canonical, StringComparison.OrdinalIgnoreCase) ||
                name.IndexOf(canonical, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return canonical;
            }
        }

        return name;
    }

    private static string GetCategoryPurpose(string categoryName)
    {
        if (string.IsNullOrWhiteSpace(categoryName))
        {
            return UpdateCategoryPurposes["Other Updates"];
        }

        foreach (var canonical in UpdateCategoryOrder)
        {
            if (categoryName.Equals(canonical, StringComparison.OrdinalIgnoreCase) ||
                categoryName.IndexOf(canonical, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                if (UpdateCategoryPurposes.TryGetValue(canonical, out var purpose))
                {
                    return purpose;
                }
            }
        }

        if (UpdateCategoryPurposes.TryGetValue(categoryName, out var existing))
        {
            return existing;
        }

        return UpdateCategoryPurposes["Other Updates"];
    }

    private static async Task HandleInstallUpdatesAsync(ClientWebSocket socket, JsonElement element, CancellationToken cancellationToken)
    {
        if (!element.TryGetProperty("ids", out var idsElement) || idsElement.ValueKind != JsonValueKind.Array)
        {
            await SendUpdateInstallResultAsync(socket, false, "No updates selected.", false, cancellationToken);
            return;
        }

        var ids = idsElement.EnumerateArray()
            .Select(idElement => idElement.GetString())
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .Select(id => id!.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (ids.Length == 0)
        {
            await SendUpdateInstallResultAsync(socket, false, "No updates selected.", false, cancellationToken);
            return;
        }

        UpdateInstallResult result;
        try
        {
            result = await Task.Run(() => InstallSelectedUpdates(ids), cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        catch (Exception ex)
        {
            await SendUpdateInstallResultAsync(socket, false, $"Install failed: {ex.Message}", false, cancellationToken);
            return;
        }

        await SendUpdateInstallResultAsync(socket, result.Success, result.Message, result.RebootRequired, cancellationToken);
        if (result.Success)
        {
            await SendAgentUpdateSummaryAsync(socket, cancellationToken, true);
        }
    }

    private static UpdateInstallResult InstallSelectedUpdates(string[] requestedIds)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return new UpdateInstallResult(false, "Update installation is only supported on Windows.");
        }

        var sessionType = Type.GetTypeFromProgID("Microsoft.Update.Session");
        if (sessionType is null)
        {
            return new UpdateInstallResult(false, "Failed to initialize Windows Update session.");
        }

        object? sessionObj = Activator.CreateInstance(sessionType);
        if (sessionObj is null)
        {
            return new UpdateInstallResult(false, "Failed to initialize Windows Update session.");
        }

        dynamic session = sessionObj;

        dynamic searcher = session.CreateUpdateSearcher();
        if (searcher is null)
        {
            return new UpdateInstallResult(false, "Failed to initialize Windows Update session.");
        }
        dynamic results = searcher.Search("IsInstalled=0 and IsHidden=0");
        var requestedSet = new HashSet<string>(requestedIds, StringComparer.OrdinalIgnoreCase);
        dynamic collection = session.CreateUpdateCollection();

        foreach (dynamic update in results.Updates)
        {
            string? updateId = (update?.Identity?.UpdateID as string)?.Trim();
            if (string.IsNullOrWhiteSpace(updateId))
            {
                continue;
            }

            if (requestedSet.Contains(updateId))
            {
                collection.Add(update);
            }
        }

        var collectionCount = 0;
        try
        {
            collectionCount = Convert.ToInt32(collection.Count);
        }
        catch
        {
            collectionCount = 0;
        }

        if (collectionCount == 0)
        {
            return new UpdateInstallResult(false, "Selected updates are no longer available.");
        }

        dynamic installer = session.CreateUpdateInstaller();
        installer.Updates = collection;
        dynamic installResult = installer.Install();
        var resultCode = Convert.ToInt32(installResult?.ResultCode ?? 0);
        var reboot = installResult?.RebootRequired is bool rebootRequired && rebootRequired;
        var success = resultCode == 2;
        var message = success ? "Updates installed successfully." : $"Update installation completed with code {resultCode}.";
        return new UpdateInstallResult(success, message, reboot);
    }

    private static Task SendUpdateInstallResultAsync(ClientWebSocket socket, bool success, string message, bool rebootRequired, CancellationToken cancellationToken)
    {
        return SendJsonAsync(socket, new
        {
            type = "update-install-result",
            success,
            message,
            rebootRequired
        }, cancellationToken);
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
                        var screenId = document.RootElement.TryGetProperty("screenId", out var screenIdElement)
                            ? screenIdElement.GetString()
                            : null;
                        await StartScreenSessionAsync(socket, sessionId, screenId, cancellationToken);
                    }
                }

                break;
            }
            case "get-screen-list":
                await SendScreenListAsync(socket, cancellationToken);
                break;
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
            case "request-updates":
                await SendAgentUpdateSummaryAsync(socket, cancellationToken, true);
                break;
            case "install-updates":
                await HandleInstallUpdatesAsync(socket, document.RootElement, cancellationToken);
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

    private static async Task StartScreenSessionAsync(ClientWebSocket socket, string sessionId, string? screenId, CancellationToken cancellationToken)
    {
        selectedScreenId = screenId;
        Console.WriteLine($"Starting screen session {sessionId} (screen:{selectedScreenId ?? "primary"})");
        if (!await RequestScreenConsentAsync(cancellationToken))
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
        selectedScreenId = null;

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

    private static async Task<bool> RequestScreenConsentAsync(CancellationToken cancellationToken)
    {
        Console.WriteLine("Remote screen share requested. Please respond in the popup within 30 seconds.");
        var dialogTask = TrayIconManager.ShowConsentDialogAsync(
            "Remote screen share",
            "The server wants to view/share your screen. Allow?",
            cancellationToken);

        var timeout = Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);
        var completed = await Task.WhenAny(dialogTask, timeout);
        if (completed != dialogTask)
        {
            Console.WriteLine("Screen share request timed out.");
            return false;
        }

        var approved = await dialogTask == true;
        Console.WriteLine(approved ? "Screen share approved." : "Screen share denied.");
        return approved;
    }

    private static async Task SendScreenListAsync(ClientWebSocket socket, CancellationToken cancellationToken)
    {
        try
        {
            var descriptors = Screen.AllScreens.Select((screen, index) => new
            {
                id = screen.DeviceName,
                name = screen.DeviceName,
                width = screen.Bounds.Width,
                height = screen.Bounds.Height,
                x = screen.Bounds.X,
                y = screen.Bounds.Y,
                primary = screen.Primary,
                index
            }).ToArray();

            await SendJsonAsync(socket, new { type = "screen-list", screens = descriptors }, cancellationToken);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to send screen list: {ex.Message}");
            await SendJsonAsync(socket, new { type = "screen-error", message = "Failed to enumerate displays." }, cancellationToken);
        }
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
        var targetScreen = GetCaptureScreen();
        var screenBounds = targetScreen.Bounds;
        using var bitmap = new Bitmap(screenBounds.Width, screenBounds.Height);
        using var g = Graphics.FromImage(bitmap);
        g.CopyFromScreen(screenBounds.Location, Point.Empty, screenBounds.Size);
        using var ms = new MemoryStream();
        bitmap.Save(ms, ImageFormat.Png);
        return ms.ToArray();
    }

    private static Screen GetCaptureScreen()
    {
        var screens = Screen.AllScreens;
        if (screens.Length == 0)
        {
            throw new InvalidOperationException("No displays detected.");
        }

        if (!string.IsNullOrWhiteSpace(selectedScreenId))
        {
            var match = screens.FirstOrDefault(s => string.Equals(s.DeviceName, selectedScreenId, StringComparison.OrdinalIgnoreCase));
            if (match is not null)
            {
                return match;
            }
        }

        var primary = screens.FirstOrDefault(s => s.Primary);
        if (primary is not null)
        {
            return primary;
        }

        return screens[0];
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

    private sealed class DeviceSpecs
    {
        public string? Manufacturer { get; set; }
        public string? Model { get; set; }
        public string? Edition { get; set; }
        public string? SerialNumber { get; set; }
        public string? CpuName { get; set; }
        public int? CpuCores { get; set; }
        public long TotalMemoryBytes { get; set; }
        public long AvailableMemoryBytes { get; set; }
        public StorageInfo[] Storages { get; set; } = Array.Empty<StorageInfo>();
    }

    private sealed class StorageInfo
    {
        public string? Name { get; set; }
        public long TotalBytes { get; set; }
        public long FreeBytes { get; set; }
    }

    private sealed class UpdateSummary
    {
        [JsonPropertyName("retrievedAt")]
        public DateTime RetrievedAt { get; set; }
        [JsonPropertyName("totalCount")]
        public int TotalCount { get; set; }
        [JsonPropertyName("categories")]
        public UpdateCategoryInfo[] Categories { get; set; } = Array.Empty<UpdateCategoryInfo>();
    }

    private sealed class UpdateCategoryInfo
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;
        [JsonPropertyName("purpose")]
        public string Purpose { get; set; } = string.Empty;
        [JsonPropertyName("updates")]
        public UpdateEntry[] Updates { get; set; } = Array.Empty<UpdateEntry>();
    }

    private sealed class UpdateEntry
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;
        [JsonPropertyName("title")]
        public string Title { get; set; } = string.Empty;
        [JsonPropertyName("description")]
        public string? Description { get; set; }
        [JsonPropertyName("kbArticleIDs")]
        public string[] KBArticleIDs { get; set; } = Array.Empty<string>();
        [JsonPropertyName("categories")]
        public string[] Categories { get; set; } = Array.Empty<string>();
    }

    private sealed class UpdateInstallResult
    {
        [JsonPropertyName("success")]
        public bool Success { get; }
        [JsonPropertyName("message")]
        public string Message { get; }
        [JsonPropertyName("rebootRequired")]
        public bool RebootRequired { get; }

        public UpdateInstallResult(bool success, string message, bool rebootRequired = false)
        {
            Success = success;
            Message = message;
            RebootRequired = rebootRequired;
        }
    }
}
