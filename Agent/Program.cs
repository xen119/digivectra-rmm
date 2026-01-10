using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Diagnostics.Eventing.Reader;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using Microsoft.MixedReality.WebRTC;
using System.Net.NetworkInformation;
using Microsoft.Win32;
using System.ServiceProcess;

namespace Agent;

internal static class Program
{
    private static readonly SemaphoreSlim SendLock = new(1, 1);
    private static Process? shellProcess;
    private static CancellationTokenSource? shellCts;
    private static CancellationTokenSource? shellLinkedCts;
    private const int ScreenCaptureIntervalMs = 200;
    private const double DefaultCaptureScale = 0.75;
    private const double MinCaptureScale = 0.35;
    private const double MaxCaptureScale = 1.0;
    private static double captureScale = DefaultCaptureScale;
    private const long ScreenJpegQuality = 65L;
    private static PeerConnection? screenPeerConnection;
    private static DataChannel? screenDataChannel;
    private static CancellationTokenSource? screenCaptureCts;
    private static Task? screenCaptureTask;
    private static string? screenSessionId;
    private static string? currentChatSessionId;
    private static string? selectedScreenId;
    private static readonly TimeSpan ScreenOfferTimeout = TimeSpan.FromSeconds(10);
    private const int MaxFileEntries = 512;
    private static readonly Dictionary<string, PendingUpload> uploadSessions = new(StringComparer.OrdinalIgnoreCase);
    private static Action? screenDataChannelStateHandler;
    private static PerformanceCounter? totalCpuCounter;
    private static CancellationTokenSource? monitoringCts;
    private static Task? monitoringTask;
    private const int MonitoringIntervalMs = 5_000;
    private static bool monitoringEnabled;
    private static PerformanceCounter? diskTimeCounter;
    private static long previousNetworkBytes = -1;
    private static DateTime previousNetworkSample = DateTime.MinValue;
    private static string[] activeMonitoringMetrics = Array.Empty<string>();
    private static readonly ImageCodecInfo? JpegEncoder = ImageCodecInfo.GetImageEncoders()
        .FirstOrDefault(codec => codec.FormatID == ImageFormat.Jpeg.Guid);
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
            var agentUser = GetAgentLocalUser();
            TrayIconManager.RegisterChatHandler(
                async (text) => await SendChatResponseAsync(socket, text, CancellationToken.None),
                agentUser);
            Console.WriteLine("Type messages and press Enter. Send an empty line to close.");

            var receiveLoop = ReceiveAsync(socket, cts.Token);
            await SendAsync(socket, cts.Token);

            cts.Cancel();
            await receiveLoop;
            Console.WriteLine("Closed.");
        }
        finally
        {
            StopMonitoringLoop();
            totalCpuCounter?.Dispose();
            totalCpuCounter = null;
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

            if (line.StartsWith("/chat ", StringComparison.OrdinalIgnoreCase))
            {
                var text = line["/chat ".Length..].Trim();
                if (string.IsNullOrWhiteSpace(text))
                {
                    Console.WriteLine("Enter a message after /chat.");
                    continue;
                }

                await SendChatResponseAsync(socket, text, cancellationToken);
            }
            else
            {
                await SendTextAsync(socket, line, cancellationToken);
            }
        }
    }

    private const string AgentIdFile = "agent.id";
    private static string? agentId;
    private static DeviceSpecs? deviceSpecs;
    private static UpdateSummary? lastUpdateSummary;
    private static BsodSummary? lastBsodSummary;
    private static readonly Dictionary<int, ProcessSample> processSamples = new();
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
            specs = GetDeviceSpecs(),
            loggedInUser = GetAgentLocalUser()
        });
        await SendTextAsync(socket, identity, cancellationToken);
        await SendAgentUpdateSummaryAsync(socket, cancellationToken);
        await SendBsodSummaryAsync(socket, cancellationToken);
    }

    private static Task StartMonitoringLoopAsync(ClientWebSocket socket, CancellationToken cancellationToken)
    {
        monitoringCts?.Cancel();
        monitoringCts?.Dispose();
        monitoringCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        monitoringTask = Task.Run(() => MonitoringLoopAsync(socket, monitoringCts.Token), monitoringCts.Token);
        return monitoringTask;
    }

    private static void StopMonitoringLoop()
    {
        monitoringCts?.Cancel();
        monitoringCts?.Dispose();
        monitoringCts = null;
        monitoringTask = null;
    }

    private static void UpdateMonitoringStatus(bool enabled, string[] metrics, ClientWebSocket socket, CancellationToken cancellationToken)
    {
        if (enabled)
        {
            UpdateActiveMonitoringMetrics(metrics);
        }
        else
        {
            UpdateActiveMonitoringMetrics(null);
        }

        if (monitoringEnabled == enabled)
        {
            return;
        }

        monitoringEnabled = enabled;
        if (enabled)
        {
            _ = StartMonitoringLoopAsync(socket, cancellationToken);
        }
        else
        {
            StopMonitoringLoop();
        }
    }

    private static void UpdateActiveMonitoringMetrics(IEnumerable<string>? metrics)
    {
        if (metrics is null)
        {
            activeMonitoringMetrics = Array.Empty<string>();
            return;
        }

        activeMonitoringMetrics = metrics
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim().ToLowerInvariant())
            .Where(value => value == "cpu" || value == "ram" || value == "disk-usage" || value == "disk-performance" || value == "network")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static async Task MonitoringLoopAsync(ClientWebSocket socket, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var metricsSnapshot = activeMonitoringMetrics;
                if (metricsSnapshot.Length == 0)
                {
                    await Task.Delay(MonitoringIntervalMs, cancellationToken);
                    continue;
                }

                var payload = new Dictionary<string, double>();

                if (MonitoringMetricRequested(metricsSnapshot, "cpu"))
                {
                    if (totalCpuCounter is null)
                    {
                        totalCpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                        _ = totalCpuCounter.NextValue();
                        try
                        {
                            await Task.Delay(1000, cancellationToken);
                        }
                        catch (TaskCanceledException)
                        {
                            break;
                        }
                    }

                    var cpu = Math.Clamp(Math.Round(totalCpuCounter?.NextValue() ?? 0.0, 2), 0.0, 100.0);
                    payload["cpuPercent"] = cpu;
                }
                else if (totalCpuCounter is not null)
                {
                    totalCpuCounter.Dispose();
                    totalCpuCounter = null;
                }

                if (MonitoringMetricRequested(metricsSnapshot, "ram"))
                {
                    var ram = Math.Clamp(Math.Round(GetMemoryUsagePercent(), 2), 0.0, 100.0);
                    payload["ramPercent"] = ram;
                }

                if (MonitoringMetricRequested(metricsSnapshot, "disk-usage"))
                {
                    payload["diskUsagePercent"] = GetDiskUsagePercent();
                }

                if (MonitoringMetricRequested(metricsSnapshot, "disk-performance"))
                {
                    payload["diskPerformancePercent"] = GetDiskPerformancePercent();
                }

                if (MonitoringMetricRequested(metricsSnapshot, "network"))
                {
                    payload["networkKbSec"] = GetNetworkThroughputKbPerSec();
                }

                if (payload.Count > 0)
                {
                    await SendJsonAsync(socket, new
                    {
                        type = "monitoring-metrics",
                        metrics = payload,
                    }, cancellationToken);
                }

                await Task.Delay(MonitoringIntervalMs, cancellationToken);
            }
            catch (TaskCanceledException)
            {
                break;
            }
            catch (Exception)
            {
                // ignore transient monitoring failures
                await Task.Delay(MonitoringIntervalMs, cancellationToken);
            }
        }
    }

    private static string[] ParseMonitoringMetrics(JsonElement root)
    {
        if (!root.TryGetProperty("metrics", out var metricsElement) || metricsElement.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<string>();
        }

        var values = new List<string>();
        foreach (var metricElement in metricsElement.EnumerateArray())
        {
            if (metricElement.ValueKind != JsonValueKind.String)
            {
                continue;
            }

            var metric = metricElement.GetString()?.Trim();
            if (string.IsNullOrWhiteSpace(metric))
            {
                continue;
            }

            var normalized = metric.ToLowerInvariant();
            if (normalized == "cpu" || normalized == "ram" || normalized == "disk-usage" || normalized == "disk-performance" || normalized == "network")
            {
                values.Add(normalized);
            }
        }

        return values.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static bool MonitoringMetricRequested(string[] metrics, string metric)
    {
        if (metrics.Length == 0)
        {
            return false;
        }

        foreach (var value in metrics)
        {
            if (string.Equals(value, metric, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static double GetDiskUsagePercent()
    {
        long totalSpace = 0;
        long usedSpace = 0;
        foreach (var drive in DriveInfo.GetDrives())
        {
            if (!drive.IsReady || drive.TotalSize <= 0)
            {
                continue;
            }

            totalSpace += drive.TotalSize;
            usedSpace += drive.TotalSize - drive.AvailableFreeSpace;
        }

        if (totalSpace <= 0)
        {
            return 0.0;
        }

        var percent = (double)usedSpace / totalSpace * 100.0;
        return Math.Clamp(Math.Round(percent, 2), 0.0, 100.0);
    }

    private static double GetDiskPerformancePercent()
    {
        if (diskTimeCounter is null)
        {
            diskTimeCounter = new PerformanceCounter("PhysicalDisk", "% Disk Time", "_Total");
            _ = diskTimeCounter.NextValue();
        }

        var value = diskTimeCounter.NextValue();
        return Math.Clamp(Math.Round(value, 2), 0.0, 100.0);
    }

    private static double GetNetworkThroughputKbPerSec()
    {
        long totalBytes = 0;
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }

            var stats = nic.GetIPv4Statistics();
            totalBytes += stats.BytesSent + stats.BytesReceived;
        }

        var now = DateTime.UtcNow;
        if (previousNetworkBytes < 0 || previousNetworkSample == DateTime.MinValue)
        {
            previousNetworkBytes = totalBytes;
            previousNetworkSample = now;
            return 0.0;
        }

        var deltaSeconds = (now - previousNetworkSample).TotalSeconds;
        if (deltaSeconds <= 0)
        {
            previousNetworkBytes = totalBytes;
            previousNetworkSample = now;
            return 0.0;
        }

        var deltaBytes = Math.Max(0, totalBytes - previousNetworkBytes);
        previousNetworkBytes = totalBytes;
        previousNetworkSample = now;

        var kbPerSec = (deltaBytes / 1024.0) / deltaSeconds;
        return Math.Round(kbPerSec, 2);
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

    private static string GetAgentLocalUser()
    {
        try
        {
            return WindowsIdentity.GetCurrent()?.Name?.Trim() ?? Environment.UserName;
        }
        catch
        {
            return Environment.UserName;
        }
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

    private static double GetMemoryUsagePercent()
    {
        var status = new MEMORYSTATUSEX();
        status.dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>();
        if (!GlobalMemoryStatusEx(ref status) || status.ullTotalPhys == 0)
        {
            return 0.0;
        }

        var used = status.ullTotalPhys - status.ullAvailPhys;
        return Math.Round(used / (double)status.ullTotalPhys * 100, 2);
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

    private static async Task SendBsodSummaryAsync(ClientWebSocket socket, CancellationToken cancellationToken, bool force = false)
    {
        if (!force && lastBsodSummary is not null)
        {
            await SendJsonAsync(socket, new { type = "bsod-summary", summary = lastBsodSummary }, cancellationToken);
            return;
        }

        var summary = CollectBsodSummary();
        lastBsodSummary = summary;
        await SendJsonAsync(socket, new { type = "bsod-summary", summary }, cancellationToken);
    }

    private static async Task SendProcessListAsync(ClientWebSocket socket, CancellationToken cancellationToken)
    {
        var snapshot = CollectProcessSnapshot();
        await SendJsonAsync(socket, new { type = "process-list", snapshot }, cancellationToken);
    }

    private static async Task SendSoftwareListAsync(ClientWebSocket socket, string requestId, CancellationToken cancellationToken)
    {
        IReadOnlyCollection<InstalledSoftwareEntry> entries;
        try
        {
            entries = await CollectInstalledSoftwareAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to collect installed software: {ex.Message}");
            entries = Array.Empty<InstalledSoftwareEntry>();
        }

        var payload = new
        {
            type = "software-list",
            requestId,
            entries,
            retrievedAt = DateTime.UtcNow.ToString("o"),
        };

        await SendJsonAsync(socket, payload, cancellationToken);
    }

    private static async Task SendServiceListAsync(ClientWebSocket socket, string requestId, CancellationToken cancellationToken)
    {
        var services = new List<object>();
        try
        {
            foreach (var controller in ServiceController.GetServices().OrderBy(s => s.DisplayName))
            {
                services.Add(new
                {
                    name = controller.ServiceName,
                    displayName = controller.DisplayName,
                    status = controller.Status.ToString(),
                    serviceType = controller.ServiceType.ToString(),
                    startType = GetServiceStartMode(controller.ServiceName) ?? "Unknown"
                });
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to enumerate services: {ex.Message}");
        }

        var payload = new
        {
            type = "service-list",
            requestId,
            services
        };

        await SendJsonAsync(socket, payload, cancellationToken);
    }

    private static async Task HandleServiceActionAsync(ClientWebSocket socket, JsonElement element, CancellationToken cancellationToken)
    {
        var requestId = element.TryGetProperty("requestId", out var requestIdElement) && requestIdElement.ValueKind == JsonValueKind.String
            ? requestIdElement.GetString()?.Trim() ?? string.Empty
            : string.Empty;

        var serviceName = element.TryGetProperty("serviceName", out var serviceElement) && serviceElement.ValueKind == JsonValueKind.String
            ? serviceElement.GetString()?.Trim() ?? string.Empty
            : string.Empty;

        var action = element.TryGetProperty("action", out var actionElement) && actionElement.ValueKind == JsonValueKind.String
            ? actionElement.GetString()?.Trim().ToLowerInvariant() ?? string.Empty
            : string.Empty;

        var message = string.Empty;
        var success = false;

        if (string.IsNullOrWhiteSpace(serviceName) || string.IsNullOrWhiteSpace(action))
        {
            message = "Missing service name or action";
        }
        else
        {
            try
            {
                using var controller = new ServiceController(serviceName);
                switch (action)
                {
                    case "start":
                        if (controller.Status != ServiceControllerStatus.Running)
                        {
                            controller.Start();
                            controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(15));
                        }
                        success = true;
                        message = "Service started";
                        break;
                    case "stop":
                        if (controller.Status != ServiceControllerStatus.Stopped)
                        {
                            controller.Stop();
                            controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15));
                        }
                        success = true;
                        message = "Service stopped";
                        break;
                    case "restart":
                        if (controller.Status != ServiceControllerStatus.Stopped)
                        {
                            controller.Stop();
                            controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15));
                        }
                        controller.Start();
                        controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(15));
                        success = true;
                        message = "Service restarted";
                        break;
                    default:
                        message = $"Unsupported action '{action}'";
                        break;
                }
            }
            catch (Exception ex)
            {
                message = ex.Message;
            }
        }

        var result = new
        {
            type = "service-action-result",
            requestId,
            serviceName,
            action,
            success,
            message
        };

        await SendJsonAsync(socket, result, cancellationToken);
    }

    private static string? GetServiceStartMode(string serviceName)
    {
        try
        {
            var safeName = serviceName.Replace("'", "''");
            using var searcher = new ManagementObjectSearcher($"SELECT StartMode FROM Win32_Service WHERE Name = '{safeName}'");
            foreach (ManagementObject obj in searcher.Get())
            {
                return obj["StartMode"] as string;
            }
        }
        catch
        {
            // ignore
        }

        return null;
    }

    private static async Task<IReadOnlyCollection<InstalledSoftwareEntry>> CollectInstalledSoftwareAsync(CancellationToken cancellationToken)
    {
        var entries = new List<InstalledSoftwareEntry>();
        entries.AddRange(CollectRegistryInstalledSoftware());
        entries.AddRange(await CollectAppxPackagesAsync(cancellationToken));

        var unique = new Dictionary<string, InstalledSoftwareEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            var normalizedName = NormalizeForKey(entry.Name);
            var normalizedVersion = NormalizeForKey(entry.Version);
            if (string.IsNullOrEmpty(normalizedName) && string.IsNullOrEmpty(normalizedVersion))
            {
                continue;
            }

            var key = $"{normalizedName}|{normalizedVersion}";
            if (unique.TryGetValue(key, out var existing))
            {
                unique[key] = PickPreferredSoftwareEntry(existing, entry);
                continue;
            }

            unique[key] = entry;
        }

        return unique.Values.ToList();
    }

    private static InstalledSoftwareEntry PickPreferredSoftwareEntry(InstalledSoftwareEntry current, InstalledSoftwareEntry candidate)
    {
        if (current == null)
        {
            return candidate;
        }

        if (candidate == null)
        {
            return current;
        }

        if (string.IsNullOrEmpty(current.InstallLocation) && !string.IsNullOrEmpty(candidate.InstallLocation))
        {
            return candidate;
        }

        if (!string.IsNullOrEmpty(current.InstallLocation) && string.IsNullOrEmpty(candidate.InstallLocation))
        {
            return current;
        }

        var currentIs64 = current.Source?.Contains("64-bit", StringComparison.OrdinalIgnoreCase) ?? false;
        var candidateIs64 = candidate.Source?.Contains("64-bit", StringComparison.OrdinalIgnoreCase) ?? false;
        if (candidateIs64 && !currentIs64)
        {
            return candidate;
        }

        if (currentIs64 && !candidateIs64)
        {
            return current;
        }

        return current;
    }

    private static IEnumerable<InstalledSoftwareEntry> CollectRegistryInstalledSoftware()
    {
        var views = new (RegistryHive Hive, RegistryView View, string Label)[]
        {
            (RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM 64-bit"),
            (RegistryHive.LocalMachine, RegistryView.Registry32, "HKLM 32-bit"),
            (RegistryHive.CurrentUser, RegistryView.Registry64, "HKCU"),
        };

        var results = new List<InstalledSoftwareEntry>();
        foreach (var (hive, view, label) in views)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var uninstallKey = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                if (uninstallKey is null)
                {
                    continue;
                }

                foreach (var subKeyName in uninstallKey.GetSubKeyNames())
                {
                    using var subKey = uninstallKey.OpenSubKey(subKeyName);
                    if (subKey is null)
                    {
                        continue;
                    }

                    var displayName = subKey.GetValue("DisplayName") as string;
                    if (string.IsNullOrWhiteSpace(displayName))
                    {
                        continue;
                    }

                    var uninstallString = TrimToNull(subKey.GetValue("UninstallString") as string);
                    var entry = new InstalledSoftwareEntry
                    {
                        Id = $"registry-{label}-{subKeyName}".Replace(" ", "-"),
                        Name = displayName.Trim(),
                        Version = (subKey.GetValue("DisplayVersion") as string ?? string.Empty).Trim(),
                        Publisher = (subKey.GetValue("Publisher") as string ?? string.Empty).Trim(),
                        Source = $"Registry ({label})",
                        InstallLocation = TrimToNull(subKey.GetValue("InstallLocation") as string),
                        UninstallCommand = uninstallString,
                        ProductCode = TrimToNull(subKey.GetValue("ProductCode") as string),
                    };
                    if (string.IsNullOrEmpty(entry.ProductCode))
                    {
                        entry.ProductCode = ExtractGuidFromUninstallString(uninstallString);
                    }

                    var installDateRaw = subKey.GetValue("InstallDate") as string;
                    if (!string.IsNullOrWhiteSpace(installDateRaw) &&
                        DateTime.TryParseExact(installDateRaw.Trim(), "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var installDate))
                    {
                        entry.InstallDate = installDate.ToString("yyyy-MM-dd");
                    }

                    results.Add(entry);
                }
            }
            catch (Exception)
            {
                continue;
            }
        }

        return results;
    }

    private static async Task<IEnumerable<InstalledSoftwareEntry>> CollectAppxPackagesAsync(CancellationToken cancellationToken)
    {
        var entries = new List<InstalledSoftwareEntry>();
        try
        {
            const string command = "Get-AppxPackage | Select Name, PackageFullName, Publisher, Version | ConvertTo-Json -Compress";
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{command}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            using var process = Process.Start(psi);
            if (process is null)
            {
                return entries;
            }

            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();
            var waitTask = process.WaitForExitAsync(cancellationToken);
            await Task.WhenAll(stdoutTask, stderrTask, waitTask);

            if (process.ExitCode != 0)
            {
                var stderr = await stderrTask;
                if (!string.IsNullOrWhiteSpace(stderr))
                {
                    Console.WriteLine($"Appx enumeration failed: {stderr}");
                }

                return entries;
            }

            var output = (await stdoutTask).Trim();
            if (string.IsNullOrWhiteSpace(output))
            {
                return entries;
            }

            using var document = JsonDocument.Parse(output);
            static string GetString(JsonElement element, string key)
            {
                return element.TryGetProperty(key, out var property) && property.ValueKind == JsonValueKind.String
                    ? property.GetString()?.Trim() ?? string.Empty
                    : string.Empty;
            }

            void AddEntry(JsonElement element)
            {
                if (element.ValueKind != JsonValueKind.Object)
                {
                    return;
                }

                var packageFullName = GetString(element, "PackageFullName");
                if (string.IsNullOrWhiteSpace(packageFullName))
                {
                    return;
                }

                entries.Add(new InstalledSoftwareEntry
                {
                    Id = $"appx-{packageFullName}",
                    Name = GetString(element, "Name"),
                    Version = GetString(element, "Version"),
                    Publisher = GetString(element, "Publisher"),
                    Source = "Microsoft Store",
                    PackageFullName = packageFullName,
                });
            }

            if (document.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var element in document.RootElement.EnumerateArray())
                {
                    AddEntry(element);
                }
            }
            else
            {
                AddEntry(document.RootElement);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Appx enumeration failed: {ex.Message}");
        }

        return entries;
    }

    private static string? TrimToNull(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return value.Trim();
    }

    private static string? ExtractGuidFromUninstallString(string? uninstall)
    {
        if (string.IsNullOrWhiteSpace(uninstall))
        {
            return null;
        }

        var match = Regex.Match(uninstall, @"\{[0-9A-Fa-f\-]{36}\}");
        if (!match.Success)
        {
            return null;
        }

        return match.Value;
    }

    private static string[] SplitCommandLine(string commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return Array.Empty<string>();
        }

        var ptr = CommandLineToArgvW(commandLine, out var count);
        if (ptr == IntPtr.Zero || count == 0)
        {
            return Array.Empty<string>();
        }

        var args = new string[count];
        try
        {
            for (var i = 0; i < count; i++)
            {
                var argPtr = Marshal.ReadIntPtr(ptr, i * IntPtr.Size);
                args[i] = Marshal.PtrToStringUni(argPtr) ?? string.Empty;
            }

            return args;
        }
        finally
        {
            LocalFree(ptr);
        }
    }

    private static string QuoteArgument(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        if (value.StartsWith("\"", StringComparison.Ordinal) && value.EndsWith("\"", StringComparison.Ordinal))
        {
            return value;
        }

        var needsQuotes = value.Any(char.IsWhiteSpace);
        if (!needsQuotes)
        {
            return value;
        }

        var escaped = value.Replace("\"", "\\\"");
        return $"\"{escaped}\"";
    }

    private static string NormalizeForKey(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var trimmed = value.Trim();
        var collapsed = Regex.Replace(trimmed, @"\s+", " ");
        return collapsed.ToLowerInvariant();
    }

    private static async Task HandleKillProcessAsync(ClientWebSocket socket, JsonElement root, CancellationToken cancellationToken)
    {
        if (!root.TryGetProperty("processId", out var idElement) || !idElement.TryGetInt32(out var processId))
        {
            await SendJsonAsync(socket, new { type = "process-kill-result", success = false, message = "Invalid process id." }, cancellationToken);
            return;
        }

        try
        {
            using var target = Process.GetProcessById(processId);
            target.Kill(true);
            await SendJsonAsync(socket, new { type = "process-kill-result", success = true, processId }, cancellationToken);
        }
        catch (Exception ex)
        {
            await SendJsonAsync(socket, new { type = "process-kill-result", success = false, processId, message = ex.Message }, cancellationToken);
        }
    }

    private static ProcessSnapshot CollectProcessSnapshot()
    {
        var now = DateTime.UtcNow;
        var metrics = new List<ProcessSnapshotEntry>();
        var seen = new HashSet<int>();
        var totalMemoryBytes = GetDeviceSpecs().TotalMemoryBytes;

        foreach (var process in Process.GetProcesses())
        {
            try
            {
                using var proc = process;
                var pid = proc.Id;
                seen.Add(pid);

                processSamples.TryGetValue(pid, out var previousSample);

                var currentCpuMs = proc.TotalProcessorTime.TotalMilliseconds;
                var intervalMs = previousSample is not null
                    ? Math.Max((now - previousSample.Timestamp).TotalMilliseconds, 1)
                    : 1000;
                var intervalSeconds = intervalMs / 1000.0;
                var cpuDeltaMs = previousSample is not null ? currentCpuMs - previousSample.TotalCpuMilliseconds : 0.0;
                cpuDeltaMs = Math.Max(cpuDeltaMs, 0.0);

                var ioCounters = TryGetIoCounters(proc);
                var readBytes = ioCounters?.ReadTransferCount ?? 0;
                var writeBytes = ioCounters?.WriteTransferCount ?? 0;
                var otherBytes = ioCounters?.OtherTransferCount ?? 0;

                var prevRead = previousSample?.ReadBytes ?? readBytes;
                var prevWrite = previousSample?.WriteBytes ?? writeBytes;
                var prevOther = previousSample?.OtherBytes ?? otherBytes;

                var diskDelta = (double)(readBytes + writeBytes - prevRead - prevWrite);
                var networkDelta = (double)(otherBytes - prevOther);
                diskDelta = Math.Max(diskDelta, 0.0);
                networkDelta = Math.Max(networkDelta, 0.0);

                var workingSet = proc.WorkingSet64;
                var memoryPercent = totalMemoryBytes > 0
                    ? Math.Round(workingSet / (double)totalMemoryBytes * 100, 2)
                    : 0.0;

                var snapshotInfo = new ProcessInfo
                {
                    ProcessId = pid,
                    Name = proc.ProcessName,
                    ThreadCount = proc.Threads.Count,
                    StartTime = TryGetStartTime(proc),
                    WorkingSetBytes = workingSet,
                    PrivateMemoryBytes = proc.PrivateMemorySize64,
                    CpuPercent = 0.0,
                    MemoryPercent = Math.Min(memoryPercent, 100.0),
                    DiskPercent = 0.0,
                    NetworkPercent = 0.0,
                    IoBytesPerSecond = intervalSeconds > 0 ? Math.Round(diskDelta / intervalSeconds, 2) : 0.0,
                    NetworkBytesPerSecond = intervalSeconds > 0 ? Math.Round(networkDelta / intervalSeconds, 2) : 0.0,
                    IntervalSeconds = intervalSeconds
                };

                metrics.Add(new ProcessSnapshotEntry
                {
                    Info = snapshotInfo,
                    CpuDeltaMs = cpuDeltaMs,
                    DiskDeltaBytes = diskDelta,
                    NetworkDeltaBytes = networkDelta
                });

                processSamples[pid] = new ProcessSample
                {
                    TotalCpuMilliseconds = currentCpuMs,
                    ReadBytes = readBytes,
                    WriteBytes = writeBytes,
                    OtherBytes = otherBytes,
                    Timestamp = now
                };
            }
            catch (Exception)
            {
                continue;
            }
        }

        var removed = processSamples.Keys.Except(seen).ToList();
        foreach (var pid in removed)
        {
            processSamples.Remove(pid);
        }

        var totalCpuDelta = metrics.Sum(entry => entry.CpuDeltaMs);
        var totalDiskDelta = metrics.Sum(entry => entry.DiskDeltaBytes);
        var totalNetworkDelta = metrics.Sum(entry => entry.NetworkDeltaBytes);

        foreach (var entry in metrics)
        {
            entry.Info.CpuPercent = totalCpuDelta > 0
                ? Math.Round(Math.Clamp(entry.CpuDeltaMs / totalCpuDelta * 100, 0, 100), 2)
                : 0.0;
            entry.Info.DiskPercent = totalDiskDelta > 0
                ? Math.Round(Math.Clamp(entry.DiskDeltaBytes / totalDiskDelta * 100, 0, 100), 2)
                : 0.0;
            entry.Info.NetworkPercent = totalNetworkDelta > 0
                ? Math.Round(Math.Clamp(entry.NetworkDeltaBytes / totalNetworkDelta * 100, 0, 100), 2)
                : 0.0;
        }

        var ordered = metrics
            .OrderByDescending(entry => entry.Info.CpuPercent)
            .ThenBy(entry => entry.Info.Name, StringComparer.OrdinalIgnoreCase)
            .Select(entry => entry.Info)
            .ToArray();

        return new ProcessSnapshot
        {
            RetrievedAt = now,
            Processes = ordered
        };
    }

    private static DateTime? TryGetStartTime(Process process)
    {
        try
        {
            return process.StartTime;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static IoCounters? TryGetIoCounters(Process process)
    {
        if (GetProcessIoCounters(process.Handle, out var counters))
        {
            return counters;
        }

        return null;
    }

    private static Task<UpdateSummary> GetUpdateSummaryAsync()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return Task.FromResult(new UpdateSummary());
        }

        return Task.Run(() => CollectUpdateSummary());
    }

    private static BsodSummary CollectBsodSummary()
    {
        var summary = new BsodSummary();
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return summary;
        }

        try
        {
            var queryText = "*[System/EventID=1001]";
            var query = new EventLogQuery("System", PathType.LogName, queryText);
            using var reader = new EventLogReader(query);
            var events = new List<BsodEvent>();
            EventRecord? record;
            while (events.Count < 50 && (record = reader.ReadEvent()) is not null)
            {
                using (record)
                {
                    var description = record.FormatDescription() ?? record.ProviderName ?? string.Empty;
                    events.Add(new BsodEvent
                    {
                        TimestampUtc = record.TimeCreated?.ToUniversalTime() ?? DateTime.MinValue,
                        Description = description
                    });
                }
            }

            summary.TotalCount = events.Count;
            summary.Events = events.ToArray();
        }
        catch (EventLogNotFoundException)
        {
            // ignore missing log
        }
        catch (Exception)
        {
            // ignore other failures
        }

        return summary;
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
        string? scheduleId = null;
        if (element.TryGetProperty("scheduleId", out var scheduleElement) && scheduleElement.ValueKind == JsonValueKind.String)
        {
            var candidate = scheduleElement.GetString()?.Trim();
            if (!string.IsNullOrWhiteSpace(candidate))
            {
                scheduleId = candidate;
            }
        }

        if (!element.TryGetProperty("ids", out var idsElement) || idsElement.ValueKind != JsonValueKind.Array)
        {
            await SendUpdateInstallResultAsync(socket, false, "No updates selected.", false, cancellationToken, scheduleId);
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
            await SendUpdateInstallResultAsync(socket, false, "No updates selected.", false, cancellationToken, scheduleId);
            return;
        }

        UpdateInstallResult result;
        try
        {
            result = await Task.Run(() => InstallSelectedUpdates(ids, cancellationToken), cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        catch (Exception ex)
        {
            await SendUpdateInstallResultAsync(socket, false, $"Install failed: {ex.Message}", false, cancellationToken, scheduleId);
            return;
        }

        await SendUpdateInstallResultAsync(socket, result.Success, result.Message, result.RebootRequired, cancellationToken, scheduleId);
        if (result.Success)
        {
            await SendAgentUpdateSummaryAsync(socket, cancellationToken, true);
        }
    }

    private static UpdateInstallResult InstallSelectedUpdates(string[] requestedIds, CancellationToken cancellationToken)
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
        #pragma warning disable CS8600
        dynamic collection;
        var collectionType = Type.GetTypeFromProgID("Microsoft.Update.UpdateCollection");
        if (collectionType is not null)
        {
            collection = Activator.CreateInstance(collectionType);
        }
        else
        {
            try
            {
                collection = session.CreateUpdateCollection();
            }
            catch
            {
                collection = null;
            }
        }

        #pragma warning restore CS8600

        if (collection is null)
        {
            try
            {
                return InstallUpdatesViaPowerShell(requestedIds, cancellationToken).GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                return new UpdateInstallResult(false, $"PowerShell fallback failed: {ex.Message}");
            }
        }

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

    private static Task SendUpdateInstallResultAsync(ClientWebSocket socket, bool success, string message, bool rebootRequired, CancellationToken cancellationToken, string? scheduleId = null)
    {
        return SendJsonAsync(socket, new
        {
            type = "update-install-result",
            success,
            message,
            rebootRequired,
            scheduleId
        }, cancellationToken);
    }

    private static Task SendActionResultAsync(ClientWebSocket socket, bool success, string message, string action, string? scheduleId, CancellationToken cancellationToken)
    {
        return SendJsonAsync(socket, new
        {
            type = "action-result",
            success,
            message,
            action,
            scheduleId
        }, cancellationToken);
    }

    private static async Task HandleInvokeActionAsync(ClientWebSocket socket, JsonElement element, CancellationToken cancellationToken)
    {
        var action = element.TryGetProperty("action", out var actionElement) && actionElement.ValueKind == JsonValueKind.String
            ? actionElement.GetString()?.Trim()
            : null;

        var scheduleId = element.TryGetProperty("scheduleId", out var scheduleElement) && scheduleElement.ValueKind == JsonValueKind.String
            ? scheduleElement.GetString()?.Trim()
            : null;

        if (string.IsNullOrWhiteSpace(action))
        {
            await SendActionResultAsync(socket, false, "Action missing.", string.Empty, scheduleId, cancellationToken);
            return;
        }

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            await SendActionResultAsync(socket, false, "Action requires Windows.", action, scheduleId, cancellationToken);
            return;
        }

        var args = action switch
        {
            "restart" => "/r /t 0",
            "shutdown" => "/s /t 0",
            "update-restart" => "/g /t 0",
            "update-shutdown" => "/s /t 0 /d p:4:1",
            _ => null
        };

        if (args is null)
        {
            await SendActionResultAsync(socket, false, "Unknown action.", action, scheduleId, cancellationToken);
            return;
        }

        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "shutdown",
                    Arguments = args,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                }
            };

            if (!process.Start())
            {
                await SendActionResultAsync(socket, false, "Failed to start action.", action, scheduleId, cancellationToken);
                return;
            }

            await SendActionResultAsync(socket, true, "Action triggered.", action, scheduleId, cancellationToken);
        }
        catch (Exception ex)
        {
            await SendActionResultAsync(socket, false, $"Action failed: {ex.Message}", action, scheduleId, cancellationToken);
        }
    }

    private static async Task HandleUninstallRequestAsync(ClientWebSocket socket, JsonElement element, CancellationToken cancellationToken)
    {
        var requestId = element.TryGetProperty("requestId", out var requestIdElement) && requestIdElement.ValueKind == JsonValueKind.String
            ? requestIdElement.GetString()?.Trim() ?? string.Empty
            : string.Empty;

        var softwareId = element.TryGetProperty("softwareId", out var idElement) && idElement.ValueKind == JsonValueKind.String
            ? idElement.GetString()?.Trim() ?? string.Empty
            : string.Empty;

        var source = element.TryGetProperty("source", out var sourceElement) && sourceElement.ValueKind == JsonValueKind.String
            ? sourceElement.GetString()?.Trim() ?? string.Empty
            : string.Empty;

        var uninstallCommand = element.TryGetProperty("uninstallCommand", out var uninstallElement) && uninstallElement.ValueKind == JsonValueKind.String
            ? uninstallElement.GetString()
            : null;

        var packageFullName = element.TryGetProperty("packageFullName", out var packageElement) && packageElement.ValueKind == JsonValueKind.String
            ? packageElement.GetString()
            : null;

        var productCode = element.TryGetProperty("productCode", out var codeElement) && codeElement.ValueKind == JsonValueKind.String
            ? codeElement.GetString()?.Trim()
            : null;

        var success = false;
        var message = "No uninstall instructions provided for this item.";

        if (source.Equals("appx", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(packageFullName))
        {
            var safeName = packageFullName.Replace("'", "''");
            var args = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Remove-AppxPackage -Package '{safeName}'\"";
            (success, message) = await RunCommandAsync($"powershell.exe {args}", cancellationToken);
        }
        else if (!string.IsNullOrWhiteSpace(productCode))
        {
            var sanitized = productCode.Trim('{', '}');
            var args = $"wmic product where \"IdentifyingNumber='{{{sanitized}}}'\" call uninstall /nointeractive";
            (success, message) = await RunCommandAsync(args, cancellationToken);
        }
        else if (!string.IsNullOrWhiteSpace(uninstallCommand))
        {
            (success, message) = await RunCommandAsync(uninstallCommand, cancellationToken);
        }

        await SendSoftwareOperationResultAsync(socket, requestId, softwareId, "uninstall", success, message, cancellationToken);
    }

    private static Task SendSoftwareOperationResultAsync(ClientWebSocket socket, string requestId, string softwareId, string operation, bool success, string message, CancellationToken cancellationToken)
    {
        return SendJsonAsync(socket, new
        {
            type = "software-operation-result",
            requestId,
            softwareId,
            operation,
            success,
            message
        }, cancellationToken);
    }

    private static async Task<(bool success, string message)> RunCommandAsync(string commandLine, CancellationToken cancellationToken)
    {
        try
        {
            var args = SplitCommandLine(commandLine);
            if (args.Length == 0)
            {
                return (false, "Command line was empty.");
            }

            var target = args[0];
            var commandArguments = args.Skip(1)
                .Select(QuoteArgument)
                .Where(arg => !string.IsNullOrEmpty(arg))
                .ToArray();

            var psi = new ProcessStartInfo
            {
                FileName = target,
                Arguments = string.Join(" ", commandArguments),
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            using var process = Process.Start(psi);
            if (process is null)
            {
                return (false, "Unable to launch command.");
            }

            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();
            var waitTask = process.WaitForExitAsync(cancellationToken);
            await Task.WhenAll(stdoutTask, stderrTask, waitTask);

            var outputParts = new[] { stdoutTask.Result, stderrTask.Result }
                .Where(text => !string.IsNullOrWhiteSpace(text))
                .Select(text => text.Trim())
                .ToArray();
            var combined = string.Join(Environment.NewLine, outputParts);
            var success = process.ExitCode == 0;
            var finalMessage = string.IsNullOrWhiteSpace(combined)
                ? success ? "Command completed successfully." : $"Command failed with exit code {process.ExitCode}."
                : combined;

            return (success, finalMessage);
        }
        catch (OperationCanceledException)
        {
            return (false, "Operation canceled.");
        }
        catch (Exception ex)
        {
            return (false, $"Command failed: {ex.Message}");
        }
    }

    private static async Task<UpdateInstallResult> InstallUpdatesViaPowerShell(string[] requestedIds, CancellationToken cancellationToken)
    {
        var quotedIds = requestedIds
            .Select(id => id?.Replace("'", "''"))
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .Select(id => $"'{id}'")
            .ToArray();

        if (quotedIds.Length == 0)
        {
            return new UpdateInstallResult(false, "No valid update ids for PowerShell fallback.");
        }

        var idsArray = string.Join(",", quotedIds);
        var script = $"Import-Module PSWindowsUpdate -ErrorAction Stop; $ids=@({idsArray}); Install-WindowsUpdate -KBArticleID $ids -AcceptAll -AutoReboot:$false -IgnoreUserInput";
        var command = $"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{script}\"";
        var (success, message) = await RunCommandAsync(command, cancellationToken);
        return new UpdateInstallResult(success, success ? "Updates installed via PowerShell." : $"PowerShell install failed: {message}");
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
                        var scale = GetRequestedCaptureScale(document.RootElement);
                        await StartScreenSessionAsync(socket, sessionId, screenId, scale, cancellationToken);
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
            case "chat-request":
            {
                HandleChatRequest(document.RootElement);
                break;
            }
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
            case "list-processes":
                await SendProcessListAsync(socket, cancellationToken);
                break;
            case "kill-process":
                await HandleKillProcessAsync(socket, document.RootElement, cancellationToken);
                break;
            case "list-software":
                 if (document.RootElement.TryGetProperty("requestId", out var requestIdElement) &&
                     requestIdElement.ValueKind == JsonValueKind.String &&
                     !string.IsNullOrWhiteSpace(requestIdElement.GetString()))
                 {
                     await SendSoftwareListAsync(socket, requestIdElement.GetString()!, cancellationToken);
                 }
                 break;
            case "list-services":
                if (document.RootElement.TryGetProperty("requestId", out var serviceRequestId) &&
                    serviceRequestId.ValueKind == JsonValueKind.String &&
                    !string.IsNullOrWhiteSpace(serviceRequestId.GetString()))
                {
                    await SendServiceListAsync(socket, serviceRequestId.GetString()!, cancellationToken);
                }
                break;
            case "uninstall-software":
                await HandleUninstallRequestAsync(socket, document.RootElement, cancellationToken);
                break;
            case "manage-service":
                await HandleServiceActionAsync(socket, document.RootElement, cancellationToken);
                break;
            case "request-bsod":
                await SendBsodSummaryAsync(socket, cancellationToken, true);
                break;
            case "request-updates":
                await SendAgentUpdateSummaryAsync(socket, cancellationToken, true);
                break;
            case "list-files":
                await HandleFileListRequestAsync(socket, document.RootElement, cancellationToken);
                break;
            case "download-file":
                await HandleFileDownloadRequestAsync(socket, document.RootElement, cancellationToken);
                break;
            case "upload-file-chunk":
                await HandleFileUploadChunkAsync(socket, document.RootElement, cancellationToken);
                break;
            case "upload-file-complete":
                await HandleFileUploadCompleteAsync(socket, document.RootElement, cancellationToken);
                break;
            case "install-updates":
                await HandleInstallUpdatesAsync(socket, document.RootElement, cancellationToken);
                break;
            case "invoke-action":
                await HandleInvokeActionAsync(socket, document.RootElement, cancellationToken);
                break;
            case "run-remediation":
                await RunRemediationScriptAsync(socket, document.RootElement, cancellationToken);
                break;
            case "monitoring-status":
            {
                if (document.RootElement.TryGetProperty("enabled", out var enabledElement) &&
                    (enabledElement.ValueKind == JsonValueKind.True || enabledElement.ValueKind == JsonValueKind.False))
                {
                    var metrics = ParseMonitoringMetrics(document.RootElement);
                    UpdateMonitoringStatus(enabledElement.GetBoolean(), metrics, socket, cancellationToken);
                }

                break;
            }
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

    private static void HandleChatRequest(JsonElement root)
    {
        if (!root.TryGetProperty("text", out var textElement) || textElement.ValueKind != JsonValueKind.String)
        {
            return;
        }

        var text = textElement.GetString()?.Trim();
        if (string.IsNullOrWhiteSpace(text))
        {
            return;
        }

        if (root.TryGetProperty("sessionId", out var sessionIdElement) && sessionIdElement.ValueKind == JsonValueKind.String)
        {
            var sessionId = sessionIdElement.GetString()?.Trim();
            if (!string.IsNullOrWhiteSpace(sessionId))
            {
                currentChatSessionId = sessionId;
            }
        }

        Console.WriteLine();
        Console.WriteLine("🔔 Chat request from the server:");
        Console.WriteLine(text);
        Console.WriteLine("Reply by typing \"/chat <your message>\".");
        Console.WriteLine();

        var serverUser = "Server";
        var serverRole = (string?)null;
        if (root.TryGetProperty("user", out var userElement) && userElement.ValueKind == JsonValueKind.String)
        {
            var value = userElement.GetString()?.Trim();
            if (!string.IsNullOrWhiteSpace(value))
            {
                serverUser = value;
            }
        }

        if (root.TryGetProperty("role", out var roleElement) && roleElement.ValueKind == JsonValueKind.String)
        {
            var value = roleElement.GetString()?.Trim();
            if (!string.IsNullOrWhiteSpace(value))
            {
                serverRole = value;
            }
        }

        var timestamp = GetChatTimestamp(root);
        TrayIconManager.PostChatMessage(serverUser, serverRole, text, true, timestamp);
    }

    private static string GetChatTimestamp(JsonElement root)
    {
        if (root.TryGetProperty("timestamp", out var timestampElement) &&
            timestampElement.ValueKind == JsonValueKind.String &&
            DateTime.TryParse(timestampElement.GetString(), out var parsed))
        {
            return parsed.ToLocalTime().ToShortTimeString();
        }

        return DateTime.Now.ToShortTimeString();
    }

    private static double GetRequestedCaptureScale(JsonElement root)
    {
        if (root.TryGetProperty("scale", out var element) && element.TryGetDouble(out var value))
        {
            return ClampCaptureScale(value);
        }

        return DefaultCaptureScale;
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

    private static async Task StartScreenSessionAsync(ClientWebSocket socket, string sessionId, string? screenId, double requestedScale, CancellationToken cancellationToken)
    {
        selectedScreenId = screenId;
        captureScale = ClampCaptureScale(requestedScale);
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
                var targetScreen = GetCaptureScreen();
                var frame = CaptureScreenFrame(targetScreen);
                if (screenDataChannel is not null)
                {
                    if (frame.Length > 0)
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

                    var cursorState = GetCursorState(targetScreen.Bounds);
                    var cursorMessage = JsonSerializer.Serialize(new
                    {
                        type = "cursor",
                        x = cursorState.x,
                        y = cursorState.y,
                        visible = cursorState.visible
                    });

                    try
                    {
                        screenDataChannel.SendMessage(Encoding.UTF8.GetBytes(cursorMessage));
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

    private static byte[] CaptureScreenFrame(Screen targetScreen)
    {
        var bounds = targetScreen.Bounds;
        if (bounds.Width <= 0 || bounds.Height <= 0)
        {
            return Array.Empty<byte>();
        }

        var captureWidth = Math.Max(1, bounds.Width);
        var captureHeight = Math.Max(1, bounds.Height);

        using var capture = new Bitmap(captureWidth, captureHeight);
        using (var g = Graphics.FromImage(capture))
        {
            g.CopyFromScreen(bounds.Location, Point.Empty, bounds.Size);
        }

        var scaledWidth = Math.Max(1, (int)Math.Round(bounds.Width * captureScale));
        var scaledHeight = Math.Max(1, (int)Math.Round(bounds.Height * captureScale));

        if (scaledWidth == captureWidth && scaledHeight == captureHeight)
        {
            return EncodeBitmapToJpeg(capture);
        }

        using var scaled = new Bitmap(scaledWidth, scaledHeight);
        using (var g = Graphics.FromImage(scaled))
        {
            g.InterpolationMode = InterpolationMode.HighQualityBicubic;
            g.DrawImage(capture, 0, 0, scaledWidth, scaledHeight);
        }

        return EncodeBitmapToJpeg(scaled);
    }

    private static (double x, double y, bool visible) GetCursorState(Rectangle bounds)
    {
        var cursor = Cursor.Position;
        var visible = bounds.Contains(cursor) && bounds.Width > 0 && bounds.Height > 0;
        var normalizedX = visible ? (cursor.X - bounds.X) / (double)bounds.Width : 0.0;
        var normalizedY = visible ? (cursor.Y - bounds.Y) / (double)bounds.Height : 0.0;
        return (Math.Clamp(normalizedX, 0.0, 1.0), Math.Clamp(normalizedY, 0.0, 1.0), visible);
    }

    private static double ClampCaptureScale(double value)
    {
        if (double.IsNaN(value))
        {
            return DefaultCaptureScale;
        }

        return Math.Min(Math.Max(value, MinCaptureScale), MaxCaptureScale);
    }

    private static byte[] EncodeBitmapToJpeg(Bitmap bitmap)
    {
        using var ms = new MemoryStream();
        var encoder = JpegEncoder ?? ImageCodecInfo.GetImageEncoders()
            .FirstOrDefault(codec => codec.FormatID == ImageFormat.Jpeg.Guid);
        var encoderParams = new EncoderParameters(1);
        encoderParams.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, ScreenJpegQuality);
        bitmap.Save(ms, encoder ?? ImageCodecInfo.GetImageEncoders()[0], encoderParams);
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

    private static async Task SendChatResponseAsync(ClientWebSocket socket, string text, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(currentChatSessionId))
        {
            Console.WriteLine("No active chat session available.");
            return;
        }

        await SendJsonAsync(socket, new
        {
            type = "chat-response",
            sessionId = currentChatSessionId,
            text
        }, cancellationToken);
    }

    private static async Task SendJsonAsync(ClientWebSocket socket, object payload, CancellationToken cancellationToken)
    {
        var text = JsonSerializer.Serialize(payload);
        await SendTextAsync(socket, text, cancellationToken);
    }

    private static string? ExtractRequestId(JsonElement root)
    {
        if (!root.TryGetProperty("requestId", out var requestIdElement) || requestIdElement.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        string? value = requestIdElement.GetString();
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    private static string ResolveBrowsePath(string? requestedPath)
    {
        var candidate = string.IsNullOrWhiteSpace(requestedPath)
            ? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
            : requestedPath!;

        try
        {
            candidate = Path.GetFullPath(candidate);
        }
        catch
        {
            candidate = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        }

        if (!Directory.Exists(candidate))
        {
            var parent = Path.GetDirectoryName(candidate);
            if (!string.IsNullOrWhiteSpace(parent) && Directory.Exists(parent))
            {
                candidate = parent;
            }
            else
            {
                candidate = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            }
        }

        return candidate;
    }

    private static async Task HandleFileListRequestAsync(ClientWebSocket socket, JsonElement root, CancellationToken cancellationToken)
    {
        var requestId = ExtractRequestId(root);
        var requestedPath = root.TryGetProperty("path", out var pathElement) && pathElement.ValueKind == JsonValueKind.String
            ? pathElement.GetString()
            : null;
        var resolvedPath = ResolveBrowsePath(requestedPath);
        var entries = new List<FileEntry>();
        var parentPath = Directory.GetParent(resolvedPath)?.FullName ?? resolvedPath;

        try
        {
            var directoryInfo = new DirectoryInfo(resolvedPath);
            foreach (var dir in directoryInfo.EnumerateDirectories())
            {
                if (entries.Count >= MaxFileEntries)
                {
                    break;
                }

                entries.Add(new FileEntry
                {
                    Name = dir.Name,
                    Path = dir.FullName,
                    IsDirectory = true,
                    LastModifiedUtc = dir.LastWriteTimeUtc,
                });
            }

            if (entries.Count < MaxFileEntries)
            {
                foreach (var file in directoryInfo.EnumerateFiles())
                {
                    if (entries.Count >= MaxFileEntries)
                    {
                        break;
                    }

                    entries.Add(new FileEntry
                    {
                        Name = file.Name,
                        Path = file.FullName,
                        IsDirectory = false,
                        Size = file.Length,
                        LastModifiedUtc = file.LastWriteTimeUtc,
                    });
                }
            }
        }
        catch (Exception ex)
        {
            await SendJsonAsync(socket, new
            {
                type = "file-list",
                requestId,
                path = resolvedPath,
                parentPath,
                entries,
                error = ex.Message,
            }, cancellationToken);
            return;
        }

            await SendJsonAsync(socket, new
            {
                type = "file-list",
                requestId,
                path = resolvedPath,
                parentPath,
                entries,
            }, cancellationToken);
    }

    private static async Task HandleFileDownloadRequestAsync(ClientWebSocket socket, JsonElement root, CancellationToken cancellationToken)
    {
        var requestId = ExtractRequestId(root);
        var requestedPath = root.TryGetProperty("path", out var pathElement) && pathElement.ValueKind == JsonValueKind.String
            ? pathElement.GetString()
            : null;

        if (string.IsNullOrWhiteSpace(requestedPath))
        {
            await SendFileDownloadErrorAsync(socket, requestId, "Path is required", cancellationToken);
            return;
        }

        try
        {
            var normalized = Path.GetFullPath(requestedPath);
            var fileInfo = new FileInfo(normalized);
            if (!fileInfo.Exists)
            {
                await SendFileDownloadErrorAsync(socket, requestId, "File not found", cancellationToken);
                return;
            }

            var bytes = await File.ReadAllBytesAsync(normalized, cancellationToken);
            var encoded = Convert.ToBase64String(bytes);
            await SendJsonAsync(socket, new
            {
                type = "file-download-result",
                requestId,
                path = normalized,
                name = fileInfo.Name,
                size = fileInfo.Length,
                data = encoded,
            }, cancellationToken);
        }
        catch (Exception ex)
        {
            await SendFileDownloadErrorAsync(socket, requestId, ex.Message, cancellationToken);
        }
    }

    private static async Task HandleFileUploadChunkAsync(ClientWebSocket socket, JsonElement root, CancellationToken cancellationToken)
    {
        var requestId = ExtractRequestId(root);
        if (string.IsNullOrWhiteSpace(requestId))
        {
            return;
        }

        var destinationPath = root.TryGetProperty("path", out var pathElement) && pathElement.ValueKind == JsonValueKind.String
            ? pathElement.GetString()
            : null;
        var data = root.TryGetProperty("data", out var dataElement) && dataElement.ValueKind == JsonValueKind.String
            ? dataElement.GetString()
            : null;

        if (string.IsNullOrWhiteSpace(destinationPath) || data is null)
        {
            await SendFileUploadResultAsync(socket, requestId, false, "Invalid upload chunk", cancellationToken);
            return;
        }

        try
        {
            var normalized = Path.GetFullPath(destinationPath);
            if (!uploadSessions.TryGetValue(requestId, out var session))
            {
                var directory = Path.GetDirectoryName(normalized);
                if (!string.IsNullOrWhiteSpace(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                var stream = new FileStream(normalized, FileMode.Create, FileAccess.Write, FileShare.None);
                session = new PendingUpload
                {
                    FilePath = normalized,
                    Stream = stream,
                };
                uploadSessions[requestId] = session;
            }

            var bytes = Convert.FromBase64String(data);
            await session.Stream.WriteAsync(bytes, cancellationToken);
        }
        catch (Exception ex)
        {
            await SendFileUploadResultAsync(socket, requestId, false, ex.Message, cancellationToken);
            await CleanupUploadSessionAsync(requestId);
        }
    }

    private static async Task HandleFileUploadCompleteAsync(ClientWebSocket socket, JsonElement root, CancellationToken cancellationToken)
    {
        var requestId = ExtractRequestId(root);
        if (string.IsNullOrWhiteSpace(requestId))
        {
            return;
        }

        if (!uploadSessions.TryGetValue(requestId, out var session))
        {
            await SendFileUploadResultAsync(socket, requestId, false, "Upload session not found", cancellationToken);
            return;
        }

        try
        {
            await session.Stream.FlushAsync(cancellationToken);
            session.Stream.Dispose();
            uploadSessions.Remove(requestId);
            await SendFileUploadResultAsync(socket, requestId, true, "File uploaded", cancellationToken);
        }
        catch (Exception ex)
        {
            await SendFileUploadResultAsync(socket, requestId, false, ex.Message, cancellationToken);
            await CleanupUploadSessionAsync(requestId);
        }
    }

    private static Task CleanupUploadSessionAsync(string requestId)
    {
        if (!uploadSessions.TryGetValue(requestId, out var session))
        {
            return Task.CompletedTask;
        }

        uploadSessions.Remove(requestId);
        try
        {
            session.Stream.Dispose();
        }
        catch
        {
            // ignore disposal failures
        }

        return Task.CompletedTask;
    }

    private static Task SendFileDownloadErrorAsync(ClientWebSocket socket, string? requestId, string message, CancellationToken cancellationToken)
    {
        return SendJsonAsync(socket, new
        {
            type = "file-download-result",
            requestId,
            success = false,
            message,
        }, cancellationToken);
    }

    private static Task SendFileUploadResultAsync(ClientWebSocket socket, string? requestId, bool success, string message, CancellationToken cancellationToken)
    {
        return SendJsonAsync(socket, new
        {
            type = "file-upload-result",
            requestId,
            success,
            message,
        }, cancellationToken);
    }

    private static Task SendRemediationResultAsync(ClientWebSocket socket, string? requestId, string scriptName, bool success, string message, CancellationToken cancellationToken)
    {
        return SendJsonAsync(socket, new
        {
            type = "remediation-result",
            requestId,
            scriptName,
            success,
            message,
        }, cancellationToken);
    }

    private static async Task RunRemediationScriptAsync(ClientWebSocket socket, JsonElement root, CancellationToken cancellationToken)
    {
        var requestId = ExtractRequestId(root);
        var scriptName = root.TryGetProperty("scriptName", out var scriptNameElement) ? scriptNameElement.GetString() : null;
        if (string.IsNullOrWhiteSpace(requestId) || string.IsNullOrWhiteSpace(scriptName))
        {
            return;
        }

        var language = root.TryGetProperty("language", out var languageElement) ? languageElement.GetString()?.ToLowerInvariant() : null;
        var content = root.TryGetProperty("content", out var contentElement) ? contentElement.GetString() : null;
        if (string.IsNullOrWhiteSpace(content))
        {
            await SendRemediationResultAsync(socket, requestId, scriptName, false, "Script content missing", cancellationToken);
            return;
        }

        var extension = language == "python" ? ".py" : ".ps1";
        var interpreter = language == "python" ? "python" : "powershell.exe";
        var tempPath = Path.Combine(Path.GetTempPath(), $"{scriptName}-{Guid.NewGuid():N}{extension}");

        try
        {
            await File.WriteAllTextAsync(tempPath, content, cancellationToken);
            var startInfo = new ProcessStartInfo
            {
                FileName = interpreter,
                Arguments = language == "python"
                    ? $"\"{tempPath}\""
                    : $"-NoProfile -ExecutionPolicy Bypass -File \"{tempPath}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            using var process = Process.Start(startInfo);
            if (process is null)
            {
                await SendRemediationResultAsync(socket, requestId, scriptName, false, "Failed to start remediation process", cancellationToken);
                return;
            }

            var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken);
            var output = await outputTask;
            var error = await errorTask;
            var lines = new List<string>();
            if (!string.IsNullOrWhiteSpace(output))
            {
                lines.Add(output.Trim());
            }

            if (!string.IsNullOrWhiteSpace(error))
            {
                lines.Add(error.Trim());
            }

            var message = lines.Count > 0 ? string.Join(Environment.NewLine, lines) : "Remediation completed.";
            await SendRemediationResultAsync(socket, requestId, scriptName, process.ExitCode == 0, message, cancellationToken);
        }
        catch (Exception ex)
        {
            await SendRemediationResultAsync(socket, requestId, scriptName, false, ex.Message, cancellationToken);
        }
        finally
        {
            try
            {
                if (File.Exists(tempPath))
                {
                    File.Delete(tempPath);
                }
            }
            catch
            {
                // ignore cleanup failures
            }
        }
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

    private sealed class ProcessSnapshot
    {
        [JsonPropertyName("retrievedAt")]
        public DateTime RetrievedAt { get; set; }

        [JsonPropertyName("processes")]
        public ProcessInfo[] Processes { get; set; } = Array.Empty<ProcessInfo>();
    }

    private sealed class ProcessInfo
    {
        [JsonPropertyName("processId")]
        public int ProcessId { get; set; }

        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("cpuPercent")]
        public double CpuPercent { get; set; }

        [JsonPropertyName("memoryPercent")]
        public double MemoryPercent { get; set; }

        [JsonPropertyName("diskPercent")]
        public double DiskPercent { get; set; }

        [JsonPropertyName("networkPercent")]
        public double NetworkPercent { get; set; }

        [JsonPropertyName("workingSetBytes")]
        public long WorkingSetBytes { get; set; }

        [JsonPropertyName("privateMemoryBytes")]
        public long PrivateMemoryBytes { get; set; }

        [JsonPropertyName("threads")]
        public int ThreadCount { get; set; }

        [JsonPropertyName("startTime")]
        public DateTime? StartTime { get; set; }

        [JsonPropertyName("ioBytesPerSecond")]
        public double IoBytesPerSecond { get; set; }

        [JsonPropertyName("networkBytesPerSecond")]
        public double NetworkBytesPerSecond { get; set; }

        [JsonPropertyName("intervalSeconds")]
        public double IntervalSeconds { get; set; }
    }

    private sealed class ProcessSnapshotEntry
    {
        public ProcessInfo Info { get; set; } = new();
        public double CpuDeltaMs { get; set; }
        public double DiskDeltaBytes { get; set; }
        public double NetworkDeltaBytes { get; set; }
    }

    private sealed class ProcessSample
    {
        public double TotalCpuMilliseconds { get; set; }
        public ulong ReadBytes { get; set; }
        public ulong WriteBytes { get; set; }
        public ulong OtherBytes { get; set; }
        public DateTime Timestamp { get; set; }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    private sealed class InstalledSoftwareEntry
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("version")]
        public string Version { get; set; } = string.Empty;

        [JsonPropertyName("publisher")]
        public string Publisher { get; set; } = string.Empty;

        [JsonPropertyName("source")]
        public string Source { get; set; } = string.Empty;

        [JsonPropertyName("installDate")]
        public string? InstallDate { get; set; }

        [JsonPropertyName("installLocation")]
        public string? InstallLocation { get; set; }

        [JsonPropertyName("uninstallCommand")]
        public string? UninstallCommand { get; set; }

        [JsonPropertyName("packageFullName")]
        public string? PackageFullName { get; set; }

        [JsonPropertyName("productCode")]
        public string? ProductCode { get; set; }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessIoCounters(IntPtr handle, out IoCounters counters);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr CommandLineToArgvW(string lpCmdLine, out int pNumArgs);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);

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

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    private sealed class BsodSummary
    {
        [JsonPropertyName("totalCount")]
        public int TotalCount { get; set; }

        [JsonPropertyName("events")]
        public BsodEvent[] Events { get; set; } = Array.Empty<BsodEvent>();
    }

    private sealed class BsodEvent
    {
        [JsonPropertyName("timestampUtc")]
        public DateTime TimestampUtc { get; set; }

        [JsonPropertyName("description")]
        public string Description { get; set; } = string.Empty;
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

    private sealed class FileEntry
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;
        [JsonPropertyName("path")]
        public string Path { get; set; } = string.Empty;
        [JsonPropertyName("isDirectory")]
        public bool IsDirectory { get; set; }
        [JsonPropertyName("size")]
        public long? Size { get; set; }
        [JsonPropertyName("lastModifiedUtc")]
        public DateTime? LastModifiedUtc { get; set; }
    }

    private sealed class PendingUpload
    {
        public string FilePath { get; set; } = string.Empty;
        public FileStream Stream { get; set; } = null!;
    }
}
