using System;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Agent;

internal static class TrayIconManager
{
    private static Thread? uiThread;
    private static TrayApplicationContext? context;
    private static SynchronizationContext? uiContext;
    private static readonly ManualResetEventSlim Started = new();
    private static ChatWindow? chatWindow;
    private static Func<string, Task>? chatSendHandler;
    private static string? chatAgentUser;

    public static void Start()
    {
        if (uiThread is not null)
        {
            return;
        }

        uiThread = new Thread(() =>
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            context = new TrayApplicationContext();
            var syncContext = SynchronizationContext.Current ?? new WindowsFormsSynchronizationContext();
            SynchronizationContext.SetSynchronizationContext(syncContext);
            uiContext = syncContext;
            Started.Set();
            Application.Run(context);
        })
        {
            IsBackground = true
        };
        uiThread.SetApartmentState(ApartmentState.STA);
        uiThread.Start();
        Started.Wait();
    }

    public static void Stop()
    {
        if (context is not null && uiContext is not null)
        {
            uiContext.Post(_ => context.RequestExit(), null);
            uiThread?.Join(1000);
        }

        context = null;
        uiThread = null;
        uiContext = null;
        Started.Reset();
    }

        public static void RegisterChatHandler(Func<string, Task> sendHandler, string agentUser)
        {
            if (uiContext is null)
            {
                chatSendHandler = sendHandler;
                chatAgentUser = agentUser;
                return;
            }

            uiContext.Post(_ =>
            {
                chatSendHandler = sendHandler;
                chatAgentUser = agentUser;
                EnsureChatWindow();
                chatWindow?.SetAgentUserName(agentUser);
            }, null);
        }

    public static void PostChatMessage(string fromUser, string? role, string text, bool isServerMessage, string? timestamp = null)
    {
        if (uiContext is null)
        {
            return;
        }

        uiContext.Post(_ =>
        {
            EnsureChatWindow();
            chatWindow?.AddMessage(fromUser, role, text, isServerMessage, timestamp);
            chatWindow?.EnsureVisible();
        }, null);
    }

    private static void EnsureChatWindow()
    {
        if (chatWindow is not null)
        {
            return;
        }

        chatWindow = new ChatWindow();
        if (!string.IsNullOrWhiteSpace(chatAgentUser))
        {
            chatWindow.SetAgentUserName(chatAgentUser);
        }
        chatWindow.MessageSent += async (message) =>
        {
            if (chatSendHandler is null)
            {
                return;
            }

            try
            {
                await chatSendHandler(message);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Chat send failed: {ex.Message}");
            }
        };

        chatWindow.FormClosing += (sender, args) =>
        {
            args.Cancel = true;
            chatWindow?.Hide();
        };
    }

    public static Task<bool?> ShowConsentDialogAsync(string title, string message, CancellationToken cancellationToken)
    {
        if (uiContext is null)
        {
            return Task.FromResult<bool?>(null);
        }

        var tcs = new TaskCompletionSource<bool?>(TaskCreationOptions.RunContinuationsAsynchronously);
        uiContext.Post(_ =>
        {
            if (cancellationToken.IsCancellationRequested)
            {
                tcs.TrySetResult(null);
                return;
            }

            BringConsoleToFront();

            try
            {
                using var dialog = new ConsentDialog(title, message, 30);
                Console.WriteLine("Displaying consent dialog.");
                var result = dialog.ShowDialog();
                tcs.TrySetResult(result == DialogResult.Yes);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Consent dialog failed: {ex.Message}");
                tcs.TrySetResult(null);
            }
        }, null);

        return tcs.Task;
    }

    private static void BringConsoleToFront()
    {
        var consoleHandle = GetConsoleWindow();
        if (consoleHandle == IntPtr.Zero)
        {
            return;
        }

        ShowWindow(consoleHandle, SW_RESTORE);
        SetForegroundWindow(consoleHandle);
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr hIcon);

    private const int SW_RESTORE = 9;

    private sealed class TrayApplicationContext : ApplicationContext
    {
        private readonly NotifyIcon notifyIcon;
        private readonly Icon? icon;
        private readonly IntPtr iconHandle;

        public TrayApplicationContext()
        {
            (icon, iconHandle) = LoadIcon();
            notifyIcon = new NotifyIcon
            {
                Icon = icon ?? SystemIcons.Application,
                Text = "RMM Agent",
                Visible = true,
            };

            notifyIcon.ContextMenuStrip = BuildContextMenu();
            notifyIcon.DoubleClick += (_, _) => ShowConsoleWindow();

            notifyIcon.BalloonTipTitle = "RMM Agent";
            notifyIcon.BalloonTipText = "Agent is running in the system tray.";
            notifyIcon.ShowBalloonTip(1000);
        }

        public void RequestExit()
        {
            notifyIcon.Visible = false;
            ExitThread();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                notifyIcon.Dispose();
                icon?.Dispose();
                if (iconHandle != IntPtr.Zero)
                {
                    DestroyIcon(iconHandle);
                }
            }

            base.Dispose(disposing);
        }

        private ContextMenuStrip BuildContextMenu()
        {
            var menu = new ContextMenuStrip();
            var showItem = new ToolStripMenuItem("Show console");
            showItem.Click += (_, _) => ShowConsoleWindow();
            var exitItem = new ToolStripMenuItem("Exit agent");
            exitItem.Click += (_, _) => RequestExit();
            menu.Items.Add(showItem);
            menu.Items.Add(exitItem);
            return menu;
        }

        private static (Icon?, IntPtr) LoadIcon()
        {
            var assetDir = Path.Combine(AppContext.BaseDirectory, "assets");
            var icoPath = Path.Combine(assetDir, "rmm-icon.ico");
            if (File.Exists(icoPath))
            {
                var ico = new Icon(icoPath);
                return (ico, ico.Handle);
            }

            var pngPath = Path.Combine(assetDir, "rmm-icon.png");
            if (!File.Exists(pngPath))
            {
                return (SystemIcons.Application, IntPtr.Zero);
            }

            using var bitmap = new Bitmap(pngPath);
            var handle = bitmap.GetHicon();
            var icon = Icon.FromHandle(handle);
            return (icon, handle);
        }

        private static void ShowConsoleWindow()
        {
            var handle = GetConsoleWindow();
            if (handle == IntPtr.Zero)
            {
                return;
            }

            ShowWindow(handle, SW_RESTORE);
            SetForegroundWindow(handle);
        }
    }

    private sealed class ConsentDialog : Form
    {
        private readonly Label countdownLabel;
        private readonly System.Windows.Forms.Timer countdownTimer;
        private int remainingSeconds;

        public ConsentDialog(string title, string message, int timeoutSeconds)
        {
            remainingSeconds = Math.Max(1, timeoutSeconds);
            Text = title;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterScreen;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            AutoScaleMode = AutoScaleMode.None;
            ClientSize = new Size(380, 180);
            TopMost = true;

            var messageLabel = new Label
            {
                Text = message,
                Location = new Point(16, 16),
                Size = new Size(348, 60),
                AutoSize = false
            };
            Controls.Add(messageLabel);

            countdownLabel = new Label
            {
                Text = $"{remainingSeconds}s remaining",
                Location = new Point(16, 84),
                Size = new Size(348, 20),
                TextAlign = ContentAlignment.MiddleCenter
            };
            Controls.Add(countdownLabel);

            var yesButton = new Button
            {
                Text = "Yes",
                Size = new Size(120, 32),
                Location = new Point(70, 120),
                DialogResult = DialogResult.Yes
            };
            Controls.Add(yesButton);

            var noButton = new Button
            {
                Text = "No",
                Size = new Size(120, 32),
                Location = new Point(190, 120),
                DialogResult = DialogResult.No
            };
            Controls.Add(noButton);

            AcceptButton = yesButton;
            CancelButton = noButton;

            countdownTimer = new System.Windows.Forms.Timer { Interval = 1000 };
            countdownTimer.Tick += (_, _) => OnTick();
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            countdownTimer.Start();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            countdownTimer.Stop();
            base.OnFormClosing(e);
        }

        private void OnTick()
        {
            remainingSeconds--;
            if (remainingSeconds <= 0)
            {
                countdownTimer.Stop();
                DialogResult = DialogResult.No;
                Close();
                return;
            }

            countdownLabel.Text = $"{remainingSeconds}s remaining";
        }
    }

    private sealed class ChatWindow : Form
    {
        private readonly FlowLayoutPanel messagePanel;
        private readonly TextBox inputBox;
        private readonly Button sendButton;
        private readonly Panel inputPanel;
        private string agentUserName = "Agent";
        public event Func<string, Task>? MessageSent;

        public ChatWindow()
        {
            Text = "Agent Chat";
            FormBorderStyle = FormBorderStyle.SizableToolWindow;
            StartPosition = FormStartPosition.Manual;
            TopMost = true;
            ShowInTaskbar = false;
            Size = new Size(360, 260);

            var workingArea = Screen.PrimaryScreen?.WorkingArea ?? new Rectangle(0, 0, 1024, 768);
            Location = new Point(Math.Max(workingArea.Left, workingArea.Right - Width - 10), workingArea.Bottom - Height - 10);

            messagePanel = new FlowLayoutPanel
            {
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false,
                Dock = DockStyle.Fill,
                    AutoSize = false,
                    Margin = new Padding(8, 32, 8, 48),
                    Padding = new Padding(2),
                    AutoScroll = true
                };

            inputPanel = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 40,
                Padding = new Padding(4)
            };

            inputBox = new TextBox
            {
                Dock = DockStyle.Fill,
                Multiline = false
            };

            sendButton = new Button
            {
                Text = "Send",
                Dock = DockStyle.Right,
                Width = 80
            };
            sendButton.Click += OnSendClicked;

            inputPanel.Controls.Add(inputBox);
            inputPanel.Controls.Add(sendButton);

            Controls.Add(messagePanel);
            Controls.Add(inputPanel);
        }

        public void SetAgentUserName(string userName)
        {
            agentUserName = string.IsNullOrWhiteSpace(userName) ? "Agent" : userName;
        }

        public void AddMessage(string fromUser, string? role, string text, bool isServerMessage, string? timestamp = null)
        {
            var containerWidth = Math.Max(200, messagePanel.ClientSize.Width - 32);
            var messagePanelContainer = new FlowLayoutPanel
            {
                    FlowDirection = FlowDirection.TopDown,
                    WrapContents = false,
                    AutoSize = true,
                    AutoSizeMode = AutoSizeMode.GrowAndShrink,
                    Margin = new Padding(0, 4, 0, 4),
                    BackColor = isServerMessage ? Color.FromArgb(20, 51, 102) : Color.FromArgb(30, 30, 30),
                    Padding = new Padding(8),
                    MaximumSize = new Size(containerWidth, 0),
                    Width = containerWidth
                };

            var metaLabel = new Label
            {
                Text = string.IsNullOrWhiteSpace(role) ? fromUser : $"{fromUser} ({role})",
                ForeColor = Color.LightGray,
                AutoSize = true
            };

                var textLabel = new Label
                {
                    Text = text,
                    AutoSize = true,
                    MaximumSize = new Size(messagePanelContainer.MaximumSize.Width - 12, 0),
                    ForeColor = Color.White,
                    Margin = new Padding(0, 4, 0, 0)
                };

            var metaText = timestamp is not null ? $"{metaLabel.Text} • {timestamp}" : metaLabel.Text;
            metaLabel.Text = metaText;
            messagePanelContainer.Controls.Add(metaLabel);
            messagePanelContainer.Controls.Add(textLabel);
            messagePanel.Controls.Add(messagePanelContainer);
            messagePanel.ScrollControlIntoView(messagePanelContainer);
            messagePanel.Invalidate();
        }

        public void EnsureVisible()
        {
            if (!Visible)
            {
                Show();
            }

            if (WindowState == FormWindowState.Minimized)
            {
                WindowState = FormWindowState.Normal;
            }

            BringToFront();
        }

        private async void OnSendClicked(object? sender, EventArgs e)
        {
            var text = inputBox.Text.Trim();
            if (string.IsNullOrWhiteSpace(text))
            {
                return;
            }

            inputBox.Clear();
                AddMessage(agentUserName, null, text, false, DateTime.Now.ToShortTimeString());
            sendButton.Enabled = false;
            try
            {
                if (MessageSent is not null)
                {
                    await MessageSent.Invoke(text);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to send chat message: {ex.Message}");
            }
            finally
            {
                sendButton.Enabled = true;
            }
        }
    }
}
