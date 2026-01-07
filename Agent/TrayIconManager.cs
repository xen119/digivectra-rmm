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
            var path = Path.Combine(AppContext.BaseDirectory, "rmm-icon.png");
            if (!File.Exists(path))
            {
                return (SystemIcons.Application, IntPtr.Zero);
            }

            using var bitmap = new Bitmap(path);
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
}
