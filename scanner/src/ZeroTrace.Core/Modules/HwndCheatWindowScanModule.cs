using ZeroTrace.Core.Models;
using System.Runtime.InteropServices;
using System.Text;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Enumerates all windows and detects cheat tool windows hidden from the taskbar
/// but visible on screen, invisible overlay windows, and windows with cheat-keyword titles.
///
/// Cheat tools use several window concealment techniques:
///
///   1. SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE):
///      - Window is visible to the player but invisible in screenshots/OBS/game capture
///      - Used by ESP overlay windows — the cheat shows on physical monitor, invisible on stream
///      - Detectable: GetWindowDisplayAffinity() returns WDA_EXCLUDEFROMCAPTURE (0x11)
///
///   2. WS_EX_TOOLWINDOW (not shown in taskbar or Alt+Tab):
///      - Combined with WS_EX_TRANSPARENT and WS_EX_TOPMOST = invisible overlay pattern
///      - Cheat overlays use this to stay on top without appearing in task managers
///
///   3. Hidden windows with cheat-keyword class names:
///      - Cheat tools create invisible windows for IPC and message passing
///      - Window class names like "GamesenseWindow", "CheatBridge", "ESPOverlay"
///
///   4. Windows with cheat-keyword titles (even if hidden):
///      - Some cheat loaders leave a hidden window titled "Cheat Engine" or "Injector"
///      - Enumerable via EnumWindows even if ShowWindow(SW_HIDE) was called
///
/// Ocean and detect.ac enumerate all windows including hidden ones because:
///   - Cheat overlay windows leave HWND artifacts even after the visual overlay is dismissed
///   - Hidden message-only windows are used for cheat component IPC
///   - Window class name registration persists for the process lifetime
/// </summary>
public sealed class HwndCheatWindowScanModule : IScanModule
{
    public string Name => "Versteckte Cheat-Fenster und Overlay-Erkennung (HWND Scan)";
    public double Weight => 0.5;
    public int ParallelGroup => 2;

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool EnumChildWindows(IntPtr hWndParent, EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll")]
    private static extern long GetWindowLongPtr(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll")]
    private static extern bool GetWindowDisplayAffinity(IntPtr hWnd, out uint pdwAffinity);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    private const int GWL_EXSTYLE = -20;
    private const long WS_EX_TOOLWINDOW = 0x00000080L;
    private const long WS_EX_TOPMOST    = 0x00000008L;
    private const long WS_EX_TRANSPARENT = 0x00000020L;
    private const long WS_EX_LAYERED    = 0x00080000L;
    private const uint WDA_EXCLUDEFROMCAPTURE = 0x00000011;

    private static readonly string[] CheatWindowTitles =
    {
        "cheat", "hack", "aimbot", "esp", "wallhack", "injector", "loader",
        "gamesense", "onetap", "fatality", "aimware", "neverlose", "skeet",
        "2take1", "kiddion", "cherax", "ozark", "stand",
        "radar", "triggerbot", "bhop", "spinbot", "no_recoil",
        "cheat engine", "x64dbg", "windbg", "ida pro",
        "process hacker", "systeminformer",
        "trainer", "godmode", "fly hack", "speed hack",
    };

    private static readonly string[] CheatWindowClasses =
    {
        "gamesense", "cheat", "esp", "aimbot", "radar",
        "overlaywindow", "esp_overlay", "cheatbridge",
        "directx overlay", "transparent_window",
        "trainer_", "hack_", "inject_",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        var findings = new System.Collections.Concurrent.ConcurrentBag<Finding>();

        EnumWindows((hWnd, _) =>
        {
            ct.ThrowIfCancellationRequested();
            CheckWindow(hWnd, findings);
            return true;
        }, IntPtr.Zero);

        foreach (var f in findings)
            ctx.AddFinding(f);
    }

    private void CheckWindow(IntPtr hWnd, System.Collections.Concurrent.ConcurrentBag<Finding> findings)
    {
        try
        {
            var titleBuf = new StringBuilder(512);
            var classBuf = new StringBuilder(256);
            GetWindowText(hWnd, titleBuf, 512);
            GetClassName(hWnd, classBuf, 256);

            string title = titleBuf.ToString().ToLowerInvariant();
            string cls   = classBuf.ToString().ToLowerInvariant();
            bool isVisible = IsWindowVisible(hWnd);

            GetWindowThreadProcessId(hWnd, out uint pid);
            long exStyle = GetWindowLongPtr(hWnd, GWL_EXSTYLE);

            bool isToolWindow   = (exStyle & WS_EX_TOOLWINDOW) != 0;
            bool isTopmost      = (exStyle & WS_EX_TOPMOST) != 0;
            bool isTransparent  = (exStyle & WS_EX_TRANSPARENT) != 0;
            bool isLayered      = (exStyle & WS_EX_LAYERED) != 0;

            // Check 1: WDA_EXCLUDEFROMCAPTURE (hidden from screenshots)
            if (GetWindowDisplayAffinity(hWnd, out uint affinity) &&
                affinity == WDA_EXCLUDEFROMCAPTURE && isVisible)
            {
                findings.Add(new Finding
                {
                    Module   = Name,
                    Title    = $"Fenster mit WDA_EXCLUDEFROMCAPTURE (für Screenshots unsichtbar): '{titleBuf}'",
                    Risk     = RiskLevel.High,
                    Location = $"HWND 0x{hWnd:X} | PID {pid}",
                    FileName = cls,
                    Reason   = $"Fenster '{titleBuf}' (Klasse: {classBuf}, PID: {pid}) ist für Spieler " +
                               "sichtbar aber in Screenshots/OBS/Capture unsichtbar (WDA_EXCLUDEFROMCAPTURE). " +
                               "Cheat ESP-Overlays verwenden diesen API-Aufruf um das Overlay vor Turnier-" +
                               "Screenshot-Tools zu verstecken während es auf dem physischen Monitor sichtbar bleibt.",
                    Detail   = $"HWND: 0x{hWnd:X} | Titel: {titleBuf} | Klasse: {classBuf} | PID: {pid}"
                });
            }

            // Check 2: Invisible topmost transparent layered overlay window (overlay pattern)
            if (isTopmost && isLayered && isTransparent && !isToolWindow && !isVisible && pid != 0)
            {
                // This matches the classic ESP overlay window: invisible, topmost, transparent, layered
                findings.Add(new Finding
                {
                    Module   = Name,
                    Title    = $"Unsichtbares Topmost-Transparent-Fenster (ESP Overlay Pattern): PID {pid}",
                    Risk     = RiskLevel.High,
                    Location = $"HWND 0x{hWnd:X} | PID {pid}",
                    FileName = cls,
                    Reason   = $"Fenster mit Overlay-Attributen (Topmost+Layered+Transparent+Unsichtbar) " +
                               $"von PID {pid}. Dieses Muster entspricht einem ESP/Radar-Overlay-Fenster: " +
                               "unsichtbar für Benutzer aber zeichnet ESP-Boxen frame-synchron mit dem Spiel.",
                    Detail   = $"HWND: 0x{hWnd:X} | ExStyle: 0x{exStyle:X} | Klasse: {classBuf} | PID: {pid}"
                });
            }

            // Check 3: Cheat keyword in window title
            if (!string.IsNullOrEmpty(title))
            {
                string? titleMatch = CheatWindowTitles.FirstOrDefault(kw =>
                    title.Contains(kw, StringComparison.OrdinalIgnoreCase));
                if (titleMatch != null)
                {
                    findings.Add(new Finding
                    {
                        Module   = Name,
                        Title    = $"Cheat-Keyword in Fenstertitel: '{titleMatch}' — '{titleBuf}'",
                        Risk     = RiskLevel.High,
                        Location = $"HWND 0x{hWnd:X} | PID {pid}",
                        FileName = cls,
                        Reason   = $"Fenster mit Titel '{titleBuf}' (PID {pid}) enthält Cheat-Keyword '{titleMatch}'. " +
                                   "Cheat-Tools erstellen Fenster mit erkennbaren Titeln für Status-Anzeige " +
                                   "und IPC. Sichtbar: {isVisible}.",
                        Detail   = $"HWND: 0x{hWnd:X} | Titel: {titleBuf} | Sichtbar: {isVisible} | PID: {pid}"
                    });
                }
            }

            // Check 4: Cheat keyword in window class name
            if (!string.IsNullOrEmpty(cls))
            {
                string? classMatch = CheatWindowClasses.FirstOrDefault(kw =>
                    cls.Contains(kw, StringComparison.OrdinalIgnoreCase));
                if (classMatch != null)
                {
                    findings.Add(new Finding
                    {
                        Module   = Name,
                        Title    = $"Cheat-Keyword in Fensterklasse: '{classMatch}' ('{classBuf}')",
                        Risk     = RiskLevel.High,
                        Location = $"HWND 0x{hWnd:X} | PID {pid}",
                        FileName = cls,
                        Reason   = $"Fensterklasse '{classBuf}' (PID {pid}) enthält Cheat-Pattern '{classMatch}'. " +
                                   "Cheat-Overlays registrieren Fensterklassen mit erkennbaren Namen für " +
                                   "internen Komponentenzugriff. Auch versteckte Fenster sind durch " +
                                   "EnumWindows sichtbar.",
                        Detail   = $"HWND: 0x{hWnd:X} | Klasse: {classBuf} | Titel: {titleBuf} | PID: {pid}"
                    });
                }
            }
        }
        catch { }
    }
}
