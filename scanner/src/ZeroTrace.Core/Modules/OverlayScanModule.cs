using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Read-only detection of external ESP/overlay cheats: windows that are visible,
/// layered + click-through (transparent) + always-on-top, cover a large area, and
/// are owned by a process running from a user-writable location. Such windows draw
/// boxes/info over the game without injecting into it. This is a hint, not proof —
/// some legitimate tools also use overlays, so it is reported for review.
/// </summary>
public sealed class OverlayScanModule : IScanModule
{
    public string Name => "Overlay / ESP";
    public double Weight => 0.3;
    public int ParallelGroup => 2;

    private const int GWL_EXSTYLE = -20;
    private const long WS_EX_TRANSPARENT = 0x20;
    private const long WS_EX_TOPMOST = 0x8;
    private const long WS_EX_LAYERED = 0x80000;

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsProc cb, IntPtr p);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW")]
    private static extern IntPtr GetWindowLongPtr(IntPtr hWnd, int index);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("user32.dll")] private static extern bool GetWindowRect(IntPtr hWnd, out RECT r);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowTextW(IntPtr hWnd, StringBuilder s, int max);
    [DllImport("user32.dll")] private static extern int GetSystemMetrics(int index);

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int Left, Top, Right, Bottom; }

    private ScanContext _ctx = null!;
    private int _emitted;

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        _ctx = ctx;
        _emitted = 0;
        try { EnumWindows(OnWindow, IntPtr.Zero); } catch { }
        ctx.Report(1.0, "Overlay", "Overlay-/ESP-Fenster geprueft");
        return Task.CompletedTask;
    }

    private bool OnWindow(IntPtr hWnd, IntPtr _)
    {
        if (_emitted >= 12) return false;
        try
        {
            if (!IsWindowVisible(hWnd)) return true;
            long ex = GetWindowLongPtr(hWnd, GWL_EXSTYLE).ToInt64();
            bool overlayStyle = (ex & WS_EX_LAYERED) != 0 &&
                                (ex & WS_EX_TRANSPARENT) != 0 &&
                                (ex & WS_EX_TOPMOST) != 0;
            if (!overlayStyle) return true;

            if (!GetWindowRect(hWnd, out var r)) return true;
            int w = r.Right - r.Left, h = r.Bottom - r.Top;
            int screenW = GetSystemMetrics(0), screenH = GetSystemMetrics(1);
            if (screenW <= 0 || screenH <= 0) return true;
            // must cover a large portion of the screen to look like an ESP layer
            if (w < screenW * 0.5 || h < screenH * 0.5) return true;

            GetWindowThreadProcessId(hWnd, out uint pid);
            string proc = "?", path = "";
            try
            {
                using var p = Process.GetProcessById((int)pid);
                proc = p.ProcessName + ".exe";
                path = p.MainModule?.FileName ?? "";
            }
            catch { }

            // lower false positives: only flag if the owner runs from a user-writable path
            if (!IsUserWritable(path)) return true;

            var sb = new StringBuilder(256);
            GetWindowTextW(hWnd, sb, sb.Capacity);
            var title = sb.ToString();

            _emitted++;
            _ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Moegliches ESP-/Overlay-Fenster (Hinweis)",
                Risk = RiskLevel.Medium,
                Recommendation = Recommendation.Review,
                Location = string.IsNullOrEmpty(path) ? proc : path,
                FileName = proc,
                Reason = $"Ein bildschirmfuellendes, klick-durchlaessiges Always-on-Top-Fenster gehoert zu " +
                         $"'{proc}' aus einem benutzer-schreibbaren Pfad. Das ist typisch fuer externe ESP-" +
                         "Overlays, kann aber auch ein legitimes Tool sein – bitte pruefen.",
                Detail = $"Fenster: '{title}' · {w}x{h}"
            });
        }
        catch { }
        return true;
    }

    private static bool IsUserWritable(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var p = path.ToLowerInvariant();
        if (p.Contains(@"\windows\")) return false;
        if (p.Contains(@"\program files")) return false;
        return p.Contains(@"\users\") || p.Contains(@"\temp\") ||
               p.Contains(@"\appdata\") || p.Contains(@"\downloads\");
    }
}
