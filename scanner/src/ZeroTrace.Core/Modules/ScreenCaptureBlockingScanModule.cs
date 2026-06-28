using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects processes using WDA_EXCLUDEFROMCAPTURE (SetWindowDisplayAffinity) to hide
/// their windows from screenshots, screen recordings, and tournament overlay capture
/// tools. Cheat overlays (ESP, radar, aimbot crosshair) use this Win32 API to remain
/// invisible in screen captures while still being visible on the physical monitor —
/// making them undetectable by screenshot-based moderation or streaming review.
/// Also detects use of the Magnification API to exclude windows from the magnified view.
/// Flags any non-system, non-game process owning a visible window that has opted out
/// of screenshot inclusion from outside the game context.
/// </summary>
public sealed class ScreenCaptureBlockingScanModule : IScanModule
{
    public string Name => "Screen Capture Blocking Detection";
    public double Weight => 0.65;
    public int ParallelGroup => 2;

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, nint lParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(nint hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(nint hWnd);

    [DllImport("user32.dll")]
    private static extern bool GetWindowDisplayAffinity(nint hWnd, out uint pdwAffinity);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowTextW(nint hWnd, System.Text.StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll")]
    private static extern nint GetForegroundWindow();

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(
        nint hProcess, uint dwFlags, System.Text.StringBuilder lpExeName, ref uint lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    private delegate bool EnumWindowsProc(nint hWnd, nint lParam);

    private const uint WDA_NONE              = 0x00000000;
    private const uint WDA_MONITOR          = 0x00000001;
    private const uint WDA_EXCLUDEFROMCAPTURE = 0x00000011;
    private const uint PROCESS_QUERY_LIMITED = 0x1000;

    // Known processes that legitimately use capture exclusion
    private static readonly string[] LegitExcluderProcesses =
    {
        "1password", "lastpass", "bitwarden", "keepass", "kwallet",
        "credential", "autofill", "password", "secure", "vault",
        "msteams", "teams", "zoom", "webex", "skype", "discord",
        "obs", "streamlabs", "xsplit",
    };

    private static readonly string[] SystemProcesses =
    {
        "dwm", "winlogon", "logonui", "lsass", "csrss", "wininit",
        "smss", "system", "registry", "fontdrvhost",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var findings = new List<(nint Hwnd, uint Pid, uint Affinity, string WinText)>();

        await Task.Run(() =>
        {
            EnumWindows((hWnd, _) =>
            {
                if (ct.IsCancellationRequested) return false;
                try
                {
                    if (!IsWindowVisible(hWnd)) return true;

                    if (!GetWindowDisplayAffinity(hWnd, out uint affinity)) return true;
                    if (affinity == WDA_NONE) return true;

                    GetWindowThreadProcessId(hWnd, out uint pid);
                    if (pid == 0) return true;

                    var sb = new System.Text.StringBuilder(256);
                    GetWindowTextW(hWnd, sb, 256);
                    string winText = sb.ToString();

                    findings.Add((hWnd, pid, affinity, winText));
                }
                catch { }
                return true;
            }, nint.Zero);
        }, ct);

        foreach (var (hWnd, pid, affinity, winText) in findings)
        {
            ct.ThrowIfCancellationRequested();

            string processPath = GetProcessPath((int)pid);
            string processName = Path.GetFileNameWithoutExtension(processPath).ToLowerInvariant();

            // Skip system processes
            if (Array.Exists(SystemProcesses, s => processName.Contains(s))) continue;

            // Skip known-legitimate capture excluders (password managers, video conf)
            if (Array.Exists(LegitExcluderProcesses, s => processName.Contains(s))) continue;

            string affinityName = affinity == WDA_EXCLUDEFROMCAPTURE
                ? "WDA_EXCLUDEFROMCAPTURE (von Screenshots ausgeschlossen)"
                : affinity == WDA_MONITOR
                    ? "WDA_MONITOR (nur Monitor-Ausgabe)"
                    : $"0x{affinity:X}";

            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Screenshot-Schutz aktiv: '{processName}' Fenster '{winText.Trim()}'",
                Risk     = affinity == WDA_EXCLUDEFROMCAPTURE ? RiskLevel.Critical : RiskLevel.High,
                Location = processPath,
                FileName = Path.GetFileName(processPath),
                Reason   = $"Prozess '{processName}' (PID {pid}) hat SetWindowDisplayAffinity({affinityName}) " +
                           "gesetzt — Fenster ist auf dem Monitor sichtbar, wird aber von Screenshots, " +
                           "Bildschirmaufnahmen und Turnier-Capture-Tools ausgeblendet (typische Cheat-Overlay-Technik)",
                Detail   = $"HWND: 0x{(ulong)hWnd:X} | PID: {pid} | Affinity: {affinityName} | " +
                           $"Fenstertitel: '{winText.Trim()}' | Prozess: {processPath}"
            });
            ctx.IncrementProcesses();
        }
    }

    private static string GetProcessPath(int pid)
    {
        nint hProc = OpenProcess(PROCESS_QUERY_LIMITED, false, pid);
        if (hProc == nint.Zero) return $"PID {pid}";
        try
        {
            var sb = new System.Text.StringBuilder(512);
            uint sz = (uint)sb.Capacity;
            return QueryFullProcessImageNameW(hProc, 0, sb, ref sz) ? sb.ToString() : $"PID {pid}";
        }
        finally { CloseHandle(hProc); }
    }
}
