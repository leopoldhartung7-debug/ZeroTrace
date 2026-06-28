using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects external ESP/radar overlay windows: cheat overlays render on a transparent
/// topmost window layered over the game window. This module enumerates all desktop windows,
/// identifies those with WS_EX_LAYERED + WS_EX_TOPMOST + WS_EX_TRANSPARENT style
/// combinations from processes other than the foreground game, and cross-references their
/// owning process against known cheat/overlay tool names and suspicious paths.
/// Also detects DX hook overlay DLLs (ReShade, d3d11.dll proxies, dxgi.dll proxies)
/// loaded in game processes from non-game paths.
/// </summary>
public sealed class ExternalOverlayDetectionScanModule : IScanModule
{
    public string Name => "External Overlay Detection";
    public double Weight => 0.75;
    public int ParallelGroup => 2;

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, nint lParam);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(nint hWnd);

    [DllImport("user32.dll")]
    private static extern uint GetWindowLong(nint hWnd, int nIndex);

    [DllImport("user32.dll")]
    private static extern uint GetWindowLongPtr(nint hWnd, int nIndex);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(nint hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(nint hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(nint hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("user32.dll")]
    private static extern bool GetWindowRect(nint hWnd, out RECT lpRect);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageNameW(nint hProcess, uint dwFlags,
        StringBuilder lpExeName, ref uint lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll")]
    private static extern bool Module32First(nint hSnapshot, ref MODULEENTRY32 lpme);

    [DllImport("kernel32.dll")]
    private static extern bool Module32Next(nint hSnapshot, ref MODULEENTRY32 lpme);

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int Left, Top, Right, Bottom; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    private struct MODULEENTRY32
    {
        public uint dwSize;
        public uint th32ModuleID, th32ProcessID, GlblcntUsage, ProccntUsage;
        public nint modBaseAddr;
        public uint modBaseSize;
        public nint hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExePath;
    }

    private delegate bool EnumWindowsProc(nint hWnd, nint lParam);

    private const int GWL_EXSTYLE              = -20;
    private const uint WS_EX_LAYERED           = 0x00080000;
    private const uint WS_EX_TRANSPARENT       = 0x00000020;
    private const uint WS_EX_TOPMOST           = 0x00000008;
    private const uint WS_EX_NOACTIVATE        = 0x08000000;
    private const uint PROCESS_QUERY_LIMITED   = 0x1000;
    private const uint TH32CS_SNAPMODULE       = 0x00000008;
    private const uint TH32CS_SNAPMODULE32     = 0x00000010;
    private static readonly nint InvalidHandle = new nint(-1);

    // DLL names associated with D3D hook overlays loaded inside game processes
    private static readonly string[] OverlayHookDlls =
    {
        "reshade", "openxr", "d3d11_hook", "d3d12_hook", "dxgi_hook",
        "overlay", "esp_", "wallhack", "aimbot_", "cheat_",
        "skeet", "aimware", "fatality", "neverlose", "gamesense", "2take1",
        "kiddion", "cherax", "menyoo", "scripthookv",
        "steamoverlay", // Steam overlay is legit — but custom ones are not
        "nvapioverlay", "rtsshooks",
    };

    // Window class names used by known cheat overlays
    private static readonly string[] CheatWindowClasses =
    {
        "ESP_WINDOW", "CHEAT_OVERLAY", "RADAR_WINDOW", "AIM_OVERLAY",
        "WALLHACK_OVERLAY", "DirectX Window", "SDL_app", // SDL sometimes used by overlays
    };

    // Process names that are legitimate overlay producers (to reduce FP)
    private static readonly string[] LegitOverlayProcesses =
    {
        "steamwebhelper", "gameoverlayui", "steam", "discord", "nvidia", "rtss",
        "afterburner", "geforce", "riva", "fraps", "obs", "xsplit", "msi afterburner",
        "rivatuner", "bandicam", "playclaw", "action", "dxtory",
    };

    private static readonly string[] GameProcessNames =
    {
        "cs2", "csgo", "hl2", "game", "r5apex", "pubg", "rust", "fortnite",
        "valorant", "apex", "eft", "destiny", "warzone", "overwatch", "cod",
        "dota2", "tf2", "hll", "battlefront", "paladins", "rocketleague"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // Step 1: Check for suspicious overlay windows
            CheckOverlayWindows(ctx, ct);

            // Step 2: Check for D3D hook DLLs in game processes
            CheckGameProcessOverlayDlls(ctx, ct);
        }, ct);
    }

    private void CheckOverlayWindows(ScanContext ctx, CancellationToken ct)
    {
        var gameProcessIds = GetGameProcessIds();
        if (gameProcessIds.Count == 0) return;

        var suspiciousWindows = new List<(nint hWnd, string Title, string Class, uint Pid, string ProcPath)>();

        EnumWindows((hWnd, _) =>
        {
            ct.ThrowIfCancellationRequested();
            if (!IsWindowVisible(hWnd)) return true;

            uint exStyle = IntPtr.Size == 8
                ? GetWindowLongPtr(hWnd, GWL_EXSTYLE)
                : GetWindowLong(hWnd, GWL_EXSTYLE);

            // Overlay signature: LAYERED + TOPMOST + (TRANSPARENT or NOACTIVATE)
            bool isLayered   = (exStyle & WS_EX_LAYERED) != 0;
            bool isTopmost   = (exStyle & WS_EX_TOPMOST) != 0;
            bool isTransp    = (exStyle & WS_EX_TRANSPARENT) != 0;
            bool isNoActivate= (exStyle & WS_EX_NOACTIVATE) != 0;

            if (!isLayered || !isTopmost) return true;
            if (!isTransp && !isNoActivate) return true;

            GetWindowThreadProcessId(hWnd, out uint pid);

            // Skip if this is a game process itself
            if (gameProcessIds.Contains((int)pid)) return true;

            // Skip zero-size windows (invisible placeholders)
            if (GetWindowRect(hWnd, out var rc) &&
                rc.Right - rc.Left == 0 && rc.Bottom - rc.Top == 0) return true;

            string procPath = GetProcessPath((int)pid);
            string procName = Path.GetFileNameWithoutExtension(procPath).ToLowerInvariant();

            // Skip known legitimate overlay producers
            if (Array.Exists(LegitOverlayProcesses, lp => procName.Contains(lp))) return true;

            var title = new StringBuilder(256);
            GetWindowText(hWnd, title, title.Capacity);
            var cls = new StringBuilder(256);
            GetClassName(hWnd, cls, cls.Capacity);

            suspiciousWindows.Add((hWnd, title.ToString(), cls.ToString(), pid, procPath));
            return true;
        }, nint.Zero);

        foreach (var (hWnd, title, cls, pid, path) in suspiciousWindows)
        {
            string procName = Path.GetFileNameWithoutExtension(path);
            bool knownCheatClass = CheatWindowClasses.Any(c =>
                cls.Contains(c, StringComparison.OrdinalIgnoreCase));
            bool cheatTitle = IsCheatKeyword(title) || IsCheatKeyword(procName);

            RiskLevel risk = (knownCheatClass || cheatTitle) ? RiskLevel.Critical : RiskLevel.High;

            ctx.AddFinding(new Finding
            {
                Module = "External Overlay Detection",
                Title = $"Verdaechtiges Overlay-Fenster von Prozess {procName}",
                Risk = risk,
                Location = $"Fenster '{title}' (Klasse: {cls}) von PID {pid}",
                FileName = Path.GetFileName(path),
                Reason = $"Transparentes Topmost-Fenster (WS_EX_LAYERED+TOPMOST) von Nicht-Spiel-Prozess '{procName}' — " +
                         "typisches Muster fuer ESP/Radar-Overlays ueber dem Spielfenster",
                Detail = $"Prozess: {path} | Fensterklasse: {cls} | Titel: {title} | PID: {pid}"
            });
            ctx.IncrementProcesses();
        }
    }

    private void CheckGameProcessOverlayDlls(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    string name = proc.ProcessName.ToLowerInvariant();
                    bool isGame = Array.Exists(GameProcessNames, n => name.Contains(n));
                    if (!isGame) { proc.Dispose(); continue; }

                    nint hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (uint)proc.Id);
                    if (hSnap != InvalidHandle)
                    {
                        try
                        {
                            var me = new MODULEENTRY32 { dwSize = (uint)Marshal.SizeOf<MODULEENTRY32>() };
                            if (Module32First(hSnap, ref me))
                            {
                                do
                                {
                                    ct.ThrowIfCancellationRequested();
                                    string modName = me.szModule.ToLowerInvariant();
                                    string modPath = me.szExePath.ToLowerInvariant();

                                    bool isHookDll = OverlayHookDlls.Any(h =>
                                        modName.Contains(h, StringComparison.OrdinalIgnoreCase));

                                    if (isHookDll && !modPath.Contains(@"\steam\") &&
                                        !modPath.Contains(@"\nvidia\") && !modPath.Contains(@"\amd\"))
                                    {
                                        ctx.AddFinding(new Finding
                                        {
                                            Module = "External Overlay Detection",
                                            Title = $"Overlay-Hook DLL in Spielprozess: {me.szModule}",
                                            Risk = RiskLevel.High,
                                            Location = me.szExePath,
                                            FileName = me.szModule,
                                            Reason = $"DLL '{me.szModule}' mit Overlay-Hook-Muster in Spielprozess '{proc.ProcessName}' gefunden",
                                            Detail = $"Pfad: {me.szExePath} | DX-Hook-DLLs koennen Present/Reset-Hooks fuer ESP setzen"
                                        });
                                    }
                                }
                                while (Module32Next(hSnap, ref me));
                            }
                        }
                        finally { CloseHandle(hSnap); }
                    }
                }
                catch { }
                finally { proc.Dispose(); }
                ctx.IncrementProcesses();
            }
        }
        catch { }
    }

    private static bool IsCheatKeyword(string s)
    {
        if (string.IsNullOrEmpty(s)) return false;
        var sl = s.ToLowerInvariant();
        return sl.Contains("esp") || sl.Contains("aimbot") || sl.Contains("wallhack") ||
               sl.Contains("radar") || sl.Contains("cheat") || sl.Contains("hack") ||
               sl.Contains("triggerbot") || sl.Contains("overlay_cheat") ||
               sl.Contains("norecoil") || sl.Contains("bhop");
    }

    private static HashSet<int> GetGameProcessIds()
    {
        var ids = new HashSet<int>();
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    string name = proc.ProcessName.ToLowerInvariant();
                    if (Array.Exists(GameProcessNames, n => name.Contains(n)))
                        ids.Add(proc.Id);
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
        return ids;
    }

    private static string GetProcessPath(int pid)
    {
        nint hProc = OpenProcess(PROCESS_QUERY_LIMITED, false, pid);
        if (hProc == nint.Zero) return $"PID {pid}";
        try
        {
            var sb = new StringBuilder(512);
            uint sz = (uint)sb.Capacity;
            return QueryFullProcessImageNameW(hProc, 0, sb, ref sz)
                ? sb.ToString()
                : $"PID {pid}";
        }
        finally { CloseHandle(hProc); }
    }
}
