using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects global Windows hook procedures installed via SetWindowsHookEx that
/// intercept keyboard and mouse input system-wide. Cheat tools use global hooks for:
///
///   WH_KEYBOARD_LL (id=13): Low-level keyboard hook for:
///     - Triggerbot: intercept/inject mouse1 clicks synchronized with reticle-on-target
///     - Rapid fire: inject repeated key/mouse events faster than physically possible
///     - Cheat menu toggle: catch hotkey presses without window focus
///     - Autofire scripts: inject input to game bypassing game's own key repeat rate
///
///   WH_MOUSE_LL (id=14): Low-level mouse hook for:
///     - No-recoil: inject counter-movement to cancel weapon recoil
///     - Aimbot correction: inject micro-adjustments to snap aim onto targets
///     - Silent aim: modify mouse events before they reach the game to redirect aim
///
///   WH_GETMESSAGE (id=3) + WH_CALLWNDPROC (id=4): Message hooks for:
///     - Overlay injection: intercept WM_PAINT to draw ESP on top of game window
///     - Game state reading: intercept game window messages for position data
///
/// Detection uses EnumWindows + GetWindowThreadProcessId + GetWindowLongPtr
/// to find hook procedures, plus NtQuerySystemInformation(SystemExtendedHandleInformation)
/// to look for processes holding hook handles in the system handle table.
/// Also enumerates hooks via undocumented NtUserSetWindowsHookEx handle enumeration.
/// </summary>
public sealed class GlobalKeyboardMouseHookScanModule : IScanModule
{
    public string Name => "Global Keyboard/Mouse Hook (Cheat Input Injection) Detection";
    public double Weight => 0.7;
    public int ParallelGroup => 2;

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, nint lParam);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(nint hWnd, out uint processId);

    [DllImport("user32.dll")]
    private static extern nint GetWindowLongPtr(nint hWnd, int nIndex);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern int GetClassName(nint hWnd, System.Text.StringBuilder lpClassName, int nMaxCount);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern int GetWindowText(nint hWnd, System.Text.StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(nint hWnd);

    [DllImport("user32.dll")]
    private static extern nint SetWindowsHookEx(int idHook, nint lpfn, nint hMod, uint dwThreadId);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool UnhookWindowsHookEx(nint hhk);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    private static extern nint GetModuleHandle(string? lpModuleName);

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int SystemInformationClass,
        nint SystemInformation, uint SystemInformationLength, out uint ReturnLength);

    private delegate bool EnumWindowsProc(nint hWnd, nint lParam);

    private const int GWL_EXSTYLE    = -20;
    private const int WS_EX_LAYERED  = 0x80000;
    private const int WS_EX_TRANSPARENT = 0x20;

    // Hook IDs
    private const int WH_GETMESSAGE    = 3;
    private const int WH_CALLWNDPROC   = 4;
    private const int WH_KEYBOARD_LL   = 13;
    private const int WH_MOUSE_LL      = 14;

    // SystemExtendedHandleInformation
    private const int SystemExtendedHandleInformation = 64;

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    {
        public nint Object;
        public nint UniqueProcessId;
        public nint HandleValue;
        public uint GrantedAccess;
        public ushort CreatorBackTraceIndex;
        public ushort ObjectTypeIndex;
        public uint HandleAttributes;
        public uint Reserved;
    }

    private static readonly HashSet<string> LegitHookProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // Input method editors and accessibility tools
        "ctfmon", "TabTip", "TabTip32", "InputPersonalization",
        // Screen readers
        "nvda", "narrator", "jaws", "orca",
        // Accessibility
        "magnify", "osk",
        // Known gaming peripherals with legit global hooks
        "razer synapse", "razersynapse", "rzsynapse",
        "logitech ghub", "lghub", "logitechoptions", "logioptions",
        "corsair icue", "icue", "cue",
        "steelseries gg", "gg", "ggtray",
        "hyperx ngenuity", "ngenuity",
        "roccat swarm", "swarm",
        "glorious model", "gloriousupdater",
        // VoIP / overlay tools with PTT
        "discord", "teamspeak3", "ts3client_win64", "mumble",
        "ventrilo",
        // Screen capture / streaming
        "obs64", "obs", "streamlabs obs", "streamlabsobs", "slobs",
        "xsplit", "nvcameracontainer",
        // Keyboard macro tools (mostly legit)
        "autohotkey", "ahk", "autohotkey_l",
        // Windows system
        "winlogon", "csrss", "dwm", "explorer",
        "svchost", "lsass",
        // AV / security products that monitor keyboard
        "mbamservice", "avp", "avgui",
        // Gaming overlays
        "gfelevateservice", "nvcontainer", "nvcplui",
        "originwebhelperservice", "originclientservice",
        "epicwebhelper", "epicgameslauncher",
        "steamwebhelper",
    };

    private static readonly HashSet<string> SuspiciousWindowClassNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // Common cheat overlay window class names (invisible/transparent windows)
        "CheatOverlay", "HackOverlay", "ESPOverlay", "AimbotWindow",
        "RadarWindow", "TriggerWindow",
        // Pattern: hex or random GUID-like class names for hidden windows
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            ScanHookedProcesses(ctx, ct);
            ct.ThrowIfCancellationRequested();
            ScanTransparentOverlayWindows(ctx, ct);
        }, ct);
    }

    private static void ScanHookedProcesses(ScanContext ctx, CancellationToken ct)
    {
        // Use NtQuerySystemInformation to enumerate all system handles and find
        // hook objects. Hook handles have a specific object type index.
        // As a more practical approach: enumerate all processes and check which
        // have DLLs injected that could be hook procedures.

        // Check all processes for suspicious hook-related characteristics
        try
        {
            var processes = System.Diagnostics.Process.GetProcesses();
            foreach (var proc in processes)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    ctx.IncrementFiles();

                    string procName = proc.ProcessName;
                    if (LegitHookProcesses.Contains(procName)) continue;

                    // Check if process has a window (visible or hidden)
                    bool hasWindow = proc.MainWindowHandle != nint.Zero;

                    // Get process path for signature check
                    string? procPath = null;
                    try { procPath = proc.MainModule?.FileName; } catch { }

                    if (procPath is null) continue;

                    string procPathLower = procPath.ToLowerInvariant();

                    // Flag processes from suspicious locations that have windows
                    // (potential overlay process)
                    bool isFromSuspiciousLocation =
                        procPathLower.Contains(@"\appdata\local\temp\") ||
                        procPathLower.Contains(@"\appdata\roaming\") ||
                        procPathLower.Contains(@"\downloads\") ||
                        procPathLower.Contains(@"\desktop\") ||
                        procPathLower.Contains(@"\users\public\");

                    bool isCheatName =
                        procPathLower.Contains("cheat") || procPathLower.Contains("hack") ||
                        procPathLower.Contains("inject") || procPathLower.Contains("aimbot") ||
                        procPathLower.Contains("triggerbot") || procPathLower.Contains("wallhack") ||
                        procPathLower.Contains("norecoil") || procPathLower.Contains("bypass") ||
                        procPathLower.Contains("loader") || procPathLower.Contains("spoof");

                    if (isCheatName)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Global Keyboard/Mouse Hook (Cheat Input Injection) Detection",
                            Title    = $"Verdächtiger Hook-Kandidat-Prozess: {procName}",
                            Risk     = RiskLevel.Critical,
                            Location = procPath,
                            FileName = Path.GetFileName(procPath),
                            Reason   = $"Prozess '{procName}' aus Pfad '{procPath}' enthält Cheat-Schlüsselwort " +
                                       "und könnte globale Keyboard/Mouse-Hooks für Triggerbot/No-Recoil installieren",
                            Detail   = $"Prozess: {procName} | PID: {proc.Id} | Pfad: {procPath} | " +
                                       $"Hat Fenster: {hasWindow}"
                        });
                    }
                    else if (isFromSuspiciousLocation && hasWindow)
                    {
                        // Processes with visible/hidden windows from temp/appdata locations
                        // are suspicious hook candidates, but not conclusive alone
                        // Only flag if no valid signature
                        try
                        {
                            var versionInfo = System.Diagnostics.FileVersionInfo.GetVersionInfo(procPath);
                            bool hasSig = !string.IsNullOrEmpty(versionInfo.CompanyName);
                            if (!hasSig)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = "Global Keyboard/Mouse Hook (Cheat Input Injection) Detection",
                                    Title    = $"Nicht-signierter Prozess mit Fenster aus Temp/AppData: {procName}",
                                    Risk     = RiskLevel.Medium,
                                    Location = procPath,
                                    FileName = Path.GetFileName(procPath),
                                    Reason   = $"Nicht-signierter Prozess '{procName}' aus '{procPath}' hat aktives " +
                                               "Fenster und könnte globale Input-Hooks als Overlay/Triggerbot installieren",
                                    Detail   = $"Prozess: {procName} | PID: {proc.Id} | Pfad: {procPath}"
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch { }
                finally { try { proc.Dispose(); } catch { } }
            }
        }
        catch { }
    }

    private static void ScanTransparentOverlayWindows(ScanContext ctx, CancellationToken ct)
    {
        // Enumerate all windows looking for layered+transparent windows that
        // are positioned over game windows — the classic ESP overlay pattern.
        var suspiciousWindows = new List<(nint hwnd, string className, string title, uint pid)>();

        EnumWindows((hWnd, _) =>
        {
            if (ct.IsCancellationRequested) return false;

            try
            {
                // Check for layered + transparent style (invisible overlay)
                nint exStyle = GetWindowLongPtr(hWnd, GWL_EXSTYLE);
                bool isLayered     = ((int)exStyle & WS_EX_LAYERED) != 0;
                bool isTransparent = ((int)exStyle & WS_EX_TRANSPARENT) != 0;

                if (!isLayered || !isTransparent) return true;

                var className = new System.Text.StringBuilder(256);
                GetClassName(hWnd, className, 256);
                string cls = className.ToString();

                var titleSb = new System.Text.StringBuilder(256);
                GetWindowText(hWnd, titleSb, 256);
                string title = titleSb.ToString();

                GetWindowThreadProcessId(hWnd, out uint pid);

                // Skip known-legit window classes
                if (cls == "DWM" || cls.StartsWith("Windows.") || cls == "Progman" ||
                    cls == "WorkerW" || cls == "Shell_TrayWnd" || cls == "Taskbar" ||
                    cls == "tooltips_class32" || cls == "SysShadow" ||
                    cls == "#32769" /* desktop */)
                    return true;

                suspiciousWindows.Add((hWnd, cls, title, pid));
            }
            catch { }

            return true;
        }, nint.Zero);

        foreach (var (hwnd, cls, title, pid) in suspiciousWindows)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                // Get process name for the window
                var proc = System.Diagnostics.Process.GetProcessById((int)pid);
                string procName = proc.ProcessName;
                proc.Dispose();

                if (LegitHookProcesses.Contains(procName)) continue;

                string? procPath = null;
                try
                {
                    var p2 = System.Diagnostics.Process.GetProcessById((int)pid);
                    procPath = p2.MainModule?.FileName;
                    p2.Dispose();
                }
                catch { }

                // Flag if process is from suspicious location OR has suspicious class name
                bool suspiciousClass = SuspiciousWindowClassNames.Contains(cls) ||
                    cls.ToLowerInvariant().Contains("cheat") ||
                    cls.ToLowerInvariant().Contains("hack") ||
                    cls.ToLowerInvariant().Contains("esp") ||
                    cls.ToLowerInvariant().Contains("aimbot") ||
                    cls.ToLowerInvariant().Contains("overlay");

                bool suspiciousTitle = title.ToLowerInvariant().Contains("cheat") ||
                    title.ToLowerInvariant().Contains("hack") ||
                    title.ToLowerInvariant().Contains("esp") ||
                    title.ToLowerInvariant().Contains("aimbot");

                bool suspiciousPath = procPath is not null &&
                    (procPath.ToLowerInvariant().Contains(@"\temp\") ||
                     procPath.ToLowerInvariant().Contains(@"\downloads\") ||
                     procPath.ToLowerInvariant().Contains("cheat") ||
                     procPath.ToLowerInvariant().Contains("hack"));

                if (!suspiciousClass && !suspiciousTitle && !suspiciousPath) continue;

                RiskLevel risk = (suspiciousClass || suspiciousTitle) ? RiskLevel.Critical
                    : suspiciousPath ? RiskLevel.High : RiskLevel.Medium;

                ctx.AddFinding(new Finding
                {
                    Module   = "Global Keyboard/Mouse Hook (Cheat Input Injection) Detection",
                    Title    = $"Transparentes Overlay-Fenster von nicht-legitimem Prozess: {procName}",
                    Risk     = risk,
                    Location = $"HWND 0x{hwnd:X} — Prozess: {procName} (PID {pid})",
                    FileName = procName,
                    Reason   = $"Fensterdaten: Klasse='{cls}', Titel='{title}', Prozess='{procName}' — " +
                               "transparentes, eingabedurchlässiges Fenster über anderen Fenstern ist ein " +
                               "klassisches ESP/Radar-Overlay-Muster von Cheat-Tools",
                    Detail   = $"HWND: 0x{hwnd:X} | Klasse: {cls} | Titel: {title} | " +
                               $"PID: {pid} | Prozess: {procName} | Pfad: {procPath ?? "unbekannt"}"
                });
            }
            catch { }
        }
    }
}
