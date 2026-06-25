using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects ntdll.dll double-loading in game processes — a common technique to bypass
/// userland hooks placed by anti-cheat engines. The attacker maps a fresh copy of ntdll.dll
/// directly from disk (bypassing the Windows loader's shared section) so all exported NT
/// functions are clean originals without any hook patches. Also detects other critical system
/// DLLs (kernel32, kernelbase, win32u) loaded from non-system paths or appearing more than
/// once in the module list, which indicates DLL stomping or reflective loading.
/// </summary>
public sealed class NtdllDoubleLoadScanModule : IScanModule
{
    public string Name => "NTDLL Double-Load Detection";
    public double Weight => 0.85;
    public int ParallelGroup => 0;

    // Critical system DLLs that should appear exactly once and from system paths
    private static readonly string[] CriticalDlls =
    {
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "win32u.dll",
        "user32.dll",
        "advapi32.dll",
        "ntoskrnl.exe",
        "hal.dll",
    };

    private static readonly string[] ValidSystemPaths =
    {
        @"\windows\system32\",
        @"\windows\syswow64\",
        @"\windows\sysnative\",
        @"\windows\winsxs\",
    };

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll")]
    private static extern bool Module32First(nint hSnapshot, ref MODULEENTRY32 lpme);

    [DllImport("kernel32.dll")]
    private static extern bool Module32Next(nint hSnapshot, ref MODULEENTRY32 lpme);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        nint hProcess, nint lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    private struct MODULEENTRY32
    {
        public uint dwSize;
        public uint th32ModuleID;
        public uint th32ProcessID;
        public uint GlblcntUsage;
        public uint ProccntUsage;
        public nint modBaseAddr;
        public uint modBaseSize;
        public nint hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExePath;
    }

    private const uint TH32CS_SNAPMODULE     = 0x00000008;
    private const uint TH32CS_SNAPMODULE32   = 0x00000010;
    private const uint PROCESS_VM_READ       = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private static readonly nint InvalidHandle = new nint(-1);

    private static readonly string[] GameProcessNames =
    {
        "cs2", "csgo", "hl2", "game", "r5apex", "pubg", "rust", "fortnite",
        "valorant", "apex", "eft", "destiny", "warzone", "overwatch", "cod",
        "dota2", "tf2", "hll", "cheat", "loader", "injector", "client", "battleye",
        "easyanticheat", "faceit", "vgc"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var targets = GetTargetProcesses();
        if (targets.Count == 0) return;

        await Task.Run(() =>
        {
            foreach (var proc in targets)
            {
                ct.ThrowIfCancellationRequested();
                try { ScanProcess(proc, ctx, ct); }
                catch { /* skip unreadable */ }
                finally { proc.Dispose(); }
                ctx.IncrementProcesses();
            }
        }, ct);
    }

    private void ScanProcess(Process proc, ScanContext ctx, CancellationToken ct)
    {
        nint hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (uint)proc.Id);
        if (hSnap == InvalidHandle) return;

        // Track: DLL base name → list of (path, base address)
        var modulesByName = new Dictionary<string, List<(string Path, nint Base)>>(
            StringComparer.OrdinalIgnoreCase);

        try
        {
            var me = new MODULEENTRY32 { dwSize = (uint)Marshal.SizeOf<MODULEENTRY32>() };
            if (!Module32First(hSnap, ref me)) return;

            do
            {
                ct.ThrowIfCancellationRequested();
                string baseName = Path.GetFileName(me.szExePath).ToLowerInvariant();
                if (!modulesByName.TryGetValue(baseName, out var list))
                {
                    list = new List<(string, nint)>();
                    modulesByName[baseName] = list;
                }
                list.Add((me.szExePath, me.modBaseAddr));
            }
            while (Module32Next(hSnap, ref me));
        }
        finally { CloseHandle(hSnap); }

        // Check each critical DLL
        foreach (var dll in CriticalDlls)
        {
            if (!modulesByName.TryGetValue(dll, out var instances)) continue;

            // Check for double-loading
            if (instances.Count > 1)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "NTDLL Double-Load Detection",
                    Title = $"{dll} doppelt geladen in {proc.ProcessName} ({instances.Count}x)",
                    Risk = RiskLevel.Critical,
                    Location = $"Prozess {proc.ProcessName} (PID {proc.Id})",
                    Reason = $"Kritische System-DLL '{dll}' ist {instances.Count}x im Prozess vorhanden — " +
                             "Doppel-Load umgeht Anti-Cheat Hooks in der ersten Kopie",
                    Detail = $"Lade-Pfade: {string.Join(" | ", instances.Select(i => i.Path))}"
                });
            }

            // Check each instance for invalid path
            foreach (var (path, baseAddr) in instances)
            {
                string pathLower = path.ToLowerInvariant();
                bool validPath = Array.Exists(ValidSystemPaths, sp => pathLower.Contains(sp));
                if (!validPath)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "NTDLL Double-Load Detection",
                        Title = $"{dll} aus verdaechtigem Pfad in {proc.ProcessName}",
                        Risk = RiskLevel.Critical,
                        Location = path,
                        FileName = dll,
                        Reason = $"Kritische DLL '{dll}' geladen aus Nicht-System-Pfad — " +
                                 "moeglicher DLL-Hijack, Stomping oder reflektive Lade-Technik",
                        Detail = $"Pfad: {path} | Basisadresse: 0x{baseAddr:X} | " +
                                 "Erwartet: System32/SysWOW64/WinSxS"
                    });
                }
            }
        }

        // Detect: any module loaded from temp/download/appdata directories
        nint hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, proc.Id);
        bool hasHandle = hProc != nint.Zero;

        try
        {
            foreach (var (name, instances) in modulesByName)
            {
                foreach (var (path, baseAddr) in instances)
                {
                    ct.ThrowIfCancellationRequested();
                    string pathLower = path.ToLowerInvariant();

                    bool isSuspiciousPath =
                        pathLower.Contains(@"\temp\") ||
                        pathLower.Contains(@"\tmp\") ||
                        pathLower.Contains(@"\downloads\") ||
                        pathLower.Contains(@"\appdata\local\temp\");

                    if (!isSuspiciousPath) continue;

                    // Read first 2 bytes to verify it's a real PE
                    string headerNote = "";
                    if (hasHandle)
                    {
                        var peek = new byte[2];
                        if (ReadProcessMemory(hProc, baseAddr, peek, 2, out _))
                            headerNote = (peek[0] == 'M' && peek[1] == 'Z')
                                ? " [MZ-Header bestaetigt]" : " [Kein MZ-Header]";
                    }

                    ctx.AddFinding(new Finding
                    {
                        Module = "NTDLL Double-Load Detection",
                        Title = $"Modul aus Temp-Pfad geladen: {name}",
                        Risk = RiskLevel.High,
                        Location = path,
                        FileName = name,
                        Reason = $"Modul '{name}' in Prozess {proc.ProcessName} aus verdaechtigem Temp-Pfad geladen",
                        Detail = $"Pfad: {path}{headerNote} — Temp-Pfad DLLs deuten auf Dropper oder Injektion hin"
                    });
                }
            }
        }
        finally
        {
            if (hasHandle) CloseHandle(hProc);
        }
    }

    private static List<Process> GetTargetProcesses()
    {
        var result = new List<Process>();
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    string name = proc.ProcessName.ToLowerInvariant();
                    if (Array.Exists(GameProcessNames, n => name.Contains(n)))
                        result.Add(proc);
                    else
                        proc.Dispose();
                }
                catch { proc.Dispose(); }
            }
        }
        catch { }
        return result;
    }
}
