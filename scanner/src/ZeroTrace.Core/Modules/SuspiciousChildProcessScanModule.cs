using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Analyzes process trees to detect suspicious parent-child relationships: anti-cheat
/// processes spawning unexpected children (sign of AC compromise), game processes
/// spawning command interpreters or admin tools (sign of cheat hook executing OS commands),
/// and common LOLBIN (living-off-the-land binary) chains used by cheat loaders to
/// execute unsigned code under trusted process names.
/// </summary>
public sealed class SuspiciousChildProcessScanModule : IScanModule
{
    public string Name => "Suspicious Child Process Detection";
    public double Weight => 0.75;
    public int ParallelGroup => 2;

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        nint ProcessHandle, int ProcessInformationClass,
        out PROCESS_BASIC_INFORMATION ProcessInformation,
        int ProcessInformationLength, out int ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageNameW(nint hProcess, uint dwFlags,
        StringBuilder lpExeName, ref uint lpdwSize);

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public nint Reserved1;
        public nint PebBaseAddress;
        public nint Reserved2_0;
        public nint Reserved2_1;
        public nint UniqueProcessId;
        public nint InheritedFromUniqueProcessId;
    }

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_QUERY_LIMITED     = 0x1000;
    private const int  ProcessBasicInformation   = 0;
    private const int  STATUS_SUCCESS            = 0;

    // Processes whose children should always be examined
    private static readonly string[] AntiCheatProcesses =
    {
        "battleye", "beyondgame", "easyanticheat", "easyanticheat_eos",
        "faceit", "vgc", "vgk", "anticheatexpert", "xigncode",
        "hackshield", "ahnlab", "themida", "beservice",
    };

    // Game processes — should not spawn admin/debug tools
    private static readonly string[] GameProcesses =
    {
        "cs2", "csgo", "hl2", "game", "r5apex", "pubg", "rust", "fortnite",
        "valorant", "apex", "eft", "destiny", "warzone", "overwatch", "cod",
        "dota2", "tf2", "hll", "battlefront", "paladins", "rocketleague"
    };

    // Suspicious child process names (these should never be children of games/AC)
    private static readonly string[] SuspiciousChildren =
    {
        "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta",
        "certutil", "regsvr32", "rundll32", "msiexec", "wmic",
        "bitsadmin", "curl", "wget", "ftp", "net", "net1",
        "reg", "sc", "schtasks", "at", "eventvwr",
        "explorer", // game spawning Explorer is suspicious
        "taskkill", // game killing processes?
        "bcdedit",  // boot config modification
        "netsh",    // network config change
        "regedit",  // registry editor
        "msconfig", // system config
        "dism",     // deployment imaging
        "vssadmin", // shadow copy
    };

    // LOLBINs that can execute arbitrary code
    private static readonly string[] LolbinNames =
    {
        "mshta", "wscript", "cscript", "regsvr32", "rundll32", "certutil",
        "bitsadmin", "msiexec", "odbcconf", "ieexec", "infdefaultinstall",
        "cmstp", "xwizard", "syncappvpublishingserver", "appsyncpublishingserver",
        "msdeploy", "installutil", "msbuild", "regasm", "regsvcs",
        "aspnet_compiler", "ilasm", "jsc", "vbc", "csc",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // Build PID → (name, ppid, path) mapping for all processes
            var processMap = BuildProcessMap(ct);
            AnalyzeProcessTree(processMap, ctx, ct);
        }, ct);
    }

    private record ProcessInfo(int Pid, int PPid, string Name, string Path);

    private static Dictionary<int, ProcessInfo> BuildProcessMap(CancellationToken ct)
    {
        var map = new Dictionary<int, ProcessInfo>();
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    int ppid = GetParentPid(proc.Id);
                    string path = GetProcessPath(proc.Id);
                    map[proc.Id] = new ProcessInfo(proc.Id, ppid, proc.ProcessName, path);
                }
                catch { map[proc.Id] = new ProcessInfo(proc.Id, 0, proc.ProcessName, ""); }
                finally { proc.Dispose(); }
            }
        }
        catch { }
        return map;
    }

    private static void AnalyzeProcessTree(
        Dictionary<int, ProcessInfo> map, ScanContext ctx, CancellationToken ct)
    {
        foreach (var proc in map.Values)
        {
            ct.ThrowIfCancellationRequested();
            if (proc.PPid == 0) continue;
            if (!map.TryGetValue(proc.PPid, out var parent)) continue;

            string childName  = proc.Name.ToLowerInvariant();
            string parentName = parent.Name.ToLowerInvariant();

            bool parentIsAc   = AntiCheatProcesses.Any(ac => parentName.Contains(ac));
            bool parentIsGame = GameProcesses.Any(gp => parentName.Contains(gp));
            bool childIsSusp  = SuspiciousChildren.Any(s => childName == s || childName == s + ".exe");
            bool childIsLolbin= LolbinNames.Any(lb => childName == lb || childName == lb + ".exe");

            // Case 1: Anti-cheat spawned suspicious child
            if (parentIsAc && childIsSusp)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Suspicious Child Process Detection",
                    Title = $"Anti-Cheat '{parent.Name}' spawnte verdaechtigen Kindprozess: {proc.Name}",
                    Risk = RiskLevel.Critical,
                    Location = proc.Path,
                    FileName = proc.Name,
                    Reason = $"Anti-Cheat Prozess '{parent.Name}' (PID {proc.PPid}) spawnte " +
                             $"'{proc.Name}' (PID {proc.Pid}) — moegliche AC-Kompromittierung durch Injektion",
                    Detail = $"Parent: {parent.Path} | Child: {proc.Path} | " +
                             $"Verdaechtig: Kein normaler AC-Kind-Prozess erwartet"
                });
                ctx.IncrementProcesses();
            }

            // Case 2: Game process spawned command interpreter or admin tool
            if (parentIsGame && childIsSusp)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Suspicious Child Process Detection",
                    Title = $"Spielprozess '{parent.Name}' spawnte Befehlsinterpreter: {proc.Name}",
                    Risk = RiskLevel.High,
                    Location = proc.Path,
                    FileName = proc.Name,
                    Reason = $"Spiel '{parent.Name}' (PID {proc.PPid}) spawnte " +
                             $"'{proc.Name}' (PID {proc.Pid}) — Cheat-Hook fuehrt OS-Befehle aus",
                    Detail = $"Parent: {parent.Path} | Child: {proc.Path} | " +
                             "Cheat-DLLs koennen ueber CreateProcess Befehle im Kontext des Spiels ausfuehren"
                });
                ctx.IncrementProcesses();
            }

            // Case 3: LOLBIN chain — any process spawning a LOLBIN that is itself child of game/AC
            if (childIsLolbin && (parentIsGame || parentIsAc))
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Suspicious Child Process Detection",
                    Title = $"LOLBIN-Aufruf aus Spielkontext: {parent.Name} → {proc.Name}",
                    Risk = RiskLevel.Critical,
                    Location = proc.Path,
                    FileName = proc.Name,
                    Reason = $"Living-Off-the-Land Binary '{proc.Name}' spawnte von " +
                             $"'{parent.Name}' — bekannte Technik um beliebigen Code unter vertrautem Prozess-Kontext auszufuehren",
                    Detail = $"LOLBIN-Kette: {parent.Name} (PID {proc.PPid}) → " +
                             $"{proc.Name} (PID {proc.Pid}) | Pfad: {proc.Path}"
                });
            }

            // Case 4: Multiple suspicious processes sharing same parent (coordinated cheat launch)
            // This is checked implicitly by flagging each child individually

            // Case 5: Detect grandchild chains - LOLBIN that is grandchild of game/AC
            if (childIsLolbin && proc.PPid > 0 && map.TryGetValue(proc.PPid, out var grandparent))
            {
                string gpName = grandparent.Name.ToLowerInvariant();
                bool gpIsLolbin = LolbinNames.Any(lb => gpName == lb || gpName == lb + ".exe");
                bool gpParentIsGame = false;
                if (gpIsLolbin && map.TryGetValue(grandparent.PPid, out var ggp))
                    gpParentIsGame = GameProcesses.Any(gp => ggp.Name.ToLowerInvariant().Contains(gp));

                if (gpIsLolbin && gpParentIsGame)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "Suspicious Child Process Detection",
                        Title = $"LOLBIN-Kette (3-Ebenen): ...→{parent.Name}→{proc.Name}",
                        Risk = RiskLevel.Critical,
                        Location = proc.Path,
                        FileName = proc.Name,
                        Reason = $"3-Ebenen LOLBIN-Kette aus Spielkontext — komplexe Umgehungs-Technik fuer Code-Ausfuehrung",
                        Detail = $"Kette: Spiel → {parent.Name} (PID {proc.PPid}) → {proc.Name} (PID {proc.Pid})"
                    });
                }
            }
        }
    }

    private static int GetParentPid(int pid)
    {
        nint hProc = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
        if (hProc == nint.Zero) return 0;
        try
        {
            int status = NtQueryInformationProcess(hProc, ProcessBasicInformation,
                out var pbi, Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _);
            return status == STATUS_SUCCESS ? (int)pbi.InheritedFromUniqueProcessId : 0;
        }
        finally { CloseHandle(hProc); }
    }

    private static string GetProcessPath(int pid)
    {
        nint hProc = OpenProcess(PROCESS_QUERY_LIMITED, false, pid);
        if (hProc == nint.Zero) return "";
        try
        {
            var sb = new StringBuilder(512);
            uint sz = (uint)sb.Capacity;
            return QueryFullProcessImageNameW(hProc, 0, sb, ref sz) ? sb.ToString() : "";
        }
        finally { CloseHandle(hProc); }
    }
}
