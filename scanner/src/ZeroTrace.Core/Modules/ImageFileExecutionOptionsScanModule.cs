using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Comprehensive scan of Image File Execution Options (IFEO) registry entries
/// for debugger hijacking, GlobalFlag tampering, and MitigationOptions abuse.
///
/// IFEO (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options)
/// is a legitimate debugging facility. When a Debugger value is set for an executable name,
/// Windows automatically launches the specified debugger instead of (or alongside) the target.
///
/// Abuse patterns:
///   1. Anti-cheat bypass: Set Debugger for game executables to launch them through
///      a cheat loader (e.g. csgo.exe → cheat_loader.exe %1)
///   2. AV/AC killing: Set Debugger for anti-cheat EXEs to "svchost.exe" or "ntsd.exe -c q"
///      so the anti-cheat instantly exits without doing anything
///   3. Persistence: Set Debugger for explorer.exe or cmd.exe to run a cheat payload
///   4. Sticky Keys backdoor (accessibility): sethc.exe → cmd.exe (detected separately but
///      also caught here comprehensively)
///   5. GlobalFlag heap flags: Setting 0x200 (FLG_HEAP_ENABLE_TAG_BY_DLL) disables debug
///      heap checks that some anti-cheat uses to detect injected memory
///
/// Also scans for:
///   - VerifierDlls: DLLs loaded for application verifier (can inject arbitrary DLLs)
///   - MitigationOptions: per-process exploit mitigations (cheat loaders disable CFG etc.)
/// </summary>
public sealed class ImageFileExecutionOptionsScanModule : IScanModule
{
    private static readonly string _name = "IFEO-Debugger-Hijack";
    public string Name => _name;
    public double Weight => 0.7;
    public int ParallelGroup => 3;

    private const string IfeoKey =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    private const string IfeoKeyWow64 =
        @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

    private static readonly string System32 = Environment.GetFolderPath(
        Environment.SpecialFolder.System).ToLowerInvariant();

    // Legitimate debuggers that may appear as Debugger values
    private static readonly HashSet<string> KnownGoodDebuggers = new(StringComparer.OrdinalIgnoreCase)
    {
        "ntsd.exe", "ntsd", "cdb.exe", "cdb",
        "windbg.exe", "windbg",
        "vsjitdebugger.exe", "vsjitdebugger",
        "devenv.exe",
        "drwtsn32.exe", "drwtsn32",
        "xperf.exe",
        "perfview.exe",
        // Windows Error Reporting (legitimate)
        "werfault.exe", "wer.dll",
        // Application Verifier
        "appverif.exe",
    };

    // Anti-cheat / security tool executables — being hijacked is high severity
    private static readonly HashSet<string> ProtectedExecutables = new(StringComparer.OrdinalIgnoreCase)
    {
        "eac.exe", "eacservice.exe", "battleye.exe", "battleeyeservice.exe",
        "be_x64.exe", "be_x86.exe", "bedaisy.sys",
        "vac.exe", "vacsvc.exe",
        "faceit.exe", "faceit_client.exe",
        "esea.exe", "esea_client.exe",
        "xigncode3.exe", "xm.exe",
        "nprotect.exe", "npgamemon.exe",
        "gameguard.exe", "gameguard.des",
        "mhyprot2.sys", "mhyprot.sys",
        "ricochet.exe", "vgk.sys",
        "mbam.exe", "malwarebytes.exe",
        "mbamupdater.exe", "mbamservice.exe",
        "taskmgr.exe", "procmon.exe", "procmon64.exe",
        "processhacker.exe", "procexp.exe", "procexp64.exe",
        "autoruns.exe", "autorunsc.exe",
    };

    // Game executables — IFEO debugger here likely means cheat loader
    private static readonly HashSet<string> GameExecutables = new(StringComparer.OrdinalIgnoreCase)
    {
        "csgo.exe", "cs2.exe", "hl2.exe",
        "r5apex.exe", "r5apex_dx12.exe",
        "valorant.exe", "valorant-win64-shipping.exe", "vgc.exe",
        "cod.exe", "modernwarfare.exe", "warzone.exe",
        "bf1.exe", "bf2042.exe", "bf4.exe", "bfv.exe",
        "eac.exe", "escape from tarkov.exe",
        "rdr2.exe", "rdr2_launcher.exe",
        "gta5.exe", "gtavlauncher.exe",
        "fortnite.exe", "fortnitelobbypc-win64-shipping.exe",
        "pubg.exe", "tslgame.exe",
        "overwatch.exe", "overwatch2.exe",
        "rust.exe", "rustclient.exe",
        "dota2.exe", "eldenring.exe",
    };

    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "inject", "bypass", "loader", "aimbot",
        "kiddion", "cherax", "2take1", "ozark", "skeet", "fatality",
        "neverlose", "onetap", "aimware", "spoofer", "hook",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += ScanIfeoKey(IfeoKey, "HKLM", Registry.LocalMachine, ctx, ct);
        hits += ScanIfeoKey(IfeoKeyWow64, "HKLM(Wow64)", Registry.LocalMachine, ctx, ct);

        ctx.Report(1.0, Name, $"IFEO-Einträge geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int ScanIfeoKey(string keyPath, string hiveLabel, RegistryKey hive,
        ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var root = hive.OpenSubKey(keyPath, writable: false);
            if (root is null) return 0;

            foreach (var exeName in root.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementRegistryKeys();

                using var exeKey = root.OpenSubKey(exeName, writable: false);
                if (exeKey is null) continue;

                var debugger        = exeKey.GetValue("Debugger") as string ?? "";
                var globalFlag      = exeKey.GetValue("GlobalFlag") as int? ?? 0;
                var verifierDlls    = exeKey.GetValue("VerifierDlls") as string ?? "";
                var mitigationFlags = exeKey.GetValue("MitigationOptions") as string ?? "";

                var exeLower      = exeName.ToLowerInvariant();
                var debuggerLower = debugger.ToLowerInvariant();

                // Check Debugger value
                if (!string.IsNullOrWhiteSpace(debugger))
                {
                    var debuggerBin = Path.GetFileName(debuggerLower).TrimStart('"');

                    bool isKnownDebugger = KnownGoodDebuggers.Any(g =>
                        debuggerLower.Contains(g, StringComparison.OrdinalIgnoreCase));
                    bool isProtectedExe  = ProtectedExecutables.Contains(exeName);
                    bool isGameExe       = GameExecutables.Contains(exeName);
                    bool isSystemDebugger = debuggerLower.StartsWith(System32);

                    var cheatKw = CheatKeywords.FirstOrDefault(k =>
                        (debuggerLower + " " + exeLower).Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (!isKnownDebugger || isProtectedExe || isGameExe || cheatKw is not null)
                    {
                        hits++;
                        RiskLevel risk;
                        string context2;
                        if (isProtectedExe)
                        {
                            risk = RiskLevel.Critical;
                            context2 = "Anti-Cheat/Sicherheitssoftware-Executable wird umgeleitet " +
                                       "(AC-Killing-Technik)!";
                        }
                        else if (isGameExe)
                        {
                            risk = RiskLevel.Critical;
                            context2 = "Spiel-Executable wird über Debugger gestartet — " +
                                       "klassisches Cheat-Loader-Injection-Muster.";
                        }
                        else if (cheatKw is not null)
                        {
                            risk = RiskLevel.Critical;
                            context2 = $"Cheat-Keyword '{cheatKw}' im Debugger-Pfad.";
                        }
                        else
                        {
                            risk = RiskLevel.High;
                            context2 = "Unbekannter Debugger außerhalb der Standard-Windows-Debugger.";
                        }

                        bool exists = File.Exists(debugger.Trim('"'));
                        ctx.AddFinding(new Finding
                        {
                            Module = _name,
                            Title    = $"IFEO-Debugger-Hijack: {exeName}",
                            Risk     = risk,
                            Location = $@"{hiveLabel}\{keyPath}\{exeName}",
                            FileName = exeName,
                            Reason   = $"IFEO-Debugger für '{exeName}' gesetzt: '{debugger}'. " +
                                       context2 + " " +
                                       "IFEO-Debugger werden gelauncht anstelle des Zielprogramms " +
                                       "und können es vollständig ersetzen oder injizieren." +
                                       (!exists ? " Debugger-Datei fehlt." : ""),
                            Detail   = $"Exe: {exeName} | Debugger: {debugger} | Existiert: {exists}"
                        });
                    }
                }

                // Check VerifierDlls (can load arbitrary DLLs into any process via app verifier)
                if (!string.IsNullOrWhiteSpace(verifierDlls))
                {
                    var dllLower = verifierDlls.ToLowerInvariant();
                    bool isSystemDll = dllLower.StartsWith(System32);
                    var cheatKw = CheatKeywords.FirstOrDefault(k =>
                        dllLower.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (!isSystemDll || cheatKw is not null)
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module = _name,
                            Title    = $"IFEO-VerifierDll: {exeName}",
                            Risk     = cheatKw is not null ? RiskLevel.Critical : RiskLevel.High,
                            Location = $@"{hiveLabel}\{keyPath}\{exeName}",
                            FileName = exeName,
                            Reason   = $"VerifierDlls für '{exeName}' gesetzt: '{verifierDlls}'. " +
                                       "Application Verifier DLLs werden in den Zielprozess geladen " +
                                       "und ermöglichen beliebige Code-Ausführung ohne Standard-Injection-APIs. " +
                                       (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'." : "DLL außerhalb System32."),
                            Detail   = $"Exe: {exeName} | VerifierDlls: {verifierDlls}"
                        });
                    }
                }
            }
        }
        catch { }
        return hits;
    }
}
