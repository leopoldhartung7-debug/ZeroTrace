using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects advanced registry hijacking for DLL injection and persistence.
///
/// Beyond standard COM hijacking (covered by ComHijackScanModule), several
/// less-known registry extension points allow DLL loading without admin rights:
///
///   1. TypeLib registration: DLLs registered as COM type libraries
///      HKCU\SOFTWARE\Classes\TypeLib\{GUID}
///
///   2. Protocol handlers: DLLs that handle URI protocols (mycheattool://)
///      HKCU\SOFTWARE\Classes\{protocol}\shell\open\command
///
///   3. Shell extensions: Context menu, column handlers, namespace extensions
///      HKCU\SOFTWARE\Classes\*\shellex\
///      HKCU\SOFTWARE\Classes\Directory\shellex\
///
///   4. Internet Explorer/Edge extensions: BHOs (Browser Helper Objects)
///      HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\
///
///   5. Explorer extensions in HKCU:
///      HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved
///
///   6. Namespace extensions / Virtual Folders:
///      HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace
///
///   7. Column/Detail handlers registered per user:
///      HKCU\SOFTWARE\Classes\*\shellex\PropertySheetHandlers
///
///   8. Session Manager SubSystems (very rare, very critical):
///      HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems
/// </summary>
public sealed class RegistryHijackScanModule : IScanModule
{
    public string Name => "Registry-Hijack-Analyse";
    public double Weight => 0.7;
    public int ParallelGroup => 3;

    private static readonly string System32 = Environment.GetFolderPath(
        Environment.SpecialFolder.System).ToLowerInvariant();
    private static readonly string WinDir = Environment.GetFolderPath(
        Environment.SpecialFolder.Windows).ToLowerInvariant();

    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "inject", "bypass", "loader", "aimbot",
        "kiddion", "cherax", "2take1", "ozark", "skeet", "fatality",
        "neverlose", "onetap", "aimware", "spoofer", "hook",
        "gta5", "fivem", "tarkov", "apex", "valorant",
    };

    // Known good BHOs
    private static readonly HashSet<string> KnownGoodBhoGuids = new(StringComparer.OrdinalIgnoreCase)
    {
        "{72853161-30C5-4D22-B7F9-0BBC1D38A37E}", // Office
        "{8E5E2654-AD2D-48bf-AC2D-D17F00898D06}", // Acrobat PDF
        "{DBC80044-A445-435b-BC74-9C25C1C588A9}", // Java
        "{9030D464-4C02-4ABF-8ECC-5164760863C6}", // Microsoft Live
        "{18DF081C-E8AD-4283-A596-FA578C2EBDC3}", // Adobe Acrobat
        "{761497BB-D6F0-462C-B6EB-D4DAF1D92D43}", // Java QuickStarter
        "{E7E6F031-17CE-4C07-BC86-EABFE594F69C}", // Java
    };

    // Known legitimate shell extension GUIDs
    private static readonly HashSet<string> KnownGoodShellExtGuids = new(StringComparer.OrdinalIgnoreCase)
    {
        "{00021500-0000-0000-C000-000000000046}", // OLE2 Shell Extension
        "{0006F045-0000-0000-C000-000000000046}", // Outlook Msg Thumb
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckBrowserHelperObjects(ctx, ct);
        hits += CheckUserShellExtensions(ctx, ct);
        hits += CheckSessionManagerSubsystems(ctx, ct);
        hits += CheckProtocolHandlers(ctx, ct);
        hits += CheckDesktopNamespaceExtensions(ctx, ct);

        ctx.Report(1.0, Name, $"Registry-Hijack-Punkte geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckBrowserHelperObjects(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            var keys = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
            };

            foreach (var keyPath in keys)
            {
                if (ct.IsCancellationRequested) break;
                using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
                if (key is null) continue;
                ctx.IncrementRegistryKeys();

                foreach (var guidName in key.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) break;
                    ctx.IncrementRegistryKeys();

                    if (KnownGoodBhoGuids.Contains(guidName)) continue;

                    // Resolve CLSID to get DLL path
                    var dllPath = ResolveCLSIDDll(guidName);
                    var dllLower = dllPath?.ToLowerInvariant() ?? "";

                    bool isSystem = string.IsNullOrEmpty(dllPath) ||
                                    dllLower.StartsWith(System32) ||
                                    dllLower.StartsWith(WinDir);

                    var cheatKw = CheatKeywords.FirstOrDefault(k =>
                        (dllLower + " " + guidName.ToLowerInvariant()).Contains(k,
                            StringComparison.OrdinalIgnoreCase));

                    if (!isSystem || cheatKw is not null)
                    {
                        hits++;
                        bool exists = !string.IsNullOrEmpty(dllPath) && File.Exists(dllPath);
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Unbekanntes Browser-Helper-Objekt: {guidName}",
                            Risk     = cheatKw is not null ? RiskLevel.Critical : RiskLevel.High,
                            Location = $@"HKLM\{keyPath}\{guidName}",
                            FileName = dllPath is not null ? Path.GetFileName(dllPath) : guidName,
                            Reason   = $"Unbekanntes BHO (GUID: {guidName}) registriert. " +
                                       "BHOs werden in Internet Explorer und ältere Edge-Versionen geladen. " +
                                       "Sie können Webtraffic überwachen, Credentials abfangen und " +
                                       "beliebigen Code im Browser-Prozess ausführen. " +
                                       (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'. " : "") +
                                       (!isSystem ? "DLL außerhalb System32. " : "") +
                                       (!exists ? "DLL fehlt." : ""),
                            Detail   = $"GUID: {guidName} | DLL: {dllPath ?? "unbekannt"} | Existiert: {exists}"
                        });
                    }
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckUserShellExtensions(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
                writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            foreach (var guidName in key.GetValueNames())
            {
                if (ct.IsCancellationRequested) break;

                if (KnownGoodShellExtGuids.Contains(guidName)) continue;

                var desc = key.GetValue(guidName) as string ?? "";
                var dllPath = ResolveCLSIDDll(guidName);
                var dllLower = dllPath?.ToLowerInvariant() ?? "";

                bool isSystem = string.IsNullOrEmpty(dllPath) ||
                                dllLower.StartsWith(System32) ||
                                dllLower.StartsWith(WinDir);

                if (!isSystem)
                {
                    var cheatKw = CheatKeywords.FirstOrDefault(k =>
                        (dllLower + " " + desc.ToLowerInvariant()).Contains(k,
                            StringComparison.OrdinalIgnoreCase));

                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Benutzerdefinierte Shell-Erweiterung: {guidName}",
                        Risk     = cheatKw is not null ? RiskLevel.Critical : RiskLevel.High,
                        Location = $@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
                        FileName = dllPath is not null ? Path.GetFileName(dllPath) : guidName,
                        Reason   = $"Shell-Erweiterung '{desc}' (GUID: {guidName}) in HKCU registriert. " +
                                   "Shell-Erweiterungen werden von explorer.exe geladen. " +
                                   "HKCU-Registrierungen erfordern keine Administratorrechte. " +
                                   (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'. " : "") +
                                   "DLL außerhalb System-Verzeichnis.",
                        Detail   = $"GUID: {guidName} | Beschreibung: {desc} | DLL: {dllPath ?? "unbekannt"}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckSessionManagerSubsystems(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems",
                writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            foreach (var valueName in key.GetValueNames())
            {
                if (ct.IsCancellationRequested) break;

                // Known good subsystems
                if (valueName.Equals("Optional", StringComparison.OrdinalIgnoreCase) ||
                    valueName.Equals("Windows", StringComparison.OrdinalIgnoreCase) ||
                    valueName.Equals("Posix", StringComparison.OrdinalIgnoreCase) ||
                    valueName.Equals("Required", StringComparison.OrdinalIgnoreCase) ||
                    valueName.Equals("Kmode", StringComparison.OrdinalIgnoreCase) ||
                    valueName.Equals("Debug", StringComparison.OrdinalIgnoreCase))
                    continue;

                var value = key.GetValue(valueName) as string ?? "";
                var lower = value.ToLowerInvariant();
                bool isSystem = lower.StartsWith(System32) || lower.StartsWith(WinDir) ||
                                lower.StartsWith("%systemroot%");

                if (!isSystem)
                {
                    var cheatKw = CheatKeywords.FirstOrDefault(k =>
                        lower.Contains(k, StringComparison.OrdinalIgnoreCase));
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Unbekanntes Session-Manager-Subsystem: {valueName}",
                        Risk     = RiskLevel.Critical,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems",
                        Reason   = $"Unbekanntes SubSystem '{valueName}' = '{value}'. " +
                                   "Session-Manager-Subsysteme werden sehr früh im Boot-Prozess gestartet, " +
                                   "noch vor dem Windows-Subsystem (csrss.exe). " +
                                   "Dies ermöglicht Kernel-Level-Code-Ausführung mit minimaler Erkennung. " +
                                   (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'." : ""),
                        Detail   = $"Subsystem: {valueName} | Wert: {value}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckProtocolHandlers(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            foreach (var (hive, hiveName) in new[] {
                (Registry.CurrentUser, "HKCU"), (Registry.LocalMachine, "HKLM") })
            {
                if (ct.IsCancellationRequested) break;
                using var classesKey = hive.OpenSubKey(@"SOFTWARE\Classes", writable: false);
                if (classesKey is null) continue;

                foreach (var protoName in classesKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) break;

                    // Only check keys that have "URL Protocol" value (= URI handler)
                    using var protoKey = classesKey.OpenSubKey(protoName, writable: false);
                    if (protoKey is null) continue;

                    var urlProto = protoKey.GetValue("URL Protocol");
                    if (urlProto is null) continue;

                    // Get the open command
                    using var cmdKey = protoKey.OpenSubKey(@"shell\open\command", writable: false);
                    if (cmdKey is null) continue;
                    ctx.IncrementRegistryKeys();

                    var command = cmdKey.GetValue(null) as string ?? "";
                    if (string.IsNullOrWhiteSpace(command)) continue;

                    var lower = command.ToLowerInvariant();
                    var cheatKw = CheatKeywords.FirstOrDefault(k =>
                        (lower + " " + protoName.ToLowerInvariant()).Contains(k,
                            StringComparison.OrdinalIgnoreCase));
                    bool isSystem = lower.StartsWith(System32) || lower.StartsWith(WinDir) ||
                                    lower.StartsWith("%programfiles%");

                    if (cheatKw is not null || (!isSystem && hiveName == "HKCU"))
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Verdächtiger URI-Protocol-Handler: {protoName}",
                            Risk     = cheatKw is not null ? RiskLevel.High : RiskLevel.Medium,
                            Location = $@"{hiveName}\SOFTWARE\Classes\{protoName}\shell\open\command",
                            Reason   = $"URI-Protocol-Handler '{protoName}://' ist auf '{command}' gesetzt. " +
                                       "Benutzerdefinierte Protocol-Handler können Code ausführen, " +
                                       "wenn eine URL mit diesem Schema geöffnet wird. " +
                                       (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'." : "") +
                                       (!isSystem ? " Handler außerhalb System-Verzeichnis." : ""),
                            Detail   = $"Protokoll: {protoName} | Handler: {command} | Hive: {hiveName}"
                        });
                    }
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckDesktopNamespaceExtensions(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            var keys = new[]
            {
                (Registry.CurrentUser, "HKCU",
                 @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace"),
                (Registry.LocalMachine, "HKLM",
                 @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace"),
            };

            foreach (var (hive, hiveName, keyPath) in keys)
            {
                if (ct.IsCancellationRequested) break;
                using var key = hive.OpenSubKey(keyPath, writable: false);
                if (key is null) continue;
                ctx.IncrementRegistryKeys();

                foreach (var guidName in key.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) break;

                    var dllPath = ResolveCLSIDDll(guidName);
                    var dllLower = dllPath?.ToLowerInvariant() ?? "";
                    bool isSystem = string.IsNullOrEmpty(dllPath) ||
                                    dllLower.StartsWith(System32) || dllLower.StartsWith(WinDir);

                    var cheatKw = CheatKeywords.FirstOrDefault(k =>
                        dllLower.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (!isSystem || cheatKw is not null)
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Verdächtiger Desktop-Namespace: {guidName}",
                            Risk     = cheatKw is not null ? RiskLevel.Critical : RiskLevel.Medium,
                            Location = $@"{hiveName}\{keyPath}\{guidName}",
                            FileName = dllPath is not null ? Path.GetFileName(dllPath) : guidName,
                            Reason   = $"Desktop-Namespace-Erweiterung (GUID: {guidName}) in {hiveName} registriert. " +
                                       $"DLL: '{dllPath ?? "unbekannt"}'. " +
                                       "Namespace-Erweiterungen werden in explorer.exe geladen, " +
                                       "wenn der Desktop angezeigt wird. " +
                                       (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'." : "DLL außerhalb System32."),
                            Detail   = $"GUID: {guidName} | DLL: {dllPath ?? "unbekannt"} | Hive: {hiveName}"
                        });
                    }
                }
            }
        }
        catch { }
        return hits;
    }

    private static string? ResolveCLSIDDll(string guidName)
    {
        try
        {
            // Check HKLM first, then HKCU
            foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
            {
                using var key = hive.OpenSubKey(
                    $@"SOFTWARE\Classes\CLSID\{guidName}\InProcServer32", writable: false);
                var dll = key?.GetValue(null) as string;
                if (!string.IsNullOrEmpty(dll))
                    return Environment.ExpandEnvironmentVariables(dll);
            }
        }
        catch { }
        return null;
    }
}
