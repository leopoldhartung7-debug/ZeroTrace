using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects malicious services hosted inside svchost.exe via the SvcHost registry groups.
///
/// Many Windows services run as DLLs hosted inside svchost.exe rather than standalone
/// processes. svchost.exe reads groups of service names from:
///   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost
///
/// Each value name is a "group" (e.g. "netsvcs"), and each value is a multi-string
/// list of service names that run in a shared svchost.exe process for that group.
///
/// Cheat tools and malware abuse this for:
///   1. Persistence as a DLL service inside a trusted svchost.exe process
///   2. Evading process-based detection (svchost.exe is always trusted)
///   3. Running as SYSTEM without a standalone executable
///   4. Surviving process scanning (injected into a legitimate Windows host)
///
/// Also checks:
///   - Whether each registered service's DLL is in System32
///   - Whether the service description matches known cheat patterns
///   - Newly added groups not present in the standard Windows set
/// </summary>
public sealed class SvcHostGroupScanModule : IScanModule
{
    private static readonly string _name = "SvcHost-Gruppen-Analyse";
    public string Name => _name;
    public double Weight => 0.6;
    public int ParallelGroup => 3;

    private const string SvcHostKey =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost";
    private const string ServicesKey =
        @"SYSTEM\CurrentControlSet\Services";

    private static readonly string System32 = Environment.GetFolderPath(
        Environment.SpecialFolder.System).ToLowerInvariant();

    // Standard Windows svchost groups — any unknown group is suspicious
    private static readonly HashSet<string> KnownGoodGroups = new(StringComparer.OrdinalIgnoreCase)
    {
        "netsvcs", "LocalService", "LocalServiceNetworkRestricted", "LocalServiceNoNetwork",
        "LocalServiceNoNetworkFirewall", "LocalServicePeerNet",
        "NetworkService", "NetworkServiceNetworkRestricted",
        "DcomLaunch", "rpcss", "imgsvc",
        "termsvcs", "secsvcs",
        "RPCSS", "DCOM",
        "swprv", "GPSvcGroup",
        "HardwareDeviceInstallation", "RemoteRegistry",
        "wercplsupport", "iissvcs",
        "WbioSvcGroup", "SDRSVC",
        "utcsvc", "pla",
        "LocalSystemNetworkRestricted",
        "FontCache",
        "CoreMessagingRegistrar",
        "ClipboardSvcGroup", "PrintWorkflow",
        "UnistackSvcGroup", "BcastDVRUserService",
        "WepGroup",
    };

    // Known standard services that live in svchost
    private static readonly HashSet<string> KnownGoodServices = new(StringComparer.OrdinalIgnoreCase)
    {
        "wuauserv", "bits", "cryptsvc", "dnscache", "eventlog",
        "winmgmt", "spooler", "schedule", "lanmanserver", "lanmanworkstation",
        "rpcss", "dcomlaunch", "sysmain", "themes", "sens",
        "netman", "dhcp", "browser", "TermService",
        "w32tm", "wlansvc", "mpssvc", "bfe",
        "wscsvc", "nsi", "winrm", "wudf",
        "diagtrack", "dmwappushservice", "lfsvc",
        "lmhosts", "netprofm", "nlasvc", "nsiproxy",
        "p2pimsvc", "p2psvc", "peerhost", "pnrpsvc",
        "sessenv", "sharedaccess", "slsvc",
        "ssdpsrv", "stisvc", "tapisrv", "trkwks",
        "upnphost", "wcsvc", "wdiservicehost",
        "wecsvc", "winhttpautoproxysvc",
        "wlan", "wlansvc", "wudf",
    };

    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "inject", "bypass", "loader", "aimbot",
        "kiddion", "cherax", "2take1", "ozark", "skeet", "fatality",
        "neverlose", "onetap", "aimware", "spoofer", "hook", "persist",
        "gta", "fivem", "tarkov", "apex", "valorant",
        "driver", "rootkit", "byovd",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckSvcHostGroups(ctx, ct);

        ctx.Report(1.0, Name, $"SvcHost-Gruppen geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckSvcHostGroups(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(SvcHostKey, writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            foreach (var groupName in key.GetValueNames())
            {
                if (ct.IsCancellationRequested) break;

                var services = key.GetValue(groupName);
                string[] svcNames;

                if (services is string[] arr)
                    svcNames = arr;
                else if (services is string s)
                    svcNames = new[] { s };
                else
                    continue;

                bool isKnownGroup = KnownGoodGroups.Contains(groupName);

                foreach (var svcName in svcNames)
                {
                    if (ct.IsCancellationRequested) break;
                    if (string.IsNullOrWhiteSpace(svcName)) continue;

                    bool isKnownService = KnownGoodServices.Contains(svcName);
                    if (isKnownGroup && isKnownService) continue;

                    // Look up the service's DLL
                    var (dllPath, svcDescription) = GetServiceDll(svcName);
                    var combined = (svcName + " " + dllPath + " " + svcDescription +
                                    " " + groupName).ToLowerInvariant();

                    var cheatKw = CheatKeywords.FirstOrDefault(k =>
                        combined.Contains(k, StringComparison.OrdinalIgnoreCase));

                    bool dllIsSystem32 = dllPath.ToLowerInvariant().StartsWith(System32);
                    bool dllExists     = File.Exists(dllPath);

                    if (cheatKw is not null || (!isKnownGroup) || (!dllIsSystem32 && !string.IsNullOrEmpty(dllPath)))
                    {
                        hits++;
                        ctx.IncrementRegistryKeys();
                        ctx.AddFinding(new Finding
                        {
                            Module = _name,
                            Title    = $"Verdächtiger SvcHost-Dienst: {svcName} ({groupName})",
                            Risk     = cheatKw is not null ? RiskLevel.Critical :
                                       !isKnownGroup ? RiskLevel.High : RiskLevel.Medium,
                            Location = $@"HKLM\{SvcHostKey} → Gruppe: {groupName} → Dienst: {svcName}",
                            FileName = Path.GetFileName(dllPath),
                            Reason   = $"SvcHost-Dienst '{svcName}' in Gruppe '{groupName}' " +
                                       (!isKnownGroup ? "(UNBEKANNTE GRUPPE) " : "") +
                                       $"lädt DLL '{dllPath}'. " +
                                       "Dienste in svchost.exe laufen in vertrauenswürdigen Windows-Prozessen " +
                                       "und sind schwer zu erkennen. " +
                                       (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'. " : "") +
                                       (!dllIsSystem32 && !string.IsNullOrEmpty(dllPath) ? "DLL außerhalb System32. " : "") +
                                       (!dllExists && !string.IsNullOrEmpty(dllPath) ? "DLL fehlt." : ""),
                            Detail   = $"Dienst: {svcName} | Gruppe: {groupName} | DLL: {dllPath} | Keyword: {cheatKw ?? "keins"}"
                        });
                    }
                }
            }
        }
        catch { }
        return hits;
    }

    private static (string dllPath, string description) GetServiceDll(string serviceName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"{ServicesKey}\{serviceName}\Parameters", writable: false);
            if (key is null) goto fallback;

            var dll = key.GetValue("ServiceDll") as string ?? "";
            if (!string.IsNullOrEmpty(dll))
            {
                var desc = GetServiceDescription(serviceName);
                return (Environment.ExpandEnvironmentVariables(dll), desc);
            }
        }
        catch { }

        fallback:
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"{ServicesKey}\{serviceName}", writable: false);
            if (key is null) return ("", "");

            var dll = key.GetValue("ServiceDll") as string ?? "";
            var desc = key.GetValue("Description") as string ?? "";
            return (Environment.ExpandEnvironmentVariables(dll), desc);
        }
        catch { return ("", ""); }
    }

    private static string GetServiceDescription(string serviceName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"{ServicesKey}\{serviceName}", writable: false);
            return key?.GetValue("Description") as string ?? "";
        }
        catch { return ""; }
    }
}
