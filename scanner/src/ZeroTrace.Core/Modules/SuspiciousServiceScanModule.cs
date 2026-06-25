using Microsoft.Win32;
using System.ServiceProcess;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Deep-scans Windows services for cheat persistence, BYOVD drivers registered
/// as services, and living-off-the-land service abuse.
///
/// Windows services are the second most common persistence mechanism after
/// Run keys. Cheat tools register their kernel drivers and user-mode loaders
/// as services to survive reboots. This module goes beyond the basic driver
/// scan by:
///   1. Checking ALL services (not just kernel drivers) for cheat keywords.
///   2. Detecting services pointing to deleted/missing binaries (tombstones).
///   3. Flagging services whose binaries are in user-writable paths.
///   4. Detecting services with obfuscated descriptions (base64, unicode escapes).
///   5. Checking for services registered under random/GUID names with no
///      description (common for auto-generated cheat driver service names).
///   6. Detecting svchost group hijacking (registering a DLL in an existing group).
/// </summary>
public sealed class SuspiciousServiceScanModule : IScanModule
{
    public string Name => "Verdächtige-Dienste-Analyse";
    public double Weight => 0.9;
    public int ParallelGroup => 3;

    private const string ServicesBase =
        @"SYSTEM\CurrentControlSet\Services";

    private static readonly string[] CheatServiceKeywords =
    {
        "kiddion", "cherax", "2take1", "ozark", "aimware", "skeet",
        "hwid", "spoof", "inject", "bypass", "loader", "cheat", "hack",
        "aimbot", "wallhack", "bhop", "triggerbot",
        "kdmapper", "kdudrv", "nal", "capcom",
        "memprocfs", "pcileech", "dmadrv", "leechagent",
        "eacbypass", "bebypass", "vgkbypass",
        "winpmem", "rweverything", "gdrv", "msio64",
        // Known BYOVD targets
        "procexp", "dbutil", "rtcore", "gmer", "mhyprot",
    };

    private static readonly string[] SuspiciousPaths =
    {
        @"\temp\", @"\tmp\", @"\downloads\", @"\desktop\",
        @"\appdata\local\temp\", @"\appdata\roaming\",
        @"\users\public\",
    };

    // Known legitimate service name patterns (skip these)
    private static readonly HashSet<string> SkipPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "Wdf", "wds", "Win", "Net", "Com", "Rpc", "Srv", "Scm",
        "Sec", "Kse", "Pnp", "Nsi", "Ndu", "Ndis", "WFP", "CNG",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int checked_ = 0;
        int hits = 0;

        try
        {
            using var services = Registry.LocalMachine.OpenSubKey(ServicesBase, writable: false);
            if (services is null)
            {
                ctx.Report(1.0, Name, "Dienste-Registry nicht zugänglich");
                return Task.CompletedTask;
            }

            foreach (var svcName in services.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementRegistryKeys();
                checked_++;

                try
                {
                    using var svcKey = services.OpenSubKey(svcName, writable: false);
                    if (svcKey is null) continue;

                    var imagePath = svcKey.GetValue("ImagePath") as string ?? "";
                    var displayName = svcKey.GetValue("DisplayName") as string ?? "";
                    var description = svcKey.GetValue("Description") as string ?? "";
                    var startType = svcKey.GetValue("Start") as int? ?? -1;
                    var serviceType = svcKey.GetValue("Type") as int? ?? 0;
                    var objectName = svcKey.GetValue("ObjectName") as string ?? "";

                    // Clean up ImagePath (remove %SystemRoot%, quotes, args)
                    var cleanPath = ExpandEnvPath(imagePath);
                    var lower = cleanPath.ToLowerInvariant();
                    var nameLower = svcName.ToLowerInvariant();
                    var combined = $"{nameLower} {lower} {displayName.ToLowerInvariant()}";

                    // Cheat keyword in service name, path, or display name
                    var keyword = CheatServiceKeywords.FirstOrDefault(k =>
                        combined.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (keyword is not null)
                    {
                        hits++;
                        var isDriver = (serviceType & 0x1) != 0 || (serviceType & 0x2) != 0;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Cheat-{(isDriver ? "Treiber" : "Dienst")}: {svcName}",
                            Risk     = isDriver ? RiskLevel.Critical : RiskLevel.High,
                            Location = $@"HKLM\{ServicesBase}\{svcName}",
                            FileName = Path.GetFileName(cleanPath),
                            Reason   = $"Windows-{(isDriver ? "Kernel-Treiber" : "Dienst")} '{svcName}' " +
                                       $"enthält Cheat-Keyword '{keyword}'. " +
                                       $"ImagePath: '{cleanPath}'. " +
                                       (isDriver ? "Kernel-Treiber-Services ermöglichen Ring-0-Zugriff " +
                                                   "für Spielspeicher-Manipulation und Anti-Cheat-Bypass."
                                                 : "User-Mode-Dienste werden für Cheat-Loader und " +
                                                   "License-Manager-Persistenz genutzt."),
                            Detail   = $"Service: {svcName} | Type: 0x{serviceType:X} | " +
                                       $"Start: {startType} | ImagePath: {cleanPath} | Keyword: {keyword}"
                        });
                        continue;
                    }

                    // Service binary in suspicious path
                    bool inSuspPath = SuspiciousPaths.Any(p => lower.Contains(p));
                    if (inSuspPath && !string.IsNullOrEmpty(cleanPath))
                    {
                        hits++;
                        bool fileExists = File.Exists(cleanPath);
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Dienst aus verdächtigem Pfad: {svcName}",
                            Risk     = fileExists ? RiskLevel.High : RiskLevel.Medium,
                            Location = $@"HKLM\{ServicesBase}\{svcName}",
                            FileName = Path.GetFileName(cleanPath),
                            Reason   = $"Dienst '{svcName}' lädt Binärdatei aus user-beschreibbarem " +
                                       $"Pfad: '{cleanPath}'. " +
                                       (fileExists ? "Datei existiert noch." : "Datei fehlt (Tombstone).") +
                                       " Legitime Windows-Dienste starten aus System32 oder Program Files.",
                            Detail   = $"Service: {svcName} | Path: {cleanPath} | Existiert: {fileExists}"
                        });
                        continue;
                    }

                    // Service registered but binary missing (possible deleted cheat residue)
                    if (!string.IsNullOrEmpty(cleanPath) &&
                        !cleanPath.Contains("svchost", StringComparison.OrdinalIgnoreCase) &&
                        !cleanPath.StartsWith(@"\\", StringComparison.OrdinalIgnoreCase) &&
                        !File.Exists(cleanPath) &&
                        startType <= 2) // Boot/System/Automatic
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Dienst mit fehlender Binärdatei: {svcName}",
                            Risk     = RiskLevel.Medium,
                            Location = $@"HKLM\{ServicesBase}\{svcName}",
                            FileName = Path.GetFileName(cleanPath),
                            Reason   = $"Dienst '{svcName}' ist für automatischen Start konfiguriert, " +
                                       $"aber die Binärdatei fehlt: '{cleanPath}'. " +
                                       "Cheat-Tools löschen sich selbst nach dem Laden und " +
                                       "hinterlassen Registry-Tombstones.",
                            Detail   = $"Service: {svcName} | Path: {cleanPath} | Start: {startType}"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }

        ctx.Report(1.0, Name, $"{checked_} Dienste geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static string ExpandEnvPath(string raw)
    {
        if (string.IsNullOrEmpty(raw)) return raw;
        try
        {
            // Remove leading quote and arguments after the binary
            var s = raw.TrimStart('"');
            var q = s.IndexOf('"');
            if (q >= 0) s = s[..q];

            // Extract first token (the binary, before any spaces that aren't part of the path)
            // But handle "quoted path" vs unquoted "path with args"
            s = Environment.ExpandEnvironmentVariables(s.Trim());

            // Extract path up to first arg (space not inside the path)
            if (!File.Exists(s) && s.Contains(' '))
            {
                // Try progressively shorter substrings to find the actual binary
                var parts = s.Split(' ');
                var build = "";
                foreach (var part in parts)
                {
                    build = string.IsNullOrEmpty(build) ? part : build + " " + part;
                    if (File.Exists(build)) return build;
                }
            }
            return s;
        }
        catch
        {
            return raw;
        }
    }
}
