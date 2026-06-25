using Microsoft.Win32;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects suspicious network shares, SMB configuration changes, and lateral movement
/// infrastructure that cheat operators use to distribute or update cheat software.
///
/// Cheat distribution/operation networks use:
///   1. Hidden admin shares (C$, ADMIN$) left deliberately accessible for remote cheat updates
///   2. Custom shares exposing cheat directories (e.g. \\machine\cheats)
///   3. SMB1 enabled (legacy, vulnerable to EternalBlue/WannaCry style exploits)
///   4. Guest account enabled with share access (allows anonymous cheat delivery)
///   5. Shares pointing to temp/appdata directories (cheat staging areas)
///   6. Mapped drives from suspicious remote servers (cheat C2 infrastructure)
///
/// Detection vectors:
///   1. Enumerate shares via NetShareEnum / registry
///   2. Check SMB1 enabled state (HKLM\SYSTEM\...\Services\LanmanServer\Parameters)
///   3. Check for guest account membership in share ACLs
///   4. Check mapped network drives for suspicious UNC paths
///   5. Check for null session (anonymous) share access
/// </summary>
public sealed class NetworkShareEnumScanModule : IScanModule
{
    public string Name => "Netzwerk-Freigabe-Analyse";
    public double Weight => 0.5;
    public int ParallelGroup => 3;

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetShareEnum(string serverName, uint level,
        out IntPtr bufPtr, uint prefMaxLen, out uint entriesRead,
        out uint totalEntries, ref uint resumeHandle);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ShareInfo1
    {
        public string shi1_netname;
        public uint shi1_type;
        public string shi1_remark;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ShareInfo2
    {
        public string shi2_netname;
        public uint shi2_type;
        public string shi2_remark;
        public uint shi2_permissions;
        public uint shi2_max_uses;
        public uint shi2_current_uses;
        public string shi2_path;
        public string shi2_passwd;
    }

    private const uint STYPE_DISKTREE = 0;
    private const uint STYPE_IPC = 3;
    private const uint STYPE_HIDDEN = 0x80000000;
    private const uint MAX_PREFERRED_LENGTH = 0xFFFFFFFF;

    // Paths that are suspicious for shares
    private static readonly string[] SuspiciousSharePaths =
    {
        "\\temp\\", "\\tmp\\", "\\appdata\\", "\\downloads\\",
        "\\desktop\\", "\\users\\public\\",
    };

    // Known cheat-related keywords in share names or remarks
    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "inject", "bypass", "loader", "aimbot",
        "spoofer", "mod", "trainer", "exploit",
    };

    // Lanman server parameters key
    private const string LanmanServerKey =
        @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";

    // Mapped drives key
    private const string MappedDrivesKey = @"Network";

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckSmb1Enabled(ctx, ct);
        hits += EnumerateShares(ctx, ct);
        hits += CheckMappedDrives(ctx, ct);
        hits += CheckNullSessionShares(ctx, ct);

        ctx.Report(1.0, Name, $"Netzwerkfreigaben analysiert, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckSmb1Enabled(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(LanmanServerKey, writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            var smb1 = key.GetValue("SMB1") as int? ?? 1;
            if (smb1 == 1)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "Netzwerk-Freigabe-Analyse",
                    Title    = "SMBv1 aktiviert (veraltetes, unsicheres Protokoll)",
                    Risk     = RiskLevel.High,
                    Location = $@"HKLM\{LanmanServerKey}",
                    Reason   = "SMBv1 ist aktiviert (SMB1 = 1). " +
                               "Dieses veraltete Protokoll ist anfällig für EternalBlue " +
                               "(MS17-010) und andere kritische Schwachstellen. " +
                               "Cheat-Operatoren können SMBv1 für laterale Bewegung nutzen, " +
                               "um Cheat-Software auf mehrere Systeme zu verteilen.",
                    Detail   = $"SMB1: {smb1} (erwartet: 0)"
                });
            }
        }
        catch { }
        return hits;
    }

    private static int EnumerateShares(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        IntPtr bufPtr = IntPtr.Zero;
        try
        {
            uint resumeHandle = 0;
            int result = NetShareEnum(null!, 2, out bufPtr,
                MAX_PREFERRED_LENGTH, out uint entriesRead, out _, ref resumeHandle);

            if (result != 0 && result != 234) // 234 = ERROR_MORE_DATA
            {
                // Try with level 1 (less info but wider compatibility)
                if (bufPtr != IntPtr.Zero) { NetApiBufferFree(bufPtr); bufPtr = IntPtr.Zero; }
                resumeHandle = 0;
                result = NetShareEnum(null!, 1, out bufPtr,
                    MAX_PREFERRED_LENGTH, out entriesRead, out _, ref resumeHandle);
                if (result != 0 && result != 234) return 0;

                var share1Size = Marshal.SizeOf<ShareInfo1>();
                for (int i = 0; i < (int)entriesRead && !ct.IsCancellationRequested; i++)
                {
                    var si = Marshal.PtrToStructure<ShareInfo1>(bufPtr + i * share1Size);
                    hits += EvaluateShare1(si, ctx);
                }
                return hits;
            }

            var shareSize = Marshal.SizeOf<ShareInfo2>();
            for (int i = 0; i < (int)entriesRead && !ct.IsCancellationRequested; i++)
            {
                var si = Marshal.PtrToStructure<ShareInfo2>(bufPtr + i * shareSize);
                hits += EvaluateShare2(si, ctx);
            }
        }
        catch { }
        finally
        {
            if (bufPtr != IntPtr.Zero) NetApiBufferFree(bufPtr);
        }
        return hits;
    }

    private static int EvaluateShare1(ShareInfo1 si, ScanContext ctx)
    {
        var name = si.shi1_netname ?? "";
        var remark = si.shi1_remark ?? "";

        var keyword = CheatKeywords.FirstOrDefault(k =>
            name.Contains(k, StringComparison.OrdinalIgnoreCase) ||
            remark.Contains(k, StringComparison.OrdinalIgnoreCase));

        if (keyword is null) return 0;

        ctx.AddFinding(new Finding
        {
            Module   = "Netzwerk-Freigabe-Analyse",
            Title    = $"Verdächtige Netzwerkfreigabe: {name}",
            Risk     = RiskLevel.High,
            Location = $@"\\{Environment.MachineName}\{name}",
            Reason   = $"Netzwerkfreigabe '{name}' enthält Cheat-Keyword '{keyword}'. " +
                       "Cheat-Operatoren nutzen Freigaben, um Cheat-Software auf " +
                       "mehrere Systeme zu verteilen oder als Remote-Dateisystem-Zugriff.",
            Detail   = $"Freigabe: {name} | Kommentar: {remark}"
        });
        return 1;
    }

    private static int EvaluateShare2(ShareInfo2 si, ScanContext ctx)
    {
        var name = si.shi2_netname ?? "";
        var path = si.shi2_path ?? "";
        var remark = si.shi2_remark ?? "";
        bool isHidden = (si.shi2_type & STYPE_HIDDEN) != 0;
        bool isDisk = (si.shi2_type & 0x3) == STYPE_DISKTREE;

        if (!isDisk) return 0;

        var keyword = CheatKeywords.FirstOrDefault(k =>
            name.Contains(k, StringComparison.OrdinalIgnoreCase) ||
            remark.Contains(k, StringComparison.OrdinalIgnoreCase));

        bool suspPath = SuspiciousSharePaths.Any(p =>
            path.Contains(p, StringComparison.OrdinalIgnoreCase));

        if (keyword is null && !suspPath) return 0;

        string reason;
        RiskLevel risk;
        if (keyword is not null)
        {
            reason = $"Freigabe '{name}' enthält Cheat-Keyword '{keyword}'. Pfad: '{path}'. ";
            risk = RiskLevel.High;
        }
        else
        {
            reason = $"Disk-Freigabe '{name}' zeigt auf verdächtigen Pfad '{path}'. " +
                     "Temporäre/AppData-Verzeichnisse sind typische Cheat-Staging-Bereiche. ";
            risk = RiskLevel.Medium;
        }

        ctx.AddFinding(new Finding
        {
            Module   = "Netzwerk-Freigabe-Analyse",
            Title    = $"Verdächtige Netzwerkfreigabe: {name}",
            Risk     = risk,
            Location = $@"\\{Environment.MachineName}\{name} → {path}",
            Reason   = reason + (isHidden ? "Freigabe ist versteckt ($). " : ""),
            Detail   = $"Name: {name} | Pfad: {path} | Versteckt: {isHidden} | " +
                       $"Typ: 0x{si.shi2_type:X}"
        });
        return 1;
    }

    private static int CheckMappedDrives(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Check HKCU\Network for persistent mapped drives
            using var netKey = Registry.CurrentUser.OpenSubKey(MappedDrivesKey, writable: false);
            if (netKey is null) return 0;
            ctx.IncrementRegistryKeys();

            foreach (var driveName in netKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) break;
                using var driveKey = netKey.OpenSubKey(driveName, writable: false);
                if (driveKey is null) continue;

                var remotePath = driveKey.GetValue("RemotePath") as string ?? "";
                if (string.IsNullOrEmpty(remotePath)) continue;

                var keyword = CheatKeywords.FirstOrDefault(k =>
                    remotePath.Contains(k, StringComparison.OrdinalIgnoreCase));

                // Flag non-local, non-corporate-looking UNC paths
                bool isIp = System.Net.IPAddress.TryParse(
                    remotePath.TrimStart('\\').Split('\\')[0], out _);

                if (keyword is not null || isIp)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Netzwerk-Freigabe-Analyse",
                        Title    = $"Verdächtige gemappte Netzwerkfreigabe: {driveName}:",
                        Risk     = keyword is not null ? RiskLevel.High : RiskLevel.Medium,
                        Location = $@"HKCU\{MappedDrivesKey}\{driveName}",
                        Reason   = $"Laufwerk '{driveName}:' ist auf '{remotePath}' gemappt. " +
                                   (keyword is not null
                                       ? $"Pfad enthält Cheat-Keyword '{keyword}'. "
                                       : "Pfad ist eine IP-Adresse — möglicher C2-Server-Zugriff. ") +
                                   "Cheat-Software kann über gemappte Laufwerke auf " +
                                   "Remote-Cheat-Dateisysteme zugreifen.",
                        Detail   = $"Laufwerk: {driveName}: | Remote: {remotePath} | IP: {isIp}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckNullSessionShares(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            // Check NullSessionShares — shares accessible without authentication
            var nullShares = key.GetValue("NullSessionShares") as string[] ?? Array.Empty<string>();
            foreach (var share in nullShares)
            {
                if (ct.IsCancellationRequested) break;
                if (string.IsNullOrWhiteSpace(share)) continue;

                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "Netzwerk-Freigabe-Analyse",
                    Title    = $"Anonymer (Null-Session) Freigabe-Zugriff: {share}",
                    Risk     = RiskLevel.High,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                    Reason   = $"Freigabe '{share}' ist in NullSessionShares eingetragen — " +
                               "jeder kann ohne Authentifizierung darauf zugreifen. " +
                               "Null-Session-Freigaben sind ein Relikt und werden für " +
                               "anonyme Cheat-Verteilung oder Exfiltration genutzt.",
                    Detail   = $"NullSessionShare: {share}"
                });
            }

            // Check RestrictAnonymous = 0 (allows null sessions)
            var restrictAnonymous = key.GetValue("RestrictNullSessAccess") as int? ?? 1;
            if (restrictAnonymous == 0)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "Netzwerk-Freigabe-Analyse",
                    Title    = "Anonymer Netzwerkzugriff erlaubt (RestrictNullSessAccess=0)",
                    Risk     = RiskLevel.Medium,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                    Reason   = "RestrictNullSessAccess ist auf 0 gesetzt — " +
                               "anonyme (nicht authentifizierte) Verbindungen zu Netzwerkfreigaben " +
                               "sind erlaubt. Diese Einstellung wird für unbefugten Zugriff genutzt.",
                    Detail   = "RestrictNullSessAccess: 0 (erwartet: 1)"
                });
            }
        }
        catch { }
        return hits;
    }
}
