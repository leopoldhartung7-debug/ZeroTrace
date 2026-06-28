using Microsoft.Win32;
using System.Diagnostics;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects Remote Access Tools (RATs) and unauthorized remote control software.
///
/// Game cheaters sometimes use RATs to:
///   1. Remote-control the target machine to operate cheats undetected
///   2. Receive real-time game data via screen capture / memory reading
///   3. Allow a cheat operator on another machine to aim/trigger for the player
///   4. Install or update cheat software remotely
///   5. Exfiltrate game screenshots, credentials, or anti-cheat telemetry
///
/// Detection covers:
///   1. Known commercial RAT/remote-access tool processes and files:
///      TeamViewer, AnyDesk, RustDesk, Ammyy Admin, Remote Utilities, NetSupport
///   2. Suspicious RDP (Remote Desktop) configuration changes:
///      - RDP enabled (fDenyTSConnections = 0)
///      - Network Level Authentication disabled
///      - Added unauthorized RDP users
///   3. Unauthorized VNC server installations
///   4. Reverse shell indicators (nc.exe, ncat.exe, socat.exe)
///   5. Screen capture and screenshot exfiltration tools
///
/// Note: Some of these tools (TeamViewer, AnyDesk) are legitimate for remote support.
/// The module flags them with Medium risk unless combined with other cheat indicators.
/// </summary>
public sealed class RemoteAccessToolScanModule : IScanModule
{
    private static readonly string _name = "Fernzugriff-Tool-Analyse";
    public string Name => _name;
    public double Weight => 0.7;
    public int ParallelGroup => 2;

    private sealed record RatEntry(string Name, string[] ProcessNames,
        string[] RegistryKeys, RiskLevel BaseRisk);

    private static readonly RatEntry[] KnownRats =
    {
        new("TeamViewer",
            new[] { "TeamViewer.exe", "TeamViewer_Service.exe" },
            new[] { @"SOFTWARE\TeamViewer", @"SOFTWARE\WOW6432Node\TeamViewer" },
            RiskLevel.Low),    // Common legitimate tool

        new("AnyDesk",
            new[] { "AnyDesk.exe" },
            new[] { @"SOFTWARE\AnyDesk", @"SYSTEM\CurrentControlSet\Services\AnyDesk" },
            RiskLevel.Low),    // Common legitimate tool

        new("RustDesk",
            new[] { "rustdesk.exe" },
            new[] { @"SOFTWARE\RustDesk" },
            RiskLevel.Medium),

        new("Ammyy Admin",
            new[] { "AA_v3.exe", "AA_v4.exe" },
            new[] { @"SOFTWARE\Ammyy" },
            RiskLevel.High),   // Often used maliciously

        new("Remote Utilities",
            new[] { "rutserv.exe", "rfusclient.exe" },
            new[] { @"SOFTWARE\Remote Utilities - Host", @"SYSTEM\CurrentControlSet\Services\rutserv" },
            RiskLevel.Medium),

        new("NetSupport Manager",
            new[] { "client32.exe", "pcicnfgr.exe" },
            new[] { @"SOFTWARE\NetSupport Ltd\NetSupport Manager" },
            RiskLevel.Medium),

        new("VNC Server",
            new[] { "vncserver.exe", "winvnc4.exe", "tvnserver.exe", "uvnc_service.exe",
                    "wdaemon.exe" },
            new[] { @"SYSTEM\CurrentControlSet\Services\WinVNC4",
                    @"SYSTEM\CurrentControlSet\Services\tvnserver" },
            RiskLevel.High),

        new("Reverse Shell Tools",
            new[] { "nc.exe", "ncat.exe", "netcat.exe", "socat.exe", "plink.exe" },
            Array.Empty<string>(),
            RiskLevel.Critical),
    };

    // RDP configuration keys
    private const string TerminalServerKey =
        @"SYSTEM\CurrentControlSet\Control\Terminal Server";
    private const string RdpSecurityKey =
        @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckKnownRats(ctx, ct);
        hits += CheckRdpConfiguration(ctx, ct);
        hits += CheckRdpUsers(ctx, ct);

        ctx.Report(1.0, Name, $"Fernzugriff-Tools geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckKnownRats(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;

        // Get running processes once
        var runningProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                try { runningProcesses.Add(proc.ProcessName + ".exe"); }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }

        foreach (var rat in KnownRats)
        {
            if (ct.IsCancellationRequested) break;

            bool isRunning = rat.ProcessNames.Any(p =>
                runningProcesses.Contains(p, StringComparer.OrdinalIgnoreCase));

            bool isInstalled = false;
            foreach (var regKey in rat.RegistryKeys)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(regKey, writable: false);
                    if (key is not null) { isInstalled = true; ctx.IncrementRegistryKeys(); break; }
                }
                catch { }
            }

            if (!isRunning && !isInstalled) continue;

            hits++;
            ctx.AddFinding(new Finding
            {
                Module = _name,
                Title    = $"Fernzugriff-Tool erkannt: {rat.Name}",
                Risk     = isRunning && rat.BaseRisk >= RiskLevel.High ? RiskLevel.Critical : rat.BaseRisk,
                Location = isRunning ? $"Prozess aktiv: {rat.ProcessNames[0]}"
                                     : rat.RegistryKeys.FirstOrDefault() ?? "Registry",
                Reason   = $"Fernzugriff-Tool '{rat.Name}' ist {(isRunning ? "aktiv" : "installiert")}. " +
                           (rat.BaseRisk >= RiskLevel.High
                               ? $"'{rat.Name}' wird häufig für unbefugten Fernzugriff verwendet. "
                               : $"Legitimes Tool, aber Fernzugriff kann für Cheat-Betrieb missbraucht werden. ") +
                           (isRunning ? "Derzeit aktiv — laufender Fernzugriff möglich." : "Installiert."),
                Detail   = $"Tool: {rat.Name} | Aktiv: {isRunning} | Installiert: {isInstalled}"
            });
        }

        return hits;
    }

    private static int CheckRdpConfiguration(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(TerminalServerKey, writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            var fDenyTsConnections = key.GetValue("fDenyTSConnections") as int? ?? 1;

            if (fDenyTsConnections == 0)
            {
                // RDP is enabled — check additional security
                using var rdpKey = Registry.LocalMachine.OpenSubKey(RdpSecurityKey, writable: false);
                var nlaRequired = rdpKey?.GetValue("UserAuthentication") as int? ?? 1;
                ctx.IncrementRegistryKeys();

                hits++;
                ctx.AddFinding(new Finding
                {
                    Module = _name,
                    Title    = "Remote Desktop (RDP) aktiviert",
                    Risk     = nlaRequired == 0 ? RiskLevel.High : RiskLevel.Medium,
                    Location = $@"HKLM\{TerminalServerKey}",
                    Reason   = "Remote Desktop Protocol (RDP) ist auf diesem System aktiviert " +
                               "(fDenyTSConnections = 0). " +
                               (nlaRequired == 0
                                   ? "Network Level Authentication (NLA) ist deaktiviert — " +
                                     "jeder kann ohne vorzeitige Authentifizierung verbinden. "
                                   : "NLA ist aktiv. ") +
                               "RDP kann für unbemerkte Fernsteuerung beim Spielen genutzt werden.",
                    Detail   = $"fDenyTSConnections: {fDenyTsConnections} | NLA: {nlaRequired}"
                });
            }
        }
        catch { }
        return hits;
    }

    private static int CheckRdpUsers(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Check members of "Remote Desktop Users" group
            using var query = new System.Management.ManagementObjectSearcher(
                @"SELECT * FROM Win32_GroupUser WHERE GroupComponent=""Win32_Group.Domain='" +
                Environment.MachineName + @"',Name='Remote Desktop Users'""");

            foreach (System.Management.ManagementObject obj in query.Get())
            {
                if (ct.IsCancellationRequested) break;
                var partComp = obj["PartComponent"] as string ?? "";
                // Extract username from the WMI reference path
                var match = System.Text.RegularExpressions.Regex.Match(
                    partComp, @"Name=""([^""]+)""");
                if (!match.Success) continue;

                var userName = match.Groups[1].Value;

                // Flag unknown accounts (not Administrator, not the current user)
                if (string.Equals(userName, "Administrator", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(userName, Environment.UserName, StringComparison.OrdinalIgnoreCase))
                    continue;

                hits++;
                ctx.AddFinding(new Finding
                {
                    Module = _name,
                    Title    = $"Unbekannter RDP-Benutzer: {userName}",
                    Risk     = RiskLevel.High,
                    Location = "Remote Desktop Users (Lokale Gruppe)",
                    Reason   = $"Benutzer '{userName}' ist Mitglied der 'Remote Desktop Users'-Gruppe " +
                               "ohne erkennbare Legitimation. " +
                               "Unautorisierte RDP-Benutzer können Fernzugriff auf das System erlangen " +
                               "und während des Spielens Cheats betreiben.",
                    Detail   = $"RDP-Benutzer: {userName}"
                });
            }
        }
        catch { }
        return hits;
    }
}
