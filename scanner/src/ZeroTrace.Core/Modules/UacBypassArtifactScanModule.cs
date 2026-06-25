using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects Windows UAC bypass artifacts in the current user's registry hive. Cheat loaders
/// and privilege escalation tools abuse HKCU registry keys to hijack trusted elevated processes
/// that perform auto-elevate without a UAC prompt. These keys override COM activations,
/// shell commands, and application behaviors to execute arbitrary code with elevated privileges.
/// The module checks all known HKCU-based UAC bypass locations:
///   - Fodhelper/SilentCleanup/EventViewer bypass (ms-settings, mscfile, mmc)
///   - exefile/batfile/cmdfile runas override (executes arbitrary command as admin)
///   - sdclt.exe bypass (AppPath/Control Panel override)
///   - DiskCleanup bypass via HKCU\Environment%SystemRoot%
///   - Byovd/WScript/cscript handler hijacking
/// Any HKCU shell command override pointing to non-system paths is flagged.
/// </summary>
public sealed class UacBypassArtifactScanModule : IScanModule
{
    public string Name => "UAC Bypass Artifact Detection";
    public double Weight => 0.7;
    public int ParallelGroup => 3;

    private static readonly (string KeyPath, string CommandValueName, string BypassName)[] UacBypassKeys =
    {
        // Fodhelper bypass — most common cheat UAC bypass
        (@"Software\Classes\ms-settings\shell\open\command",   "default", "Fodhelper"),
        (@"Software\Classes\ms-settings\CurVer",               "default", "Fodhelper CurVer"),
        // Event Viewer bypass
        (@"Software\Classes\mscfile\shell\open\command",       "default", "EventViewer"),
        // MMC bypass
        (@"Software\Classes\mmc\shell\open\command",           "default", "MMC"),
        // sdclt bypass
        (@"Software\Classes\exefile\shell\runas\command\IsolatedCommand", null, "sdclt/exefile runas"),
        (@"Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe", "default", "sdclt Control"),
        // SilentCleanup / DiskCleanup bypass via HKCU environment
        (@"Environment",  "%SystemRoot%", "SystemRoot Environment Override"),
        // WSReset bypass
        (@"Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command", "default", "WSReset"),
        // cmstplua bypass (Connection Manager)
        (@"Software\Classes\Folder\shell\open\command",        "default", "Folder Shell Override"),
        // Cmstp bypass
        (@"Software\Classes\ms-settings\shell\open\DelegateExecute", "default", "CMSTP/DelegateExecute"),
        // ComputerDefaults bypass
        (@"Software\Classes\software\Classes\exefile\shell\open\command", "default", "ComputerDefaults"),
        // CompMgmtLauncher bypass
        (@"Software\Classes\mmc\Shell\Open\command",           "default", "CompMgmtLauncher"),
        // Winsat bypass via wusa
        (@"Software\Classes\batfile\shell\open\command",       "default", "batfile Shell Override"),
        (@"Software\Classes\cmdfile\shell\open\command",       "default", "cmdfile Shell Override"),
    };

    // Command content patterns that indicate a payload (not a legit redirect)
    private static readonly string[] SuspiciousCommandPatterns =
    {
        ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        "powershell", "cmd.exe", "wscript", "cscript",
        "rundll32", "regsvr32", "mshta", "certutil",
        "bitsadmin", "wmic", "msiexec",
    };

    private static readonly string[] SystemCommandPaths =
    {
        @"%windir%\", @"%systemroot%\", @"c:\windows\",
        @"c:\program files\windows ",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => CheckUacBypassKeys(ctx, ct), ct);
    }

    private void CheckUacBypassKeys(ScanContext ctx, CancellationToken ct)
    {
        foreach (var (keyPath, valueName, bypassName) in UacBypassKeys)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(keyPath);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();

                string? command = null;

                if (valueName is null)
                {
                    // Check default value
                    command = key.GetValue(null) as string;
                }
                else if (valueName == "default")
                {
                    command = key.GetValue(string.Empty) as string ??
                              key.GetValue(null) as string;
                }
                else
                {
                    command = key.GetValue(valueName) as string;
                }

                if (string.IsNullOrWhiteSpace(command)) continue;

                string commandLower = command.ToLowerInvariant();

                // Check if the command contains a payload indicator
                bool hasPayloadIndicator = Array.Exists(SuspiciousCommandPatterns,
                    p => commandLower.Contains(p));
                if (!hasPayloadIndicator) continue;

                // Skip if it points to a legitimate system path
                bool isSystemPath = Array.Exists(SystemCommandPaths,
                    p => commandLower.StartsWith(p));
                if (isSystemPath) continue;

                bool isActiveBypass = File.Exists(
                    command.Trim('"').Split(' ')[0].Replace("%windir%",
                        Environment.GetEnvironmentVariable("WINDIR") ?? @"C:\Windows")
                         .Replace("%systemroot%",
                             Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows"));

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"UAC-Bypass-Artefakt ({bypassName}): {keyPath.Split('\\').Last()}",
                    Risk     = isActiveBypass ? RiskLevel.Critical : RiskLevel.High,
                    Location = $@"HKCU\{keyPath}",
                    FileName = command.Trim('"').Split(' ').LastOrDefault() ?? "",
                    Reason   = $"UAC-Bypass via {bypassName}: HKCU\\{keyPath} enthält Befehl '{command}' — " +
                               $"diese Technik übernimmt vertrauenswürdige auto-elevierende Prozesse " +
                               $"um Code ohne UAC-Prompt mit erhöhten Rechten auszuführen",
                    Detail   = $"Bypass-Methode: {bypassName} | Schlüssel: HKCU\\{keyPath} | " +
                               $"Wert: '{valueName ?? "(Standard)"}' | Befehl: '{command}' | " +
                               $"Datei vorhanden: {isActiveBypass}"
                });
            }
            catch { }
        }
    }
}
