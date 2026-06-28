using System.Runtime.InteropServices;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Registry forensic timestamp analysis: inspects LastWriteTime of high-value persistence
/// registry keys for recent modifications indicating cheat tool installation, BYOVD driver
/// registration, or anti-cheat service tampering. Registry key timestamps persist even after
/// the value entries are deleted, making them a strong forensic artifact that cheats rarely
/// clean up. Keys modified within the last 72 hours in persistence locations are flagged.
/// </summary>
public sealed class RegistryKeyTimestampScanModule : IScanModule
{
    public string Name => "Registry Key Timestamp Forensics";
    public double Weight => 0.75;
    public int ParallelGroup => 3;

    // (key path, hive, description, maxAgeHoursForHigh, maxAgeHoursForMedium)
    private static readonly (RegistryHive Hive, string SubKey, string Description)[] TargetKeys =
    {
        // Persistence run keys
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
         "HKLM\\Run — Autostart bei Systemstart"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
         "HKLM\\RunOnce — Einmalige Autostart-Ausfuehrung"),
        (RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
         "HKCU\\Run — Autostart bei Benutzeranmeldung"),
        (RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
         "HKCU\\RunOnce — Einmalige Benutzer-Autostart"),
        (RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
         "HKLM\\Run (WOW64) — 32-Bit Autostart"),

        // Services and drivers
        (RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services",
         "HKLM\\Services — Windows Dienste und Treiber"),

        // IFEO — Image File Execution Options (debugger hijacking)
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
         "HKLM\\IFEO — Debugger-Hijacking, VerifierDll Injektion"),

        // Winlogon — login process hijacking
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
         "HKLM\\Winlogon — Shell/Userinit/GinaDLL Hijacking"),

        // AppInit DLLs — inject into every User32 process
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
         "HKLM\\Windows AppInit_DLLs — Injektion in alle User32-Prozesse"),

        // Browser Helper Objects
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
         "HKLM\\BHO — Browser Helper Objects (veraltete Injektion)"),

        // Known DLLs hijacking
        (RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
         "HKLM\\KnownDLLs — Kern-DLL Liste (Hijacking moeglich)"),

        // LSA authentication packages
        (RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa",
         "HKLM\\LSA — Authentication Packages, Security Providers"),

        // Security providers
        (RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\SecurityProviders",
         "HKLM\\SecurityProviders — SSPI Provider DLLs"),

        // Print monitor / processor persistence
        (RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Print\Monitors",
         "HKLM\\Print\\Monitors — Druckmonitor DLL Persistenz"),
        (RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors",
         "HKLM\\Print\\Processors (x64) — Druckprozessor Persistenz"),

        // AppCompat shims
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom",
         "HKLM\\AppCompat Custom — Appkompatibilitaets-Shim Injektion"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB",
         "HKLM\\AppCompat SDB — Installierte Shim-Datenbanken"),

        // SIP / Trust Providers (signature bypass)
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData",
         "HKLM\\CryptSIP VerifyIndirectData — Authenticode Bypass Vektor"),

        // Windows Defender exclusions (cheat tools add these)
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
         "HKLM\\Defender Exclusions Paths — AV-Ausschluss (Cheat-Schutz)"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
         "HKLM\\Defender Exclusions Processes — AV-Ausschluss fuer Prozesse"),

        // WMI subscriptions
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\WBEM\ESS",
         "HKLM\\WMI ESS — WMI Event Subscription Persistenz"),

        // COM object registrations
        (RegistryHive.LocalMachine, @"SOFTWARE\Classes\CLSID",
         "HKLM\\CLSID — COM Objekt Registrierungen"),
        (RegistryHive.CurrentUser, @"SOFTWARE\Classes\CLSID",
         "HKCU\\CLSID — Benutzer COM Hijacking"),

        // Boot execute (very early execution, before services)
        (RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager",
         "HKLM\\Session Manager — BootExecute (Pre-Boot Persistenz)"),
    };

    // Subkeys whose names contain these strings trigger a cheat-specific flag
    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "aimbot", "wallhack", "esp_", "triggerbot",
        "norecoil", "softaim", "spoofer", "hwid", "byovd", "radar",
        "external", "internal", "inject", "loader", "kiddion", "cherax",
        "2take1", "neverlose", "fatality", "aimware", "skeet", "gamesense",
        "memprocfs", "pcileech", "dmalib", "mhyprot", "dbutil", "gdrv",
        "capcom", "speedfan", "physmem", "rtcore", "vulnerable",
        "zerotrace_bypass", "eac_bypass", "be_bypass", "vac_bypass",
        "silentaim", "legit", "vischeck", "smoothing",
    };

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int RegOpenKeyEx(
        nint hKey, string lpSubKey, uint ulOptions, uint samDesired, out nint phkResult);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int RegQueryInfoKey(
        nint hKey, [Out] char[]? lpClass, ref uint lpcClass,
        nint lpReserved, out uint lpcSubKeys, out uint lpcMaxSubKeyLen,
        out uint lpcMaxClassLen, out uint lpcValues, out uint lpcMaxValueNameLen,
        out uint lpcMaxValueLen, out uint lpcbSecurityDescriptor,
        out FILETIME lpftLastWriteTime);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int RegEnumKeyEx(
        nint hKey, uint dwIndex, [Out] char[] lpName, ref uint lpcName,
        nint lpReserved, [Out] char[]? lpClass, nint lpcClass, out FILETIME lpftLastWriteTime);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int RegCloseKey(nint hKey);

    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME
    {
        public uint dwLowDateTime;
        public uint dwHighDateTime;
    }

    private static readonly nint HKEY_LOCAL_MACHINE = new nint(unchecked((int)0x80000002));
    private static readonly nint HKEY_CURRENT_USER  = new nint(unchecked((int)0x80000001));
    private const uint KEY_READ    = 0x20019;
    private const int  ERROR_SUCCESS = 0;
    private const int  ERROR_NO_MORE_ITEMS = 259;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            DateTime now = DateTime.UtcNow;

            foreach (var (hive, subKey, description) in TargetKeys)
            {
                ct.ThrowIfCancellationRequested();
                try { AnalyzeKey(hive, subKey, description, now, ctx, ct); }
                catch { /* skip inaccessible */ }
                ctx.IncrementRegistryKeys();
            }
        }, ct);
    }

    private void AnalyzeKey(
        RegistryHive hive, string subKey, string description,
        DateTime now, ScanContext ctx, CancellationToken ct)
    {
        nint hRoot = hive == RegistryHive.LocalMachine ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;

        if (RegOpenKeyEx(hRoot, subKey, 0, KEY_READ, out nint hKey) != ERROR_SUCCESS)
            return;

        try
        {
            // Check the top-level key's own timestamp
            uint classLen = 256;
            int ret = RegQueryInfoKey(hKey, null, ref classLen, nint.Zero,
                out uint subKeyCount, out _, out _, out _, out _, out _, out _,
                out FILETIME ftParent);

            if (ret == ERROR_SUCCESS)
            {
                DateTime parentModified = FileTimeToDateTime(ftParent);
                double hoursAgo = (now - parentModified).TotalHours;

                if (hoursAgo < 72)
                {
                    // Check if the subkey path itself contains cheat keywords
                    bool cheatKeyword = CheatKeywords.Any(k =>
                        subKey.ToLowerInvariant().Contains(k));

                    RiskLevel risk = hoursAgo < 2 ? RiskLevel.High
                                   : hoursAgo < 24 ? RiskLevel.Medium
                                   : RiskLevel.Low;

                    if (cheatKeyword) risk = RiskLevel.Critical;

                    ctx.AddFinding(new Finding
                    {
                        Module = "Registry Key Timestamp Forensics",
                        Title = $"Kuerzlich geaenderter Persistenz-Schluessel: {subKey.Split('\\').Last()}",
                        Risk = risk,
                        Location = $@"{(hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU")}\{subKey}",
                        Reason = $"{description} — zuletzt geaendert vor {hoursAgo:F1} Stunden ({parentModified:yyyy-MM-dd HH:mm} UTC)",
                        Detail = cheatKeyword
                            ? "Schluessel-Pfad enthaelt Cheat-Schluesselwort — moegliche Cheat-Installation"
                            : "Persistenz-Schluessel kuerzlich modifiziert — forensisch relevant"
                    });
                }
            }

            // Enumerate subkeys and check their timestamps
            var nameBuf = new char[256];
            for (uint idx = 0; idx < Math.Min(subKeyCount, 2000u); idx++)
            {
                ct.ThrowIfCancellationRequested();
                uint nameLen = (uint)nameBuf.Length;
                ret = RegEnumKeyEx(hKey, idx, nameBuf, ref nameLen,
                    nint.Zero, null, nint.Zero, out FILETIME ftSub);

                if (ret == ERROR_NO_MORE_ITEMS) break;
                if (ret != ERROR_SUCCESS) continue;

                string name = new string(nameBuf, 0, (int)nameLen);
                DateTime subModified = FileTimeToDateTime(ftSub);
                double subHoursAgo = (now - subModified).TotalHours;

                bool isCheatKeyword = CheatKeywords.Any(k =>
                    name.ToLowerInvariant().Contains(k));

                // Only flag if modified very recently (24h) OR matches cheat keyword
                if (subHoursAgo >= 24 && !isCheatKeyword) continue;

                RiskLevel risk;
                string reason;

                if (isCheatKeyword && subHoursAgo < 72)
                {
                    risk = RiskLevel.Critical;
                    reason = $"Cheat-Schluessel-Keyword '{name}' in Persistenz-Pfad, geaendert vor {subHoursAgo:F1} Stunden";
                }
                else if (isCheatKeyword)
                {
                    risk = RiskLevel.High;
                    reason = $"Cheat-Schluessel-Keyword '{name}' in Persistenz-Pfad ({subModified:yyyy-MM-dd} UTC)";
                }
                else // recently modified, no keyword
                {
                    risk = subHoursAgo < 4 ? RiskLevel.Medium : RiskLevel.Low;
                    reason = $"Persistenz-Unterschluessel '{name}' vor {subHoursAgo:F1} Stunden geaendert";
                }

                ctx.AddFinding(new Finding
                {
                    Module = "Registry Key Timestamp Forensics",
                    Title = isCheatKeyword
                        ? $"Cheat-Registry-Schluessel: {name}"
                        : $"Kuerzlich geaenderter Unterschluessel: {name}",
                    Risk = risk,
                    Location = $@"{(hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU")}\{subKey}\{name}",
                    Reason = reason,
                    Detail = $"Letzter Schreibzugriff: {subModified:yyyy-MM-dd HH:mm:ss} UTC | " +
                             $"Quelle: {description}"
                });
            }
        }
        finally { RegCloseKey(hKey); }
    }

    private static DateTime FileTimeToDateTime(FILETIME ft)
    {
        try
        {
            long raw = ((long)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
            return DateTime.FromFileTimeUtc(raw);
        }
        catch { return DateTime.MinValue; }
    }
}
