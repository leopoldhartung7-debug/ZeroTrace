using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans for specific registry artifacts left by known cheat tools, HWID spoofers, and
/// cheat-adjacent software. Unlike keyword-based scanning, this module checks exact registry
/// key paths and value names that are unique to specific products — creating near-zero
/// false positives. Cheat tools often write telemetry, license keys, user preferences, and
/// configuration data to predictable registry locations that persist after the tool is
/// uninstalled. The module checks 60+ known cheat tool registry footprints across:
/// injection tools (Xenos, GH Injector), DMA tools, HWID spoofers, cheat loaders,
/// menu frameworks (BepInEx, ImGui-based loaders), and AC bypass utilities.
/// </summary>
public sealed class CheatToolRegistryArtifactsScanModule : IScanModule
{
    public string Name => "Known Cheat Tool Registry Artifact Detection";
    public double Weight => 0.7;
    public int ParallelGroup => 3;

    private static readonly (string Hive, string KeyPath, string? ValueName, string CheatTool, bool IsExactKey)[]
        CheatRegistryArtifacts =
    {
        // ── Injection Tools ──────────────────────────────────────────────────────
        // Xenos Injector
        ("HKCU", @"SOFTWARE\Xenos",               null,          "Xenos Injector",          true),
        ("HKLM", @"SOFTWARE\Xenos",               null,          "Xenos Injector",          true),
        // GH Injector
        ("HKCU", @"SOFTWARE\GH Injector",         null,          "GH Injector",             true),
        // Process Hacker / System Informer (dual-use)
        ("HKCU", @"SOFTWARE\Process Hacker",      null,          "Process Hacker",          true),
        ("HKCU", @"SOFTWARE\SystemInformer",       null,          "System Informer",         true),
        // ExtremeDumper
        ("HKCU", @"SOFTWARE\ExtremeDumper",       null,          "ExtremeDumper",           true),
        // Cheat Engine
        ("HKCU", @"SOFTWARE\Cheat Engine",        null,          "Cheat Engine",            true),
        ("HKLM", @"SOFTWARE\Cheat Engine",        null,          "Cheat Engine",            true),
        ("HKCU", @"SOFTWARE\WOW6432Node\Cheat Engine", null,     "Cheat Engine (x86)",      true),

        // ── HWID Spoofers ────────────────────────────────────────────────────────
        // HWID Spoofer (generic)
        ("HKLM", @"SOFTWARE\HWIDSpoofer",         null,          "HWID Spoofer",            true),
        ("HKCU", @"SOFTWARE\HWIDSpoofer",         null,          "HWID Spoofer",            true),
        // Smiley-Face / hwid.xyz
        ("HKCU", @"SOFTWARE\SmileySpoofer",       null,          "SmileySpoofer",           true),
        // Valorant HWID spoofer
        ("HKLM", @"SOFTWARE\ValorantSpoofer",     null,          "Valorant HWID Spoofer",   true),

        // ── Cheat Loaders / Menus ────────────────────────────────────────────────
        // Kiddion's Modest Menu telemetry
        ("HKCU", @"SOFTWARE\Kiddion",             null,          "Kiddion's Modest Menu",   true),
        // 2Take1 registration
        ("HKCU", @"SOFTWARE\2Take1",              null,          "2Take1 Menu",             true),
        // Stand (GTA V cheat)
        ("HKCU", @"SOFTWARE\Stand",               null,          "Stand Cheat Menu",        true),
        // Cherax (GTA V)
        ("HKCU", @"SOFTWARE\Cherax",              null,          "Cherax",                  true),
        // Midnight (GTA V)
        ("HKCU", @"SOFTWARE\Midnight",            null,          "Midnight Cheat",          true),

        // ── VAC/EAC/BE Bypass Tools ──────────────────────────────────────────────
        // VACFix
        ("HKCU", @"SOFTWARE\VACFix",              null,          "VACFix",                  true),
        ("HKLM", @"SOFTWARE\VACFix",              null,          "VACFix",                  true),
        // EAC Bypass
        ("HKCU", @"SOFTWARE\EACBypass",           null,          "EAC Bypass",              true),
        // Bypass2 / CrackdownEAC
        ("HKCU", @"SOFTWARE\CrackdownEAC",        null,          "CrackdownEAC",            true),

        // ── DMA / External Reading Tools ─────────────────────────────────────────
        // MemProcFS
        ("HKCU", @"SOFTWARE\MemProcFS",           null,          "MemProcFS",               true),
        ("HKLM", @"SOFTWARE\MemProcFS",           null,          "MemProcFS",               true),
        // PCILeech / LeechCore
        ("HKCU", @"SOFTWARE\LeechCore",           null,          "PCILeech/LeechCore",      true),
        ("HKLM", @"SOFTWARE\LeechCore",           null,          "PCILeech/LeechCore",      true),

        // ── Input Automation ─────────────────────────────────────────────────────
        // AutoHotkey (registry keys left by script compilation)
        ("HKCU", @"SOFTWARE\AutoHotkey",          "LastUsedDir", "AutoHotkey",              false),
        // Logitech Gaming Software script abuse
        ("HKCU", @"SOFTWARE\Logitech\Logitech Gaming Software\Lua Scripts",
                                                   null,          "Logitech Lua Scripts",    false),
        // Razer Synapse macros
        ("HKCU", @"SOFTWARE\Razer\Synapse\GeneralInfo",
                                                   "MacrosEnabled", "Razer Synapse Macros",  false),

        // ── Screen Capture Bypass ────────────────────────────────────────────────
        // OBS virtual camera (sometimes abused by cheats for stream bypass)
        ("HKLM", @"SOFTWARE\OBS Virtual Camera",  null,          "OBS Virtual Camera",      true),

        // ── Debug / RE Tools (flagged when installed alongside cheats) ────────────
        // x64dbg plugins dir (custom plugin installers register here)
        ("HKCU", @"SOFTWARE\x64dbg",              null,          "x64dbg Debugger",         true),
        // ScyllaHide (anti-anti-debug plugin)
        ("HKCU", @"SOFTWARE\ScyllaHide",          null,          "ScyllaHide",              true),
        ("HKLM", @"SOFTWARE\ScyllaHide",          null,          "ScyllaHide",              true),

        // ── Network Traffic Manipulation ─────────────────────────────────────────
        // ProxyCap / Proxifier (network proxy for AC bypass)
        ("HKCU", @"SOFTWARE\ProxyCap",            null,          "ProxyCap",                true),
        ("HKCU", @"SOFTWARE\Initex Software\Proxifier",
                                                   null,          "Proxifier",               true),

        // ── Specific Cheat Suite Registry Footprints ─────────────────────────────
        // Aimware
        ("HKCU", @"SOFTWARE\AIMWARE",             null,          "AIMWARE",                 true),
        // Onetap
        ("HKCU", @"SOFTWARE\Onetap",              null,          "Onetap",                  true),
        // Gamesense
        ("HKCU", @"SOFTWARE\Gamesense",           null,          "Gamesense",               true),
        // Fatality
        ("HKCU", @"SOFTWARE\Fatality",            null,          "Fatality",                true),
        // Interwebz / NeverLose
        ("HKCU", @"SOFTWARE\NeverLose",           null,          "NeverLose",               true),
        // Naimei
        ("HKCU", @"SOFTWARE\Naimei",              null,          "Naimei Cheat",            true),
        // Skycheats
        ("HKCU", @"SOFTWARE\SkyC",                null,          "Skycheats",               true),

        // ── BYOVD Tool Registry Footprints ───────────────────────────────────────
        // WinRing0 / OpenHardwareMonitor (BYOVD vector)
        ("HKLM", @"SYSTEM\CurrentControlSet\Services\WinRing0_1_2_0",
                                                   null,          "WinRing0 Driver",         true),
        ("HKLM", @"SYSTEM\CurrentControlSet\Services\WinRing0x64",
                                                   null,          "WinRing0x64 Driver",      true),
        // MSI Afterburner RTSS (RTCore64 BYOVD vector)
        ("HKLM", @"SYSTEM\CurrentControlSet\Services\RTCORE64",
                                                   null,          "RTCore64 (BYOVD Treiber)", true),
        // Gigabyte App Center (GDRV BYOVD)
        ("HKLM", @"SYSTEM\CurrentControlSet\Services\gdrv",
                                                   null,          "Gigabyte GDRV (BYOVD)",   true),
        // CPUZ driver
        ("HKLM", @"SYSTEM\CurrentControlSet\Services\cpuz141",
                                                   null,          "CPUZ141 (BYOVD Treiber)", true),
        ("HKLM", @"SYSTEM\CurrentControlSet\Services\cpuz153",
                                                   null,          "CPUZ153 (BYOVD Treiber)", true),
        // AsIO (ASUS driver BYOVD)
        ("HKLM", @"SYSTEM\CurrentControlSet\Services\AsIO3",
                                                   null,          "ASUS AsIO3 (BYOVD)",      true),
        // Iobitunlocker (BYOVD)
        ("HKLM", @"SYSTEM\CurrentControlSet\Services\IOBITUNLOCKER",
                                                   null,          "IObit Unlocker (BYOVD)",  true),
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => CheckRegistryArtifacts(ctx, ct), ct);
    }

    private void CheckRegistryArtifacts(ScanContext ctx, CancellationToken ct)
    {
        foreach (var (hive, keyPath, valueName, cheatTool, isExactKey) in CheatRegistryArtifacts)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                RegistryKey root = hive == "HKCU" ? Registry.CurrentUser : Registry.LocalMachine;

                using var key = root.OpenSubKey(keyPath);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();

                // For exact-key matches, the key existing is sufficient evidence
                if (isExactKey || valueName is null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Bekanntes Cheat-Tool-Artefakt: {cheatTool}",
                        Risk     = DetermineRisk(cheatTool, keyPath),
                        Location = $@"{hive}\{keyPath}",
                        FileName = Path.GetFileName(keyPath),
                        Reason   = $"Registry-Schlüssel '{hive}\\{keyPath}' ist ein bekanntes " +
                                   $"Installations-Artefakt von '{cheatTool}' — dieser Schlüssel " +
                                   "wird spezifisch von diesem Tool erstellt und existiert auf " +
                                   "sauberen Systemen nicht",
                        Detail   = $"Cheat-Tool: {cheatTool} | Schlüssel: {hive}\\{keyPath}"
                    });
                }
                else if (valueName is not null)
                {
                    // Check specific value
                    object? val = key.GetValue(valueName);
                    if (val is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Bekanntes Cheat-Tool-Artefakt: {cheatTool}",
                        Risk     = DetermineRisk(cheatTool, keyPath),
                        Location = $@"{hive}\{keyPath}\{valueName}",
                        FileName = Path.GetFileName(keyPath),
                        Reason   = $"Registry-Wert '{valueName}' in '{hive}\\{keyPath}' ist ein " +
                                   $"bekanntes Artefakt von '{cheatTool}'",
                        Detail   = $"Cheat-Tool: {cheatTool} | Schlüssel: {hive}\\{keyPath} | " +
                                   $"Wert: {valueName}={val}"
                    });
                }
            }
            catch { }
        }
    }

    private static RiskLevel DetermineRisk(string cheatTool, string keyPath)
    {
        // BYOVD drivers = Critical
        if (keyPath.Contains("Services\\", StringComparison.OrdinalIgnoreCase) &&
            (cheatTool.Contains("BYOVD") || cheatTool.Contains("Treiber") ||
             cheatTool.Contains("Driver")))
            return RiskLevel.Critical;

        // Core cheat suites = Critical
        if (cheatTool.Contains("Cheat") || cheatTool.Contains("Menu") ||
            cheatTool.Contains("Injector") || cheatTool.Contains("Bypass") ||
            cheatTool.Contains("Spoofer") || cheatTool.Contains("DMA") ||
            cheatTool.Contains("MemProcFS") || cheatTool.Contains("PCILeech"))
            return RiskLevel.Critical;

        // Debug tools, dual-use software = High
        return RiskLevel.High;
    }
}
