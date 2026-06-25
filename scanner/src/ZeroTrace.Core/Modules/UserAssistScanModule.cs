using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Analyses Windows UserAssist registry entries for evidence of cheat tool
/// execution.
///
/// UserAssist records every application a user has run from Windows Explorer
/// (double-click, Start Menu, taskbar). The entries are ROT13-encoded to
/// obscure them from casual inspection, but they persist even after the
/// binary is deleted. Each entry records:
///   - Execution count
///   - Last execution time (FILETIME in a GUID key)
///   - Focus count / session count
///
/// Key path:
///   HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\
///     {GUID}\Count
///
/// GUIDs used:
///   {CEBFF5CD-ACE2-4F4F-9178-9926F41749EA} — Executable programs
///   {F4E57C4B-2036-45F0-A9AB-443BCFE33D9F} — Shortcut (.lnk) files
///
/// Detection: ROT13-decode each entry name, check against cheat keyword list,
/// and report with execution count and last-seen timestamp.
/// </summary>
public sealed class UserAssistScanModule : IScanModule
{
    public string Name => "UserAssist-Forensik";
    public double Weight => 0.5;
    public int ParallelGroup => 1;

    private static readonly string UserAssistBase =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

    // ROT13 decode table for A-Z, a-z
    private static string Rot13(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            if      (c >= 'A' && c <= 'Z') sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else if (c >= 'a' && c <= 'z') sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else sb.Append(c);
        }
        return sb.ToString();
    }

    private static readonly string[] CheatKeywords =
    {
        // GTA/FiveM menus
        "kiddion", "2take1", "cherax", "ozark", "tsunami", "rxce",
        "yimmenu", "stand", "lambdamenu", "absolutemenu", "spectre",
        "susanomenu", "hyperionmenu", "primordial", "reapermenu",
        // CS2/CSGO
        "aimware", "fecurity", "onetap", "neverlose", "gamesense",
        "fatality", "nixware", "lumina", "cs2cheat",
        // Valorant/Apex/Warzone
        "valorhack", "predatorlegend", "apexhack", "ringone",
        "blackcell", "ricochetbypass", "engineowning",
        // EFT
        "evilcheats", "gamerpride", "exvalid", "ohwow",
        // Rust/R6
        "rustez", "r6hacks", "strikecheats",
        // General tools
        "spoofer", "hwid_spoof", "serialchanger",
        "injector", "xenos", "extremeinjector", "processinjector",
        "dllinjector", "manualmap",
        // DMA
        "memprocfs", "pcileech", "dmasoftware",
        // Macro tools
        "triggerbot", "aimassist", "bhoptool", "norecscript",
        // Analysis evasion
        "process_hacker", "x64dbg", "cheatengine", "ollydbg",
        // Cheat loaders
        "cheatloader", "hackloader", "bypassloader",
        "modloader", "modmenu",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int entriesChecked = 0;

        try
        {
            using var base_ = Registry.CurrentUser.OpenSubKey(UserAssistBase, writable: false);
            if (base_ is null)
            {
                ctx.Report(1.0, "UserAssist-Forensik", "Kein UserAssist-Schlüssel gefunden");
                return Task.CompletedTask;
            }

            foreach (var guidName in base_.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    using var countKey = base_.OpenSubKey($@"{guidName}\Count", writable: false);
                    if (countKey is null) continue;

                    foreach (var encodedName in countKey.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) break;
                        entriesChecked++;
                        ctx.IncrementRegistryKeys();

                        // Decode ROT13
                        var decoded = Rot13(encodedName).ToLowerInvariant();

                        var hit = CheatKeywords.FirstOrDefault(k =>
                            decoded.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (hit is null) continue;

                        // Parse the DWORD value — contains run count + last run time
                        int runCount = 0;
                        DateTime? lastRun = null;
                        try
                        {
                            var data = countKey.GetValue(encodedName) as byte[];
                            if (data is { Length: >= 16 })
                            {
                                runCount = BitConverter.ToInt32(data, 4);
                                var fileTime = BitConverter.ToInt64(data, 8);
                                if (fileTime > 0)
                                    lastRun = DateTime.FromFileTimeUtc(fileTime);
                            }
                        }
                        catch { }

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"UserAssist: Cheat ausgeführt — {hit}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKCU\{UserAssistBase}\{guidName}\Count",
                            FileName = Path.GetFileName(decoded),
                            Reason   = $"Windows UserAssist-Eintrag zeigt Ausführung von '{Path.GetFileName(decoded)}' " +
                                       $"({runCount}× ausgeführt" +
                                       (lastRun.HasValue ? $", zuletzt {lastRun.Value:yyyy-MM-dd HH:mm} UTC" : "") +
                                       $"). Keyword-Treffer: '{hit}'. " +
                                       "UserAssist-Einträge bleiben auch nach dem Löschen der Datei erhalten.",
                            Detail   = $"Dekodiert: {decoded} | Ausführungen: {runCount} | " +
                                       $"Zuletzt: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unbekannt")}"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }

        ctx.Report(1.0, "UserAssist-Forensik",
            $"{entriesChecked} UserAssist-Einträge analysiert");
        return Task.CompletedTask;
    }
}
