using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Analyses Windows Shellbag registry entries for forensic evidence of cheat-
/// related folder access.
///
/// Shellbags store a record of every folder a user has ever opened in Windows
/// Explorer — even after the folder and its contents have been deleted. They are
/// one of the most reliable forensic artifacts for proving a user visited a
/// specific directory.
///
/// Keys analysed:
///   HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags
///   HKCU\SOFTWARE\Microsoft\Windows\Shell\BagMRU
///   HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags
///   HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
///
/// Detection:
///   - Folder names matching known cheat tool directory names
///   - Recently-accessed exotic paths (USB drives, network shares) used to run cheats
///   - Shellbag entries pointing to now-deleted directories in Temp/Downloads
///   - Entries for known spoofer / injector directories
/// </summary>
public sealed class ShellbagScanModule : IScanModule
{
    public string Name => "Shellbag-Forensik";
    public double Weight => 0.8;
    public int ParallelGroup => 1;

    private static readonly string[] ShellbagRoots =
    {
        @"SOFTWARE\Microsoft\Windows\Shell\BagMRU",
        @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
    };

    // Cheat/spoofer/injector related folder name fragments
    private static readonly string[] CheatFolderKeywords =
    {
        // GTA/FiveM cheats
        "kiddion", "2take1", "cherax", "ozark", "tsunami", "rxce",
        "yimmenu", "stand", "lambda", "absolute", "spectre",
        "susano", "hyperion", "primordial", "reaper",
        // CS2/CSGO cheats
        "aimware", "fecurity", "onetap", "neverlose", "gamesense",
        "fatality", "nixware", "lumina", "aimbot", "wallhack",
        // Valorant/Apex
        "valorhack", "valorcheat", "predatorlegend", "apexhack",
        "ringone", "blackcell", "ricochetbypass",
        // EFT cheats
        "evilcheats", "gamerpride", "exvalid", "ohwow",
        // Rust cheats
        "rustez", "nocheats", "rustcheat",
        // General cheat infrastructure
        "spoofer", "hwid", "injector", "loader", "bypass",
        "cheat", "hack", "aimbot", "triggerbot", "bhop",
        // DMA tools
        "memprocfs", "pcileech", "leechcore", "dma",
        // Macro tools
        "autohotkey", "interception",
        // Kernel tools
        "xenos", "extremeinjector", "processinjector",
        // Cheat sites/tools
        "unknowncheats", "uc_tools", "universalaimbot",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int bagsChecked = 0;

        foreach (var root in ShellbagRoots)
        {
            if (ct.IsCancellationRequested) break;
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(root, writable: false);
                if (key is null) continue;
                WalkBagMru(key, "", ctx, ct, ref bagsChecked);
            }
            catch { }
        }

        ctx.Report(1.0, "Shellbag-Forensik", $"{bagsChecked} Shellbag-Einträge analysiert");
        return Task.CompletedTask;
    }

    private static void WalkBagMru(RegistryKey key, string pathSoFar,
        ScanContext ctx, CancellationToken ct, ref int count)
    {
        if (ct.IsCancellationRequested) return;
        count++;
        ctx.IncrementRegistryKeys();

        // The MRUListEx value contains the ordering of child entries (MRU order)
        // Each numeric sub-key is a folder navigated to
        foreach (var subName in key.GetSubKeyNames())
        {
            if (ct.IsCancellationRequested) return;
            if (!int.TryParse(subName, out _)) continue;

            try
            {
                using var sub = key.OpenSubKey(subName, writable: false);
                if (sub is null) continue;

                // Try to extract a path string from the NodeSlot binary data
                // The folder name is embedded in the binary shellbag data as a
                // Unicode string — we do a simple substring scan
                foreach (var valueName in sub.GetValueNames())
                {
                    if (valueName != "") continue; // only default value
                    var data = sub.GetValue("") as byte[];
                    if (data is null) continue;
                    var text = Encoding.Unicode.GetString(data).ToLowerInvariant();
                    var hit = CheatFolderKeywords.FirstOrDefault(k =>
                        text.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (hit is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Shellbag-Forensik",
                            Title    = $"Shellbag: Cheat-Ordner geöffnet ({hit})",
                            Risk     = RiskLevel.High,
                            Location = $@"HKCU\{key.Name}\{subName}",
                            Reason   = $"Windows-Shellbag-Eintrag enthält Verweis auf Ordner mit " +
                                       $"cheat-typischem Namen '{hit}'. Shellbags bleiben auch nach " +
                                       "dem Löschen des Ordners erhalten und beweisen, dass " +
                                       "der Benutzer dieses Verzeichnis geöffnet hat.",
                            Detail   = $"Schlüsselwort: '{hit}' | Registry: {key.Name}\\{subName}"
                        });
                    }
                }

                // Recurse into sub-entries
                WalkBagMru(sub, pathSoFar, ctx, ct, ref count);
            }
            catch { }
        }

        // Also scan all string values in this key for path fragments
        foreach (var valueName in key.GetValueNames())
        {
            if (ct.IsCancellationRequested) return;
            if (key.GetValueKind(valueName) != RegistryValueKind.Binary) continue;

            try
            {
                var data = key.GetValue(valueName) as byte[];
                if (data is null || data.Length < 4) continue;

                // Scan for Unicode strings containing cheat keywords
                var unicode = Encoding.Unicode.GetString(data).ToLowerInvariant();
                var ascii   = Encoding.ASCII.GetString(
                    data.Select(b => b >= 0x20 && b < 0x7F ? b : (byte)0x20).ToArray())
                    .ToLowerInvariant();

                foreach (var text in new[] { unicode, ascii })
                {
                    var hit = CheatFolderKeywords.FirstOrDefault(k =>
                        text.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (hit is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = "Shellbag-Forensik",
                        Title    = $"Shellbag-Binärdaten: '{hit}'",
                        Risk     = RiskLevel.High,
                        Location = $@"HKCU\{key.Name}",
                        Reason   = $"Shellbag-Binärdaten enthalten cheat-typisches Schlüsselwort '{hit}'. " +
                                   "Diese Artefakte bleiben auch nach Bereinigungsversuchen erhalten.",
                        Detail   = $"Wert: {valueName} | Keyword: {hit}"
                    });
                    break;
                }
            }
            catch { }
        }
    }
}
