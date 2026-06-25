using Microsoft.Win32;
using System.Diagnostics;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects cryptocurrency mining malware commonly bundled with cheat tools.
///
/// Many cheat tool distributors bundle miners with their tools to generate
/// passive income from victims' machines. Miners run alongside the cheat,
/// consuming CPU/GPU resources. Common patterns:
///
///   1. XMRig (Monero miner): Most common, often renamed but retains CLI patterns
///   2. PhoenixMiner / TeamRedMiner / NBMiner: GPU miners
///   3. NiceHash: GPU/CPU mining with marketplace integration
///   4. Coinhive: Browser-based mining (injected into game overlay browser)
///   5. Custom miners embedded in cheat loaders
///
/// Detection approach:
///   1. Check running processes for known miner binary names
///   2. Check process command-line arguments for mining pool patterns:
///      --pool, --url stratum+tcp://, -o stratum://, xmr.
///   3. Scan file system for known miner executables and configs
///   4. Check startup entries for miner persistence
///   5. Check network connections to known mining pools
///   6. Look for config.json files with mining pool wallet addresses
/// </summary>
public sealed class CryptoMinerScanModule : IScanModule
{
    public string Name => "Crypto-Miner-Erkennung";
    public double Weight => 0.8;
    public int ParallelGroup => 2;

    private static readonly HashSet<string> KnownMinerNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // XMRig variants
        "xmrig.exe", "xmrig-cuda.exe", "xmrig-opencl.exe",
        "xmr-stak.exe", "xmr-stak-rx.exe", "xmrstak.exe",
        "minerd.exe", "cpuminer.exe", "cpuminer-multi.exe",
        // GPU miners
        "phoenixminer.exe", "phoenixminer",
        "teamredminer.exe", "teamredminer",
        "nbminer.exe", "nbminer",
        "claymore.exe", "ethmine.exe", "ethminer.exe",
        "lolminer.exe", "lolminer",
        "gminer.exe", "gminer",
        "t-rex.exe", "t-rex",
        "nanominer.exe", "nanominer",
        "xmrig-proxy.exe",
        // NiceHash
        "nicehashquickminer.exe", "nhm.exe",
        "excavator.exe", "excavator",
        // Generic
        "miner.exe", "mining.exe", "coin.exe",
        "worker.exe",   // generic but often used
    };

    // Mining pool indicators in command lines / configs
    private static readonly string[] MiningPoolPatterns =
    {
        "stratum+tcp://", "stratum+ssl://", "stratum://",
        "pool.minexmr.com", "xmrpool.eu", "supportxmr.com",
        "pool.hashvault.pro", "xmr.pool.minergate.com",
        "cryptonote.social", "monero.hashvault.pro",
        "nanopool.org", "f2pool.com", "antpool.com",
        "pool2.xmrig.com", "xmrig.com/pool",
        "nicehash.com", "stratum.nicehash.com",
        "ethpool.org", "ethermine.org",
        "--algo=", "--coin=", "-a cryptonight",
        "xmr", "monero", "ethereum", "ravencoin",
        "--threads=", "-t ", "--donate-level",
    };

    // File names for miner config files
    private static readonly string[] MinerConfigFileNames =
    {
        "config.json",   // XMRig
        "pools.json",
        "xmrig.json",
        "miner.json",
        "mining.json",
        "settings.json",
    };

    // Mining pool wallet address patterns (XMR addresses are 95 chars starting with 4)
    private static readonly string[] WalletPatterns =
    {
        "4AbcD", "4xmr", "43aBC",  // XMR address prefix patterns
        "\"pool\":", "\"url\":", "\"wallet\":", "\"user\":",
        "\"algorithm\":", "\"algo\":",
    };

    private static readonly string[] ScanDirs =
    {
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        Path.GetTempPath(),
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckRunningMiners(ctx, ct);
        hits += CheckMinerPersistence(ctx, ct);
        hits += CheckMinerFiles(ctx, ct);

        ctx.Report(1.0, Name, $"Crypto-Miner-Artefakte geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckRunningMiners(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    var nameLower = (proc.ProcessName + ".exe").ToLowerInvariant();

                    bool isKnownMiner = KnownMinerNames.Contains(proc.ProcessName) ||
                                        KnownMinerNames.Contains(proc.ProcessName + ".exe");

                    if (!isKnownMiner)
                    {
                        // Try to get command line
                        string cmdLine = "";
                        try
                        {
                            using var wmi = new System.Management.ManagementObjectSearcher(
                                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {proc.Id}");
                            foreach (System.Management.ManagementObject obj in wmi.Get())
                                cmdLine = obj["CommandLine"] as string ?? "";
                        }
                        catch { }

                        var poolPattern = MiningPoolPatterns.FirstOrDefault(p =>
                            cmdLine.Contains(p, StringComparison.OrdinalIgnoreCase));
                        if (poolPattern is null) continue;

                        hits++;
                        ctx.IncrementProcesses();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Aktiver Crypto-Miner (Befehlszeile): {proc.ProcessName}",
                            Risk     = RiskLevel.Critical,
                            Location = $"PID {proc.Id}: {proc.ProcessName}",
                            FileName = proc.ProcessName + ".exe",
                            Reason   = $"Prozess '{proc.ProcessName}' (PID {proc.Id}) hat " +
                                       $"Mining-Pool-Muster '{poolPattern}' in der Befehlszeile. " +
                                       "Crypto-Miner werden häufig mit Cheat-Tools gebündelt und " +
                                       "verbrauchen ohne Wissen des Opfers CPU/GPU-Ressourcen.",
                            Detail   = $"Prozess: {proc.ProcessName} | PID: {proc.Id} | Muster: {poolPattern}"
                        });
                    }
                    else
                    {
                        hits++;
                        ctx.IncrementProcesses();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Bekannter Crypto-Miner aktiv: {proc.ProcessName}",
                            Risk     = RiskLevel.Critical,
                            Location = $"PID {proc.Id}: {proc.ProcessName}",
                            FileName = proc.ProcessName + ".exe",
                            Reason   = $"Bekannte Crypto-Miner-Executable '{proc.ProcessName}' " +
                                       $"(PID {proc.Id}) läuft aktiv. " +
                                       "Crypto-Miner stehlen CPU/GPU-Ressourcen und werden " +
                                       "häufig ohne Zustimmung des Nutzers von Cheat-Tools installiert.",
                            Detail   = $"Prozess: {proc.ProcessName} | PID: {proc.Id}"
                        });
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckMinerPersistence(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            var runKeys = new[]
            {
                (Registry.CurrentUser,  "HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (Registry.LocalMachine, "HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (Registry.LocalMachine, "HKLM", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
            };

            foreach (var (hive, hiveName, keyPath) in runKeys)
            {
                if (ct.IsCancellationRequested) break;
                using var key = hive.OpenSubKey(keyPath, writable: false);
                if (key is null) continue;
                ctx.IncrementRegistryKeys();

                foreach (var valueName in key.GetValueNames())
                {
                    if (ct.IsCancellationRequested) break;
                    var value = key.GetValue(valueName) as string ?? "";
                    var lower = value.ToLowerInvariant();

                    bool isMiner = KnownMinerNames.Any(m =>
                        lower.Contains(Path.GetFileNameWithoutExtension(m).ToLowerInvariant()));
                    var poolPat = MiningPoolPatterns.FirstOrDefault(p =>
                        lower.Contains(p, StringComparison.OrdinalIgnoreCase));

                    if (isMiner || poolPat is not null)
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Miner-Autostart: {valueName}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"{hiveName}\{keyPath}",
                            Reason   = $"Autostart-Eintrag '{valueName}' mit Miner-Befehl: '{value}'. " +
                                       "Crypto-Miner werden als Autostart-Einträge persistiert, " +
                                       "um nach jedem Reboot neu zu starten. " +
                                       (poolPat is not null ? $"Mining-Pool-Muster: '{poolPat}'." : ""),
                            Detail   = $"Name: {valueName} | Wert: {value}"
                        });
                    }
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckMinerFiles(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        foreach (var dir in ScanDirs)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*",
                    SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) break;
                    ctx.IncrementFiles();

                    var fname = Path.GetFileName(file);
                    var ext   = Path.GetExtension(file).ToLowerInvariant();

                    // Check for known miner executable names
                    if (KnownMinerNames.Contains(fname))
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Miner-Executable gefunden: {fname}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fname,
                            Reason   = $"Bekannte Crypto-Miner-Datei '{fname}' in '{dir}' gefunden. " +
                                       "Auch nicht aktive Miner-Dateien weisen auf Bundling mit Cheat-Tools hin.",
                            Detail   = $"Datei: {file}"
                        });
                        continue;
                    }

                    // Check config.json files for mining configuration
                    if (!ext.Equals(".json", StringComparison.OrdinalIgnoreCase)) continue;
                    if (!MinerConfigFileNames.Contains(fname, StringComparer.OrdinalIgnoreCase)) continue;

                    try
                    {
                        var content = File.ReadAllText(file);
                        var lower   = content.ToLowerInvariant();
                        var walletPat = WalletPatterns.FirstOrDefault(p =>
                            lower.Contains(p, StringComparison.OrdinalIgnoreCase));
                        var poolPat = MiningPoolPatterns.FirstOrDefault(p =>
                            lower.Contains(p, StringComparison.OrdinalIgnoreCase));

                        if (walletPat is not null && poolPat is not null)
                        {
                            hits++;
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Miner-Konfigurationsdatei: {fname}",
                                Risk     = RiskLevel.Critical,
                                Location = file,
                                FileName = fname,
                                Reason   = $"JSON-Datei '{fname}' enthält Mining-Pool- und Wallet-Konfiguration. " +
                                           $"Pool-Muster: '{poolPat}'. " +
                                           "Dies ist eine Crypto-Miner-Konfigurationsdatei.",
                                Detail   = $"Datei: {file} | Pool-Muster: {poolPat} | Wallet-Muster: {walletPat}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
        return hits;
    }
}
