using System.Diagnostics;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class CryptoMinerCheatBundleScanModule : IScanModule
{
    public string Name => "Crypto Miner & Cheat Bundle Scan";
    public double Weight => 3.1;
    public int ParallelGroup => 4;

    private const string ModuleName = "CryptoMinerCheatBundle";

    // ── Known miner executable names ─────────────────────────────────────────

    private static readonly HashSet<string> KnownMinerExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "xmrig.exe",
        "xmrig-notls.exe",
        "xmrig-cuda.exe",
        "xmrig-mo.exe",
        "xmrig_x64.exe",
        "xmrig_x86.exe",
        "xmrig-proxy.exe",
        "xmr-stak.exe",
        "xmr-stak-cpu.exe",
        "xmr-stak-amd.exe",
        "xmr-stak-nvidia.exe",
        "cast-xmr.exe",
        "ryo.exe",
        "phoenixminer.exe",
        "phoenix_miner.exe",
        "ethminer.exe",
        "eth_miner.exe",
        "trex.exe",
        "t-rex.exe",
        "t_rex.exe",
        "nbminer.exe",
        "nb_miner.exe",
        "teamredminer.exe",
        "team_red_miner.exe",
        "lolminer.exe",
        "lol_miner.exe",
        "gminer.exe",
        "g_miner.exe",
        "nanominer.exe",
        "nano_miner.exe",
        "srbminer.exe",
        "srbminer-multi.exe",
        "bzminer.exe",
        "rigel.exe",
        "wildrig.exe",
        "wildrig-multi.exe",
        "miniZ.exe",
        "miniz.exe",
        "z-enemy.exe",
        "zenemy.exe",
        "kawpowminer.exe",
        "cpuminer.exe",
        "cpuminer-opt.exe",
        "cpuminer-multi.exe",
        "minerd.exe",
        "cgminer.exe",
        "cgminer_x64.exe",
        "bfgminer.exe",
        "claymore.exe",
        "claymore_dual_miner.exe",
        "ethdcrMiner64.exe",
        "nsgpucnminer.exe",
        "miner.exe",
        "cryptominer.exe",
        "coin_miner.exe",
        "coinminer.exe",
        "monero_miner.exe",
        "xmr_miner.exe",
        "eth_miner.exe",
        "bitcoin_miner.exe",
        "btc_miner.exe",
        "crypto_miner.exe",
        "winftp.exe",
        "winlogon_.exe",
        "svchost32.exe",
        "svchost64.exe",
        "lsass_.exe",
        "csrss_.exe",
        "explorer_.exe",
        "taskhost_.exe",
        "taskhostw_.exe",
        "conhost_.exe",
        "spoolsv_.exe",
        "services_.exe",
        "wuauclt_.exe",
        "dllhost_.exe",
        "rundll32_.exe",
        "sihost_.exe",
        "systemoptimizer.exe",
        "windowsoptimizer.exe",
        "windows_update.exe",
        "windowsupdate_.exe",
        "windowsupdater.exe",
        "sysmonitor.exe",
        "sys_monitor.exe",
        "sysupdater.exe",
        "updater_.exe",
        "helper_.exe",
        "service_.exe",
        "agent_.exe",
        "mshelper.exe",
        "nsgpucnminer64.exe",
    };

    // ── Known RAT / stealer / malware bundled with cheats ────────────────────

    private static readonly HashSet<string> KnownMalwareBundleExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "njrat.exe",
        "njclient.exe",
        "asyncrat.exe",
        "asyncclient.exe",
        "async_rat.exe",
        "dcrat.exe",
        "dc_rat.exe",
        "darkcomet.exe",
        "darkcometrat.exe",
        "quasar.exe",
        "quasarrat.exe",
        "remcos.exe",
        "remcosrat.exe",
        "nanocore.exe",
        "nanocorerat.exe",
        "orcusrat.exe",
        "orcus.exe",
        "stormkitty.exe",
        "redline.exe",
        "redline_stealer.exe",
        "raccoon.exe",
        "raccoon_stealer.exe",
        "vidar.exe",
        "vidar_stealer.exe",
        "mars_stealer.exe",
        "marsstealer.exe",
        "azorult.exe",
        "azorultstealer.exe",
        "loki.exe",
        "lokibot.exe",
        "phemedrone.exe",
        "lumma.exe",
        "lummastealer.exe",
        "meta_stealer.exe",
        "metastealer.exe",
        "titanstealer.exe",
        "titan_stealer.exe",
        "patriot_stealer.exe",
        "pandorastealer.exe",
        "genesis_stealer.exe",
        "clipbanker.exe",
        "clip_banker.exe",
        "clipper.exe",
        "crypto_clipper.exe",
        "cryptoclip.exe",
        "discord_token_grabber.exe",
        "discord_grab.exe",
        "tokengrabber.exe",
        "token_grabber.exe",
        "grab_discord.exe",
        "discordgrabber.exe",
        "discordtoken.exe",
        "discordhack.exe",
        "browser_stealer.exe",
        "password_stealer.exe",
        "passgrab.exe",
        "cookie_stealer.exe",
        "walletstealer.exe",
        "wallet_stealer.exe",
        "crypto_stealer.exe",
        "keylogger.exe",
        "keylog.exe",
        "ratloader.exe",
        "rat_loader.exe",
        "stubcryptor.exe",
        "crypter.exe",
        "crypter64.exe",
        "payload.exe",
        "dropper.exe",
        "loader_.exe",
        "injector_.exe",
        "builder_.exe",
    };

    // ── Miner config file content patterns ───────────────────────────────────

    private static readonly string[] MinerConfigSignatures =
    {
        "\"pool\"",
        "\"pools\"",
        "\"wallet\"",
        "\"worker\"",
        "\"user\"",
        "\"pass\"",
        "\"algo\"",
        "\"algorithm\"",
        "\"cpu-threads\"",
        "\"cuda\"",
        "\"opencl\"",
        "\"gpu-threads\"",
        "\"donate-level\"",
        "\"api-port\"",
        "\"background\"",
        "\"log-file\"",
        "\"print-time\"",
        "\"max-cpu-usage\"",
        "\"cpu-priority\"",
        "\"nicehash\"",
        "\"tls\"",
        "\"keepalive\"",
        "\"retries\"",
        "\"retry-pause\"",
        "stratum+tcp://",
        "stratum+ssl://",
        "stratum2+tcp://",
        "stratum2+ssl://",
        "pool.supportxmr.com",
        "pool.minexmr.com",
        "xmrpool.eu",
        "moneroocean.stream",
        "gulf.moneropool.com",
        "monerohash.com",
        "xmrig.com",
        "c3pool.com",
        "hashvault.pro",
        "xmr.nanopool.org",
        "ethermine.org",
        "2miners.com",
        "flexpool.io",
        "hiveon.net",
        "daggerhashimoto",
        "ethash",
        "kawpow",
        "randomx",
        "cn/r",
        "cryptonight",
        "autolykos",
        "kheavyhash",
        "zelhash",
        "beamhashIII",
    };

    // ── Known miner pool domains ──────────────────────────────────────────────

    private static readonly string[] KnownMinerPoolDomains =
    {
        "pool.supportxmr.com",
        "pool.minexmr.com",
        "xmrpool.eu",
        "moneroocean.stream",
        "gulf.moneropool.com",
        "monerohash.com",
        "xmrig.com",
        "c3pool.com",
        "hashvault.pro",
        "xmr.nanopool.org",
        "ethermine.org",
        "2miners.com",
        "2miners.com",
        "flexpool.io",
        "hiveon.net",
        "f2pool.com",
        "antpool.com",
        "viabtc.com",
        "slushpool.com",
        "poolin.com",
        "miningpoolhub.com",
        "nicehash.com",
        "prohashing.com",
        "zpool.ca",
        "mining4people.com",
        "coinotron.com",
        "dwarfpool.com",
        "nanopool.org",
        "flypool.org",
        "miningrigrentals.com",
        "sparkpool.com",
        "k1pool.com",
        "solopool.org",
        "woolypooly.com",
        "minerpool.net",
        "herominers.com",
        "rxpool.net",
        "sunpool.top",
        "luxor.tech",
        "foundryusapool.com",
        "sigmapool.com",
    };

    // ── Discord token grabber script signatures ───────────────────────────────

    private static readonly string[] DiscordTokenGrabberSignatures =
    {
        "discord",
        "token",
        "LOCALAPPDATA",
        "leveldb",
        "Local Storage",
        "tokens",
        "grab",
        "steal",
        "send",
        "webhook",
        "discord.com/api/webhooks",
        "discordapp.com/api/webhooks",
        "Authorization",
        "x-super-properties",
        "requests.get",
        "requests.post",
        "urllib",
        "httpx",
        "aiohttp",
        "base64",
        "json.loads",
        "json.dumps",
        "os.path.join",
        "os.listdir",
        "sqlite3",
        "Crypto.Cipher",
        "win32crypt",
        "CryptUnprotectData",
        "GetForegroundWindow",
        "GetClipboardData",
        "SetClipboardData",
    };

    // ── Clipboard hijacker signatures ─────────────────────────────────────────

    private static readonly string[] ClipboardHijackerSignatures =
    {
        "GetClipboardData",
        "SetClipboardData",
        "OpenClipboard",
        "EmptyClipboard",
        "CloseClipboard",
        "CF_TEXT",
        "CF_UNICODETEXT",
        "bitcoin",
        "ethereum",
        "monero",
        "wallet",
        "bc1",
        "0x",
        "BTC",
        "ETH",
        "XMR",
        "LTC",
        "USDT",
        "DOGE",
        "clipboard.*monitor",
        "monitor.*clipboard",
        "replace.*address",
        "address.*replace",
        "swap.*wallet",
        "wallet.*swap",
        "crypto.*clip",
        "clip.*hijack",
    };

    // ── Fake "anti-ban" / spyware tool names ─────────────────────────────────

    private static readonly HashSet<string> FakeAntiBanSpywareNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "anti_ban.exe",
        "antiban.exe",
        "anti-ban.exe",
        "ban_bypass.exe",
        "ban_protection.exe",
        "banprotect.exe",
        "vac_bypass.exe",
        "eac_bypass.exe",
        "be_bypass.exe",
        "bypass_vac.exe",
        "bypass_eac.exe",
        "bypass_be.exe",
        "no_ban.exe",
        "noban.exe",
        "unban.exe",
        "ban_remover.exe",
        "hwid_spoof.exe",
        "hwidspoof.exe",
        "hwid_cleaner.exe",
        "hwidcleaner.exe",
        "spoofer.exe",
        "hwid_bypass.exe",
        "serialspoof.exe",
        "serial_spoof.exe",
        "mac_spoof.exe",
        "macspoof.exe",
        "driver_cleaner.exe",
        "drivercleaner.exe",
        "trace_cleaner.exe",
        "tracecleaner.exe",
        "cleaner_pro.exe",
        "ac_cleaner.exe",
        "anticheat_cleaner.exe",
        "vac_cleaner.exe",
        "eac_cleaner.exe",
        "cleanup_tool.exe",
        "safe_loader.exe",
        "safeloader.exe",
        "secure_loader.exe",
        "crypto_protect.exe",
        "protect_loader.exe",
        "loader_protector.exe",
        "stealth_loader.exe",
        "stealthloader.exe",
        "ghost_loader.exe",
        "phantom_loader.exe",
        "shadow_loader.exe",
    };

    // ── Task Scheduler miner/malware persistence names ────────────────────────

    private static readonly string[] SuspiciousScheduledTaskNames =
    {
        "WindowsUpdate",
        "Windows Update",
        "WindowsOptimizer",
        "SystemOptimizer",
        "System Optimizer",
        "SystemMaintenance",
        "System Maintenance",
        "WindowsMaintenance",
        "Windows Maintenance",
        "WindowsHelper",
        "SystemHelper",
        "System Helper",
        "MicrosoftUpdate",
        "Microsoft Update",
        "UpdateChecker",
        "Update Checker",
        "ServiceUpdater",
        "Service Updater",
        "MSUpdater",
        "WinUpdater",
        "WindowsDefenderUpdate",
        "DriverUpdate",
        "Driver Update",
        "SecurityUpdate",
        "Security Update",
        "FlashUpdate",
        "Flash Update",
        "JavaUpdate",
        "Java Update",
        "AdobeUpdate",
        "Adobe Update",
        "SysMonitor",
        "SystemMonitor",
        "WinMonitor",
        "MinerService",
        "Miner Service",
        "CoinMiner",
        "Coin Miner",
        "CryptoMiner",
        "Crypto Miner",
        "XMRig",
        "XmrService",
        "PoolMiner",
        "NetworkService_",
        "LocalService_",
    };

    // ── Registry run key miner/malware indicators ─────────────────────────────

    private static readonly string[] MinerMalwareRunKeyNames =
    {
        "xmrig",
        "xmr-stak",
        "phoenixminer",
        "trex",
        "nbminer",
        "lolminer",
        "gminer",
        "nanominer",
        "srbminer",
        "cpuminer",
        "cryptominer",
        "coinminer",
        "njrat",
        "asyncrat",
        "dcrat",
        "darkcomet",
        "quasar",
        "remcos",
        "redline",
        "raccoon",
        "vidar",
        "lumma",
        "clipbanker",
        "token_grabber",
        "discord_grab",
        "systemminer",
        "winsvc",
        "winupd",
        "svcupd",
        "cryptosvc",
        "miner_svc",
    };

    // ── Cheat installer directory names ──────────────────────────────────────

    private static readonly string[] CheatInstallerDirKeywords =
    {
        "cheat",
        "hack",
        "aimbot",
        "esp",
        "wallhack",
        "inject",
        "bypass",
        "spoofer",
        "loader",
        "trainer",
        "modmenu",
        "mod_menu",
        "kiddion",
        "onetap",
        "gamesense",
        "2take1",
        "cherax",
        "aimware",
        "fatality",
        "neverlose",
        "skeet",
        "hvh",
        "fivem_cheat",
        "gta_cheat",
        "rust_cheat",
        "cs2_cheat",
        "csgo_cheat",
        "warzone_cheat",
        "fortnite_cheat",
        "apex_cheat",
        "free_cheat",
        "freecheat",
        "external_cheat",
        "internal_cheat",
        "premium_cheat",
        "crack",
        "keygen",
        "activator",
    };

    // ── Search roots ─────────────────────────────────────────────────────────

    private static readonly string[] MinerSearchRoots;

    static CryptoMinerCheatBundleScanModule()
    {
        var roots = new List<string>();

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var localLow = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "AppData", "LocalLow");
        var temp = Path.GetTempPath();
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "Downloads");
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        roots.Add(appData);
        roots.Add(localAppData);
        roots.Add(localLow);
        roots.Add(temp);
        roots.Add(desktop);
        roots.Add(downloads);
        roots.Add(docs);
        roots.Add(userProfile);
        roots.Add(Path.Combine(localAppData, "Temp"));
        roots.Add(Path.Combine(localAppData, "Programs"));
        roots.Add(Path.Combine(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"));

        var systemDrive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.System)) ?? "C:\\";
        roots.Add(Path.Combine(systemDrive, "Temp"));
        roots.Add(Path.Combine(systemDrive, "Users", "Public"));
        roots.Add(Path.Combine(systemDrive, "ProgramData"));

        MinerSearchRoots = roots.Where(r => !string.IsNullOrEmpty(r)).ToArray();
    }

    // ─────────────────────────────────────────────────────────────────────────

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.00, ModuleName, "Scanning running processes for crypto miners...");
        ScanRunningProcesses(ctx, ct);

        ctx.Report(0.08, ModuleName, "Scanning file system for miner executables in cheat directories...");
        await ScanCheatDirectoriesForMinersAsync(ctx, ct);

        ctx.Report(0.20, ModuleName, "Scanning for miner config files (config.json, pools.txt)...");
        await ScanMinerConfigFilesAsync(ctx, ct);

        ctx.Report(0.32, ModuleName, "Scanning hosts file for miner pool domain modifications...");
        await ScanHostsFileForMinerPoolsAsync(ctx, ct);

        ctx.Report(0.38, ModuleName, "Scanning Task Scheduler for miner/malware persistence...");
        ScanScheduledTasksForMinerPersistence(ctx, ct);

        ctx.Report(0.46, ModuleName, "Scanning registry Run keys for miner/malware persistence...");
        ScanRegistryRunKeysForMiners(ctx, ct);

        ctx.Report(0.53, ModuleName, "Scanning for RAT artifacts bundled with cheats...");
        await ScanForRatArtifactsAsync(ctx, ct);

        ctx.Report(0.62, ModuleName, "Scanning for password stealer artifacts...");
        await ScanForStealerArtifactsAsync(ctx, ct);

        ctx.Report(0.70, ModuleName, "Scanning for Discord token grabber scripts...");
        await ScanForDiscordTokenGrabbersAsync(ctx, ct);

        ctx.Report(0.78, ModuleName, "Scanning for clipboard hijacker DLLs...");
        await ScanForClipboardHijackersAsync(ctx, ct);

        ctx.Report(0.84, ModuleName, "Scanning for fake anti-ban / spyware tools...");
        await ScanForFakeAntiBanToolsAsync(ctx, ct);

        ctx.Report(0.90, ModuleName, "Scanning Startup folder for malware persistence...");
        ScanStartupFolderForMalware(ctx, ct);

        ctx.Report(0.95, ModuleName, "Scanning temp directories for GPU/CPU miner artifacts...");
        await ScanTempForMinerArtifactsAsync(ctx, ct);

        ctx.Report(1.00, ModuleName, "Crypto miner & cheat bundle scan complete.");
    }

    // ── Running process scan ──────────────────────────────────────────────────

    private static void ScanRunningProcesses(ScanContext ctx, CancellationToken ct)
    {
        var snapshot = ctx.GetProcessSnapshot();
        foreach (var proc in snapshot)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementProcesses();

            string procExeName = proc.ProcessName + ".exe";

            if (KnownMinerExeNames.Contains(procExeName))
            {
                string location = string.Empty;
                try { location = proc.MainModule?.FileName ?? string.Empty; } catch { }

                bool isDisguised = IsDisguisedAsSystemProcess(proc.ProcessName);

                ctx.AddFinding(new Finding
                {
                    Module = ModuleName,
                    Title = $"Crypto miner process running: {proc.ProcessName}",
                    Risk = isDisguised ? RiskLevel.Critical : RiskLevel.High,
                    Location = location,
                    FileName = procExeName,
                    Reason = isDisguised
                        ? $"Crypto miner '{proc.ProcessName}' (PID {proc.Id}) is disguised as a Windows system process. " +
                          "This is a critical indicator of a malicious miner bundled with cheat software: " +
                          "the miner uses a system-process-like name (e.g. svchost32.exe, lsass_.exe) to avoid detection."
                        : $"Crypto miner '{proc.ProcessName}' (PID {proc.Id}) is running. " +
                          "Miners are frequently bundled with free cheat software as a monetization mechanism, " +
                          "running in the background to mine cryptocurrency using the victim's GPU/CPU.",
                    Detail = $"PID={proc.Id} Name={proc.ProcessName} Disguised={isDisguised}",
                });
                continue;
            }

            if (KnownMalwareBundleExeNames.Contains(procExeName))
            {
                string location = string.Empty;
                try { location = proc.MainModule?.FileName ?? string.Empty; } catch { }

                ctx.AddFinding(new Finding
                {
                    Module = ModuleName,
                    Title = $"RAT/stealer malware process running: {proc.ProcessName}",
                    Risk = RiskLevel.Critical,
                    Location = location,
                    FileName = procExeName,
                    Reason = $"'{proc.ProcessName}' (PID {proc.Id}) is a known Remote Access Trojan, stealer, or other " +
                             "malware commonly bundled with free cheat software. " +
                             "Cheat distributors bundle RATs and stealers to harvest credentials, cryptocurrency wallets, " +
                             "Discord tokens, and browser cookies from victims who install their cheats.",
                    Detail = $"PID={proc.Id}",
                });
            }
        }
    }

    private static bool IsDisguisedAsSystemProcess(string processName)
    {
        return processName.EndsWith("_", StringComparison.Ordinal) ||
               (processName.Contains("svchost") && processName != "svchost") ||
               (processName.Contains("lsass") && processName != "lsass") ||
               (processName.Contains("csrss") && processName != "csrss") ||
               (processName.Contains("winlogon") && processName != "winlogon") ||
               (processName.Contains("explorer") && processName != "explorer") ||
               processName.Equals("svchost32", StringComparison.OrdinalIgnoreCase) ||
               processName.Equals("svchost64", StringComparison.OrdinalIgnoreCase) ||
               processName.Equals("wuauclt_", StringComparison.OrdinalIgnoreCase) ||
               processName.Equals("services_", StringComparison.OrdinalIgnoreCase);
    }

    // ── Cheat directory miner scan ────────────────────────────────────────────

    private static async Task ScanCheatDirectoriesForMinersAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in MinerSearchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> subDirs;
            try
            {
                subDirs = Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var subDir in subDirs)
            {
                ct.ThrowIfCancellationRequested();
                var dirName = Path.GetFileName(subDir).ToLowerInvariant();

                bool isCheatDir = false;
                foreach (var keyword in CheatInstallerDirKeywords)
                {
                    if (dirName.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        isCheatDir = true;
                        break;
                    }
                }
                if (!isCheatDir) continue;

                IEnumerable<string> dirFiles;
                try
                {
                    dirFiles = Directory.EnumerateFiles(subDir, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in dirFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);

                    if (KnownMinerExeNames.Contains(fileName))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = ModuleName,
                            Title = $"Crypto miner bundled in cheat directory: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Crypto miner '{fileName}' found inside cheat-related directory '{subDir}'. " +
                                     "This is the primary indicator of a cheat-miner bundle: cheat distributors " +
                                     "drop miner executables alongside cheat DLLs/EXEs and launch both on startup, " +
                                     "monetizing the victim's hardware while they play.",
                            Detail = $"CheatDir={subDir} MinerFile={file}",
                        });
                        continue;
                    }

                    if (KnownMalwareBundleExeNames.Contains(fileName))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = ModuleName,
                            Title = $"Malware bundled in cheat directory: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Malware executable '{fileName}' found alongside cheat files in '{subDir}'. " +
                                     "Free cheat packages frequently include RATs, credential stealers, or clipboard " +
                                     "hijackers. This file has a name matching known malware commonly found in " +
                                     "cheat bundles.",
                            Detail = $"CheatDir={subDir} MalwareFile={file}",
                        });
                    }
                }
            }
        }

        await Task.CompletedTask;
    }

    // ── Miner config file scan ────────────────────────────────────────────────

    private static async Task ScanMinerConfigFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var configFileNames = new[]
        {
            "config.json",
            "pools.txt",
            "pool.txt",
            "mining.json",
            "miner.conf",
            "miner.cfg",
            "miner.json",
            "xmrig.json",
            "xmrig.conf",
            "worker.json",
            "config_cpu.json",
            "config_gpu.json",
            "config_amd.json",
            "config_nvidia.json",
            "mining_config.json",
            "crypto_config.json",
            "pool_config.json",
            "stratum_config.json",
        };

        foreach (var root in MinerSearchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> allFiles;
            try
            {
                allFiles = Directory.EnumerateFiles(root, "*.json", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in allFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);
                bool isKnownConfigName = false;
                foreach (var cfgName in configFileNames)
                {
                    if (fileName.Equals(cfgName, StringComparison.OrdinalIgnoreCase))
                    {
                        isKnownConfigName = true;
                        break;
                    }
                }
                if (!isKnownConfigName) continue;

                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                int matchCount = 0;
                var matches = new List<string>();
                foreach (var sig in MinerConfigSignatures)
                {
                    if (content.Contains(sig, StringComparison.OrdinalIgnoreCase))
                    {
                        matchCount++;
                        matches.Add(sig);
                        if (matchCount >= 15) break;
                    }
                }

                if (matchCount >= 4)
                {
                    string poolInfo = string.Empty;
                    foreach (var domain in KnownMinerPoolDomains)
                    {
                        if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            poolInfo = domain;
                            break;
                        }
                    }

                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"Crypto miner configuration file found: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Miner configuration file '{fileName}' found at '{file}' with {matchCount} miner config " +
                                 $"indicators: {string.Join(", ", matches.Take(6))}. " +
                                 (string.IsNullOrEmpty(poolInfo)
                                     ? "File contains pool, wallet, and algorithm settings consistent with a cryptocurrency miner."
                                     : $"Pool address '{poolInfo}' identified in config.") +
                                 " This file configures a cryptocurrency miner, frequently dropped by cheat installers " +
                                 "to mine Monero or Ethereum in the background.",
                        Detail = $"Path={file} Pool={poolInfo} Matches={string.Join("|", matches)}",
                    });
                }
            }
        }
    }

    // ── Hosts file miner pool scan ────────────────────────────────────────────

    private static async Task ScanHostsFileForMinerPoolsAsync(ScanContext ctx, CancellationToken ct)
    {
        var hostsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "drivers", "etc", "hosts");

        if (!File.Exists(hostsPath)) return;

        ctx.IncrementFiles();

        string hostsContent;
        try
        {
            using var fs = new FileStream(hostsPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            hostsContent = await sr.ReadToEndAsync();
        }
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }

        var lines = hostsContent.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            ct.ThrowIfCancellationRequested();
            var trimmed = line.Trim();
            if (trimmed.StartsWith("#", StringComparison.Ordinal)) continue;

            foreach (var poolDomain in KnownMinerPoolDomains)
            {
                if (!trimmed.Contains(poolDomain, StringComparison.OrdinalIgnoreCase)) continue;

                if (trimmed.StartsWith("0.0.0.0", StringComparison.Ordinal) ||
                    trimmed.StartsWith("127.0.0.1", StringComparison.Ordinal))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"Miner pool domain blocked in hosts file: {poolDomain}",
                        Risk = RiskLevel.Medium,
                        Location = hostsPath,
                        FileName = "hosts",
                        Reason = $"Miner pool domain '{poolDomain}' is blocked in the hosts file (redirected to {trimmed.Split(' ')[0]}). " +
                                 "This can indicate a previous infection where the attacker's miner was later removed, " +
                                 "or a competing malware blocking rival miner pools. It proves prior miner activity.",
                        Detail = $"HostsEntry={trimmed.Trim()}",
                    });
                }
                else
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"Miner pool domain entry in hosts file: {poolDomain}",
                        Risk = RiskLevel.High,
                        Location = hostsPath,
                        FileName = "hosts",
                        Reason = $"Mining pool domain '{poolDomain}' appears in the hosts file as '{trimmed.Trim()}'. " +
                                 "Malware may add pool domains to the hosts file to redirect mining traffic to " +
                                 "a specific pool or to prevent pool-IP-based blocking from working.",
                        Detail = $"HostsEntry={trimmed.Trim()}",
                    });
                }
                break;
            }
        }
    }

    // ── Task Scheduler persistence scan ──────────────────────────────────────

    private static void ScanScheduledTasksForMinerPersistence(ScanContext ctx, CancellationToken ct)
    {
        var scheduledTasksDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "Tasks");

        if (!Directory.Exists(scheduledTasksDir)) return;

        IEnumerable<string> taskFiles;
        try
        {
            taskFiles = Directory.EnumerateFiles(scheduledTasksDir, "*", SearchOption.AllDirectories);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var taskFile in taskFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var taskName = Path.GetFileName(taskFile);
            var taskNameLower = taskName.ToLowerInvariant();

            bool isSuspicious = false;
            string matchedTaskName = string.Empty;
            foreach (var suspName in SuspiciousScheduledTaskNames)
            {
                if (taskNameLower.Contains(suspName.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase))
                {
                    isSuspicious = true;
                    matchedTaskName = suspName;
                    break;
                }
            }
            if (!isSuspicious) continue;

            string taskContent;
            try
            {
                using var fs = new FileStream(taskFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                taskContent = sr.ReadToEnd();
            }
            catch (IOException) { continue; }
            catch (UnauthorizedAccessException) { continue; }

            bool hasMinerRef = false;
            string minerRef = string.Empty;
            foreach (var minerExe in KnownMinerExeNames)
            {
                if (taskContent.Contains(minerExe, StringComparison.OrdinalIgnoreCase))
                {
                    hasMinerRef = true;
                    minerRef = minerExe;
                    break;
                }
            }

            bool hasMalwareRef = false;
            string malwareRef = string.Empty;
            if (!hasMinerRef)
            {
                foreach (var malExe in KnownMalwareBundleExeNames)
                {
                    if (taskContent.Contains(malExe, StringComparison.OrdinalIgnoreCase))
                    {
                        hasMalwareRef = true;
                        malwareRef = malExe;
                        break;
                    }
                }
            }

            bool hasMinerConfig = false;
            foreach (var cfgSig in MinerConfigSignatures)
            {
                if (taskContent.Contains(cfgSig, StringComparison.OrdinalIgnoreCase))
                {
                    hasMinerConfig = true;
                    break;
                }
            }

            if (!hasMinerRef && !hasMalwareRef && !hasMinerConfig) continue;

            ctx.AddFinding(new Finding
            {
                Module = ModuleName,
                Title = $"Scheduled task with suspicious name launches miner/malware: {taskName}",
                Risk = RiskLevel.Critical,
                Location = taskFile,
                FileName = taskName,
                Reason = $"Scheduled task '{taskName}' uses a system-like name ('{matchedTaskName}') to hide miner/malware persistence. " +
                         (hasMinerRef ? $"Task references miner: '{minerRef}'. " : string.Empty) +
                         (hasMalwareRef ? $"Task references malware: '{malwareRef}'. " : string.Empty) +
                         "Cheat bundles create scheduled tasks with Windows-sounding names to ensure miner " +
                         "or RAT persistence across reboots without appearing suspicious in task lists.",
                Detail = $"TaskFile={taskFile} MinerRef={minerRef} MalwareRef={malwareRef} MatchedName={matchedTaskName}",
            });
        }
    }

    // ── Registry Run key miner scan ───────────────────────────────────────────

    private static void ScanRegistryRunKeysForMiners(ScanContext ctx, CancellationToken ct)
    {
        var runKeyPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        };

        foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
        {
            foreach (var runKeyPath in runKeyPaths)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var key = hive.OpenSubKey(runKeyPath);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();

                    foreach (var valueName in key.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        var val = key.GetValue(valueName) as string ?? string.Empty;
                        var valLower = val.ToLowerInvariant();
                        var nameLower = valueName.ToLowerInvariant();

                        bool minerMatch = false;
                        string matchedMiner = string.Empty;
                        foreach (var minerKey in MinerMalwareRunKeyNames)
                        {
                            if (nameLower.Contains(minerKey) || valLower.Contains(minerKey))
                            {
                                minerMatch = true;
                                matchedMiner = minerKey;
                                break;
                            }
                        }

                        if (!minerMatch)
                        {
                            foreach (var minerExe in KnownMinerExeNames)
                            {
                                if (valLower.Contains(minerExe.ToLowerInvariant()))
                                {
                                    minerMatch = true;
                                    matchedMiner = minerExe;
                                    break;
                                }
                            }
                        }

                        if (!minerMatch)
                        {
                            foreach (var malExe in KnownMalwareBundleExeNames)
                            {
                                if (valLower.Contains(malExe.ToLowerInvariant()))
                                {
                                    minerMatch = true;
                                    matchedMiner = malExe;
                                    break;
                                }
                            }
                        }

                        if (!minerMatch) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = ModuleName,
                            Title = $"Miner/malware persisted in registry Run key: {valueName}",
                            Risk = RiskLevel.Critical,
                            Location = $@"{(hive == Registry.CurrentUser ? "HKCU" : "HKLM")}\{runKeyPath}",
                            Reason = $"Registry Run key '{valueName}' = '{val}' references a known miner or malware (matched: '{matchedMiner}'). " +
                                     "This causes the miner or RAT to launch automatically at every Windows login, " +
                                     "providing persistent background mining or remote access even after the cheat is uninstalled.",
                            Detail = $"RunKey={valueName} Value={val} Matched={matchedMiner}",
                        });
                    }
                }
                catch (Exception) { }
            }
        }
    }

    // ── RAT artifact scan ─────────────────────────────────────────────────────

    private static async Task ScanForRatArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var ratConfigSignatures = new[]
        {
            "njrat",
            "asyncrat",
            "dcrat",
            "darkcomet",
            "quasar",
            "remcos",
            "nanocore",
            "orcus",
            "c2_server",
            "c2server",
            "c&c",
            "command_and_control",
            "cnc_server",
            "backdoor",
            "back_door",
            "reverse_shell",
            "reverseshell",
            "rat_config",
            "ratconfig",
            "persistence",
            "keylogger",
            "keylog",
            "screenshot_capture",
            "remoteshell",
            "remote_shell",
            "shellcode",
            "shellexec",
            "CreateRemoteThread",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "LoadLibraryA",
            "GetProcAddress",
            "NtCreateThreadEx",
            "RtlCreateUserThread",
        };

        foreach (var root in MinerSearchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);

                if (!KnownMalwareBundleExeNames.Contains(fileName)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = ModuleName,
                    Title = $"RAT/malware executable found: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason = $"'{fileName}' is a known Remote Access Trojan or malware component. Found at '{file}'. " +
                             "Free cheat distributors frequently bundle RATs with their software to maintain " +
                             "persistent access to victims' machines for credential theft, surveillance, " +
                             "or use in botnets.",
                    Detail = $"Path={file}",
                });
            }

            var configExts = new[] { "*.ini", "*.cfg", "*.json", "*.xml", "*.txt" };
            foreach (var ext in configExts)
            {
                IEnumerable<string> cfgFiles;
                try
                {
                    cfgFiles = Directory.EnumerateFiles(root, ext, SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var cfgFile in cfgFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    var cfgNameLower = Path.GetFileName(cfgFile).ToLowerInvariant();
                    bool nameRelevant = cfgNameLower.Contains("rat") || cfgNameLower.Contains("c2") ||
                                       cfgNameLower.Contains("payload") || cfgNameLower.Contains("server") ||
                                       cfgNameLower.Contains("client") || cfgNameLower.Contains("backdoor") ||
                                       cfgNameLower.Contains("remote");
                    if (!nameRelevant) continue;

                    string content;
                    try
                    {
                        using var fs = new FileStream(cfgFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync();
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    int matchCount = 0;
                    var matches = new List<string>();
                    foreach (var sig in ratConfigSignatures)
                    {
                        if (content.Contains(sig, StringComparison.OrdinalIgnoreCase))
                        {
                            matchCount++;
                            matches.Add(sig);
                        }
                    }

                    if (matchCount >= 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = ModuleName,
                            Title = $"RAT configuration file artifact: {Path.GetFileName(cfgFile)}",
                            Risk = RiskLevel.Critical,
                            Location = cfgFile,
                            FileName = Path.GetFileName(cfgFile),
                            Reason = $"Configuration file '{Path.GetFileName(cfgFile)}' contains {matchCount} RAT indicators: " +
                                     $"{string.Join(", ", matches.Take(5))}. This file configures a Remote Access Trojan " +
                                     "bundled with cheat software.",
                            Detail = $"Path={cfgFile} Matches={string.Join("|", matches)}",
                        });
                    }
                }
            }
        }
    }

    // ── Stealer artifact scan ─────────────────────────────────────────────────

    private static async Task ScanForStealerArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var stealerSignatures = new[]
        {
            "redline",
            "raccoon",
            "vidar",
            "lumma",
            "azorult",
            "lokibot",
            "mars_stealer",
            "phemedrone",
            "stealer",
            "password",
            "credentials",
            "browser_data",
            "chrome",
            "firefox",
            "edge",
            "opera",
            "wallet",
            "crypto_wallet",
            "metamask",
            "exodus",
            "electrum",
            "atomic_wallet",
            "telegram",
            "discord",
            "cookies",
            "autofill",
            "creditcard",
            "credit_card",
            "steam_session",
            "steampath",
            "ssfn",
            "vpn_credentials",
            "ftp_credentials",
            "email_credentials",
            "smtp_credentials",
            "clipboard",
            "screenshot",
            "keylog",
            "hwid",
            "machine_id",
            "exfiltrate",
            "upload",
            "telegram_bot",
            "bot_token",
            "chat_id",
            "webhook",
        };

        foreach (var root in MinerSearchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> pyFiles;
            try
            {
                pyFiles = Directory.EnumerateFiles(root, "*.py", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var pyFile in pyFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(pyFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                int matchCount = 0;
                var matches = new List<string>();
                foreach (var sig in stealerSignatures)
                {
                    if (content.Contains(sig, StringComparison.OrdinalIgnoreCase))
                    {
                        matchCount++;
                        matches.Add(sig);
                        if (matchCount >= 12) break;
                    }
                }

                if (matchCount >= 5)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"Password/credential stealer script found: {Path.GetFileName(pyFile)}",
                        Risk = RiskLevel.Critical,
                        Location = pyFile,
                        FileName = Path.GetFileName(pyFile),
                        Reason = $"Python script '{Path.GetFileName(pyFile)}' contains {matchCount} credential stealer indicators: " +
                                 $"{string.Join(", ", matches.Take(6))}. " +
                                 "Credential stealers are frequently bundled with free cheat software. They harvest " +
                                 "browser passwords, cookies, crypto wallets, Steam sessions, and Discord tokens, " +
                                 "then exfiltrate them to a Telegram bot or HTTP webhook.",
                        Detail = $"Path={pyFile} Signatures={string.Join("|", matches)}",
                    });
                }
            }
        }
    }

    // ── Discord token grabber scan ────────────────────────────────────────────

    private static async Task ScanForDiscordTokenGrabbersAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.GetTempPath(),
        };

        var scriptExts = new[] { "*.py", "*.js", "*.ps1", "*.bat", "*.vbs" };

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            foreach (var ext in scriptExts)
            {
                IEnumerable<string> scriptFiles;
                try
                {
                    scriptFiles = Directory.EnumerateFiles(root, ext, SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var scriptFile in scriptFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(scriptFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync();
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    int matchCount = 0;
                    var matches = new List<string>();
                    foreach (var sig in DiscordTokenGrabberSignatures)
                    {
                        if (content.Contains(sig, StringComparison.OrdinalIgnoreCase))
                        {
                            matchCount++;
                            matches.Add(sig);
                        }
                    }

                    if (matchCount >= 6)
                    {
                        bool hasWebhook = content.Contains("discord.com/api/webhooks", StringComparison.OrdinalIgnoreCase) ||
                                          content.Contains("discordapp.com/api/webhooks", StringComparison.OrdinalIgnoreCase);

                        ctx.AddFinding(new Finding
                        {
                            Module = ModuleName,
                            Title = $"Discord token grabber script: {Path.GetFileName(scriptFile)}",
                            Risk = RiskLevel.Critical,
                            Location = scriptFile,
                            FileName = Path.GetFileName(scriptFile),
                            Reason = $"Script '{Path.GetFileName(scriptFile)}' contains {matchCount} Discord token grabber indicators: " +
                                     $"{string.Join(", ", matches.Take(6))}. " +
                                     (hasWebhook ? "File contains a Discord webhook URL for token exfiltration. " : string.Empty) +
                                     "Discord token grabbers are nearly universal in free cheat packages. They steal " +
                                     "Discord authentication tokens granting full account access, then send them via " +
                                     "webhook to the cheat distributor.",
                            Detail = $"Path={scriptFile} HasWebhook={hasWebhook} Signatures={string.Join("|", matches)}",
                        });
                    }
                }
            }
        }
    }

    // ── Clipboard hijacker scan ───────────────────────────────────────────────

    private static async Task ScanForClipboardHijackersAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in MinerSearchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> dlls;
            try
            {
                dlls = Directory.EnumerateFiles(root, "*.dll", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var dll in dlls)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var dllNameLower = Path.GetFileName(dll).ToLowerInvariant();
                bool nameMatch = dllNameLower.Contains("clip") || dllNameLower.Contains("clipbank") ||
                                 dllNameLower.Contains("wallet") || dllNameLower.Contains("hijack") ||
                                 dllNameLower.Contains("swapper") || dllNameLower.Contains("replace");

                if (!nameMatch) continue;

                string content;
                try
                {
                    using var fs = new FileStream(dll, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                int matchCount = 0;
                var matches = new List<string>();
                foreach (var sig in ClipboardHijackerSignatures)
                {
                    if (content.Contains(sig, StringComparison.OrdinalIgnoreCase))
                    {
                        matchCount++;
                        matches.Add(sig);
                    }
                }

                if (matchCount >= 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"Clipboard hijacker DLL (crypto address swapper): {Path.GetFileName(dll)}",
                        Risk = RiskLevel.Critical,
                        Location = dll,
                        FileName = Path.GetFileName(dll),
                        Reason = $"DLL '{Path.GetFileName(dll)}' contains {matchCount} clipboard hijacking indicators: " +
                                 $"{string.Join(", ", matches.Take(5))}. " +
                                 "Clipboard hijackers monitor the clipboard for cryptocurrency wallet addresses and " +
                                 "silently replace them with the attacker's address. Bundling these with cheats is a " +
                                 "major revenue stream for cheat distributors.",
                        Detail = $"Path={dll} Matches={string.Join("|", matches)}",
                    });
                }
            }
        }
    }

    // ── Fake anti-ban tool scan ───────────────────────────────────────────────

    private static async Task ScanForFakeAntiBanToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in MinerSearchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> exeFiles;
            try
            {
                exeFiles = Directory.EnumerateFiles(root, "*.exe", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var exeFile in exeFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var exeName = Path.GetFileName(exeFile);

                if (!FakeAntiBanSpywareNames.Contains(exeName)) continue;

                string content;
                try
                {
                    using var fs = new FileStream(exeFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                bool hasSpywareIndicator = false;
                string spywareIndicator = string.Empty;
                var spywareKeywords = new[]
                {
                    "webhook", "telegram", "discord.com/api", "bot_token", "chat_id",
                    "password", "cookie", "credential", "keylog", "screenshot",
                    "wallet", "token", "steal", "grab", "exfil", "upload",
                };
                foreach (var kw in spywareKeywords)
                {
                    if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        hasSpywareIndicator = true;
                        spywareIndicator = kw;
                        break;
                    }
                }

                ctx.AddFinding(new Finding
                {
                    Module = ModuleName,
                    Title = $"Fake anti-ban tool (potential spyware): {exeName}",
                    Risk = hasSpywareIndicator ? RiskLevel.Critical : RiskLevel.High,
                    Location = exeFile,
                    FileName = exeName,
                    Reason = hasSpywareIndicator
                        ? $"'{exeName}' presents itself as an anti-ban or HWID spoofer tool but contains spyware indicator '{spywareIndicator}'. " +
                          "Fake anti-ban tools are a social engineering vector: victims are told the tool protects them " +
                          "from bans, but it actually steals credentials, tokens, or mines cryptocurrency."
                        : $"'{exeName}' is a known fake anti-ban or HWID spoofer tool name. " +
                          "These tools are frequently hollow shells or re-branded malware that install miners, " +
                          "RATs, or stealers while claiming to protect against game bans.",
                    Detail = $"Path={exeFile} SpywareIndicator={spywareIndicator}",
                });
            }
        }
    }

    // ── Startup folder scan ───────────────────────────────────────────────────

    private static void ScanStartupFolderForMalware(ScanContext ctx, CancellationToken ct)
    {
        var startupDirs = new[]
        {
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
        };

        foreach (var startupDir in startupDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(startupDir)) continue;

            IEnumerable<string> startupFiles;
            try
            {
                startupFiles = Directory.EnumerateFiles(startupDir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var startupFile in startupFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(startupFile);

                bool isMiner = KnownMinerExeNames.Contains(fileName);
                bool isMalware = KnownMalwareBundleExeNames.Contains(fileName);
                bool isFakeAntiBan = FakeAntiBanSpywareNames.Contains(fileName);

                if (!isMiner && !isMalware && !isFakeAntiBan) continue;

                string category = isMiner ? "Crypto miner" : (isMalware ? "Malware/RAT" : "Fake anti-ban spyware");

                ctx.AddFinding(new Finding
                {
                    Module = ModuleName,
                    Title = $"{category} in Startup folder (persistence): {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = startupFile,
                    FileName = fileName,
                    Reason = $"{category} '{fileName}' found in Windows Startup folder '{startupDir}'. " +
                             "Files in the Startup folder execute automatically at every Windows login. " +
                             "Cheat installers place miners and malware here to ensure they start before " +
                             "any anti-virus scan runs, maintaining persistent access and mining.",
                    Detail = $"StartupDir={startupDir} File={startupFile} Category={category}",
                });
            }
        }
    }

    // ── Temp directory miner artifact scan ────────────────────────────────────

    private static async Task ScanTempForMinerArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var tempDirs = new[]
        {
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
        };

        foreach (var tempDir in tempDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(tempDir)) continue;

            IEnumerable<string> tempFiles;
            try
            {
                tempFiles = Directory.EnumerateFiles(tempDir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var tempFile in tempFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(tempFile);

                if (KnownMinerExeNames.Contains(fileName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"Crypto miner executable in Temp directory: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = tempFile,
                        FileName = fileName,
                        Reason = $"Crypto miner '{fileName}' found in Windows Temp directory '{tempDir}'. " +
                                 "Cheat installers frequently drop miners into %TEMP% or %LOCALAPPDATA%\\Temp " +
                                 "as a staging area before establishing persistence. The miner may have been " +
                                 "dropped by a cheat loader that then copies it to a permanent location.",
                        Detail = $"TempDir={tempDir} MinerFile={tempFile}",
                    });
                    continue;
                }

                if (KnownMalwareBundleExeNames.Contains(fileName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"Malware/RAT executable in Temp directory: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = tempFile,
                        FileName = fileName,
                        Reason = $"Malware executable '{fileName}' found in Temp directory '{tempDir}'. " +
                                 "RATs and stealers bundled with cheat loaders are frequently extracted to Temp " +
                                 "directories during installation. Even if the main cheat was uninstalled, " +
                                 "leftover Temp artifacts prove the malicious bundle was executed.",
                        Detail = $"TempDir={tempDir} MalwareFile={tempFile}",
                    });
                }

                var fileNameLower = fileName.ToLowerInvariant();
                if (fileNameLower.EndsWith(".json", StringComparison.OrdinalIgnoreCase) &&
                    (fileNameLower.Contains("config") || fileNameLower.Contains("pool") ||
                     fileNameLower.Contains("miner") || fileNameLower.Contains("mining")))
                {
                    string content;
                    try
                    {
                        using var fs = new FileStream(tempFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync();
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    int matchCount = 0;
                    foreach (var sig in MinerConfigSignatures)
                    {
                        if (content.Contains(sig, StringComparison.OrdinalIgnoreCase))
                            matchCount++;
                        if (matchCount >= 4) break;
                    }

                    if (matchCount >= 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = ModuleName,
                            Title = $"Miner config file in Temp directory: {fileName}",
                            Risk = RiskLevel.High,
                            Location = tempFile,
                            FileName = fileName,
                            Reason = $"Miner configuration file '{fileName}' found in Temp directory with {matchCount} " +
                                     "miner config indicators. Cheat loaders drop miner configs to Temp before launching " +
                                     "the miner, leaving forensic artifacts even after cleanup attempts.",
                            Detail = $"TempDir={tempDir} ConfigFile={tempFile}",
                        });
                    }
                }
            }
        }
    }
}
