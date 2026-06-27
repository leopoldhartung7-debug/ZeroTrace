using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

public sealed class AltVAntibanForensicScanModule : IScanModule
{
    public string Name => "AltV-Antibann-Forensik";
    public double Weight => 1.1;
    public int ParallelGroup => 4;

    private static readonly string LocalApp =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string RoamingApp =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string TempPath = Path.GetTempPath();
    private static readonly string Desktop =
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private static readonly string[] FileNamePrefixes =
    {
        "altv_unban",
        "altv_hwid_spoof",
        "ban_bypass_altv",
        "altv_ban_evade",
        "hwid_cleaner_altv",
        "altv_fingerprint_wipe",
        "altv_serial_spoof",
        "altv_mac_spoof",
    };

    private static readonly string[] KnownToolExeNames =
    {
        "AltVUnban.exe",
        "HWIDSpoofer.exe",
        "AltVCleaner.exe",
        "BanBypassAltV.exe",
        "altvunban.exe",
        "hwidspoofer.exe",
        "altvcleaner.exe",
        "banbypassaltv.exe",
        "altv_unban.exe",
        "altv_hwid_spoof.exe",
        "ban_bypass_altv.exe",
        "altv_ban_evade.exe",
        "hwid_cleaner_altv.exe",
        "altv_fingerprint_wipe.exe",
        "altv_serial_spoof.exe",
        "altv_mac_spoof.exe",
    };

    private static readonly string[] LogKeywords =
    {
        "altv unban",
        "hwid spoof altv",
        "ban bypass altv",
        "fingerprint wipe altv",
        "serial spoof altv",
        "mac spoof altv",
        "altv ban evade",
        "altv hwid",
        "altv spoofer",
        "altv cleaner",
        "ban evasion altv",
        "altv serial change",
        "altv mac change",
    };

    private static readonly string[] DiscordKeywords =
    {
        "altv unban",
        "hwid spoof altv",
        "ban bypass altv",
        "altv ban evade",
        "altv cleaner",
        "altv spoofer",
        "altv hwid changer",
        "altv serial spoof",
        "altv mac spoof",
        "altv fingerprint",
    };

    private static readonly string[] ScriptKeywords =
    {
        "altv",
        "hwid",
        "serial",
        "macaddress",
        "mac address",
        "ban bypass",
        "unban",
        "fingerprint",
        "volumeserial",
        "volume serial",
        "spoof",
        "cleaner",
    };

    private static readonly string[] RegistryPaths =
    {
        @"Software\AltV\BanBypass",
        @"Software\HWIDSpoofAltV",
        @"Software\AltVUnban",
        @"Software\AltVCleaner",
        @"Software\AltVSpoofer",
        @"Software\AltVBanEvasion",
        @"Software\BanBypassAltV",
        @"Software\AltVHWIDSpoof",
        @"Software\AltVFingerprintWipe",
        @"Software\AltVSerialSpoof",
        @"Software\AltVMacSpoof",
    };

    private static readonly string[] UserAssistBase =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count",
    };

    private static readonly string[] UserAssistCheatKeywords =
    {
        "altv_unban",
        "altv_hwid",
        "altvcleaner",
        "altvunban",
        "banbypassaltv",
        "ban_bypass_altv",
        "altv_ban_evade",
        "hwid_cleaner_altv",
        "altv_fingerprint",
        "altv_serial_spoof",
        "altv_mac_spoof",
        "hwidspoofer",
    };

    private static readonly string[] PrefetchKeywords =
    {
        "ALTV_UNBAN",
        "ALTVUNBAN",
        "BANBYPASSALTV",
        "ALTV_HWID",
        "ALTVCLEANER",
        "HWIDSPOOFER",
        "ALTV_BAN_EVADE",
        "ALTV_FINGERPRINT",
        "ALTV_SERIAL_SPOOF",
        "ALTV_MAC_SPOOF",
        "HWID_CLEANER_ALTV",
        "ALTV_CLEANER",
    };

    private static readonly string[] SuspiciousScriptExtensions =
    {
        ".bat", ".cmd", ".ps1", ".vbs", ".js",
    };

    private static readonly string[] AltVConfigFileNames =
    {
        "altv.cfg",
        "altv-client.cfg",
        "client.cfg",
        "data.json",
        "settings.json",
    };

    private static readonly string[] FingerprintWipedIndicators =
    {
        "null",
        "0000000000000000",
        "cleared",
        "wiped",
        "spoofed",
        "changed",
        "modified",
        "fake",
        "bypass",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starte alt:V Antibann-Forensik...");

        await Task.WhenAll(
            CheckFileSystemArtifacts(ctx, ct),
            CheckLogFiles(ctx, ct),
            CheckRegistryArtifacts(ctx, ct),
            CheckPrefetchArtifacts(ctx, ct),
            CheckUserAssistArtifacts(ctx, ct),
            CheckDiscordArtifacts(ctx, ct),
            CheckSuspiciousScripts(ctx, ct),
            CheckTempSpooferFiles(ctx, ct),
            CheckAltVConfigFiles(ctx, ct),
            CheckAltVFingerprintDirectories(ctx, ct)
        );

        ctx.Report(1.0, Name, "alt:V Antibann-Forensik abgeschlossen");
    }

    private Task CheckFileSystemArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var searchDirs = new[]
            {
                LocalApp,
                RoamingApp,
                TempPath,
                Desktop,
                Path.Combine(LocalApp, "Temp"),
                Path.Combine(UserProfile, "Downloads"),
                Path.Combine(UserProfile, "Documents"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        var fn = Path.GetFileName(file);
                        var fnLower = fn.ToLowerInvariant();

                        bool matchesPrefix = FileNamePrefixes.Any(p =>
                            fnLower.StartsWith(p, StringComparison.OrdinalIgnoreCase));
                        bool matchesKnownTool = KnownToolExeNames.Any(t =>
                            fnLower.Equals(t, StringComparison.OrdinalIgnoreCase));

                        if (!matchesPrefix && !matchesKnownTool) continue;

                        var risk = matchesKnownTool ? RiskLevel.High : RiskLevel.High;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"alt:V Antibann-Tool-Datei: {fn}",
                            Risk     = risk,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Datei '{fn}' in '{dir}' entspricht einem bekannten alt:V " +
                                       "Ban-Umgehungs- oder HWID-Spoofer-Artefakt. Diese Tools " +
                                       "manipulieren Hardware-IDs um alt:V Sperren zu umgehen.",
                            Detail   = $"Verzeichnis: {dir} | Datei: {fn}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }

                try
                {
                    foreach (var subDir in Directory.EnumerateDirectories(dir, "*", SearchOption.TopDirectoryOnly))
                    {
                        if (ct.IsCancellationRequested) return;
                        var subDirName = Path.GetFileName(subDir).ToLowerInvariant();

                        bool dirMatchesPrefix = FileNamePrefixes.Any(p =>
                            subDirName.Contains(p.Replace("_", ""), StringComparison.OrdinalIgnoreCase) ||
                            subDirName.Contains(p, StringComparison.OrdinalIgnoreCase));

                        if (!dirMatchesPrefix) continue;

                        try
                        {
                            foreach (var file in Directory.EnumerateFiles(subDir, "*", SearchOption.AllDirectories))
                            {
                                if (ct.IsCancellationRequested) return;
                                ctx.IncrementFiles();

                                var fn = Path.GetFileName(file);
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"alt:V Antibann-Tool-Verzeichnis: {subDirName}",
                                    Risk     = RiskLevel.High,
                                    Location = file,
                                    FileName = fn,
                                    Reason   = $"Datei '{fn}' in Unterverzeichnis '{subDir}' gefunden, " +
                                               "das einem alt:V Ban-Umgehungstool entspricht.",
                                    Detail   = $"Unterverzeichnis: {subDir}"
                                });
                            }
                        }
                        catch (UnauthorizedAccessException) { }
                        catch (IOException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
            await Task.CompletedTask;
        }, ct);

    private Task CheckLogFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var logDirs = new[]
            {
                LocalApp,
                RoamingApp,
                TempPath,
                Path.Combine(LocalApp, "Temp"),
                Path.Combine(UserProfile, "Downloads"),
                Path.Combine(UserProfile, "Documents"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
                Path.Combine(LocalApp, "altv"),
                Path.Combine(LocalApp, "altv-launcher"),
                Path.Combine(RoamingApp, "altv"),
            };

            foreach (var dir in logDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                IEnumerable<string> logFiles = Enumerable.Empty<string>();
                try
                {
                    logFiles = Directory.EnumerateFiles(dir, "*.log", SearchOption.TopDirectoryOnly)
                        .Concat(Directory.EnumerateFiles(dir, "*.txt", SearchOption.TopDirectoryOnly));
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in logFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        var contentLower = content.ToLowerInvariant();
                        var hit = LogKeywords.FirstOrDefault(k =>
                            contentLower.Contains(k, StringComparison.OrdinalIgnoreCase));

                        if (hit is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"alt:V Antibann-Keyword in Log: {Path.GetFileName(file)}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason   = $"Log-Datei '{Path.GetFileName(file)}' enthält Keyword '{hit}', " +
                                       "das auf die Verwendung eines alt:V Ban-Umgehungs- oder " +
                                       "HWID-Spoofer-Tools hinweist.",
                            Detail   = $"Keyword: '{hit}' | Log: {file}"
                        });
                    }
                    catch (IOException) { }
                }
            }
        }, ct);

    private Task CheckRegistryArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            foreach (var regPath in RegistryPaths)
            {
                if (ct.IsCancellationRequested) return;

                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(regPath, writable: false);
                    if (key is not null)
                    {
                        ctx.IncrementRegistryKeys();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"alt:V Antibann-Registrierungsschlüssel: {Path.GetFileName(regPath)}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKCU\{regPath}",
                            Reason   = $"Registrierungsschlüssel '{regPath}' unter HKCU gefunden. " +
                                       "Dies ist ein typisches Installations-Artefakt eines " +
                                       "alt:V Ban-Umgehungs- oder HWID-Spoofer-Tools.",
                            Detail   = $"Registry: HKCU\\{regPath}"
                        });
                    }
                }
                catch { }

                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(regPath, writable: false);
                    if (key is not null)
                    {
                        ctx.IncrementRegistryKeys();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"alt:V Antibann-Registrierungsschlüssel (HKLM): {Path.GetFileName(regPath)}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{regPath}",
                            Reason   = $"Registrierungsschlüssel '{regPath}' unter HKLM gefunden. " +
                                       "Maschinenweiter Registry-Eintrag eines alt:V " +
                                       "Ban-Umgehungs- oder HWID-Spoofer-Tools.",
                            Detail   = $"Registry: HKLM\\{regPath}"
                        });
                    }
                }
                catch { }
            }

            CheckVolumeSerialArtifacts(ctx, ct);
            CheckMacAddressChangeArtifacts(ctx, ct);
            CheckHwidSpooferDriverKeys(ctx, ct);

            await Task.CompletedTask;
        }, ct);

    private static void CheckVolumeSerialArtifacts(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        try
        {
            const string netAdaptersPath = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";
            using var adaptersKey = Registry.LocalMachine.OpenSubKey(netAdaptersPath, writable: false);
            if (adaptersKey is null) return;

            foreach (var subKeyName in adaptersKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();

                try
                {
                    using var adapterKey = adaptersKey.OpenSubKey(subKeyName, writable: false);
                    if (adapterKey is null) continue;

                    var networkAddress = adapterKey.GetValue("NetworkAddress") as string;
                    if (string.IsNullOrEmpty(networkAddress)) continue;

                    var driverDesc = adapterKey.GetValue("DriverDesc") as string ?? "Unbekannt";

                    ctx.AddFinding(new Finding
                    {
                        Module   = "AltV-Antibann-Forensik",
                        Title    = $"MAC-Adresse geändert (Registry): {driverDesc}",
                        Risk     = RiskLevel.Medium,
                        Location = $@"HKLM\{netAdaptersPath}\{subKeyName}",
                        Reason   = $"Netzwerkadapter '{driverDesc}' hat einen gesetzten 'NetworkAddress'-Wert " +
                                   $"({networkAddress}), was auf MAC-Spoofing zur alt:V Ban-Umgehung hindeutet.",
                        Detail   = $"NetworkAddress: {networkAddress} | Adapter: {driverDesc}"
                    });
                }
                catch { }
            }
        }
        catch { }
    }

    private static void CheckMacAddressChangeArtifacts(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var knownMacChangerKeys = new[]
        {
            @"SYSTEM\CurrentControlSet\Services\altv_mac_spoof",
            @"SYSTEM\CurrentControlSet\Services\macchanger",
            @"SYSTEM\CurrentControlSet\Services\altvmacspoof",
            @"SYSTEM\CurrentControlSet\Services\banbypassaltv",
            @"SOFTWARE\AltVMacChanger",
            @"SOFTWARE\AltVMacSpoof",
        };

        foreach (var keyPath in knownMacChangerKeys)
        {
            if (ct.IsCancellationRequested) return;

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module   = "AltV-Antibann-Forensik",
                    Title    = $"alt:V MAC-Spoofer Registry-Artefakt: {Path.GetFileName(keyPath)}",
                    Risk     = RiskLevel.High,
                    Location = $@"HKLM\{keyPath}",
                    Reason   = $"Registry-Schlüssel '{keyPath}' wurde von einem alt:V MAC-Spoofer " +
                               "oder Ban-Umgehungstool hinterlassen.",
                    Detail   = $"Registry: HKLM\\{keyPath}"
                });
            }
            catch { }
        }
    }

    private static void CheckHwidSpooferDriverKeys(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        const string servicesPath = @"SYSTEM\CurrentControlSet\Services";
        var hwidDriverKeywords = new[]
        {
            "altvspoof", "altv_spoof", "altv_hwid", "altv_serial",
            "altvhwid", "altvcleaner", "altvunban", "banbypassaltv",
            "altv_ban_evade", "altv_unban", "altvfingerprint",
        };

        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(servicesPath, writable: false);
            if (servicesKey is null) return;

            foreach (var svcName in servicesKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();

                var svcNameLower = svcName.ToLowerInvariant();
                bool isHwidDriver = hwidDriverKeywords.Any(k =>
                    svcNameLower.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (!isHwidDriver) continue;

                try
                {
                    using var svcKey = servicesKey.OpenSubKey(svcName, writable: false);
                    if (svcKey is null) continue;

                    var imagePath = svcKey.GetValue("ImagePath") as string ?? "";
                    ctx.AddFinding(new Finding
                    {
                        Module   = "AltV-Antibann-Forensik",
                        Title    = $"alt:V HWID-Spoofer Dienst: {svcName}",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\{servicesPath}\{svcName}",
                        Reason   = $"Windows-Dienst '{svcName}' entspricht einem alt:V HWID-Spoofer-Treiber. " +
                                   "Solche Dienste manipulieren Hardware-IDs auf Kernel-Ebene.",
                        Detail   = $"ImagePath: {imagePath}"
                    });
                }
                catch { }
            }
        }
        catch { }
    }

    private Task CheckPrefetchArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            const string prefetchDir = @"C:\Windows\Prefetch";
            if (!Directory.Exists(prefetchDir))
            {
                await Task.CompletedTask;
                return;
            }

            IEnumerable<string> prefetchFiles = Enumerable.Empty<string>();
            try
            {
                prefetchFiles = Directory.EnumerateFiles(prefetchDir, "*.pf");
            }
            catch (UnauthorizedAccessException)
            {
                await Task.CompletedTask;
                return;
            }

            foreach (var file in prefetchFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var pfName = Path.GetFileNameWithoutExtension(file);
                var dashIdx = pfName.LastIndexOf('-');
                var exeName = dashIdx > 0 && pfName.Length - dashIdx == 9
                    ? pfName[..dashIdx]
                    : pfName;

                var exeUpper = exeName.ToUpperInvariant();
                var hit = PrefetchKeywords.FirstOrDefault(k =>
                    exeUpper.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (hit is null) continue;

                DateTime? lastWrite = null;
                try { lastWrite = File.GetLastWriteTimeUtc(file); } catch { }

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Prefetch: alt:V Antibann-Tool ausgeführt — {exeName}",
                    Risk     = RiskLevel.High,
                    Location = file,
                    FileName = exeName + ".exe",
                    Reason   = $"Prefetch-Datei '{Path.GetFileName(file)}' deutet auf Ausführung von " +
                               $"'{exeName}.exe' hin — einem alt:V Ban-Umgehungs- oder HWID-Spoofer-Tool. " +
                               "Prefetch-Einträge bleiben auch nach dem Löschen der Datei erhalten.",
                    Detail   = lastWrite.HasValue
                        ? $"Prefetch zuletzt aktualisiert: {lastWrite.Value:yyyy-MM-dd HH:mm:ss} UTC | Keyword: {hit}"
                        : $"Keyword: {hit}"
                });
            }
        }, ct);

    private Task CheckUserAssistArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            foreach (var uaPath in UserAssistBase)
            {
                if (ct.IsCancellationRequested) return;

                try
                {
                    using var countKey = Registry.CurrentUser.OpenSubKey(uaPath, writable: false);
                    if (countKey is null) continue;

                    foreach (var encodedName in countKey.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        var decoded = Rot13Decode(encodedName).ToLowerInvariant();
                        var hit = UserAssistCheatKeywords.FirstOrDefault(k =>
                            decoded.Contains(k, StringComparison.OrdinalIgnoreCase));

                        if (hit is null) continue;

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
                            Title    = $"UserAssist: alt:V Antibann-Tool ausgeführt — {hit}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKCU\{uaPath}",
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
            await Task.CompletedTask;
        }, ct);

    private Task CheckDiscordArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var discordClients = new[] { "discord", "discordptb", "discordcanary" };

            foreach (var client in discordClients)
            {
                if (ct.IsCancellationRequested) return;

                var discordRoot = Path.Combine(RoamingApp, client);
                if (!Directory.Exists(discordRoot)) continue;

                var cacheDirs = new[]
                {
                    Path.Combine(discordRoot, "Cache", "Cache_Data"),
                    Path.Combine(discordRoot, "Cache"),
                    Path.Combine(discordRoot, "Local Storage", "leveldb"),
                    Path.Combine(discordRoot, "Session Storage"),
                    Path.Combine(discordRoot, "Code Cache", "js"),
                };

                foreach (var cacheDir in cacheDirs)
                {
                    if (ct.IsCancellationRequested) return;
                    if (!Directory.Exists(cacheDir)) continue;

                    IEnumerable<string> cacheFiles = Enumerable.Empty<string>();
                    try
                    {
                        cacheFiles = Directory.EnumerateFiles(cacheDir).Take(100);
                    }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var file in cacheFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        try
                        {
                            var fi = new FileInfo(file);
                            if (fi.Length > 8 * 1024 * 1024) continue;

                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs, Encoding.GetEncoding("ISO-8859-1"));
                            string content = await sr.ReadToEndAsync(ct);

                            var contentLower = content.ToLowerInvariant();
                            var hit = DiscordKeywords.FirstOrDefault(k =>
                                contentLower.Contains(k, StringComparison.OrdinalIgnoreCase));

                            if (hit is null) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Discord-Cache: alt:V Antibann-Keyword '{hit}'",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason   = $"Discord-Cache-Datei enthält Keyword '{hit}', das auf " +
                                           "die Mitgliedschaft in einem alt:V Ban-Umgehungs-Server " +
                                           "oder entsprechende Kommunikation hindeutet.",
                                Detail   = $"Client: {client} | Cache: {cacheDir} | Keyword: {hit}"
                            });
                        }
                        catch (IOException) { }
                    }
                }
            }
        }, ct);

    private Task CheckSuspiciousScripts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var scriptDirs = new[]
            {
                Desktop,
                Path.Combine(UserProfile, "Downloads"),
                Path.Combine(UserProfile, "Documents"),
                TempPath,
                Path.Combine(LocalApp, "Temp"),
            };

            foreach (var dir in scriptDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                foreach (var ext in SuspiciousScriptExtensions)
                {
                    IEnumerable<string> scriptFiles = Enumerable.Empty<string>();
                    try
                    {
                        scriptFiles = Directory.EnumerateFiles(dir, $"*{ext}", SearchOption.TopDirectoryOnly);
                    }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var file in scriptFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        var fn = Path.GetFileName(file).ToLowerInvariant();
                        bool fileNameMatch = ScriptKeywords.Any(k =>
                            fn.Contains(k, StringComparison.OrdinalIgnoreCase)) &&
                            (fn.Contains("altv", StringComparison.OrdinalIgnoreCase) ||
                             fn.Contains("ban", StringComparison.OrdinalIgnoreCase) ||
                             fn.Contains("spoof", StringComparison.OrdinalIgnoreCase));

                        if (fileNameMatch)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Verdächtiges alt:V Skript (Name): {fn}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason   = $"Skript-Datei '{fn}' hat einen Namen der auf ein " +
                                           "alt:V HWID-Manipulations- oder Ban-Umgehungs-Skript hindeutet.",
                                Detail   = $"Pfad: {file} | Extension: {ext}"
                            });
                            continue;
                        }

                        try
                        {
                            var fi = new FileInfo(file);
                            if (fi.Length > 2 * 1024 * 1024) continue;

                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);

                            var contentLower = content.ToLowerInvariant();
                            bool hasAltV = contentLower.Contains("altv", StringComparison.OrdinalIgnoreCase);
                            if (!hasAltV) continue;

                            var scriptHits = ScriptKeywords
                                .Where(k => contentLower.Contains(k, StringComparison.OrdinalIgnoreCase))
                                .ToList();

                            bool hasSpoof = contentLower.Contains("spoof", StringComparison.OrdinalIgnoreCase) ||
                                            contentLower.Contains("hwid", StringComparison.OrdinalIgnoreCase) ||
                                            contentLower.Contains("serial", StringComparison.OrdinalIgnoreCase) ||
                                            contentLower.Contains("mac address", StringComparison.OrdinalIgnoreCase) ||
                                            contentLower.Contains("macaddress", StringComparison.OrdinalIgnoreCase) ||
                                            contentLower.Contains("ban bypass", StringComparison.OrdinalIgnoreCase) ||
                                            contentLower.Contains("unban", StringComparison.OrdinalIgnoreCase);

                            if (!hasSpoof || scriptHits.Count < 2) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"alt:V HWID-Manipulations-Skript: {fn}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason   = $"Skript '{fn}' enthält Referenzen auf 'altv' " +
                                           $"kombiniert mit {scriptHits.Count} Hardware-Manipulations-Keywords " +
                                           $"({string.Join(", ", scriptHits.Take(3))}). " +
                                           "Deutet auf ein PowerShell/Batch-Skript zur alt:V HWID-Manipulation hin.",
                                Detail   = $"Keywords: {string.Join(", ", scriptHits.Take(5))} | Pfad: {file}"
                            });
                        }
                        catch (IOException) { }
                    }
                }
            }
        }, ct);

    private Task CheckTempSpooferFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var tempDirs = new[]
            {
                TempPath,
                Path.Combine(LocalApp, "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
            };

            var spooferTempPatterns = new[]
            {
                "altv",
                "altvspoof",
                "altv_spoof",
                "altv_hwid",
                "altv_serial",
                "altv_mac",
                "altv_ban",
                "altv_unban",
                "altv_cleaner",
                "altv_fingerprint",
                "altvhwid",
                "altvunban",
                "altvmac",
                "altvserial",
                "altvban",
            };

            foreach (var dir in tempDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                IEnumerable<string> tempFiles = Enumerable.Empty<string>();
                try
                {
                    tempFiles = Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in tempFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fn = Path.GetFileName(file).ToLowerInvariant();
                    bool matches = spooferTempPatterns.Any(p =>
                        fn.Contains(p, StringComparison.OrdinalIgnoreCase));

                    if (!matches) continue;

                    DateTime? createdTime = null;
                    try { createdTime = File.GetCreationTimeUtc(file); } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"alt:V Spoofer Temp-Datei: {Path.GetFileName(file)}",
                        Risk     = RiskLevel.Medium,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"Temporäre Datei '{Path.GetFileName(file)}' im Temp-Verzeichnis '{dir}' " +
                                   "entspricht einem alt:V HWID-Spoofer-Betriebsartefakt. " +
                                   "Spoofer hinterlassen oft Temp-Dateien während der Ausführung.",
                        Detail   = createdTime.HasValue
                            ? $"Erstellt: {createdTime.Value:yyyy-MM-dd HH:mm:ss} UTC | Verzeichnis: {dir}"
                            : $"Verzeichnis: {dir}"
                    });
                }

                IEnumerable<string> tempSubDirs = Enumerable.Empty<string>();
                try
                {
                    tempSubDirs = Directory.EnumerateDirectories(dir, "*", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var subDir in tempSubDirs)
                {
                    if (ct.IsCancellationRequested) return;
                    var subDirName = Path.GetFileName(subDir).ToLowerInvariant();

                    bool dirMatches = spooferTempPatterns.Any(p =>
                        subDirName.Contains(p, StringComparison.OrdinalIgnoreCase));

                    if (!dirMatches) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"alt:V Spoofer Temp-Verzeichnis: {Path.GetFileName(subDir)}",
                        Risk     = RiskLevel.Medium,
                        Location = subDir,
                        FileName = Path.GetFileName(subDir),
                        Reason   = $"Temp-Verzeichnis '{subDir}' entspricht einem alt:V " +
                                   "HWID-Spoofer-Arbeitsverzeichnis.",
                        Detail   = $"Verzeichnis: {subDir}"
                    });
                }
            }
            await Task.CompletedTask;
        }, ct);

    private Task CheckAltVConfigFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var altVDirs = new[]
            {
                Path.Combine(LocalApp, "altv"),
                Path.Combine(LocalApp, "altv-launcher"),
                Path.Combine(RoamingApp, "altv"),
                Path.Combine(UserProfile, "Documents", "altv"),
                @"C:\altv",
                @"C:\altv-launcher",
            };

            foreach (var altVDir in altVDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(altVDir)) continue;

                IEnumerable<string> configFiles = Enumerable.Empty<string>();
                try
                {
                    configFiles = AltVConfigFileNames
                        .Select(name => Path.Combine(altVDir, name))
                        .Where(File.Exists);
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in configFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        var contentLower = content.ToLowerInvariant();
                        bool hasSpoofedHwid =
                            contentLower.Contains("hwid", StringComparison.OrdinalIgnoreCase) &&
                            (contentLower.Contains("spoof", StringComparison.OrdinalIgnoreCase) ||
                             contentLower.Contains("fake", StringComparison.OrdinalIgnoreCase) ||
                             contentLower.Contains("changed", StringComparison.OrdinalIgnoreCase) ||
                             contentLower.Contains("bypass", StringComparison.OrdinalIgnoreCase));

                        bool hasSpoofedSerial =
                            contentLower.Contains("serial", StringComparison.OrdinalIgnoreCase) &&
                            (contentLower.Contains("spoof", StringComparison.OrdinalIgnoreCase) ||
                             contentLower.Contains("0000000000000000", StringComparison.OrdinalIgnoreCase) ||
                             contentLower.Contains("fake", StringComparison.OrdinalIgnoreCase));

                        bool hasSpoofedMac =
                            contentLower.Contains("mac", StringComparison.OrdinalIgnoreCase) &&
                            contentLower.Contains("spoof", StringComparison.OrdinalIgnoreCase);

                        if (!hasSpoofedHwid && !hasSpoofedSerial && !hasSpoofedMac) continue;

                        var indicators = new List<string>();
                        if (hasSpoofedHwid) indicators.Add("HWID");
                        if (hasSpoofedSerial) indicators.Add("Serial");
                        if (hasSpoofedMac) indicators.Add("MAC");

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"alt:V Config mit modifizierten Hardware-IDs: {Path.GetFileName(file)}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason   = $"alt:V Konfigurationsdatei '{Path.GetFileName(file)}' enthält " +
                                       $"Anzeichen von modifizierten Hardware-Identifikatoren: " +
                                       $"{string.Join(", ", indicators)}. " +
                                       "Dies deutet auf einen HWID-Spoofer hin.",
                            Detail   = $"Modifizierte IDs: {string.Join(", ", indicators)} | Pfad: {file}"
                        });
                    }
                    catch (IOException) { }
                }

                try
                {
                    foreach (var file in Directory.EnumerateFiles(altVDir, "*.cfg", SearchOption.TopDirectoryOnly)
                        .Concat(Directory.EnumerateFiles(altVDir, "*.json", SearchOption.TopDirectoryOnly)))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        var fn = Path.GetFileName(file).ToLowerInvariant();
                        if (fn.Contains("spoof", StringComparison.OrdinalIgnoreCase) ||
                            fn.Contains("hwid", StringComparison.OrdinalIgnoreCase) ||
                            fn.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                            fn.Contains("unban", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Verdächtige alt:V Config-Datei: {fn}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason   = $"alt:V Konfigurationsdatei '{fn}' hat einen " +
                                           "verdächtigen Namen, der auf einen HWID-Spoofer " +
                                           "oder Ban-Bypass-Tool hindeutet.",
                                Detail   = $"Pfad: {file}"
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }, ct);

    private Task CheckAltVFingerprintDirectories(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var fingerprintDirs = new[]
            {
                Path.Combine(LocalApp, "altv", "data"),
                Path.Combine(LocalApp, "altv", "cache"),
                Path.Combine(LocalApp, "altv", "fingerprint"),
                Path.Combine(LocalApp, "altv-launcher", "data"),
                Path.Combine(LocalApp, "altv-launcher", "cache"),
                Path.Combine(RoamingApp, "altv", "data"),
                Path.Combine(RoamingApp, "altv", "cache"),
            };

            foreach (var dir in fingerprintDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                bool isEmpty = false;
                try
                {
                    isEmpty = !Directory.EnumerateFileSystemEntries(dir).Any();
                }
                catch (UnauthorizedAccessException) { continue; }

                if (isEmpty)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Geleertes alt:V Fingerprint-Verzeichnis: {Path.GetFileName(dir)}",
                        Risk     = RiskLevel.Medium,
                        Location = dir,
                        Reason   = $"alt:V Fingerprint/Cache-Verzeichnis '{dir}' existiert aber ist leer. " +
                                   "Ein HWID-Cleaner oder Fingerprint-Wiper hat möglicherweise den Inhalt " +
                                   "gelöscht um die Hardware-Identifikation von alt:V zu umgehen.",
                        Detail   = $"Leeres Verzeichnis: {dir}"
                    });
                    continue;
                }

                IEnumerable<string> fpFiles = Enumerable.Empty<string>();
                try
                {
                    fpFiles = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories).Take(50);
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in fpFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fn = Path.GetFileName(file).ToLowerInvariant();
                    bool isFingerprintFile = fn.Contains("fingerprint", StringComparison.OrdinalIgnoreCase) ||
                                            fn.Contains("hwid", StringComparison.OrdinalIgnoreCase) ||
                                            fn.Contains("serial", StringComparison.OrdinalIgnoreCase) ||
                                            fn.Contains("identity", StringComparison.OrdinalIgnoreCase);

                    if (!isFingerprintFile) continue;

                    try
                    {
                        var fi = new FileInfo(file);
                        if (fi.Length == 0)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Geleerte alt:V Fingerprint-Datei: {fn}",
                                Risk     = RiskLevel.Medium,
                                Location = file,
                                FileName = fn,
                                Reason   = $"alt:V Fingerprint-Datei '{fn}' existiert aber ist leer (0 Bytes). " +
                                           "Ein Fingerprint-Wiper hat möglicherweise den Inhalt gelöscht.",
                                Detail   = $"Dateigröße: 0 Bytes | Pfad: {file}"
                            });
                            continue;
                        }

                        if (fi.Length > 1 * 1024 * 1024) continue;

                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        var contentLower = content.ToLowerInvariant().Trim();
                        var wipedHit = FingerprintWipedIndicators.FirstOrDefault(w =>
                            contentLower.Equals(w, StringComparison.OrdinalIgnoreCase) ||
                            contentLower.Contains(w, StringComparison.OrdinalIgnoreCase));

                        if (wipedHit is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Gespoofte alt:V Fingerprint-Datei: {fn}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason   = $"alt:V Fingerprint-Datei '{fn}' enthält einen Wiper-Indikator " +
                                       $"('{wipedHit}'). Ein Fingerprint-Wiper hat die Hardware-IDs " +
                                       "durch Platzhalter oder Nullen ersetzt.",
                            Detail   = $"Inhalt (gekürzt): {content[..Math.Min(content.Length, 80)].Trim()} | Indikator: {wipedHit}"
                        });
                    }
                    catch (IOException) { }
                }
            }

            CheckFingerprintWipeArtifactsInAltVRoot(ctx, ct);
            await Task.CompletedTask;
        }, ct);

    private static void CheckFingerprintWipeArtifactsInAltVRoot(ScanContext ctx, CancellationToken ct)
    {
        var altVRoots = new[]
        {
            Path.Combine(KnownPaths.LocalAppData, "altv"),
            Path.Combine(KnownPaths.LocalAppData, "altv-launcher"),
            Path.Combine(KnownPaths.RoamingAppData, "altv"),
            @"C:\altv",
        };

        foreach (var root in altVRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            var wipeIndicatorFiles = new[]
            {
                "fingerprint_wiped.txt",
                "hwid_cleared.txt",
                "ban_bypassed.log",
                "spoof_log.txt",
                "altv_spoof.log",
                "altv_hwid_wipe.log",
                "altv_ban_bypass.log",
            };

            foreach (var indicatorFile in wipeIndicatorFiles)
            {
                if (ct.IsCancellationRequested) return;
                var fullPath = Path.Combine(root, indicatorFile);

                if (!File.Exists(fullPath)) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = "AltV-Antibann-Forensik",
                    Title    = $"alt:V Wiper-Indikator-Datei: {indicatorFile}",
                    Risk     = RiskLevel.High,
                    Location = fullPath,
                    FileName = indicatorFile,
                    Reason   = $"Wiper-Indikator-Datei '{indicatorFile}' im alt:V Verzeichnis gefunden. " +
                               "Diese Datei wird von Fingerprint-Wipern oder HWID-Cleanern hinterlassen.",
                    Detail   = $"Pfad: {fullPath}"
                });
            }
        }
    }

    private static string Rot13Decode(string s)
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
}
