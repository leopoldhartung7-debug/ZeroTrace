using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

public sealed class RageMPWeaponHackScanModule : IScanModule
{
    public string Name => "RageMP Waffen-Hack Forensik";
    public double Weight => 1.1;
    public int ParallelGroup => 4;

    private static readonly string[] WeaponHackFilePatterns =
    {
        "weaponHack*", "giveAllWeapons*", "weapon_esp*", "weapon_give_hack*",
        "ammo_hack*", "weapon_bypass_ragemp*", "weapon_cheat_ragemp*",
        "give_weapon*", "all_weapons*", "weapon_override*", "weapon_inject*",
        "ammo_inject*", "weaponcheat*", "weapon_spoofer*", "giveweapon*",
        "allweapons*", "ammohack*", "weapon_esp_ragemp*", "ragemp_weapon*",
        "weaponesp*", "weapon_unlimited*", "unlimited_ammo*"
    };

    private static readonly string[] WeaponHackLogKeywords =
    {
        "weapon hack", "give weapons", "ammo hack", "weapon esp",
        "weapon bypass ragemp", "unlimited ammo", "weapon cheat",
        "giveallweapons", "give all weapons", "weapon_hack", "ammo_hack",
        "weapon bypass", "weapon override", "weapon inject",
        "ragemp weapon", "weaponhack", "weapon cheat ragemp",
        "ammo bypass", "unlimited weapons", "weapon exploit",
        "give weapon ragemp", "all weapons ragemp"
    };

    private static readonly string[] WeaponHackClientKeywords =
    {
        "giveWeapon", "addAmmo", "weapon_override", "weaponhack",
        "give_all_weapons", "mp.game.weapon.give", "giveWeaponToPed",
        "removeAllPedWeapons", "setAmmo", "weaponBypass",
        "addWeapon", "weaponGive", "ammoHack", "unlimitedAmmo",
        "weapon.give(", "weapons.give(", "mp.ped.giveWeapon",
        "mp.local.weapon", "ped.giveWeapon", "AllWeapons",
        "GiveAllWeapons", "WeaponESP", "weapon_esp", "aimbot_weapon",
        "weapon_spoof", "weapon_inject", "ammo_inject"
    };

    private static readonly string[] KnownWeaponHackExeNames =
    {
        "RageMP_WeaponHack.exe", "GiveWeapon.exe", "AmmoHack.exe", "AllWeapons.exe",
        "WeaponHack.exe", "GiveAllWeapons.exe", "WeaponESP.exe", "WeaponBypass.exe",
        "WeaponCheat.exe", "WeaponInject.exe", "AmmoInject.exe", "WeaponGive.exe",
        "RageMPWeapon.exe", "WeaponOverride.exe", "UnlimitedAmmo.exe",
        "RageMPHack.exe", "WeaponSpoof.exe", "WeaponLoader.exe",
        "AmmoLoader.exe", "AllWeaponsGive.exe"
    };

    private static readonly string[] DiscordWeaponHackKeywords =
    {
        "ragemp weapon hack", "give all weapons ragemp", "ammo hack ragemp",
        "weapon bypass", "weapon esp ragemp", "unlimited ammo ragemp",
        "weapon cheat ragemp", "giveweapon ragemp", "ragemp weapon esp",
        "weapon inject ragemp", "ragemp weapon cheat", "weapon exploit ragemp",
        "weapon override ragemp", "ammo exploit ragemp", "weapon bypass ragemp",
        "ragemp all weapons", "weapon hack gta", "ammo hack gta ragemp"
    };

    private static readonly string[] JsCsWeaponPluginKeywords =
    {
        "mp.game.weapon.give", "giveWeapon", "addAmmo bypass", "unlimited ammo",
        "mp.ped.giveWeapon", "mp.local.giveWeapon", "ped.giveWeapon(",
        "weapon_override", "weaponhack", "give_all_weapons",
        "mp.game.weapon.giveWeaponToPed", "mp.game.weapon.removeAllPedWeapons",
        "weapons.forEach", "allWeapons.forEach", "WEAPON_PISTOL",
        "setAmmo(", "addAmmo(", "weapon.bypass", "ammo.bypass",
        "weaponHash", "GetHashKey('weapon_", "GetWeaponDamageModifier",
        "SetPedWeaponDamageModifier", "SetPedWeaponReloadingTime",
        "NetworkRequestControlOfEntity", "giveWeaponToPed bypass"
    };

    private static readonly string[] MemoryDumpWeaponKeywords =
    {
        "giveWeapon", "weaponHash", "ammoCount", "weapon_override",
        "WEAPON_PISTOL", "WEAPON_RPG", "WEAPON_MINIGUN", "weaponHack",
        "give_all_weapons", "unlimited_ammo", "weapon_bypass",
        "CWeaponInfo", "CWeaponMgr", "CPlayerInfo weapons",
        "weaponComponent", "tintIndex", "ammoInClip",
        "attachmentOverride", "weaponDamage bypass"
    };

    private static readonly string[] NetworkWeaponKeywords =
    {
        "weaponSync", "weapon_rpc", "weapon_packet", "ammo_rpc",
        "give_weapon_packet", "weapon_override_packet", "sync_weapon",
        "ragemp_weapon_rpc", "weapon_net_id", "weapon_netpacket",
        "CL2SV_WEAPON", "SV2CL_WEAPON", "weaponBroadcast",
        "weapon_spoof_net", "ammo_spoof_packet"
    };

    private static readonly string[] RageMPConfigWeaponKeywords =
    {
        "weaponhack", "give_weapon", "weapon_esp", "weapon_bypass",
        "ammo_hack", "weapon_cheat", "unlimited_ammo", "all_weapons",
        "weaponOverride", "weaponInject", "weapon_plugin"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starte RageMP Waffen-Hack Forensik-Scan...");

        await Task.WhenAll(
            CheckAppDataWeaponHackFiles(ctx, ct),
            CheckTempWeaponHackFiles(ctx, ct),
            CheckDesktopWeaponHackFiles(ctx, ct),
            CheckLogFilesForWeaponHackKeywords(ctx, ct),
            CheckRageMPClientFilesWeaponKeywords(ctx, ct),
            CheckRegistryWeaponHackKeys(ctx, ct),
            CheckKnownWeaponHackExecutables(ctx, ct),
            CheckPrefetchWeaponHackExecutables(ctx, ct),
            CheckUserAssistWeaponHackTools(ctx, ct),
            CheckDiscordArtifactsWeaponHack(ctx, ct),
            CheckJsCsPluginFilesWeaponKeywords(ctx, ct),
            CheckTempWeaponInjectionFiles(ctx, ct),
            CheckMemoryDumpArtifactsWeapon(ctx, ct),
            CheckNetworkPacketManipulationTools(ctx, ct),
            CheckRageMPPackagesWeaponKeywords(ctx, ct)
        );

        ctx.Report(1.0, Name, "RageMP Waffen-Hack Forensik-Scan abgeschlossen.");
    }

    private Task CheckAppDataWeaponHackFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var roaming = KnownPaths.RoamingAppData;
        var local = KnownPaths.LocalAppData;
        var ragempRoot = KnownPaths.FindRageMpDirectory();

        var appDataDirs = new List<string>
        {
            roaming,
            local,
            Path.Combine(roaming, "RAGE Multiplayer"),
            Path.Combine(local, "RAGE Multiplayer"),
        };

        if (ragempRoot != null)
        {
            appDataDirs.Add(ragempRoot);
            appDataDirs.Add(Path.Combine(ragempRoot, "client_packages"));
            appDataDirs.Add(Path.Combine(ragempRoot, "dotnet", "scripts"));
        }

        foreach (var dir in appDataDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            foreach (var pattern in WeaponHackFilePatterns)
            {
                ct.ThrowIfCancellationRequested();
                string[] matches;
                try
                {
                    matches = Directory.GetFiles(dir, pattern, SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var file in matches)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Waffen-Hack-Datei in AppData: {Path.GetFileName(file)}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Datei mit waffen-hack-typischem Muster '{pattern}' in AppData-Verzeichnis gefunden. " +
                                     "Solche Dateien sind typische Artefakte von RageMP Weapon-Hack- oder Give-Weapon-Tools, " +
                                     "die genutzt werden, um Waffen und Munition in GTA:V/RageMP-Sitzungen zu injizieren."
                        });
                    }
                    catch (IOException) { }
                }
            }

            string[] allFiles;
            try
            {
                allFiles = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in allFiles)
            {
                ct.ThrowIfCancellationRequested();
                if (ContainsWeaponHackKeywordInName(Path.GetFileName(file)))
                {
                    ctx.IncrementFiles();
                    try
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtige Waffen-Hack-Datei: {Path.GetFileName(file)}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Dateiname '{Path.GetFileName(file)}' enthaelt waffen-hack-relevante Schluesselwoerter. " +
                                     "Dieser Fund ist ein Artefakt von RageMP Weapon-Cheat-Tools, " +
                                     "die Waffen- oder Munitionsfunktionen missbrauchen."
                        });
                    }
                    catch (IOException) { }
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckTempWeaponHackFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var tempDirs = new[]
        {
            KnownPaths.Temp,
            Path.Combine(KnownPaths.LocalAppData, "Temp"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
        };

        foreach (var tempDir in tempDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(tempDir))
                continue;

            foreach (var pattern in WeaponHackFilePatterns)
            {
                ct.ThrowIfCancellationRequested();
                string[] matches;
                try
                {
                    matches = Directory.GetFiles(tempDir, pattern, SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var file in matches)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Waffen-Hack-Datei in Temp: {Path.GetFileName(file)}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Temporaere Datei mit Muster '{pattern}' gefunden. " +
                                     "RageMP Weapon-Hack-Tools legen waehrend der Ausfuehrung temporaere Dateien mit " +
                                     "charakteristischen Namen im Temp-Verzeichnis ab."
                        });
                    }
                    catch (IOException) { }
                }
            }

            string[] allTemp;
            try
            {
                allTemp = Directory.GetFiles(tempDir, "*weapon*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in allTemp)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                if (ContainsWeaponHackKeywordInName(Path.GetFileName(file)))
                {
                    try
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Waffen-Bezug in Temp-Datei: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Medium,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Temporaere Datei '{Path.GetFileName(file)}' enthaelt waffen-hack-bezogene Begriffe im Namen. " +
                                     "Solche Artefakte verbleiben nach der Ausfuehrung von Weapon-Hack-Tools im Temp-Verzeichnis."
                        });
                    }
                    catch (IOException) { }
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckDesktopWeaponHackFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var desktop = Path.Combine(KnownPaths.UserProfile, "Desktop");

        if (!Directory.Exists(desktop))
        {
            await Task.CompletedTask;
            return;
        }

        string[] desktopFiles;
        try
        {
            desktopFiles = Directory.GetFiles(desktop, "*", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException)
        {
            await Task.CompletedTask;
            return;
        }

        foreach (var file in desktopFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();
            var fileName = Path.GetFileName(file);

            foreach (var knownExe in KnownWeaponHackExeNames)
            {
                if (fileName.Equals(knownExe, StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Bekanntes Waffen-Hack-Tool auf Desktop: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Bekanntes RageMP Weapon-Hack-Tool '{knownExe}' auf dem Desktop gefunden. " +
                                     "Diese Tools werden direkt ausgefuehrt, um Waffen in RageMP-Sitzungen zu injizieren."
                        });
                    }
                    catch (IOException) { }
                    break;
                }
            }

            if (ContainsWeaponHackKeywordInName(fileName))
            {
                try
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Waffen-Hack-Datei auf Desktop: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Desktop-Datei '{fileName}' enthaelt waffen-hack-bezogene Begriffe. " +
                                 "Nutzer platzieren Weapon-Hack-Tools haeufig auf dem Desktop fuer schnellen Zugriff."
                    });
                }
                catch (IOException) { }
            }
        }

        foreach (var pattern in WeaponHackFilePatterns)
        {
            ct.ThrowIfCancellationRequested();
            string[] patternMatches;
            try
            {
                patternMatches = Directory.GetFiles(desktop, pattern, SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in patternMatches)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                try
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Waffen-Hack-Muster auf Desktop: {Path.GetFileName(file)}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Desktop-Datei entspricht Weapon-Hack-Muster '{pattern}'. " +
                                 "Weapon-Cheat-Tools werden haeufig auf dem Desktop abgelegt."
                    });
                }
                catch (IOException) { }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckLogFilesForWeaponHackKeywords(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var ragempRoot = KnownPaths.FindRageMpDirectory();
        var roaming = KnownPaths.RoamingAppData;
        var local = KnownPaths.LocalAppData;

        var logDirs = new List<string>
        {
            KnownPaths.Temp,
            Path.Combine(local, "Temp"),
            roaming,
            local,
        };

        if (ragempRoot != null)
        {
            logDirs.Add(ragempRoot);
            logDirs.Add(Path.Combine(ragempRoot, "logs"));
        }

        logDirs.Add(Path.Combine(roaming, "RAGE Multiplayer"));
        logDirs.Add(Path.Combine(roaming, "RAGE Multiplayer", "logs"));
        logDirs.Add(Path.Combine(local, "RAGE Multiplayer"));

        var logExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".log", ".txt", ".cfg", ".ini", ".json", ".xml"
        };

        foreach (var dir in logDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            string[] logFiles;
            try
            {
                logFiles = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in logFiles)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file);
                if (!logExtensions.Contains(ext))
                    continue;

                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (var keyword in WeaponHackLogKeywords)
                    {
                        if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Waffen-Hack-Schluesselwort in Log: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Log-Datei enthaelt Schluesselwort '{keyword}', das auf den Einsatz von " +
                                         "RageMP Weapon-Hack- oder Ammo-Hack-Tools hinweist. " +
                                         "Cheat-Tools protokollieren ihre Aktivitaeten in Logdateien."
                            });
                            break;
                        }
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }, ct);

    private Task CheckRageMPClientFilesWeaponKeywords(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var ragempRoot = KnownPaths.FindRageMpDirectory();
        if (ragempRoot is null)
        {
            await Task.CompletedTask;
            return;
        }

        var clientDirs = new[]
        {
            ragempRoot,
            Path.Combine(ragempRoot, "dotnet"),
            Path.Combine(ragempRoot, "dotnet", "scripts"),
            Path.Combine(ragempRoot, "client_packages"),
            Path.Combine(ragempRoot, "plugins"),
            Path.Combine(ragempRoot, "bin"),
        };

        var clientExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".js", ".json", ".dll", ".cs", ".cfg", ".lua", ".ts"
        };

        foreach (var dir in clientDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            string[] clientFiles;
            try
            {
                clientFiles = Directory.GetFiles(dir, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in clientFiles)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file);
                if (!clientExtensions.Contains(ext))
                    continue;

                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (var keyword in WeaponHackClientKeywords)
                    {
                        if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Waffen-Exploit-Schluessel in RageMP-Client: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"RageMP-Client-Datei enthaelt Weapon-Exploit-Ausdruck '{keyword}'. " +
                                         "Solche Ausdruecke werden von Weapon-Hack-Plugins verwendet, um Waffen zu geben, " +
                                         "Munition hinzuzufuegen oder Weapon-Syncing zu manipulieren."
                            });
                            break;
                        }
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }, ct);

    private Task CheckRegistryWeaponHackKeys(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var registryPaths = new[]
        {
            (@"Software\RageMP\WeaponHack", RegistryHive.CurrentUser),
            (@"Software\WeaponCheatRageMP", RegistryHive.CurrentUser),
            (@"Software\RageMP\WeaponCheat", RegistryHive.CurrentUser),
            (@"Software\RageMP\AmmoHack", RegistryHive.CurrentUser),
            (@"Software\RageMP\GiveWeapon", RegistryHive.CurrentUser),
            (@"Software\RageMP\WeaponBypass", RegistryHive.CurrentUser),
            (@"Software\WeaponHackRageMP", RegistryHive.CurrentUser),
            (@"Software\GiveAllWeaponsRageMP", RegistryHive.CurrentUser),
            (@"Software\AmmoHackRageMP", RegistryHive.CurrentUser),
            (@"Software\RageMPWeaponESP", RegistryHive.CurrentUser),
        };

        foreach (var (keyPath, hive) in registryPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var subKey = baseKey.OpenSubKey(keyPath);
                ctx.IncrementRegistryKeys();

                if (subKey is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Waffen-Hack Registry-Schluessel: {keyPath}",
                        Risk = RiskLevel.High,
                        Location = $"{(hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM")}\\{keyPath}",
                        Reason = $"Registry-Schluessel '{keyPath}' existiert und ist typisch fuer RageMP Weapon-Hack- " +
                                 "oder Ammo-Hack-Software. Solche Schluessel werden von Cheat-Tools zur " +
                                 "Konfigurationsspeicherung hinterlassen."
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (Exception) { }
        }

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
            using var ragempKey = baseKey.OpenSubKey(@"Software\RageMP");
            ctx.IncrementRegistryKeys();

            if (ragempKey is not null)
            {
                foreach (var subName in ragempKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    if (ContainsWeaponHackKeywordInName(subName))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtiger RageMP Registry-Unterschluessel: {subName}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\Software\RageMP\{subName}",
                            Reason = $"RageMP Registry-Unterschluessel '{subName}' enthaelt waffen-hack-bezogene Begriffe. " +
                                     "Derartige Eintraege werden von Weapon-Cheat-Tools nach der Installation hinterlassen."
                        });
                    }
                }

                foreach (var valueName in ragempKey.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    var value = ragempKey.GetValue(valueName)?.ToString() ?? string.Empty;
                    if (ContainsWeaponHackKeywordInName(valueName) || ContainsWeaponHackKeywordInName(value))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtiger RageMP Registry-Wert: {valueName}",
                            Risk = RiskLevel.Medium,
                            Location = $@"HKCU\Software\RageMP",
                            Reason = $"RageMP Registry-Wert '{valueName}' = '{value}' enthaelt waffen-hack-bezogene Begriffe. " +
                                     "Weapon-Hack-Tools schreiben haeufig Konfigurationswerte in den RageMP-Registry-Zweig."
                        });
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (Exception) { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckKnownWeaponHackExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[]
        {
            KnownPaths.Temp,
            Path.Combine(KnownPaths.LocalAppData, "Temp"),
            KnownPaths.Downloads,
            Path.Combine(KnownPaths.UserProfile, "Desktop"),
            Path.Combine(KnownPaths.UserProfile, "Documents"),
            KnownPaths.RoamingAppData,
            KnownPaths.LocalAppData,
            Path.Combine(KnownPaths.LocalAppData, "Programs"),
        };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            string[] exeFiles;
            try
            {
                exeFiles = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in exeFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);

                foreach (var knownExe in KnownWeaponHackExeNames)
                {
                    if (fileName.Equals(knownExe, StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Bekanntes Waffen-Hack-Tool: {fileName}",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = fileName,
                                Reason = $"Executable '{fileName}' entspricht dem bekannten RageMP Weapon-Hack-Tool '{knownExe}'. " +
                                         "Dieses Tool wird eingesetzt, um Waffen oder Munition in GTA:V/RageMP-Sessions zu injizieren."
                            });
                        }
                        catch (IOException) { }
                        break;
                    }
                }

                if (ContainsWeaponHackKeywordInName(fileName))
                {
                    try
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtiges Waffen-Hack-Executable: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Executable '{fileName}' enthaelt waffen-hack-typische Begriffe im Dateinamen. " +
                                     "Solche Programme werden zum Ausnutzen von RageMP-Waffenfunktionen eingesetzt."
                        });
                    }
                    catch (IOException) { }
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckPrefetchWeaponHackExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var prefetchDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

        string[] pfFiles;
        try
        {
            pfFiles = Directory.GetFiles(prefetchDir, "*.pf");
        }
        catch (UnauthorizedAccessException)
        {
            await Task.CompletedTask;
            return;
        }
        catch (IOException)
        {
            await Task.CompletedTask;
            return;
        }

        foreach (var pf in pfFiles)
        {
            ct.ThrowIfCancellationRequested();
            var baseName = Path.GetFileNameWithoutExtension(pf);
            int dash = baseName.LastIndexOf('-');
            var exeName = dash > 0 ? baseName[..dash] : baseName;

            foreach (var knownExe in KnownWeaponHackExeNames)
            {
                if (exeName.Equals(Path.GetFileNameWithoutExtension(knownExe), StringComparison.OrdinalIgnoreCase))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Bekanntes Waffen-Hack-Tool in Prefetch: {exeName}",
                        Risk = RiskLevel.Critical,
                        Location = pf,
                        FileName = exeName,
                        Reason = $"Prefetch-Eintrag '{Path.GetFileName(pf)}' belegt die Ausfuehrung des bekannten " +
                                 $"Weapon-Hack-Tools '{knownExe}'. Das Programm wurde ausgefuehrt, auch wenn " +
                                 "die Datei bereits geloescht wurde."
                    });
                    break;
                }
            }

            if (ContainsWeaponHackKeywordInName(exeName))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Waffen-Hack-Executable in Prefetch: {exeName}",
                    Risk = RiskLevel.High,
                    Location = pf,
                    FileName = exeName,
                    Reason = $"Prefetch-Datei '{Path.GetFileName(pf)}' belegt die Ausfuehrung von '{exeName}', " +
                             "dessen Name auf ein RageMP Weapon-Hack- oder Ammo-Hack-Tool hindeutet. " +
                             "Prefetch protokolliert auch bereits geloeschte Programme."
                });
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckUserAssistWeaponHackTools(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
            using var ua = baseKey.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
            if (ua is null)
            {
                await Task.CompletedTask;
                return;
            }

            foreach (var guid in ua.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                using var count = ua.OpenSubKey($@"{guid}\Count");
                if (count is null)
                    continue;

                ctx.IncrementRegistryKeys();

                foreach (var valueName in count.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    var decoded = Rot13Decode(valueName);
                    if (string.IsNullOrWhiteSpace(decoded))
                        continue;

                    if (ContainsWeaponHackKeywordInName(decoded))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Waffen-Hack-Tool in UserAssist: {Path.GetFileName(decoded.TrimEnd('\\', '/'))}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{guid}\Count",
                            FileName = Path.GetFileName(decoded.TrimEnd('\\', '/')),
                            Reason = $"UserAssist-Eintrag (ROT13-dekodiert: '{decoded}') weist auf die Ausfuehrung eines " +
                                     "RageMP Weapon-Hack- oder Ammo-Hack-Launchers hin. " +
                                     "UserAssist protokolliert GUI-Programmstarts durch den Benutzer."
                        });
                    }

                    foreach (var knownExe in KnownWeaponHackExeNames)
                    {
                        if (decoded.Contains(Path.GetFileNameWithoutExtension(knownExe), StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Bekanntes Waffen-Hack-Tool in UserAssist: {knownExe}",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{guid}\Count",
                                FileName = knownExe,
                                Reason = $"UserAssist-Eintrag beweist die Ausfuehrung des bekannten Weapon-Hack-Tools '{knownExe}' " +
                                         $"(dekodierter Pfad: '{decoded}'). " +
                                         "Dieses Tool wird gezielt fuer RageMP-Waffen-Injektionen eingesetzt."
                            });
                            break;
                        }
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (Exception) { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckDiscordArtifactsWeaponHack(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var roaming = KnownPaths.RoamingAppData;
        var local = KnownPaths.LocalAppData;

        var discordDirs = new[]
        {
            Path.Combine(roaming, "discord", "Cache"),
            Path.Combine(roaming, "discord", "Local Storage", "leveldb"),
            Path.Combine(roaming, "discord", "Session Storage"),
            Path.Combine(roaming, "discordcanary", "Cache"),
            Path.Combine(roaming, "discordcanary", "Local Storage", "leveldb"),
            Path.Combine(roaming, "discordptb", "Cache"),
            Path.Combine(roaming, "discordptb", "Local Storage", "leveldb"),
            Path.Combine(local, "Discord", "Cache"),
            Path.Combine(local, "Discord", "Local Storage", "leveldb"),
        };

        foreach (var dir in discordDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            string[] cacheFiles;
            try
            {
                cacheFiles = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in cacheFiles)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext is ".png" or ".jpg" or ".jpeg" or ".gif" or ".mp4" or ".webm")
                    continue;

                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (var keyword in DiscordWeaponHackKeywords)
                    {
                        if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Waffen-Hack-Bezug in Discord-Cache: {Path.GetFileName(file)}",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Discord-Cache-Datei enthaelt Schluesselwort '{keyword}', das auf " +
                                         "Austausch ueber RageMP Weapon-Hack-Tools hinweist. " +
                                         "Solche Artefakte entstehen beim Empfangen von Nachrichten in " +
                                         "einschlaegigen Discord-Servern oder Direktnachrichten."
                            });
                            break;
                        }
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }, ct);

    private Task CheckJsCsPluginFilesWeaponKeywords(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var ragempRoot = KnownPaths.FindRageMpDirectory();
        var roaming = KnownPaths.RoamingAppData;
        var local = KnownPaths.LocalAppData;

        var pluginDirs = new List<string>
        {
            roaming,
            local,
            Path.Combine(roaming, "RAGE Multiplayer"),
        };

        if (ragempRoot != null)
        {
            pluginDirs.Add(Path.Combine(ragempRoot, "client_packages"));
            pluginDirs.Add(Path.Combine(ragempRoot, "dotnet", "scripts"));
            pluginDirs.Add(Path.Combine(ragempRoot, "plugins"));
        }

        var codeExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".js", ".json", ".cs", ".ts", ".lua", ".dll"
        };

        foreach (var dir in pluginDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            string[] pluginFiles;
            try
            {
                pluginFiles = Directory.GetFiles(dir, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in pluginFiles)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file);
                if (!codeExtensions.Contains(ext))
                    continue;

                if (ext.Equals(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.IncrementFiles();
                    if (ContainsWeaponHackKeywordInName(Path.GetFileName(file)))
                    {
                        try
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Waffen-Hack-DLL in RageMP-Plugin: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"DLL '{Path.GetFileName(file)}' im RageMP-Plugin-Verzeichnis hat einen " +
                                         "waffen-hack-typischen Namen. Weapon-Hack-DLLs werden in RageMP-Prozesse injiziert."
                            });
                        }
                        catch (IOException) { }
                    }
                    continue;
                }

                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (var keyword in JsCsWeaponPluginKeywords)
                    {
                        if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Waffen-Exploit in Plugin-Datei: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Plugin-Datei '{Path.GetFileName(file)}' enthaelt Weapon-Exploit-Ausdruck '{keyword}'. " +
                                         "JS/C#-Plugins in RageMP koennen mp.game.weapon.*-Funktionen ausnutzen, " +
                                         "um Waffen zu geben oder Munition hinzuzufuegen."
                            });
                            break;
                        }
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }, ct);

    private Task CheckTempWeaponInjectionFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var tempDirs = new[]
        {
            KnownPaths.Temp,
            Path.Combine(KnownPaths.LocalAppData, "Temp"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
        };

        var injectionKeywords = new[]
        {
            "weapon_inject", "weaponInject", "ammo_inject", "ammoInject",
            "inject_weapon", "weapon_payload", "weaponPayload",
            "give_weapon_inject", "weapon_dll_inject", "weapon_loader",
            "weaponLoader", "ragemp_inject", "weapon_hook"
        };

        foreach (var tempDir in tempDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(tempDir))
                continue;

            string[] tempFiles;
            try
            {
                tempFiles = Directory.GetFiles(tempDir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in tempFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);

                foreach (var keyword in injectionKeywords)
                {
                    if (fileName.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Waffen-Injektions-Temp-Datei: {fileName}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason = $"Temporaere Datei '{fileName}' enthaelt Injektions-Keyword '{keyword}'. " +
                                         "Weapon-Injektions-Tools legen temporaere Payload-Dateien ab, bevor " +
                                         "sie in den RageMP-Prozess injizieren."
                            });
                        }
                        catch (IOException) { }
                        break;
                    }
                }

                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext is ".log" or ".txt" or ".cfg" or ".json")
                {
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        foreach (var keyword in WeaponHackLogKeywords)
                        {
                            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Waffen-Hack-Log in Temp: {fileName}",
                                    Risk = RiskLevel.Medium,
                                    Location = file,
                                    FileName = fileName,
                                    Reason = $"Temporaere Datei enthaelt Weapon-Hack-Schluesselwort '{keyword}'. " +
                                             "Weapon-Hack-Tools schreiben Aktivitaetslogs in das Temp-Verzeichnis."
                                });
                                break;
                            }
                        }
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
        }
    }, ct);

    private Task CheckMemoryDumpArtifactsWeapon(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[]
        {
            KnownPaths.Temp,
            Path.Combine(KnownPaths.LocalAppData, "Temp"),
            KnownPaths.Downloads,
            Path.Combine(KnownPaths.UserProfile, "Desktop"),
            Path.Combine(KnownPaths.UserProfile, "Documents"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
        };

        var dumpExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".dmp", ".mdmp", ".hdmp", ".log", ".txt", ".bin"
        };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            string[] dumpFiles;
            try
            {
                dumpFiles = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in dumpFiles)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file);
                if (!dumpExtensions.Contains(ext))
                    continue;

                var fileName = Path.GetFileName(file);

                if (fileName.Contains("ragemp", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("gta", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("weapon", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                        string content = await sr.ReadToEndAsync(ct);

                        foreach (var keyword in MemoryDumpWeaponKeywords)
                        {
                            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Waffen-Hack-Artefakt in Memory-Dump: {fileName}",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = fileName,
                                    Reason = $"Memory-Dump/Log-Datei '{fileName}' enthaelt waffenbezogene Zeichenkette '{keyword}'. " +
                                             "Crash-Dumps und Speicher-Logs von RageMP-Prozessen koennen Weapon-Hack-Spuren enthalten, " +
                                             "wenn Cheats beim Ausfuehren abstuerzen oder Memory-Dumps erstellen."
                                });
                                break;
                            }
                        }
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
        }
    }, ct);

    private Task CheckNetworkPacketManipulationTools(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[]
        {
            KnownPaths.Temp,
            Path.Combine(KnownPaths.LocalAppData, "Temp"),
            KnownPaths.Downloads,
            Path.Combine(KnownPaths.UserProfile, "Desktop"),
            Path.Combine(KnownPaths.UserProfile, "Documents"),
            KnownPaths.RoamingAppData,
            KnownPaths.LocalAppData,
        };

        var networkToolKeywords = new[]
        {
            "ragemp_packet", "weapon_packet", "weapon_rpc", "ammo_rpc",
            "weapon_sync_hack", "ragemp_weapon_rpc", "packet_weapon",
            "netweapon", "net_weapon", "weapon_netpacket",
            "weaponBroadcast", "weapon_spoof_net", "ammo_spoof_packet",
            "ragemp_proxy", "weapon_proxy", "ammo_proxy"
        };

        var packetToolNames = new[]
        {
            "RageMPPacketHack.exe", "WeaponPacketManipulator.exe", "AmmoPacketHack.exe",
            "RageMPProxy.exe", "WeaponRPCHack.exe", "PacketWeapon.exe",
            "NetWeaponHack.exe", "WeaponSyncHack.exe"
        };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            string[] allFiles;
            try
            {
                allFiles = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in allFiles)
            {
                ct.ThrowIfCancellationRequested();
                var fileName = Path.GetFileName(file);

                foreach (var toolName in packetToolNames)
                {
                    if (fileName.Equals(toolName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementFiles();
                        try
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Netzwerk-Paket-Manipulations-Tool: {fileName}",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = fileName,
                                Reason = $"Datei '{fileName}' entspricht einem bekannten RageMP-Netzwerk-Paket-Manipulations-Tool. " +
                                         "Solche Tools faelschen Waffen-RPC-Pakete im RageMP-Netzwerkprotokoll, " +
                                         "um serverseitige Waffenvalidierung zu umgehen."
                            });
                        }
                        catch (IOException) { }
                        break;
                    }
                }

                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext is ".log" or ".txt" or ".cfg" or ".json" or ".xml")
                {
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        foreach (var keyword in networkToolKeywords)
                        {
                            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Netzwerk-Waffen-Exploit-Log: {fileName}",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = fileName,
                                    Reason = $"Datei enthaelt netzwerkbezogenes Weapon-Exploit-Schluesselwort '{keyword}'. " +
                                             "Netzwerk-Paket-Manipulations-Tools fuer RageMP hinterlassen Konfigurationslogs " +
                                             "mit solchen Bezeichnungen fuer Waffen-RPC-Spoofing."
                                });
                                break;
                            }
                        }
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckRageMPPackagesWeaponKeywords(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var ragempRoot = KnownPaths.FindRageMpDirectory();
        if (ragempRoot is null)
        {
            await Task.CompletedTask;
            return;
        }

        var packageDirs = new[]
        {
            Path.Combine(ragempRoot, "client_packages"),
            Path.Combine(ragempRoot, "dotnet"),
            Path.Combine(ragempRoot, "dotnet", "scripts"),
            Path.Combine(ragempRoot, "plugins"),
        };

        foreach (var dir in packageDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            string[] subDirs;
            try
            {
                subDirs = Directory.GetDirectories(dir);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var subDir in subDirs)
            {
                ct.ThrowIfCancellationRequested();
                var dirName = Path.GetFileName(subDir);

                if (ContainsWeaponHackKeywordInName(dirName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Waffen-Hack-Package-Ordner: {dirName}",
                        Risk = RiskLevel.High,
                        Location = subDir,
                        Reason = $"RageMP client_packages/plugins-Unterverzeichnis '{dirName}' traegt waffen-hack-typische Bezeichnung. " +
                                 "Weapon-Cheat-Plugins fuer RageMP werden als benannte Package-Ordner abgelegt."
                    });
                }

                string[] packageFiles;
                try
                {
                    packageFiles = Directory.GetFiles(subDir, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var file in packageFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var ext = Path.GetExtension(file).ToLowerInvariant();
                    var fileName = Path.GetFileName(file);

                    if (ContainsWeaponHackKeywordInName(fileName))
                    {
                        try
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Waffen-Hack-Datei in RageMP-Package: {fileName}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason = $"Datei '{fileName}' in RageMP-Package-Ordner '{dirName}' hat waffen-hack-typischen Namen. " +
                                         "Weapon-Cheat-Dateien werden in legitimen RageMP-Package-Strukturen versteckt."
                            });
                        }
                        catch (IOException) { }
                        continue;
                    }

                    if (ext is not ".js" and not ".json" and not ".cs" and not ".lua" and not ".ts")
                        continue;

                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        foreach (var keyword in RageMPConfigWeaponKeywords)
                        {
                            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Waffen-Hack-Konfiguration in Package: {fileName}",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = fileName,
                                    Reason = $"RageMP-Package-Datei '{fileName}' enthaelt Weapon-Hack-Konfigurationsschluessel '{keyword}'. " +
                                             "Weapon-Cheat-Packages konfigurieren ihre Funktion ueber solche Eintraege " +
                                             "in Konfigurationsdateien oder Skripten."
                                });
                                break;
                            }
                        }

                        bool hasWeaponGive = content.Contains("mp.game.weapon.give", StringComparison.OrdinalIgnoreCase)
                            || content.Contains("giveWeapon(", StringComparison.OrdinalIgnoreCase)
                            || content.Contains("AddWeapon(", StringComparison.OrdinalIgnoreCase);

                        bool hasUnlimited = content.Contains("unlimitedAmmo", StringComparison.OrdinalIgnoreCase)
                            || content.Contains("infinite_ammo", StringComparison.OrdinalIgnoreCase)
                            || content.Contains("addAmmo(", StringComparison.OrdinalIgnoreCase);

                        bool hasBypass = content.Contains("bypass", StringComparison.OrdinalIgnoreCase)
                            || content.Contains("exploit", StringComparison.OrdinalIgnoreCase)
                            || content.Contains("hack", StringComparison.OrdinalIgnoreCase);

                        if (hasWeaponGive && (hasUnlimited || hasBypass))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Kombiniertes Waffen-Exploit-Muster in Package: {fileName}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason = "RageMP-Package-Datei kombiniert Waffengabe-Funktionen (mp.game.weapon.give/giveWeapon/AddWeapon) " +
                                         "mit unlimitierter Munition oder Bypass/Exploit-Mustern. " +
                                         "Dies ist ein starkes Indiz fuer ein RageMP Weapon-Hack-Plugin."
                            });
                        }
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
        }
    }, ct);

    private static bool ContainsWeaponHackKeywordInName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return false;

        var keywords = new[]
        {
            "weaponhack", "weapon_hack", "giveallweapons", "give_all_weapons",
            "weaponesp", "weapon_esp", "weapongive", "weapon_give",
            "ammohack", "ammo_hack", "weaponbypass", "weapon_bypass",
            "weaponcheat", "weapon_cheat", "weaponinject", "weapon_inject",
            "ammoinject", "ammo_inject", "weaponoverride", "weapon_override",
            "allweapons", "all_weapons", "giveweapon", "give_weapon",
            "unlimitedammo", "unlimited_ammo", "ragemp_weapon", "ragempweapon",
            "weaponloader", "weapon_loader", "ammoloader", "ammo_loader",
            "weaponspoof", "weapon_spoof", "weaponesp", "weapon_rpc",
            "weaponpayload", "weapon_payload", "netweapon", "net_weapon"
        };

        foreach (var kw in keywords)
        {
            if (name.Contains(kw, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static string Rot13Decode(string s)
    {
        var chars = s.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            char c = chars[i];
            if (c >= 'A' && c <= 'Z')
                chars[i] = (char)('A' + (c - 'A' + 13) % 26);
            else if (c >= 'a' && c <= 'z')
                chars[i] = (char)('a' + (c - 'a' + 13) % 26);
        }
        return new string(chars);
    }
}
