using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class AltVVehicleHackScanModule : IScanModule
{
    public string Name => "AltV-VehicleHack";
    public double Weight => 1.1;
    public int ParallelGroup => 4;

    private static readonly string[] VehicleHackFilePatterns =
    {
        "vehicleHack*", "vehicleSpawn*", "godmodeCar*", "vehicle_esp*",
        "vehicle_speed_hack*", "spawnVehicle_exploit*", "vehicleMod_cheat*",
        "vehicleMod_bypass*", "VehicleSpawner*", "CarHack*", "GodmodeCar*",
        "VehicleESP*", "car_hack*", "vehicle_inject*", "vehicle_cheat*",
        "altv_vehicle*", "vehicle_bypass*", "car_spawn*", "vehicle_god*"
    };

    private static readonly string[] VehicleHackExeNames =
    {
        "VehicleSpawner.exe", "CarHack.exe", "GodmodeCar.exe", "VehicleESP.exe",
        "vehicle_spawner.exe", "car_hack.exe", "godmode_car.exe", "vehicle_esp.exe",
        "VehicleHack.exe", "SpawnCar.exe", "CarSpawner.exe", "VehicleMod.exe",
        "AltVVehicle.exe", "vehicle_bypass.exe", "car_inject.exe"
    };

    private static readonly string[] LogKeywords =
    {
        "vehicle hack", "car spawn hack", "god mode vehicle", "vehicle esp altv",
        "car speed hack", "vehicle bypass altv", "vehiclehack", "carspawn",
        "vehicle_hack", "godmode car", "vehicle esp", "car hack altv",
        "spawn vehicle exploit", "vehicle mod cheat", "vehicle cheat altv",
        "vehicle inject", "altv vehicle bypass", "vehicle speed override"
    };

    private static readonly string[] JsResourcePatterns =
    {
        "alt.Vehicle.spawn", "setVehicleIntoSnowMode", "setVehicleEngineOn bypass",
        "vehicle_god", "vehicle_speed override", "alt.Vehicle.getByID",
        "vehicle.setMod(", "vehicle.setWheels(", "vehicle.repair()",
        "alt.emit('vehicleHack'", "alt.emit(\"vehicleHack\"",
        "vehicle.invincible", "vehicle.engineOn = ", "vehicle.primaryColor",
        "spawnVehicle(", "SpawnVehicle(", "createVehicle(", "CreateVehicle(",
        "alt.Vehicle.all.forEach", "native.setVehicleInvincible",
        "SetVehicleInvincible(", "setVehicleGodMode", "vehicle.godMode",
        "GTA.Vehicle.create", "vehSpawn(", "hackVehicle(", "bypassVehicle("
    };

    private static readonly string[] CsResourcePatterns =
    {
        "Vehicle.Create(", "alt.Vehicle.spawn", "setVehicleInvincible",
        "vehicle_god", "VehicleSpawn(", "GodmodeCar(", "vehicle.godMode",
        "SetVehicleEngineOn bypass", "VehicleMod.Bypass", "vehicle_speed_override",
        "AltV.Net.Vehicle", "vehicle.Invincible = true", "vehicle.EngineOn = true",
        "API.CreateVehicle(", "API.SetVehicleInvincible(", "vehicle.Repair()"
    };

    private static readonly string[] DiscordKeywords =
    {
        "altv vehicle hack", "car hack altv", "vehicle esp altv",
        "god mode vehicle altv", "spawn car altv hack", "vehicle bypass altv",
        "altv car spawn", "vehicle cheat altv", "altv godmode car",
        "vehicle speed hack altv", "altv vehicle exploit", "altv spawn hack",
        "car god mode altv", "vehicle inject altv", "altv veh hack"
    };

    private static readonly string[] ResourceManifestKeywords =
    {
        "vehicleHack", "vehicle_hack", "VehicleSpawner", "GodmodeCar",
        "vehicle_esp", "carHack", "vehicleMod_cheat", "vehicleMod_bypass",
        "vehicle_speed_hack", "car_spawn_hack", "vehicle_exploit",
        "vehicle_inject", "vehicle_bypass"
    };

    private static readonly string[] MemDumpKeywords =
    {
        "alt::Vehicle", "vehicle_hack", "VehicleSpawner", "GodmodeCar",
        "vehicle_god", "vehicle_esp", "car_hack_altv", "vehicleHack",
        "spawn_vehicle_exploit", "vehicle_bypass", "vehicle_speed_override",
        "setVehicleInvincible", "vehicle_mod_cheat"
    };

    private static readonly string UserAssistBase =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

    private static readonly string[] UserAssistVehicleKeywords =
    {
        "vehiclespawner", "carhack", "godmodecar", "vehicleesp",
        "vehicle_hack", "vehicle_spawn", "altv_vehicle", "car_hack",
        "vehiclemod", "vehicle_esp", "vehicle_bypass", "carspawn"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting alt:V vehicle hack forensic scan");

        await Task.WhenAll(
            CheckAltVAppDataFiles(ctx, ct),
            CheckAltVResourceDirs(ctx, ct),
            CheckLogFiles(ctx, ct),
            CheckJsResourceFiles(ctx, ct),
            CheckCsResourceFiles(ctx, ct),
            CheckKnownExeFiles(ctx, ct),
            CheckRegistry(ctx, ct),
            CheckPrefetch(ctx, ct),
            CheckUserAssist(ctx, ct),
            CheckDiscordArtifacts(ctx, ct),
            CheckResourceManifests(ctx, ct),
            CheckTempFiles(ctx, ct),
            CheckMemoryDumpArtifacts(ctx, ct),
            CheckAltVCacheFiles(ctx, ct),
            CheckAltVDataDirectories(ctx, ct)
        );

        ctx.Report(1.0, Name, "alt:V vehicle hack scan complete");
    }

    private Task CheckAltVAppDataFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var searchRoots = new[]
        {
            Path.Combine(appData, "altv"),
            Path.Combine(appData, "alt-v"),
            Path.Combine(localAppData, "altv"),
            Path.Combine(localAppData, "alt-v"),
            Path.Combine(localAppData, "AltV"),
            Path.Combine(appData, "AltV")
        };

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            foreach (var pattern in VehicleHackFilePatterns)
            {
                if (ct.IsCancellationRequested) return;
                string[] found = Array.Empty<string>();
                try
                {
                    found = Directory.GetFiles(root, pattern, SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var f in found)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"AltV vehicle hack file: {Path.GetFileName(f)}",
                        Risk = RiskLevel.High,
                        Location = f,
                        FileName = Path.GetFileName(f),
                        Reason = $"File matching vehicle hack pattern '{pattern}' found in alt:V AppData directory '{root}'. " +
                                 "This file name pattern is characteristic of alt:V vehicle spawning, god mode, or ESP cheat tools. " +
                                 "The presence of this artifact indicates vehicle hack tool activity."
                    });
                }
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckAltVResourceDirs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var resourceRoots = new[]
        {
            Path.Combine(appData, "altv", "resources"),
            Path.Combine(appData, "alt-v", "resources"),
            Path.Combine(localAppData, "altv", "resources"),
            Path.Combine(localAppData, "AltV", "resources"),
            Path.Combine(appData, "altv", "data"),
            Path.Combine(localAppData, "altv", "data"),
            Path.Combine(appData, "altv", "cache"),
            Path.Combine(localAppData, "altv", "cache")
        };

        foreach (var resourceRoot in resourceRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(resourceRoot)) continue;

            string[] dirs = Array.Empty<string>();
            try
            {
                dirs = Directory.GetDirectories(resourceRoot, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var dir in dirs)
            {
                if (ct.IsCancellationRequested) return;
                var dirName = Path.GetFileName(dir);

                bool isVehicleHackDir = VehicleHackFilePatterns.Any(p =>
                {
                    var pattern = p.TrimEnd('*').TrimStart('*');
                    return dirName.Contains(pattern, StringComparison.OrdinalIgnoreCase);
                });

                if (isVehicleHackDir)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"AltV vehicle hack resource directory: {dirName}",
                        Risk = RiskLevel.High,
                        Location = dir,
                        FileName = dirName,
                        Reason = $"Directory '{dirName}' in alt:V resources path '{resourceRoot}' matches vehicle hack naming patterns. " +
                                 "Cheat resource directories persist in alt:V resource folders even after the cheat is no longer active. " +
                                 "This is a forensic artifact of vehicle hack tool deployment."
                    });
                }
            }

            foreach (var pattern in VehicleHackFilePatterns)
            {
                if (ct.IsCancellationRequested) return;
                string[] found = Array.Empty<string>();
                try
                {
                    found = Directory.GetFiles(resourceRoot, pattern, SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var f in found)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"AltV vehicle hack file in resource dir: {Path.GetFileName(f)}",
                        Risk = RiskLevel.High,
                        Location = f,
                        FileName = Path.GetFileName(f),
                        Reason = $"File matching vehicle hack pattern '{pattern}' found inside alt:V resources at '{resourceRoot}'. " +
                                 "Vehicle hack resources are deployed here to be loaded as alt:V server-side or client-side cheats. " +
                                 "This artifact strongly indicates vehicle exploitation tool use."
                    });
                }
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckLogFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var temp = Path.GetTempPath();

        var logSearchRoots = new[]
        {
            Path.Combine(appData, "altv"),
            Path.Combine(localAppData, "altv"),
            Path.Combine(appData, "alt-v"),
            Path.Combine(localAppData, "AltV"),
            temp
        };

        foreach (var logRoot in logSearchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(logRoot)) continue;

            string[] logFiles = Array.Empty<string>();
            try
            {
                logFiles = Directory.GetFiles(logRoot, "*.log", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(logRoot, "*.txt", SearchOption.AllDirectories))
                    .ToArray();
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var logFile in logFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var keyword in LogKeywords)
                {
                    if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"AltV vehicle hack log evidence: {Path.GetFileName(logFile)}",
                            Risk = RiskLevel.High,
                            Location = logFile,
                            FileName = Path.GetFileName(logFile),
                            Reason = $"Log file '{logFile}' contains vehicle hack keyword '{keyword}'. " +
                                     "Log files retain evidence of vehicle hack activity in alt:V even after the cheat tool is removed. " +
                                     "This log artifact is a forensic indicator of vehicle exploitation."
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckJsResourceFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var jsSearchRoots = new[]
        {
            Path.Combine(appData, "altv"),
            Path.Combine(localAppData, "altv"),
            Path.Combine(appData, "alt-v"),
            Path.Combine(localAppData, "AltV")
        };

        foreach (var jsRoot in jsSearchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(jsRoot)) continue;

            string[] jsFiles = Array.Empty<string>();
            try
            {
                jsFiles = Directory.GetFiles(jsRoot, "*.js", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(jsRoot, "*.mjs", SearchOption.AllDirectories))
                    .Concat(Directory.GetFiles(jsRoot, "*.ts", SearchOption.AllDirectories))
                    .ToArray();
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var jsFile in jsFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var pattern in JsResourcePatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"AltV vehicle hack JS pattern: {Path.GetFileName(jsFile)}",
                            Risk = RiskLevel.High,
                            Location = jsFile,
                            FileName = Path.GetFileName(jsFile),
                            Reason = $"JavaScript resource file '{jsFile}' contains vehicle hack pattern '{pattern}'. " +
                                     "This JavaScript code contains alt:V-specific vehicle manipulation calls consistent with " +
                                     "vehicle spawn hacks, god mode vehicles, or vehicle ESP cheats. " +
                                     "Such scripts are deployed as alt:V client or server resources."
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckCsResourceFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var csSearchRoots = new[]
        {
            Path.Combine(appData, "altv"),
            Path.Combine(localAppData, "altv"),
            Path.Combine(appData, "alt-v"),
            Path.Combine(localAppData, "AltV")
        };

        foreach (var csRoot in csSearchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(csRoot)) continue;

            string[] csFiles = Array.Empty<string>();
            try
            {
                csFiles = Directory.GetFiles(csRoot, "*.cs", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(csRoot, "*.dll", SearchOption.AllDirectories))
                    .ToArray();
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var csFile in csFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var ext = Path.GetExtension(csFile);
                if (ext.Equals(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    var fileName = Path.GetFileName(csFile);
                    bool isDllSuspicious = VehicleHackFilePatterns.Any(p =>
                    {
                        var pattern = p.TrimEnd('*').TrimStart('*');
                        return fileName.Contains(pattern, StringComparison.OrdinalIgnoreCase);
                    });

                    if (isDllSuspicious)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"AltV vehicle hack DLL: {fileName}",
                            Risk = RiskLevel.High,
                            Location = csFile,
                            FileName = fileName,
                            Reason = $"DLL file '{csFile}' in alt:V directory matches vehicle hack naming pattern. " +
                                     "This compiled .NET DLL may be an alt:V C# resource implementing vehicle hacking functionality. " +
                                     "C# resources are loaded directly by alt:V and can spawn vehicles or apply god mode."
                        });
                    }
                    continue;
                }

                string content;
                try
                {
                    using var fs = new FileStream(csFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var pattern in CsResourcePatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"AltV vehicle hack C# resource: {Path.GetFileName(csFile)}",
                            Risk = RiskLevel.High,
                            Location = csFile,
                            FileName = Path.GetFileName(csFile),
                            Reason = $"C# source file '{csFile}' contains vehicle hack API pattern '{pattern}'. " +
                                     "This alt:V C# resource file contains API calls consistent with vehicle manipulation cheats. " +
                                     "C# resources in alt:V can programmatically spawn, modify or make vehicles invincible."
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckKnownExeFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        };

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            foreach (var exeName in VehicleHackExeNames)
            {
                if (ct.IsCancellationRequested) return;
                string[] found = Array.Empty<string>();
                try
                {
                    found = Directory.GetFiles(dir, exeName, SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var exe in found)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"AltV vehicle hack executable: {exeName}",
                        Risk = RiskLevel.Critical,
                        Location = exe,
                        FileName = exeName,
                        Reason = $"Known alt:V vehicle hack executable '{exeName}' found at '{exe}'. " +
                                 "This executable is a recognized alt:V vehicle hacking tool capable of spawning any vehicle, " +
                                 "enabling god mode on vehicles, applying speed hacks, or providing vehicle ESP. " +
                                 "This is a critical forensic artifact."
                    });
                }
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckRegistry(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var registryPaths = new[]
        {
            @"Software\AltV\VehicleHack",
            @"Software\AltVTools\CarHack",
            @"Software\AltV\VehicleSpawner",
            @"Software\AltV\VehicleESP",
            @"Software\AltVTools\VehicleHack",
            @"Software\AltV\GodmodeCar",
            @"Software\AltVTools\VehicleSpawner",
            @"Software\AltVTools\GodmodeCar",
            @"Software\AltVTools\VehicleESP",
            @"Software\AltV\CarHack",
            @"Software\AltVVehicleHack",
            @"Software\VehicleHackAltV"
        };

        foreach (var regPath in registryPaths)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(regPath, writable: false);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"AltV vehicle hack registry key: {regPath}",
                    Risk = RiskLevel.High,
                    Location = $@"HKCU\{regPath}",
                    Reason = $"Registry key 'HKCU\\{regPath}' associated with alt:V vehicle hack tools was found. " +
                             "Vehicle hack tools for alt:V write configuration and state to this registry location. " +
                             "The key persists after tool removal and is a reliable forensic artifact."
                });

                foreach (var valueName in key.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();
                    var valueData = key.GetValue(valueName)?.ToString() ?? string.Empty;
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"AltV vehicle hack registry value: {valueName}",
                        Risk = RiskLevel.High,
                        Location = $@"HKCU\{regPath}\{valueName}",
                        Detail = $"Value: {valueName} = {valueData}",
                        Reason = $"Registry value '{valueName}' under vehicle hack key 'HKCU\\{regPath}' contains data: '{valueData}'. " +
                                 "Configuration values stored by alt:V vehicle hack tools remain in the registry as forensic artifacts. " +
                                 "This value indicates the tool was configured or run on this system."
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        var vehicleHackValueKeywords = new[]
        {
            "vehiclehack", "carhack", "godmodecar", "vehicleesp", "vehiclespawner",
            "vehicle_hack", "altv_vehicle", "car_hack", "vehicle_bypass"
        };

        var softwareKey = @"Software";
        try
        {
            using var swKey = Registry.CurrentUser.OpenSubKey(softwareKey, writable: false);
            if (swKey is not null)
            {
                foreach (var subKeyName in swKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    bool isVehicleHack = vehicleHackValueKeywords.Any(k =>
                        subKeyName.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (!isVehicleHack) continue;

                    ctx.IncrementRegistryKeys();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"AltV vehicle hack software key: {subKeyName}",
                        Risk = RiskLevel.High,
                        Location = $@"HKCU\Software\{subKeyName}",
                        Reason = $"Registry subkey 'HKCU\\Software\\{subKeyName}' matches alt:V vehicle hack tool naming patterns. " +
                                 "Software registry keys created by vehicle hack tools persist after uninstallation. " +
                                 "This key is a forensic artifact indicating vehicle exploitation tool installation."
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckPrefetch(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        const string prefetchDir = @"C:\Windows\Prefetch";
        if (!Directory.Exists(prefetchDir))
        {
            await Task.CompletedTask;
            return;
        }

        string[] pfFiles = Array.Empty<string>();
        try
        {
            pfFiles = Directory.GetFiles(prefetchDir, "*.pf");
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        var vehicleExeNamesNoExt = VehicleHackExeNames
            .Select(e => Path.GetFileNameWithoutExtension(e).ToUpperInvariant())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var vehicleKeywordsUpper = new[]
        {
            "VEHICLEHACK", "VEHICLESPAWN", "GODMODECAR", "VEHICLEESP",
            "CARHACK", "VEHICLE_HACK", "CAR_HACK", "VEHICLE_ESP",
            "VEHICLE_SPEED_HACK", "SPAWNVEHICLE", "VEHICLEMOD", "VEHICLE_BYPASS",
            "ALTV_VEHICLE", "CAR_SPAWN", "VEHICLE_INJECT"
        };

        foreach (var pf in pfFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var pfName = Path.GetFileNameWithoutExtension(pf).ToUpperInvariant();
            var dashIdx = pfName.LastIndexOf('-');
            var exeName = dashIdx > 0 && pfName.Length - dashIdx == 9
                ? pfName[..dashIdx]
                : pfName;

            bool isVehicleHack = vehicleExeNamesNoExt.Contains(exeName) ||
                                 vehicleKeywordsUpper.Any(k => exeName.Contains(k, StringComparison.OrdinalIgnoreCase));

            if (!isVehicleHack) continue;

            DateTime lastRun = default;
            try { lastRun = File.GetLastWriteTimeUtc(pf); } catch { }

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"AltV vehicle hack prefetch: {exeName}",
                Risk = RiskLevel.High,
                Location = pf,
                FileName = exeName + ".exe",
                Detail = lastRun != default ? $"Prefetch last updated: {lastRun:yyyy-MM-dd HH:mm:ss} UTC" : null,
                Reason = $"Windows Prefetch entry indicates execution of '{exeName}.exe', a known alt:V vehicle hack tool. " +
                         "Prefetch files are created on first execution and updated on subsequent runs. " +
                         "This artifact persists even after the executable is deleted, proving the tool was run on this system."
            });
        }
    }, ct);

    private Task CheckUserAssist(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            using var baseKey = Registry.CurrentUser.OpenSubKey(UserAssistBase, writable: false);
            if (baseKey is null)
            {
                await Task.CompletedTask;
                return;
            }

            foreach (var guidName in baseKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var countKey = baseKey.OpenSubKey($@"{guidName}\Count", writable: false);
                    if (countKey is null) continue;

                    foreach (var encodedName in countKey.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        var decoded = Rot13Decode(encodedName).ToLowerInvariant();

                        bool isVehicleHack = UserAssistVehicleKeywords.Any(k =>
                            decoded.Contains(k, StringComparison.OrdinalIgnoreCase));

                        if (!isVehicleHack) continue;

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
                            Module = Name,
                            Title = $"AltV vehicle hack UserAssist: {Path.GetFileName(decoded)}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{UserAssistBase}\{guidName}\Count",
                            FileName = Path.GetFileName(decoded),
                            Detail = $"Decoded: {decoded} | Run count: {runCount} | " +
                                     $"Last run: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unknown")}",
                            Reason = $"UserAssist registry entry shows execution of alt:V vehicle hack launcher '{Path.GetFileName(decoded)}' " +
                                     $"({runCount} time(s) executed" +
                                     (lastRun.HasValue ? $", last seen {lastRun.Value:yyyy-MM-dd HH:mm} UTC" : "") +
                                     "). UserAssist entries are ROT13-encoded and persist after file deletion. " +
                                     "This is forensic evidence of vehicle hack tool execution via Windows Explorer."
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
        await Task.CompletedTask;
    }, ct);

    private Task CheckDiscordArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var discordClients = new[] { "discord", "discordptb", "discordcanary" };

        foreach (var client in discordClients)
        {
            if (ct.IsCancellationRequested) return;
            var discordRoot = Path.Combine(appData, client);
            if (!Directory.Exists(discordRoot)) continue;

            var cachePaths = new[]
            {
                Path.Combine(discordRoot, "Cache", "Cache_Data"),
                Path.Combine(discordRoot, "Cache"),
                Path.Combine(discordRoot, "Local Storage", "leveldb"),
                Path.Combine(discordRoot, "Session Storage"),
                Path.Combine(discordRoot, "Code Cache", "js")
            };

            foreach (var cachePath in cachePaths)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(cachePath)) continue;

                string[] cacheFiles = Array.Empty<string>();
                try
                {
                    cacheFiles = Directory.GetFiles(cachePath).Take(100).ToArray();
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var cacheFile in cacheFiles)
                {
                    if (ct.IsCancellationRequested) return;

                    var fi = new FileInfo(cacheFile);
                    if (fi.Length > 10 * 1024 * 1024) continue;
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        var bytes = File.ReadAllBytes(cacheFile);
                        content = Encoding.GetEncoding("ISO-8859-1").GetString(bytes);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var keyword in DiscordKeywords)
                    {
                        if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Discord alt:V vehicle hack artifact: {keyword}",
                                Risk = RiskLevel.High,
                                Location = cacheFile,
                                FileName = Path.GetFileName(cacheFile),
                                Detail = $"Discord client: {client} | Keyword: {keyword}",
                                Reason = $"Discord cache file '{cacheFile}' contains alt:V vehicle hack keyword '{keyword}'. " +
                                         "Discord cache retains server names, message fragments, and channel content related to cheat distribution. " +
                                         "This artifact indicates membership or activity in alt:V vehicle hack communities."
                            });
                            break;
                        }
                    }
                }
            }
        }
    }, ct);

    private Task CheckResourceManifests(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var manifestSearchRoots = new[]
        {
            Path.Combine(appData, "altv"),
            Path.Combine(localAppData, "altv"),
            Path.Combine(appData, "alt-v"),
            Path.Combine(localAppData, "AltV")
        };

        foreach (var manifestRoot in manifestSearchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(manifestRoot)) continue;

            string[] manifestFiles = Array.Empty<string>();
            try
            {
                manifestFiles = Directory.GetFiles(manifestRoot, "resource.cfg", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(manifestRoot, "resource.toml", SearchOption.AllDirectories))
                    .Concat(Directory.GetFiles(manifestRoot, "resource.json", SearchOption.AllDirectories))
                    .Concat(Directory.GetFiles(manifestRoot, "*.cfg", SearchOption.AllDirectories))
                    .ToArray();
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var manifestFile in manifestFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(manifestFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var keyword in ResourceManifestKeywords)
                {
                    if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"AltV vehicle hack manifest: {Path.GetFileName(manifestFile)}",
                            Risk = RiskLevel.High,
                            Location = manifestFile,
                            FileName = Path.GetFileName(manifestFile),
                            Detail = $"Keyword matched: {keyword}",
                            Reason = $"Resource manifest '{manifestFile}' references vehicle hack component '{keyword}'. " +
                                     "Alt:V resource manifest files declare which scripts and files a resource loads. " +
                                     "A manifest referencing vehicle hack scripts is a forensic indicator of cheat resource deployment."
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckTempFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var temp = Path.GetTempPath();
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localTemp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp");

        var tempRoots = new[] { temp, localTemp };

        foreach (var tempRoot in tempRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(tempRoot)) continue;

            foreach (var pattern in VehicleHackFilePatterns)
            {
                if (ct.IsCancellationRequested) return;
                string[] found = Array.Empty<string>();
                try
                {
                    found = Directory.GetFiles(tempRoot, pattern, SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var f in found)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"AltV vehicle hack temp file: {Path.GetFileName(f)}",
                        Risk = RiskLevel.High,
                        Location = f,
                        FileName = Path.GetFileName(f),
                        Reason = $"Temporary file matching vehicle hack pattern '{pattern}' found at '{f}'. " +
                                 "Vehicle injection and spawn hack tools create temporary files during injection attempts into alt:V processes. " +
                                 "These temp artifacts indicate active use of vehicle exploitation tools."
                    });
                }
            }

            var altVTempKeywords = new[]
            {
                "altv_veh", "altv_car", "vehicle_inject", "car_spawn_tmp",
                "vehicle_hack_tmp", "godmode_car_tmp", "vehicle_esp_tmp"
            };

            string[] allTempFiles = Array.Empty<string>();
            try
            {
                allTempFiles = Directory.GetFiles(tempRoot, "*", SearchOption.TopDirectoryOnly)
                    .Where(f => {
                        var name = Path.GetFileName(f);
                        return altVTempKeywords.Any(k => name.Contains(k, StringComparison.OrdinalIgnoreCase));
                    })
                    .ToArray();
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var f in allTempFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"AltV vehicle injection temp file: {Path.GetFileName(f)}",
                    Risk = RiskLevel.Medium,
                    Location = f,
                    FileName = Path.GetFileName(f),
                    Reason = $"Temporary file '{Path.GetFileName(f)}' at '{f}' matches alt:V vehicle injection temp file patterns. " +
                             "These files are created during vehicle hack injection attempts and indicate active cheat tool use. " +
                             "Temporary files from failed injection attempts are common forensic artifacts."
                });
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckMemoryDumpArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var dumps = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var temp = Path.GetTempPath();

        var dumpSearchRoots = new[]
        {
            Path.Combine(appData, "altv"),
            Path.Combine(localAppData, "altv"),
            Path.Combine(localAppData, "CrashDumps"),
            dumps,
            temp,
            @"C:\Windows\Temp"
        };

        foreach (var dumpRoot in dumpSearchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dumpRoot)) continue;

            string[] dumpFiles = Array.Empty<string>();
            try
            {
                dumpFiles = Directory.GetFiles(dumpRoot, "*.dmp", SearchOption.TopDirectoryOnly)
                    .Concat(Directory.GetFiles(dumpRoot, "*.mdmp", SearchOption.TopDirectoryOnly))
                    .Concat(Directory.GetFiles(dumpRoot, "*.bin", SearchOption.TopDirectoryOnly))
                    .Where(f => {
                        var fi = new FileInfo(f);
                        return fi.Length < 200 * 1024 * 1024;
                    })
                    .ToArray();
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var dumpFile in dumpFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                byte[] header = new byte[Math.Min(65536, new FileInfo(dumpFile).Length)];
                int bytesRead = 0;
                try
                {
                    using var fs = new FileStream(dumpFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    bytesRead = await fs.ReadAsync(header, 0, header.Length, ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                if (bytesRead == 0) continue;

                var headerText = Encoding.ASCII.GetString(header, 0, bytesRead);

                foreach (var keyword in MemDumpKeywords)
                {
                    if (headerText.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"AltV vehicle hack memory dump: {Path.GetFileName(dumpFile)}",
                            Risk = RiskLevel.Medium,
                            Location = dumpFile,
                            FileName = Path.GetFileName(dumpFile),
                            Detail = $"Keyword in dump: {keyword}",
                            Reason = $"Memory dump file '{dumpFile}' contains alt:V vehicle hack string '{keyword}'. " +
                                     "Memory dumps from alt:V process crashes or forced dumps may contain vehicle hack code, " +
                                     "strings, and function names as forensic artifacts in process memory snapshots."
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckAltVCacheFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var cacheRoots = new[]
        {
            Path.Combine(appData, "altv", "cache"),
            Path.Combine(localAppData, "altv", "cache"),
            Path.Combine(appData, "altv", "data"),
            Path.Combine(localAppData, "altv", "data"),
            Path.Combine(appData, "altv", "client_packages"),
            Path.Combine(localAppData, "altv", "client_packages")
        };

        foreach (var cacheRoot in cacheRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(cacheRoot)) continue;

            string[] cacheFiles = Array.Empty<string>();
            try
            {
                cacheFiles = Directory.GetFiles(cacheRoot, "*.js", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(cacheRoot, "*.json", SearchOption.AllDirectories))
                    .Concat(Directory.GetFiles(cacheRoot, "*.dat", SearchOption.AllDirectories))
                    .Where(f => new FileInfo(f).Length < 5 * 1024 * 1024)
                    .ToArray();
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var cacheFile in cacheFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(cacheFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                bool foundVehicleHack = JsResourcePatterns.Any(p =>
                    content.Contains(p, StringComparison.OrdinalIgnoreCase));

                if (!foundVehicleHack) continue;

                var matchedPattern = JsResourcePatterns.First(p =>
                    content.Contains(p, StringComparison.OrdinalIgnoreCase));

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"AltV vehicle hack cache script: {Path.GetFileName(cacheFile)}",
                    Risk = RiskLevel.High,
                    Location = cacheFile,
                    FileName = Path.GetFileName(cacheFile),
                    Detail = $"Pattern: {matchedPattern}",
                    Reason = $"Alt:V cache script '{cacheFile}' contains vehicle hack pattern '{matchedPattern}'. " +
                             "Alt:V client packages and cache store JavaScript and data files served from servers. " +
                             "Vehicle hack scripts cached here were loaded and executed during alt:V sessions."
                });
            }
        }
    }, ct);

    private Task CheckAltVDataDirectories(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var altVDataRoots = new[]
        {
            Path.Combine(appData, "altv"),
            Path.Combine(localAppData, "altv"),
            Path.Combine(appData, "alt-v"),
            Path.Combine(localAppData, "AltV")
        };

        var suspiciousDataKeywords = new[]
        {
            "vehiclehack", "vehicle_hack", "carhack", "car_hack",
            "godmodecar", "godmode_car", "vehicleesp", "vehicle_esp",
            "vehiclespawner", "vehicle_spawner", "vehicle_bypass",
            "vehicle_speed", "spawnvehicle", "vehicle_exploit",
            "vehicle_inject", "vehicle_mod_cheat", "altv_vehicle_hack"
        };

        foreach (var dataRoot in altVDataRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dataRoot)) continue;

            string[] dataFiles = Array.Empty<string>();
            try
            {
                dataFiles = Directory.GetFiles(dataRoot, "*.json", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(dataRoot, "*.ini", SearchOption.AllDirectories))
                    .Concat(Directory.GetFiles(dataRoot, "*.config", SearchOption.AllDirectories))
                    .Concat(Directory.GetFiles(dataRoot, "*.xml", SearchOption.AllDirectories))
                    .Where(f => new FileInfo(f).Length < 2 * 1024 * 1024)
                    .ToArray();
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var dataFile in dataFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileNameWithoutExtension(dataFile).ToLowerInvariant();
                bool fileNameSuspicious = suspiciousDataKeywords.Any(k =>
                    fileName.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (fileNameSuspicious)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"AltV vehicle hack data file: {Path.GetFileName(dataFile)}",
                        Risk = RiskLevel.Medium,
                        Location = dataFile,
                        FileName = Path.GetFileName(dataFile),
                        Reason = $"Configuration/data file '{Path.GetFileName(dataFile)}' in alt:V directory matches vehicle hack naming patterns. " +
                                 "Vehicle hack tools save configuration, keybindings, and preferences to data files in the alt:V directory tree. " +
                                 "These files are forensic artifacts of vehicle exploitation tool use."
                    });
                    continue;
                }

                string content;
                try
                {
                    using var fs = new FileStream(dataFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                bool contentSuspicious = suspiciousDataKeywords.Any(k =>
                    content.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (!contentSuspicious) continue;

                var hitKw = suspiciousDataKeywords.First(k =>
                    content.Contains(k, StringComparison.OrdinalIgnoreCase));

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"AltV vehicle hack config content: {Path.GetFileName(dataFile)}",
                    Risk = RiskLevel.Medium,
                    Location = dataFile,
                    FileName = Path.GetFileName(dataFile),
                    Detail = $"Keyword: {hitKw}",
                    Reason = $"Alt:V data file '{dataFile}' contains vehicle hack configuration keyword '{hitKw}'. " +
                             "Vehicle hack tool configuration data stored in alt:V config files indicates the tool was actively configured and used. " +
                             "This artifact remains after the cheat is removed."
                });
            }

            string[] altVDirs = Array.Empty<string>();
            try
            {
                altVDirs = Directory.GetDirectories(dataRoot, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var dir in altVDirs)
            {
                if (ct.IsCancellationRequested) return;
                var dirName = Path.GetFileName(dir).ToLowerInvariant();
                bool dirSuspicious = suspiciousDataKeywords.Any(k =>
                    dirName.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (!dirSuspicious) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"AltV vehicle hack directory: {Path.GetFileName(dir)}",
                    Risk = RiskLevel.High,
                    Location = dir,
                    FileName = Path.GetFileName(dir),
                    Reason = $"Directory '{Path.GetFileName(dir)}' inside alt:V data path '{dataRoot}' matches vehicle hack naming patterns. " +
                             "Directories created by vehicle hack tools in the alt:V tree persist as forensic artifacts. " +
                             "The presence of this directory indicates vehicle exploitation tool installation."
                });
            }
        }
    }, ct);

    private static string Rot13Decode(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            if (c >= 'A' && c <= 'Z') sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else if (c >= 'a' && c <= 'z') sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else sb.Append(c);
        }
        return sb.ToString();
    }
}
