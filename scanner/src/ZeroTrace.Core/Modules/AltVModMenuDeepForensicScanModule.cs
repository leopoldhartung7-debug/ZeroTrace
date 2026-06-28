using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class AltVModMenuDeepForensicScanModule : IScanModule
{
    public string Name => "alt:V Mod Menu Deep Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] AltVPaths = { @"altv", @"alt-v", @"AltV" };
    private static readonly string[] CheatConfigDirs = { "AltV-Menu", "AltVCheat", "altv-hack", "AltVMenu" };
    private static readonly string[] CheatDLLNames = { "loader.dll", "cheat.dll", "menu.dll", "bypass.dll", "altv_cheat.dll", "altv_menu.dll" };
    private static readonly string[] JSExploitKeywords = { "SetEntityInvincible", "GiveWeaponToPed", "AddExplosion", "eval(", "atob(", "Function(", "discord.com/api/webhooks/", "alt.emit", "alt.emitServer" };
    private static readonly string[] CSharpExploitKeywords = { "DllImport", "VirtualProtect", "Marshal.ReadIntPtr", "NtAllocateVirtualMemory", "unsafe", "fixed (" };
    private static readonly string[] AntiBanExeNames = { "altv_antiban.exe", "altv_cleaner.exe", "altv_spoofer.exe", "altv_bypass.exe", "altv_crash.exe", "altv_dumper.exe" };
    private static readonly string[] MoneyExploitKeywords = { "grantMoney", "addCash", "giveMoney", "setBalance", "addMoney", "setCash" };
    private static readonly string[] MenuRegistryKeys = { @"Software\AltVMenu", @"Software\AltVCheat", @"Software\altv-hack" };

    private static readonly string[] LegitimateAltVDLLs = { "altv.dll", "js-module.dll", "csharp-module.dll", "libcef.dll", "d3dcompiler_47.dll", "v8.dll" };

    private static readonly string[] NativeHashPatterns = { "alt.invokeRpc", "native.invoke(0x", "invokeNative(0x", "0x9A2938DB", "0xD3A7B003", "0xB9EFD6B7", "0xE9F2CF43" };

    private static readonly string[] CrashToolNames = { "altv_crash.exe", "altv_crasher.exe", "altv_ddos.js", "altv_flood.exe", "entity_flood.js" };

    private static readonly string[] ScriptDumperNames = { "altv_dumper.exe", "script_dump.exe", "altv_extract.exe", "resource_extractor.exe" };

    private static readonly string[] ModdedClientNames = { "altv-modded.zip", "altv-hacked.zip", "altv-bypass.zip", "patched_altv.exe", "altv-client-patched.exe" };

    private static readonly string[] PcapExtensions = { ".pcap", ".pcapng", ".cap" };

    private static readonly string[] LogFileNames = { "altv_log.txt", "cheat_log.txt", "session_log.txt", "action_history.txt", "player_list.json", "server_info.json" };

    private static readonly string[] ScheduledTaskCheatKeywords = { "altv", "alt-v", "altvmenu", "altv_clean", "altv_clear", "altv_bypass" };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckAltVCheatMenuArtifacts(ctx, ct),
            CheckAltVResourceExploitArtifacts(ctx, ct),
            CheckAltVDLLInjectionArtifacts(ctx, ct),
            CheckAltVCSharpResourceCheatArtifacts(ctx, ct),
            CheckAltVVoiceBypassArtifacts(ctx, ct),
            CheckAltVNativeHashExploitArtifacts(ctx, ct),
            CheckAltVAntibanArtifacts(ctx, ct),
            CheckAltVBanEvasionTokenArtifacts(ctx, ct),
            CheckAltVMoneyExploitScripts(ctx, ct),
            CheckAltVCrashToolArtifacts(ctx, ct),
            CheckAltVScriptDumperArtifacts(ctx, ct),
            CheckAltVPlayerDataStealingArtifacts(ctx, ct),
            CheckAltVModdedClientArtifacts(ctx, ct),
            CheckAltVCEFExploitArtifacts(ctx, ct),
            CheckAltVRegistryArtifacts(ctx, ct),
            CheckAltVPrefetchArtifacts(ctx, ct),
            CheckAltVNetworkPacketCapture(ctx, ct),
            CheckAltVModMenuLogFilesAndHistory(ctx, ct)
        );
    }

    private Task CheckAltVCheatMenuArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        foreach (string dirName in CheatConfigDirs)
        {
            string cheatDir = Path.Combine(appData, dirName);
            if (Directory.Exists(cheatDir))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "alt:V Cheat Menu Config Directory Found",
                    Risk = RiskLevel.Critical,
                    Location = cheatDir,
                    FileName = dirName,
                    Reason = $"Known alt:V cheat menu configuration directory exists: '{dirName}'",
                    Detail = "This directory is created by alt:V cheat menus to store configuration — its presence proves the cheat was installed"
                });

                foreach (string configFile in new[]
                {
                    Path.Combine(cheatDir, "config.json"),
                    Path.Combine(cheatDir, "settings.json"),
                })
                {
                    if (!File.Exists(configFile)) continue;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "alt:V Cheat Menu Config File",
                        Risk = RiskLevel.Critical,
                        Location = configFile,
                        FileName = Path.GetFileName(configFile),
                        Reason = $"alt:V cheat menu configuration file found in '{dirName}'",
                        Detail = "Configuration files from alt:V cheat menus store user preferences proving active use of the cheat"
                    });
                }

                foreach (string logFile in Directory.GetFiles(cheatDir, "*.log", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "alt:V Cheat Menu Log File",
                        Risk = RiskLevel.Critical,
                        Location = logFile,
                        FileName = Path.GetFileName(logFile),
                        Reason = $"Log file from alt:V cheat menu in directory '{dirName}'",
                        Detail = "Cheat menu log files record cheat usage sessions and actions"
                    });
                }

                foreach (string dllFile in Directory.GetFiles(cheatDir, "*.dll", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "alt:V Cheat Menu DLL",
                        Risk = RiskLevel.Critical,
                        Location = dllFile,
                        FileName = Path.GetFileName(dllFile),
                        Reason = $"DLL file inside alt:V cheat menu directory '{dirName}'",
                        Detail = "DLLs stored in cheat menu config directories are cheat components or injected libraries"
                    });
                }
            }
        }

        string altVLocalDir = Path.Combine(localAppData, "altv");
        if (Directory.Exists(altVLocalDir))
        {
            string downloadsDir = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            downloadsDir = Path.Combine(downloadsDir, "Downloads");
            if (Directory.Exists(downloadsDir))
            {
                foreach (string file in Directory.GetFiles(downloadsDir, "altv_menu*.dll", SearchOption.TopDirectoryOnly)
                    .Concat(Directory.GetFiles(downloadsDir, "altv_cheat*.zip", SearchOption.TopDirectoryOnly)))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "alt:V Cheat Download Artifact",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Downloaded alt:V cheat file: '{Path.GetFileName(file)}'",
                        Detail = "Downloaded cheat DLLs and archives targeting alt:V were found in the Downloads folder"
                    });
                }
            }

            foreach (string dllFile in Directory.GetFiles(altVLocalDir, "*.dll", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                string dllName = Path.GetFileName(dllFile);
                bool isLegitimate = LegitimateAltVDLLs.Any(l => l.Equals(dllName, StringComparison.OrdinalIgnoreCase));
                if (!isLegitimate)
                {
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(dllFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        byte[] buf = new byte[Math.Min(fs.Length, 256 * 1024)];
                        int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                        string content = Encoding.UTF8.GetString(buf, 0, read);
                        bool hasCheatStrings = CheatDLLNames.Any(n => dllName.Contains(n.Replace(".dll", string.Empty), StringComparison.OrdinalIgnoreCase))
                            || content.Contains("altv", StringComparison.OrdinalIgnoreCase);
                        if (hasCheatStrings)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V Directory — Injected Non-Legitimate DLL",
                                Risk = RiskLevel.Critical,
                                Location = dllFile,
                                FileName = dllName,
                                Reason = $"Non-legitimate DLL found in alt:V LocalAppData directory: '{dllName}'",
                                Detail = "DLLs placed alongside the alt:V client that are not part of the official distribution are injection artifacts"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
    }, ct);

    private Task CheckAltVResourceExploitArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string resourcesPath = Path.Combine(localAppData, "altv", "resources");
        if (!Directory.Exists(resourcesPath)) return;

        foreach (string jsFile in Directory.GetFiles(resourcesPath, "*.js", SearchOption.AllDirectories))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                foreach (string kw in JSExploitKeywords)
                {
                    if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V Resource JS — Exploit Pattern",
                            Risk = RiskLevel.Critical,
                            Location = jsFile,
                            FileName = Path.GetFileName(jsFile),
                            Reason = $"alt:V JavaScript resource contains exploit pattern: '{kw}'",
                            Detail = "Client-side alt:V JavaScript resources using dangerous natives or obfuscation patterns indicate cheat code injection"
                        });
                        break;
                    }
                }

                if (content.Contains("discord.com/api/webhooks/", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "alt:V Resource JS — Discord Webhook Exfiltration",
                        Risk = RiskLevel.Critical,
                        Location = jsFile,
                        FileName = Path.GetFileName(jsFile),
                        Reason = "alt:V JavaScript resource contains Discord webhook URL for data exfiltration",
                        Detail = "Discord webhook URLs in alt:V client resources are used to exfiltrate player data, server information, or credentials"
                    });
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckAltVDLLInjectionArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string altVDir = Path.Combine(localAppData, "altv");
        if (!Directory.Exists(altVDir)) return;

        foreach (string dllFile in Directory.GetFiles(altVDir, "*.dll", SearchOption.TopDirectoryOnly))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            string dllName = Path.GetFileName(dllFile);
            bool isLegitimate = LegitimateAltVDLLs.Any(l => l.Equals(dllName, StringComparison.OrdinalIgnoreCase));
            if (isLegitimate) continue;

            bool isKnownCheat = CheatDLLNames.Any(c => dllName.Equals(c, StringComparison.OrdinalIgnoreCase));
            if (isKnownCheat)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "alt:V DLL Hijack — Known Cheat DLL",
                    Risk = RiskLevel.Critical,
                    Location = dllFile,
                    FileName = dllName,
                    Reason = $"Known cheat DLL found in alt:V installation directory: '{dllName}'",
                    Detail = "Cheat DLLs placed in the alt:V directory are loaded via DLL hijacking when altv.exe starts"
                });
                continue;
            }

            try
            {
                using var fs = new FileStream(dllFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                byte[] buf = new byte[Math.Min(fs.Length, 512 * 1024)];
                int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                string content = Encoding.UTF8.GetString(buf, 0, read);

                bool hasCheatContent = AltVPaths.Any(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                    && (content.Contains("inject", StringComparison.OrdinalIgnoreCase)
                        || content.Contains("bypass", StringComparison.OrdinalIgnoreCase)
                        || content.Contains("cheat", StringComparison.OrdinalIgnoreCase)
                        || content.Contains("hook", StringComparison.OrdinalIgnoreCase));

                if (hasCheatContent)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "alt:V Directory — Suspicious Non-Distribution DLL",
                        Risk = RiskLevel.Critical,
                        Location = dllFile,
                        FileName = dllName,
                        Reason = $"Unrecognized DLL in alt:V root directory with cheat-related string content: '{dllName}'",
                        Detail = "Non-standard DLLs placed in the alt:V executable directory with cheat content are injected into the alt:V process via DLL search order hijacking"
                    });
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckAltVCSharpResourceCheatArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string resourcesPath = Path.Combine(localAppData, "altv", "resources");
        if (!Directory.Exists(resourcesPath)) return;

        foreach (string csFile in Directory.GetFiles(resourcesPath, "*.cs", SearchOption.AllDirectories))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(csFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                foreach (string kw in CSharpExploitKeywords)
                {
                    if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V C# Resource — Dangerous P/Invoke Pattern",
                            Risk = RiskLevel.Critical,
                            Location = csFile,
                            FileName = Path.GetFileName(csFile),
                            Reason = $"alt:V C# resource contains dangerous interop pattern: '{kw}'",
                            Detail = "C# alt:V resources using P/Invoke to kernel functions, unsafe memory access, or reflection emit are process injection or memory manipulation tools"
                        });
                        break;
                    }
                }

                if (content.Contains("Reflection.Emit", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "alt:V C# Resource — Runtime Code Emission",
                        Risk = RiskLevel.Critical,
                        Location = csFile,
                        FileName = Path.GetFileName(csFile),
                        Reason = "alt:V C# resource uses Reflection.Emit for runtime code generation",
                        Detail = "Reflection.Emit in alt:V resources is used to generate and execute code at runtime, evading static analysis of cheat logic"
                    });
                }
            }
            catch { }
        }

        foreach (string dllFile in Directory.GetFiles(resourcesPath, "*.dll", SearchOption.AllDirectories))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(dllFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                byte[] buf = new byte[Math.Min(fs.Length, 512 * 1024)];
                int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                string content = Encoding.UTF8.GetString(buf, 0, read);

                foreach (string kw in CSharpExploitKeywords)
                {
                    if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V C# Resource DLL — Exploit Strings",
                            Risk = RiskLevel.Critical,
                            Location = dllFile,
                            FileName = Path.GetFileName(dllFile),
                            Reason = $"alt:V C# resource DLL contains exploit-related string: '{kw}'",
                            Detail = "Compiled C# resource DLLs in alt:V resources containing process injection or unsafe memory patterns are cheat components"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckAltVVoiceBypassArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string altVDir = Path.Combine(localAppData, "altv");
        if (!Directory.Exists(altVDir)) return;

        string[] voiceBypassDLLs = { "voice_bypass.dll", "spatial_bypass.dll", "voice_hook.dll", "proximity_bypass.dll" };

        foreach (string dllName in voiceBypassDLLs)
        {
            string dllPath = Path.Combine(altVDir, dllName);
            if (!File.Exists(dllPath)) continue;
            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "alt:V Voice Chat Bypass DLL",
                Risk = RiskLevel.High,
                Location = dllPath,
                FileName = dllName,
                Reason = $"Known alt:V voice proximity bypass DLL found: '{dllName}'",
                Detail = "Voice bypass DLLs in the alt:V directory hook the audio API to spoof proximity voice chat detection"
            });
        }

        foreach (string dllFile in Directory.GetFiles(altVDir, "*.dll", SearchOption.TopDirectoryOnly))
        {
            if (ct.IsCancellationRequested) return;
            string dllName = Path.GetFileName(dllFile);
            if (!dllName.Contains("voice", StringComparison.OrdinalIgnoreCase) &&
                !dllName.Contains("audio", StringComparison.OrdinalIgnoreCase) &&
                !dllName.Contains("spatial", StringComparison.OrdinalIgnoreCase)) continue;
            if (LegitimateAltVDLLs.Any(l => l.Equals(dllName, StringComparison.OrdinalIgnoreCase))) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(dllFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                byte[] buf = new byte[Math.Min(fs.Length, 256 * 1024)];
                int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                string content = Encoding.UTF8.GetString(buf, 0, read);
                if (content.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("hook", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("spoof", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "alt:V Voice-Related DLL with Bypass Content",
                        Risk = RiskLevel.High,
                        Location = dllFile,
                        FileName = dllName,
                        Reason = $"Voice/audio DLL in alt:V directory contains bypass or hook patterns: '{dllName}'",
                        Detail = "A non-standard voice or audio DLL in the alt:V directory with bypass content hooks voice proximity detection"
                    });
                }
            }
            catch { }
        }

        string[] configFiles = Directory.GetFiles(altVDir, "voice*.json", SearchOption.TopDirectoryOnly)
            .Concat(Directory.GetFiles(altVDir, "audio*.json", SearchOption.TopDirectoryOnly))
            .ToArray();

        foreach (string configFile in configFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(configFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);
                if (content.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("spoof", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("disable", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "alt:V Voice Config — Bypass Setting",
                        Risk = RiskLevel.High,
                        Location = configFile,
                        FileName = Path.GetFileName(configFile),
                        Reason = "alt:V voice configuration file contains bypass or disable settings",
                        Detail = "Voice configuration files with bypass settings disable proximity detection to allow players to hear enemies regardless of distance"
                    });
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckAltVNativeHashExploitArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        string[] nativeDbFileNames = { "altv_natives.json", "natives_altv.json", "altv_native_db.json", "altv_natives_dump.json" };

        foreach (string searchDir in new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Documents"),
            Path.Combine(localAppData, "altv"),
        })
        {
            if (!Directory.Exists(searchDir)) continue;
            foreach (string nativeDbName in nativeDbFileNames)
            {
                string nativePath = Path.Combine(searchDir, nativeDbName);
                if (!File.Exists(nativePath)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "alt:V Native Hash Database File",
                    Risk = RiskLevel.High,
                    Location = nativePath,
                    FileName = nativeDbName,
                    Reason = $"alt:V native hash database file found: '{nativeDbName}'",
                    Detail = "Native hash database files are used by cheat tools to invoke game functions directly by hash, bypassing alt:V's safe API wrapper"
                });
            }

            foreach (string jsonFile in Directory.GetFiles(searchDir, "*.json", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                var info = new FileInfo(jsonFile);
                if (info.Length < 50 * 1024) continue;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(jsonFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 128 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);
                    int hashCount = 0;
                    foreach (string pattern in NativeHashPatterns)
                    {
                        if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) hashCount++;
                    }
                    if (hashCount >= 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Large JSON File with alt:V Native Hash Patterns",
                            Risk = RiskLevel.High,
                            Location = jsonFile,
                            FileName = Path.GetFileName(jsonFile),
                            Reason = $"Large JSON file contains {hashCount} alt:V native hash invocation patterns",
                            Detail = "Large JSON files with multiple native hash patterns are alt:V native mapping databases used by cheat tools"
                        });
                    }
                }
                catch { }
            }
        }

        foreach (string searchDir in new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
        })
        {
            if (!Directory.Exists(searchDir)) continue;
            foreach (string scriptFile in Directory.GetFiles(searchDir, "*.py", SearchOption.TopDirectoryOnly)
                .Concat(Directory.GetFiles(searchDir, "*.js", SearchOption.TopDirectoryOnly)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(scriptFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    if (content.Contains("altv", StringComparison.OrdinalIgnoreCase) &&
                        content.Contains("native", StringComparison.OrdinalIgnoreCase) &&
                        content.Contains("hash", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V Native Hash Generation Script",
                            Risk = RiskLevel.High,
                            Location = scriptFile,
                            FileName = Path.GetFileName(scriptFile),
                            Reason = "Script file references alt:V native hash generation or dumping",
                            Detail = "Python/JavaScript tools generating or dumping alt:V native hashes are used to build cheat native call databases"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckAltVAntibanArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        foreach (string searchDir in new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            appData,
        })
        {
            if (!Directory.Exists(searchDir)) continue;
            foreach (string antiBanName in AntiBanExeNames)
            {
                string antiBanPath = Path.Combine(searchDir, antiBanName);
                if (!File.Exists(antiBanPath)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "alt:V Anti-Ban Tool Executable",
                    Risk = RiskLevel.Critical,
                    Location = antiBanPath,
                    FileName = antiBanName,
                    Reason = $"Known alt:V anti-ban tool found: '{antiBanName}'",
                    Detail = "Anti-ban tools for alt:V are used exclusively to evade ban systems — their presence proves ban evasion intent"
                });
            }
        }

        foreach (string searchDir in new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            appData,
        })
        {
            if (!Directory.Exists(searchDir)) continue;
            foreach (string scriptFile in Directory.GetFiles(searchDir, "*.bat", SearchOption.TopDirectoryOnly)
                .Concat(Directory.GetFiles(searchDir, "*.ps1", SearchOption.TopDirectoryOnly))
                .Concat(Directory.GetFiles(searchDir, "*.cmd", SearchOption.TopDirectoryOnly)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(scriptFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    if (content.Contains("altv", StringComparison.OrdinalIgnoreCase) &&
                        (content.Contains("rmdir", StringComparison.OrdinalIgnoreCase) ||
                         content.Contains("del ", StringComparison.OrdinalIgnoreCase) ||
                         content.Contains("Remove-Item", StringComparison.OrdinalIgnoreCase) ||
                         content.Contains("rd /s", StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V Anti-Ban Cleanup Script",
                            Risk = RiskLevel.Critical,
                            Location = scriptFile,
                            FileName = Path.GetFileName(scriptFile),
                            Reason = "Script targets alt:V directory for deletion — anti-ban cleanup artifact",
                            Detail = "Batch/PowerShell scripts that delete alt:V data directories are used to clear ban artifacts before rejoining servers"
                        });
                    }
                }
                catch { }
            }
        }

        try
        {
            using var tasksKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks");
            if (tasksKey != null)
            {
                foreach (string taskName in tasksKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();
                    try
                    {
                        using var taskKey = tasksKey.OpenSubKey(taskName);
                        if (taskKey == null) continue;
                        string actions = taskKey.GetValue("Actions")?.ToString() ?? string.Empty;
                        foreach (string kw in ScheduledTaskCheatKeywords)
                        {
                            if (actions.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Scheduled Task — alt:V Anti-Ban Automation",
                                    Risk = RiskLevel.Critical,
                                    Location = $@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{taskName}",
                                    FileName = taskName,
                                    Reason = $"Scheduled task with alt:V keyword in actions: '{kw}'",
                                    Detail = "Scheduled tasks clearing alt:V directories run automatically to destroy ban evidence before each game session"
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckAltVBanEvasionTokenArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string altVDataDir = Path.Combine(localAppData, "altv", "data");

        if (Directory.Exists(altVDataDir))
        {
            string[] tokenFiles = Directory.GetFiles(altVDataDir, "*.json", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(altVDataDir, "*.token", SearchOption.AllDirectories))
                .Concat(Directory.GetFiles(altVDataDir, "*.auth", SearchOption.AllDirectories))
                .ToArray();

            if (tokenFiles.Length > 3)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "alt:V Data Directory — Multiple Auth Token Files",
                    Risk = RiskLevel.Critical,
                    Location = altVDataDir,
                    FileName = "data",
                    Reason = $"Found {tokenFiles.Length} authentication token files in alt:V data directory — indicates multiple accounts or token rotation",
                    Detail = "Multiple alt:V auth token files prove account rotation to evade hardware bans linked to Social Club accounts"
                });
            }

            foreach (string tokenFile in tokenFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(tokenFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    if (content.Contains("token", StringComparison.OrdinalIgnoreCase) &&
                        content.Contains("account", StringComparison.OrdinalIgnoreCase) &&
                        content.Contains("hwid", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V HWID-Bound Token File",
                            Risk = RiskLevel.Critical,
                            Location = tokenFile,
                            FileName = Path.GetFileName(tokenFile),
                            Reason = "alt:V token file contains HWID binding with account rotation indicators",
                            Detail = "Token files with HWID and account fields are used by ban evasion tools to rotate alt:V Social Club accounts per hardware profile"
                        });
                    }
                }
                catch { }
            }
        }

        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string searchDir in new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
        })
        {
            if (!Directory.Exists(searchDir)) continue;
            foreach (string scriptFile in Directory.GetFiles(searchDir, "*.py", SearchOption.TopDirectoryOnly)
                .Concat(Directory.GetFiles(searchDir, "*.ps1", SearchOption.TopDirectoryOnly))
                .Concat(Directory.GetFiles(searchDir, "*.bat", SearchOption.TopDirectoryOnly)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(scriptFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    if (content.Contains("altv", StringComparison.OrdinalIgnoreCase) &&
                        content.Contains("token", StringComparison.OrdinalIgnoreCase) &&
                        content.Contains("switch", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V Token Rotation Script",
                            Risk = RiskLevel.Critical,
                            Location = scriptFile,
                            FileName = Path.GetFileName(scriptFile),
                            Reason = "Script references alt:V token switching/rotation",
                            Detail = "Token rotation scripts automate switching between multiple Rockstar/Social Club accounts to bypass alt:V bans"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckAltVMoneyExploitScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string resourcesPath = Path.Combine(localAppData, "altv", "resources");

        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string downloadsPath = Path.Combine(userProfile, "Downloads");

        foreach (string searchDir in new[] { resourcesPath, downloadsPath }.Where(Directory.Exists))
        {
            foreach (string scriptFile in Directory.GetFiles(searchDir, "*.js", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(searchDir, "*.cs", SearchOption.AllDirectories)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(scriptFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (string moneyKw in MoneyExploitKeywords)
                    {
                        if (content.Contains(moneyKw, StringComparison.OrdinalIgnoreCase))
                        {
                            bool hasServerEvent = content.Contains("alt.emitServer", StringComparison.OrdinalIgnoreCase) ||
                                                  content.Contains("alt.emit(", StringComparison.OrdinalIgnoreCase) ||
                                                  content.Contains("triggerServer", StringComparison.OrdinalIgnoreCase);
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V Money Exploit Script",
                                Risk = RiskLevel.Critical,
                                Location = scriptFile,
                                FileName = Path.GetFileName(scriptFile),
                                Reason = $"Script contains money exploit keyword: '{moneyKw}'" + (hasServerEvent ? " with server event trigger" : string.Empty),
                                Detail = "alt:V client scripts triggering server-side money events without server authorization exploit client-to-server event trust vulnerabilities"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckAltVCrashToolArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        foreach (string searchDir in new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
        }.Where(Directory.Exists))
        {
            foreach (string crashToolName in CrashToolNames)
            {
                string crashPath = Path.Combine(searchDir, crashToolName);
                if (!File.Exists(crashPath)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "alt:V Crash Tool Executable",
                    Risk = RiskLevel.Critical,
                    Location = crashPath,
                    FileName = crashToolName,
                    Reason = $"Known alt:V crash/DDoS tool found: '{crashToolName}'",
                    Detail = "alt:V crash tools are used to disconnect players or crash servers by exploiting alt:V protocol or entity streaming vulnerabilities"
                });
            }

            foreach (string jsFile in Directory.GetFiles(searchDir, "*.js", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    bool hasCrashPattern =
                        content.Contains("altv", StringComparison.OrdinalIgnoreCase) &&
                        (content.Contains("crash", StringComparison.OrdinalIgnoreCase) || content.Contains("flood", StringComparison.OrdinalIgnoreCase)) &&
                        (content.Contains("CreateVehicle", StringComparison.OrdinalIgnoreCase) ||
                         content.Contains("CreatePed", StringComparison.OrdinalIgnoreCase) ||
                         content.Contains("CreateObject", StringComparison.OrdinalIgnoreCase) ||
                         content.Contains("setInterval", StringComparison.OrdinalIgnoreCase));

                    if (hasCrashPattern)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V Entity Flood Crash Script",
                            Risk = RiskLevel.Critical,
                            Location = jsFile,
                            FileName = Path.GetFileName(jsFile),
                            Reason = "JavaScript file contains alt:V entity flood crash pattern",
                            Detail = "Rapid entity creation loops in alt:V client scripts are used to crash servers by overloading the streaming system without cleanup"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckAltVScriptDumperArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        foreach (string searchDir in new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Documents"),
        }.Where(Directory.Exists))
        {
            foreach (string dumperName in ScriptDumperNames)
            {
                string dumperPath = Path.Combine(searchDir, dumperName);
                if (!File.Exists(dumperPath)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "alt:V Script Dumper Tool",
                    Risk = RiskLevel.Critical,
                    Location = dumperPath,
                    FileName = dumperName,
                    Reason = $"Known alt:V script/resource dumper executable found: '{dumperName}'",
                    Detail = "Script dumper tools extract server-side alt:V C# or JavaScript resources to steal intellectual property or find exploitable code"
                });
            }

            foreach (string dllFile in Directory.GetFiles(searchDir, "*.dll", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                string dllName = Path.GetFileName(dllFile);
                if (!dllName.Contains("server", StringComparison.OrdinalIgnoreCase) &&
                    !dllName.Contains("resource", StringComparison.OrdinalIgnoreCase) &&
                    !dllName.Contains("altv", StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    using var fs = new FileStream(dllFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 256 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);
                    bool isDecompiled = content.Contains("ILSpy", StringComparison.OrdinalIgnoreCase) ||
                                       content.Contains("dnSpy", StringComparison.OrdinalIgnoreCase) ||
                                       content.Contains("decompiled", StringComparison.OrdinalIgnoreCase);
                    if (isDecompiled && content.Contains("altv", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Decompiled alt:V Server DLL",
                            Risk = RiskLevel.Critical,
                            Location = dllFile,
                            FileName = dllName,
                            Reason = "DLL in user directory appears to be a decompiled alt:V server-side resource",
                            Detail = "Decompiled alt:V server DLLs (via ILSpy/dnSpy) in user directories are stolen server-side code used to discover exploitable logic"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckAltVPlayerDataStealingArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string resourcesPath = Path.Combine(localAppData, "altv", "resources");

        if (Directory.Exists(resourcesPath))
        {
            foreach (string scriptFile in Directory.GetFiles(resourcesPath, "*.js", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(scriptFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    bool collectsPlayerData = content.Contains("alt.Player.all", StringComparison.OrdinalIgnoreCase) ||
                                             content.Contains("mp.players.toArray", StringComparison.OrdinalIgnoreCase);
                    bool exfiltrates = content.Contains("fetch(", StringComparison.OrdinalIgnoreCase) ||
                                      content.Contains("XMLHttpRequest", StringComparison.OrdinalIgnoreCase) ||
                                      content.Contains("discord.com/api/webhooks/", StringComparison.OrdinalIgnoreCase) ||
                                      content.Contains("http://", StringComparison.OrdinalIgnoreCase) ||
                                      content.Contains("https://", StringComparison.OrdinalIgnoreCase);
                    if (collectsPlayerData && exfiltrates)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V Player Data Exfiltration Script",
                            Risk = RiskLevel.Critical,
                            Location = scriptFile,
                            FileName = Path.GetFileName(scriptFile),
                            Reason = "alt:V resource collects all player data and sends it to an external server",
                            Detail = "Scripts harvesting alt.Player.all and posting to external URLs steal player positions, IDs, names, and other data from the server"
                        });
                    }
                }
                catch { }
            }

            foreach (string csFile in Directory.GetFiles(resourcesPath, "*.cs", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(csFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    bool collectsPlayers = content.Contains("AltV.Net.IPlayer", StringComparison.OrdinalIgnoreCase) ||
                                          content.Contains("Alt.GetAllPlayers", StringComparison.OrdinalIgnoreCase) ||
                                          content.Contains("AltV.Net.Alt.GetAllPlayers", StringComparison.OrdinalIgnoreCase);
                    bool postsData = content.Contains("HttpClient", StringComparison.OrdinalIgnoreCase) ||
                                    content.Contains("WebClient", StringComparison.OrdinalIgnoreCase) ||
                                    content.Contains("PostAsync", StringComparison.OrdinalIgnoreCase);
                    if (collectsPlayers && postsData)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V C# Resource — Player Data Harvesting",
                            Risk = RiskLevel.Critical,
                            Location = csFile,
                            FileName = Path.GetFileName(csFile),
                            Reason = "C# alt:V resource enumerates all players and posts data to external HTTP endpoint",
                            Detail = "C# code serializing all player data and POSTing to external endpoints is a player information stealer targeting alt:V servers"
                        });
                    }
                }
                catch { }
            }
        }

        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string searchDir in new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Documents"),
            Path.Combine(userProfile, "Desktop"),
        }.Where(Directory.Exists))
        {
            foreach (string jsonFile in Directory.GetFiles(searchDir, "player_list*.json", SearchOption.TopDirectoryOnly)
                .Concat(Directory.GetFiles(searchDir, "players_*.json", SearchOption.TopDirectoryOnly)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(jsonFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    if (content.Contains("position", StringComparison.OrdinalIgnoreCase) &&
                        (content.Contains("money", StringComparison.OrdinalIgnoreCase) ||
                         content.Contains("playerId", StringComparison.OrdinalIgnoreCase) ||
                         content.Contains("socialClub", StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V Player Database Dump",
                            Risk = RiskLevel.Critical,
                            Location = jsonFile,
                            FileName = Path.GetFileName(jsonFile),
                            Reason = "JSON file contains alt:V player data including positions, IDs, and money amounts",
                            Detail = "Collected player databases with positions, IDs, and economy data are output artifacts of alt:V player data stealing scripts"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckAltVModdedClientArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        foreach (string searchDir in new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
        }.Where(Directory.Exists))
        {
            foreach (string moddedName in ModdedClientNames)
            {
                string moddedPath = Path.Combine(searchDir, moddedName);
                if (!File.Exists(moddedPath)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Modded alt:V Client Distribution",
                    Risk = RiskLevel.Critical,
                    Location = moddedPath,
                    FileName = moddedName,
                    Reason = $"Modded or patched alt:V client distribution found: '{moddedName}'",
                    Detail = "Modded alt:V client distributions bypass integrity checks and include pre-patched cheat functionality"
                });
            }

            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string officialAltVExe = Path.Combine(localAppData, "altv", "altv.exe");

            foreach (string exeFile in Directory.GetFiles(searchDir, "altv*.exe", SearchOption.TopDirectoryOnly)
                .Concat(Directory.GetFiles(searchDir, "alt-v*.exe", SearchOption.TopDirectoryOnly)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                string exeName = Path.GetFileName(exeFile);
                if (exeName.Equals("altv.exe", StringComparison.OrdinalIgnoreCase) && File.Exists(officialAltVExe))
                {
                    var officialInfo = new FileInfo(officialAltVExe);
                    var foundInfo = new FileInfo(exeFile);
                    if (Math.Abs(officialInfo.Length - foundInfo.Length) > 65536)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Second alt:V Executable with Different Size",
                            Risk = RiskLevel.Critical,
                            Location = exeFile,
                            FileName = exeName,
                            Reason = $"Second altv.exe outside installation directory has significantly different size ({foundInfo.Length} vs official {officialInfo.Length} bytes)",
                            Detail = "A second altv.exe with a different file size compared to the official installation is a patched or modded client binary"
                        });
                    }
                }
                else if (!exeName.Equals("altv.exe", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Non-Official alt:V Executable",
                        Risk = RiskLevel.Critical,
                        Location = exeFile,
                        FileName = exeName,
                        Reason = $"Non-standard alt:V executable found in Downloads/Desktop: '{exeName}'",
                        Detail = "Renamed or custom alt:V client executables outside the installation directory are modded client distributions"
                    });
                }
            }

            foreach (string moduleName in new[] { "js-module.dll", "csharp-module.dll" })
            {
                string localModulePath = Path.Combine(localAppData, "altv", moduleName);
                string suspectPath = Path.Combine(searchDir, moduleName);
                if (!File.Exists(suspectPath) || !File.Exists(localModulePath)) continue;
                ctx.IncrementFiles();
                try
                {
                    using var fs1 = new FileStream(localModulePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var fs2 = new FileStream(suspectPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf1 = new byte[Math.Min(fs1.Length, 64 * 1024)];
                    byte[] buf2 = new byte[Math.Min(fs2.Length, 64 * 1024)];
                    await fs1.ReadAsync(buf1, 0, buf1.Length, ct);
                    await fs2.ReadAsync(buf2, 0, buf2.Length, ct);
                    if (!buf1.AsSpan().SequenceEqual(buf2.AsSpan()))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Modified alt:V Module DLL — {moduleName}",
                            Risk = RiskLevel.Critical,
                            Location = suspectPath,
                            FileName = moduleName,
                            Reason = $"'{moduleName}' in Downloads/Desktop differs from the installed alt:V version",
                            Detail = "Modified alt:V module DLLs (js-module.dll or csharp-module.dll) replace the official runtime to inject cheat code into all alt:V scripts"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckAltVCEFExploitArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string cefCachePath = Path.Combine(localAppData, "altv", "cache");
        if (!Directory.Exists(cefCachePath)) return;

        string[] cefExploitPatterns = { "eval(", "atob(", "document.cookie", "localStorage.setItem", "WebSocket", "fetch(\"http", "fetch('http", "XMLHttpRequest" };

        int scanned = 0;
        foreach (string cacheFile in Directory.GetFiles(cefCachePath, "*", SearchOption.AllDirectories))
        {
            if (ct.IsCancellationRequested || scanned > 300) break;
            scanned++;
            ctx.IncrementFiles();
            try
            {
                var info = new FileInfo(cacheFile);
                if (info.Length == 0 || info.Length > 2 * 1024 * 1024) continue;
                using var fs = new FileStream(cacheFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                byte[] buf = new byte[(int)Math.Min(info.Length, 512 * 1024)];
                int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                string content = Encoding.UTF8.GetString(buf, 0, read);

                foreach (string pattern in cefExploitPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        bool hasCheatContext = content.Contains("altv", StringComparison.OrdinalIgnoreCase) ||
                                              content.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                                              content.Contains("discord.com/api/webhooks/", StringComparison.OrdinalIgnoreCase);
                        if (hasCheatContext)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V CEF Cache — Exploit JavaScript Artifact",
                                Risk = RiskLevel.High,
                                Location = cacheFile,
                                FileName = Path.GetFileName(cacheFile),
                                Reason = $"alt:V Chromium cache contains exploit pattern '{pattern}' with cheat context",
                                Detail = "CEF cache entries with JavaScript exploit patterns and alt:V context indicate malicious cheat UI loaded from external cheat servers via the Chromium browser engine"
                            });
                            break;
                        }
                    }
                }

                if (content.Contains("localStorage", StringComparison.OrdinalIgnoreCase) &&
                    content.Contains("cheat", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "alt:V CEF Cache — LocalStorage Cheat Config",
                        Risk = RiskLevel.High,
                        Location = cacheFile,
                        FileName = Path.GetFileName(cacheFile),
                        Reason = "alt:V CEF cache contains localStorage entries with cheat configuration data",
                        Detail = "Cheat menus using alt:V's Chromium integration persist their configuration in CEF localStorage — these survive client reinstalls"
                    });
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckAltVRegistryArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (string cheatKey in MenuRegistryKeys)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(cheatKey);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Registry — alt:V Cheat Menu Key",
                    Risk = RiskLevel.Critical,
                    Location = $@"HKCU\{cheatKey}",
                    FileName = cheatKey,
                    Reason = $"Known alt:V cheat menu registry key found: 'HKCU\\{cheatKey}'",
                    Detail = "Cheat-specific registry keys are created by alt:V mod menus during installation or configuration — their presence is definitive evidence"
                });
            }
            catch { }
        }

        try
        {
            using var altvKey = Registry.CurrentUser.OpenSubKey(@"Software\altv");
            if (altvKey != null)
            {
                ctx.IncrementRegistryKeys();
                foreach (string valueName in altvKey.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    string val = altvKey.GetValue(valueName)?.ToString() ?? string.Empty;
                    if (val.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                        val.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                        val.Contains("inject", StringComparison.OrdinalIgnoreCase) ||
                        val.Contains("hack", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Registry — alt:V Key with Cheat Value",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKCU\Software\altv\{valueName}",
                            FileName = valueName,
                            Reason = $"alt:V registry value '{valueName}' contains cheat-related data: '{val}'",
                            Detail = "Cheat keywords in alt:V registry values indicate the official alt:V registry entries were modified by a cheat tool"
                        });
                    }
                }
            }
        }
        catch { }

        try
        {
            using var runKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
            if (runKey != null)
            {
                ctx.IncrementRegistryKeys();
                foreach (string valueName in runKey.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    string val = runKey.GetValue(valueName)?.ToString() ?? string.Empty;
                    bool hasAltVCheatRef = AltVPaths.Any(p => val.Contains(p, StringComparison.OrdinalIgnoreCase)) &&
                                          (val.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                                           val.Contains("menu", StringComparison.OrdinalIgnoreCase) ||
                                           val.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                                           val.Contains("hack", StringComparison.OrdinalIgnoreCase));
                    if (hasAltVCheatRef)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Registry Autostart — alt:V Cheat Tool",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\{valueName}",
                            FileName = valueName,
                            Reason = $"Autostart entry '{valueName}' launches alt:V cheat tool: '{val}'",
                            Detail = "Run key entries launching alt:V cheat tools autostart the cheat with Windows for persistent use"
                        });
                    }
                }
            }
        }
        catch { }

        try
        {
            using var bagMRUKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\Shell\BagMRU");
            if (bagMRUKey != null)
            {
                ctx.IncrementRegistryKeys();
                string bagMRUData = string.Join(" ", bagMRUKey.GetValueNames().Select(n => bagMRUKey.GetValue(n)?.ToString() ?? string.Empty));
                foreach (string cheatDir in CheatConfigDirs)
                {
                    if (bagMRUData.Contains(cheatDir, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Shell BagMRU — alt:V Cheat Folder Access",
                            Risk = RiskLevel.High,
                            Location = @"HKCU\Software\Microsoft\Windows\Shell\BagMRU",
                            FileName = cheatDir,
                            Reason = $"Windows Shell BagMRU records access to alt:V cheat directory: '{cheatDir}'",
                            Detail = "Shellbag entries for cheat directories persist even after the directory is deleted — proving the user browsed to the cheat folder"
                        });
                        break;
                    }
                }
            }
        }
        catch { }

        try
        {
            using var recentDocsKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.dll");
            if (recentDocsKey != null)
            {
                ctx.IncrementRegistryKeys();
                foreach (string valueName in recentDocsKey.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    byte[]? rawData = recentDocsKey.GetValue(valueName) as byte[];
                    if (rawData == null) continue;
                    string dataStr = Encoding.Unicode.GetString(rawData);
                    if (AltVPaths.Any(p => dataStr.Contains(p, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RecentDocs — alt:V DLL Opened",
                            Risk = RiskLevel.High,
                            Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.dll",
                            FileName = valueName,
                            Reason = "RecentDocs registry records a .dll file opened from an alt:V path",
                            Detail = "Recent DLL file access from alt:V paths in the RecentDocs registry proves manual loading or inspection of alt:V-related DLL files"
                        });
                    }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckAltVPrefetchArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string prefetchDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        if (!Directory.Exists(prefetchDir)) return;

        string[] cheatPrefetchPatterns = { "ALTV_CHEAT", "ALTV_MENU", "ALTV_INJECT", "ALTV_BYPASS", "ALTV_HACK", "ALTV_CRASH", "ALTV_DUMP", "ALTV_SPOOF", "ALTV_ANTIBAN" };

        foreach (string pfFile in Directory.GetFiles(prefetchDir, "ALTV*.pf", SearchOption.TopDirectoryOnly))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            string pfName = Path.GetFileName(pfFile).ToUpperInvariant();
            bool isCheatPrefetch = cheatPrefetchPatterns.Any(p => pfName.Contains(p, StringComparison.OrdinalIgnoreCase));
            if (isCheatPrefetch)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Prefetch — alt:V Cheat Executable Ran",
                    Risk = RiskLevel.High,
                    Location = pfFile,
                    FileName = pfName,
                    Reason = $"Windows Prefetch records execution of alt:V cheat executable: '{pfName}'",
                    Detail = "Prefetch files are created by Windows when a program runs and persist after deletion — proving the cheat executable was launched on this machine"
                });
            }
        }

        try
        {
            string rot13Base = @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count";
            using var userAssistKey = Registry.CurrentUser.OpenSubKey(rot13Base);
            if (userAssistKey != null)
            {
                ctx.IncrementRegistryKeys();
                foreach (string encodedName in userAssistKey.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    string decoded = Rot13Decode(encodedName);
                    bool isAltVCheat = AltVPaths.Any(p => decoded.Contains(p, StringComparison.OrdinalIgnoreCase)) &&
                                      (decoded.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                                       decoded.Contains("menu", StringComparison.OrdinalIgnoreCase) ||
                                       decoded.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                                       decoded.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                                       decoded.Contains("inject", StringComparison.OrdinalIgnoreCase));
                    if (isAltVCheat)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "UserAssist — alt:V Cheat Application Executed",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{rot13Base}\{encodedName}",
                            FileName = Path.GetFileName(decoded),
                            Reason = $"UserAssist execution history records alt:V cheat application: '{decoded}'",
                            Detail = "UserAssist ROT13-encoded entries record GUI application launch counts and timestamps — proves this cheat was run on this account"
                        });
                    }
                }
            }
        }
        catch { }
    }, ct);

    private static string Rot13Decode(string input)
    {
        var sb = new StringBuilder(input.Length);
        foreach (char c in input)
        {
            if (c >= 'A' && c <= 'Z')
                sb.Append((char)(((c - 'A' + 13) % 26) + 'A'));
            else if (c >= 'a' && c <= 'z')
                sb.Append((char)(((c - 'a' + 13) % 26) + 'a'));
            else
                sb.Append(c);
        }
        return sb.ToString();
    }

    private Task CheckAltVNetworkPacketCapture(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        DateTime cutoff = DateTime.UtcNow.AddDays(-90);

        foreach (string searchDir in new[]
        {
            Path.Combine(userProfile, "Documents"),
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            userProfile,
        }.Where(Directory.Exists))
        {
            foreach (string ext in PcapExtensions)
            {
                foreach (string pcapFile in Directory.GetFiles(searchDir, "*" + ext, SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var info = new FileInfo(pcapFile);
                    if (info.CreationTimeUtc < cutoff && info.LastWriteTimeUtc < cutoff) continue;
                    try
                    {
                        using var fs = new FileStream(pcapFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        byte[] buf = new byte[Math.Min(fs.Length, 128 * 1024)];
                        int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                        string content = Encoding.UTF8.GetString(buf, 0, read);
                        bool hasAltVContext = AltVPaths.Any(p => content.Contains(p, StringComparison.OrdinalIgnoreCase)) ||
                                             content.Contains("gtav", StringComparison.OrdinalIgnoreCase);
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Network Packet Capture — alt:V Protocol Analysis",
                            Risk = RiskLevel.High,
                            Location = pcapFile,
                            FileName = Path.GetFileName(pcapFile),
                            Reason = $"Recent packet capture file found" + (hasAltVContext ? " with alt:V/GTA V context" : string.Empty),
                            Detail = "Packet capture files are used by cheaters to analyze alt:V network protocol for exploitation, reverse engineering server communication patterns, and crafting malicious packets"
                        });
                    }
                    catch { }
                }
            }
        }

        string[] proxyConfigPaths = {
            Path.Combine(userProfile, "Documents", "Fiddler2", "Captures"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Fiddler2"),
            Path.Combine(userProfile, "Documents", "Charles"),
        };

        foreach (string proxyDir in proxyConfigPaths.Where(Directory.Exists))
        {
            foreach (string sessionFile in Directory.GetFiles(proxyDir, "*.saz", SearchOption.TopDirectoryOnly)
                .Concat(Directory.GetFiles(proxyDir, "*.chls", SearchOption.TopDirectoryOnly)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                string sessionName = Path.GetFileName(sessionFile).ToLowerInvariant();
                if (sessionName.Contains("altv", StringComparison.OrdinalIgnoreCase) ||
                    sessionName.Contains("alt-v", StringComparison.OrdinalIgnoreCase) ||
                    sessionName.Contains("gtav", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Proxy Session — alt:V Traffic Capture",
                        Risk = RiskLevel.High,
                        Location = sessionFile,
                        FileName = Path.GetFileName(sessionFile),
                        Reason = $"Fiddler/Charles proxy session targeting alt:V API traffic: '{Path.GetFileName(sessionFile)}'",
                        Detail = "Proxy session files capturing alt:V API traffic are used to reverse engineer authentication, analyze game protocol, and craft exploit requests"
                    });
                }
            }
        }
    }, ct);

    private Task CheckAltVModMenuLogFilesAndHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

        string[] logKeywords = { "teleport", "godmode", "speedhack", "noclip", "esp", "aimbot", "money", "weapon", "vehicle", "spawn", "freeze", "kick", "crash", "altv", "alt:v" };

        foreach (string searchDir in new[]
        {
            appData,
            localAppData,
            documents,
            Path.Combine(userProfile, "Desktop"),
        }.Where(Directory.Exists))
        {
            foreach (string logFileName in LogFileNames)
            {
                foreach (string logFile in Directory.GetFiles(searchDir, logFileName, SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        int matchCount = 0;
                        string? lastMatch = null;
                        foreach (string kw in logKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase)) { matchCount++; lastMatch = kw; }
                        }
                        if (matchCount >= 2)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V Cheat Menu Log — Active Use Evidence",
                                Risk = RiskLevel.Critical,
                                Location = logFile,
                                FileName = Path.GetFileName(logFile),
                                Reason = $"Cheat log file contains {matchCount} alt:V cheat action keywords (last: '{lastMatch}')",
                                Detail = "Log files recording teleport, godmode, speedhack, and other cheat actions prove active use of a mod menu on alt:V servers"
                            });
                        }
                    }
                    catch { }
                }
            }

            foreach (string playerDumpFile in Directory.GetFiles(searchDir, "player_list*.json", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(searchDir, "server_info*.json", SearchOption.AllDirectories))
                .Concat(Directory.GetFiles(searchDir, "speedhack*.log", SearchOption.AllDirectories))
                .Concat(Directory.GetFiles(searchDir, "teleport*.log", SearchOption.AllDirectories)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(playerDumpFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    if (content.Contains("altv", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("playerId", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("socialClub", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("position", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V Cheat Output — Player/Server Dump",
                            Risk = RiskLevel.Critical,
                            Location = playerDumpFile,
                            FileName = Path.GetFileName(playerDumpFile),
                            Reason = "File contains dumped alt:V player or server information from cheat tool",
                            Detail = "Player list dumps, server information files, and speedhack/teleport records are output artifacts proving cheat tool was actively used on alt:V servers"
                        });
                    }
                }
                catch { }
            }
        }

        foreach (string cheatConfigDir in CheatConfigDirs)
        {
            string cheatPath = Path.Combine(appData, cheatConfigDir);
            if (!Directory.Exists(cheatPath)) continue;
            foreach (string historyFile in Directory.GetFiles(cheatPath, "*.txt", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(cheatPath, "*.log", SearchOption.AllDirectories))
                .Concat(Directory.GetFiles(cheatPath, "*.json", SearchOption.AllDirectories)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(historyFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    if (content.Length > 32 && logKeywords.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"alt:V Cheat Menu History File in '{cheatConfigDir}'",
                            Risk = RiskLevel.Critical,
                            Location = historyFile,
                            FileName = Path.GetFileName(historyFile),
                            Reason = $"History/log file in alt:V cheat directory '{cheatConfigDir}' contains cheat action records",
                            Detail = "History files inside cheat menu configuration directories record cheat session details, proving the cheat was actively operated"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);
}
