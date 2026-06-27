using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class FiveMChatSpamScanModule : IScanModule
{
    public string Name => "FiveM-ChatSpam-Forensik";
    public double Weight => 1.1;
    public int ParallelGroup => 4;

    private static readonly string LocalApp =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string RoamingApp =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string TempPath = Path.GetTempPath();
    private static readonly string DesktopPath =
        Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static readonly string PrefetchDir = @"C:\Windows\Prefetch";

    private static readonly string[] ChatSpamFilePatterns =
    {
        "chat_spam*", "chatflood*", "fivem_spam*", "chat_flood_fivem*",
        "chatbot_fivem*", "chatspammer_fivem*", "message_spam*",
        "chat_spammer*", "fivem_chat_spam*", "chat_flooder*",
        "spam_chat_fivem*", "chatspam*", "flood_chat*"
    };

    private static readonly string[] KnownChatSpamExecutables =
    {
        "ChatSpammer.exe", "ChatFlooder.exe", "ChatBot.exe", "FiveMSpammer.exe",
        "ChatFlood.exe", "FiveMChat.exe", "SpamChat.exe", "ChatBomber.exe",
        "FiveMFlood.exe", "MessageSpammer.exe", "ChatMassSend.exe", "FiveMBot.exe",
        "ChatAutoSend.exe", "FiveMChatBot.exe", "SpamTool.exe", "ChatBurst.exe"
    };

    private static readonly string[] ChatSpamLogKeywords =
    {
        "chat spam", "chat flood", "message spam fivem", "chat bot fivem",
        "flood chat", "spam chat server", "fivem spam", "chat flooder",
        "chatspammer", "mass chat", "chat bomber", "chat burst",
        "spam message fivem", "fivem chatbot", "auto chat spam",
        "chat rate limit bypass", "chat flood fivem", "message flood"
    };

    private static readonly string[] ChatSpamPrefetchNames =
    {
        "CHATSPAMMER", "CHATFLOODER", "CHATBOT", "FIVEMSPAMMER",
        "CHATFLOOD", "FIVEMCHAT", "SPAMCHAT", "CHATBOMBER",
        "FIVEMFLOOD", "MESSAGESPAMMER", "CHATMASSSEND", "FIVEMBOT",
        "CHATAUTOSEND", "FIVEMCHATBOT", "SPAMTOOL", "CHATBURST",
        "CHAT_SPAM", "FIVEM_SPAM", "CHAT_FLOOD", "SPAM_CHAT"
    };

    private static readonly string[] UserAssistChatSpamKeywords =
    {
        "chatspammer", "chatflooder", "chatbot", "fivemspammer",
        "chatflood", "fivemchat", "spamchat", "chatbomber",
        "fivemflood", "messagespammer", "fivembot", "chatautosend",
        "fivemchatbot", "spamtool", "chatburst", "chat_spam",
        "fivem_spam", "chat_flood", "spam_chat", "chat_flooder"
    };

    private static readonly string[] DiscordChatSpamKeywords =
    {
        "fivem chat spam", "chat flood fivem", "message spam fivem",
        "chatbot fivem", "spam chat fivem", "fivem spam chat",
        "chat spammer fivem", "fivem chat flood", "chat bomb fivem",
        "fivem message spam", "chat flooder fivem", "fivem chatbot",
        "auto chat fivem", "fivem chat tool", "spam tool fivem"
    };

    private static readonly string[] LuaChatSpamPatterns =
    {
        "TriggerServerEvent('chat:message')",
        "TriggerServerEvent(\"chat:message\")",
        "addChatMessage",
        "spam_chat",
        "flood_messages",
        "chat_bypass rate limit",
        "chat_bypass_rate_limit",
        "while true do",
        "TriggerEvent('chatMessage'",
        "TriggerEvent(\"chatMessage\"",
        "exports['chat']:addMessage",
        "exports[\"chat\"]:addMessage",
        "chat:addMessage",
        "NetworkSendChatMessage",
        "CHAT_IS_INPUT_ACTIVE",
        "spam_message",
        "flood_chat",
        "chatSpam",
        "messageBomb",
        "autoChat"
    };

    private static readonly string[] JsChatSpamPatterns =
    {
        "mp.events.call('chat:message'",
        "mp.events.call(\"chat:message\"",
        "chat.push(",
        "sendChatMessage",
        "spamChat",
        "floodChat",
        "chatBomb",
        "autoMessage",
        "messageSpam",
        "triggerChat",
        "setInterval.*chat",
        "chatMessage.*loop",
        "while.*sendMessage"
    };

    private static readonly string[] BatchPsChatSpamPatterns =
    {
        "chat spam", "chatspam", "fivem spam", "message spam",
        "chat flood", "chatflood", "flood chat", "spam chat",
        "SendMessage", "AutoHotkey.*chat", "ahk.*chat",
        "Invoke-WebRequest.*fivem", "chat.*while.*true",
        "loop.*chat.*send", "repeat.*chat"
    };

    private static readonly string[] CefCacheSpamPatterns =
    {
        "chat:addMessage", "chatMessage", "spamChat", "floodChat",
        "TriggerServerEvent.*chat", "chat.*spam.*script",
        "messageFlood", "chatBomb", "autoSendMessage"
    };

    private static readonly string[] TempSpamFilePatterns =
    {
        "chat_spam*", "chatspam*", "fivem_spam*", "message_spam*",
        "chat_flood*", "flood_chat*", "spam_list*", "chat_messages*",
        "spam_messages*", "chatbot_config*", "chat_flood_config*",
        "fivem_chat_tool*", "message_list*", "spam_config*"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.02, Name, "Starte FiveM Chat-Spam Forensik-Scan");

        await Task.WhenAll(
            CheckChatSpamFilesInDirs(ctx, ct),
            CheckLogFilesForChatSpam(ctx, ct),
            CheckKnownChatSpamExecutables(ctx, ct),
            CheckRegistryKeys(ctx, ct),
            CheckPrefetchArtifacts(ctx, ct),
            CheckUserAssistArtifacts(ctx, ct),
            CheckDiscordArtifacts(ctx, ct),
            CheckFiveMDirLuaScripts(ctx, ct),
            CheckFiveMDirJsScripts(ctx, ct),
            CheckBatchPowerShellScripts(ctx, ct),
            CheckCefBrowserCache(ctx, ct),
            CheckTempSpamFiles(ctx, ct)
        ).ConfigureAwait(false);

        ctx.Report(1.0, Name, "FiveM Chat-Spam Forensik-Scan abgeschlossen");
    }

    private Task CheckChatSpamFilesInDirs(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var searchDirs = new[]
            {
                LocalApp,
                RoamingApp,
                TempPath,
                DesktopPath,
                Path.Combine(UserProfile, "Downloads"),
                Path.Combine(UserProfile, "Documents"),
                Path.Combine(LocalApp, "FiveM"),
                Path.Combine(LocalApp, "FiveM", "FiveM.app"),
                Path.Combine(LocalApp, "Temp"),
                Path.Combine(RoamingApp, "FiveM")
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var pattern in ChatSpamFilePatterns)
                    {
                        if (ct.IsCancellationRequested) return;
                        string[] found;
                        try
                        {
                            found = Directory.GetFiles(dir, pattern, SearchOption.TopDirectoryOnly);
                        }
                        catch (UnauthorizedAccessException) { continue; }
                        catch (IOException) { continue; }

                        foreach (var file in found)
                        {
                            if (ct.IsCancellationRequested) return;
                            ctx.IncrementFiles();
                            var fn = Path.GetFileName(file);
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"FiveM Chat-Spam Datei gefunden: {fn}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason = $"Datei mit Chat-Spam-typischem Namen '{fn}' wurde in '{dir}' gefunden. " +
                                         "Chat-Spam-Tools fuer FiveM hinterlassen Dateien mit solchen Mustern " +
                                         "beim Herunterladen, Entpacken oder Ausfuehren.",
                                Detail = $"Muster: {pattern} | Verzeichnis: {dir}"
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }, ct);

    private Task CheckLogFilesForChatSpam(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var logDirs = new[]
            {
                LocalApp,
                RoamingApp,
                TempPath,
                Path.Combine(LocalApp, "FiveM"),
                Path.Combine(LocalApp, "FiveM", "FiveM.app", "logs"),
                Path.Combine(LocalApp, "FiveM", "FiveM.app", "data"),
                Path.Combine(UserProfile, "Downloads"),
                Path.Combine(UserProfile, "Documents")
            };

            var logExtensions = new[] { "*.log", "*.txt" };

            foreach (var dir in logDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                foreach (var ext in logExtensions)
                {
                    string[] logFiles;
                    try
                    {
                        logFiles = Directory.GetFiles(dir, ext, SearchOption.TopDirectoryOnly);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var logFile in logFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        FileInfo fi;
                        try { fi = new FileInfo(logFile); } catch { continue; }
                        if (fi.Length > 10 * 1024 * 1024) continue;

                        string content;
                        try
                        {
                            using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);
                        }
                        catch (IOException) { continue; }
                        catch (UnauthorizedAccessException) { continue; }

                        foreach (var keyword in ChatSpamLogKeywords)
                        {
                            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            {
                                var fn = Path.GetFileName(logFile);
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Chat-Spam Log-Eintrag: {fn}",
                                    Risk = RiskLevel.High,
                                    Location = logFile,
                                    FileName = fn,
                                    Reason = $"Log-Datei '{fn}' enthaelt den Chat-Spam-Hinweis '{keyword}'. " +
                                             "Protokolldateien von FiveM-Chat-Spam-Tools werden auch nach dem Loeschen " +
                                             "des Tools zurueckgelassen und sind ein forensischer Nachweis.",
                                    Detail = $"Schluesselwort: '{keyword}' | Datei: {logFile}"
                                });
                                break;
                            }
                        }
                    }
                }
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }, ct);

    private Task CheckKnownChatSpamExecutables(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var searchDirs = new[]
            {
                LocalApp,
                RoamingApp,
                TempPath,
                DesktopPath,
                Path.Combine(UserProfile, "Downloads"),
                Path.Combine(UserProfile, "Documents"),
                Path.Combine(UserProfile, "AppData", "Local", "Temp"),
                Path.Combine(LocalApp, "FiveM")
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                foreach (var exeName in KnownChatSpamExecutables)
                {
                    if (ct.IsCancellationRequested) return;
                    var fullPath = Path.Combine(dir, exeName);
                    ctx.IncrementFiles();

                    if (!File.Exists(fullPath)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Bekanntes Chat-Spam-Tool gefunden: {exeName}",
                        Risk = RiskLevel.Critical,
                        Location = fullPath,
                        FileName = exeName,
                        Reason = $"Die Datei '{exeName}' ist ein bekanntes FiveM Chat-Spam-Tool und wurde in '{dir}' gefunden. " +
                                 "Diese Anwendung wird verwendet, um den FiveM-Ingame-Chat mit Nachrichten zu fluten " +
                                 "und Server zu stoeren oder zum Absturz zu bringen.",
                        Detail = $"Bekanntes Tool: {exeName} | Pfad: {fullPath}"
                    });
                }
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }, ct);

    private Task CheckRegistryKeys(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var registryPaths = new[]
            {
                @"Software\FiveM\ChatSpam",
                @"Software\ChatFloodFiveM",
                @"Software\FiveMChatSpammer",
                @"Software\ChatSpamTool",
                @"Software\FiveMChatFlood",
                @"Software\ChatBotFiveM",
                @"Software\MessageSpamFiveM",
                @"Software\FiveMSpam",
                @"Software\ChatFlooder",
                @"Software\FiveMChatBot"
            };

            foreach (var regPath in registryPaths)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();

                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(regPath, writable: false);
                    if (key is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Chat-Spam Registry-Schluessel: {regPath}",
                        Risk = RiskLevel.High,
                        Location = $@"HKCU\{regPath}",
                        Reason = $"Registry-Schluessel 'HKCU\\{regPath}' gefunden. " +
                                 "FiveM-Chat-Spam-Tools schreiben Konfigurationsdaten in diese Registry-Pfade. " +
                                 "Der Schluessel bleibt auch nach dem Deinstallieren des Tools erhalten.",
                        Detail = $"Registry-Pfad: HKCU\\{regPath} | Werte: {string.Join(", ", key.GetValueNames().Take(5))}"
                    });
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }, ct);

    private Task CheckPrefetchArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            if (!Directory.Exists(PrefetchDir))
            {
                await Task.CompletedTask.ConfigureAwait(false);
                return;
            }

            string[] pfFiles;
            try
            {
                pfFiles = Directory.GetFiles(PrefetchDir, "*.pf");
            }
            catch (UnauthorizedAccessException)
            {
                await Task.CompletedTask.ConfigureAwait(false);
                return;
            }
            catch (IOException)
            {
                await Task.CompletedTask.ConfigureAwait(false);
                return;
            }

            foreach (var pfFile in pfFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var pfName = Path.GetFileNameWithoutExtension(pfFile);
                var dashIdx = pfName.LastIndexOf('-');
                var exeName = dashIdx > 0 && pfName.Length - dashIdx == 9
                    ? pfName[..dashIdx]
                    : pfName;

                var hit = ChatSpamPrefetchNames.FirstOrDefault(n =>
                    exeName.Contains(n, StringComparison.OrdinalIgnoreCase));
                if (hit is null) continue;

                DateTime lastWrite = default;
                try { lastWrite = File.GetLastWriteTimeUtc(pfFile); } catch { }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Prefetch: Chat-Spam-Tool ausgefuehrt: {exeName}",
                    Risk = RiskLevel.High,
                    Location = pfFile,
                    FileName = exeName + ".exe",
                    Reason = $"Prefetch-Datei '{Path.GetFileName(pfFile)}' belegt die frueherer Ausfuehrung von " +
                             $"'{exeName}.exe', einem FiveM Chat-Spam-Tool (Muster: '{hit}'). " +
                             "Prefetch-Eintraege bleiben auch nach dem Loeschen der Datei erhalten.",
                    Detail = lastWrite != default
                        ? $"Prefetch zuletzt aktualisiert: {lastWrite:yyyy-MM-dd HH:mm:ss} UTC"
                        : $"Prefetch-Datei: {pfFile}"
                });
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }, ct);

    private Task CheckUserAssistArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            const string userAssistBase =
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

            try
            {
                using var baseKey = Registry.CurrentUser.OpenSubKey(userAssistBase, writable: false);
                if (baseKey is null)
                {
                    await Task.CompletedTask.ConfigureAwait(false);
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

                            var decoded = Rot13Decode(encodedName);
                            var hit = UserAssistChatSpamKeywords.FirstOrDefault(k =>
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
                                Module = Name,
                                Title = $"UserAssist: Chat-Spam-Tool ausgefuehrt: {hit}",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                                FileName = Path.GetFileName(decoded),
                                Reason = $"UserAssist-Eintrag belegt die Ausfuehrung von '{Path.GetFileName(decoded)}' " +
                                         $"({runCount}x ausgefuehrt" +
                                         (lastRun.HasValue ? $", zuletzt {lastRun.Value:yyyy-MM-dd HH:mm} UTC" : "") +
                                         $"). Keyword-Treffer: '{hit}'. " +
                                         "UserAssist-Eintraege bleiben auch nach dem Loeschen der ausfuehrbaren Datei erhalten.",
                                Detail = $"Dekodiert: {decoded} | Ausfuehrungen: {runCount} | " +
                                         $"Zuletzt: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unbekannt")}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }

            await Task.CompletedTask.ConfigureAwait(false);
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
                    Path.Combine(discordRoot, "Code Cache", "js"),
                    Path.Combine(discordRoot, "Session Storage")
                };

                foreach (var cacheDir in cacheDirs)
                {
                    if (ct.IsCancellationRequested) return;
                    if (!Directory.Exists(cacheDir)) continue;

                    string[] cacheFiles;
                    try
                    {
                        cacheFiles = Directory.GetFiles(cacheDir).Take(100).ToArray();
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var cacheFile in cacheFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        FileInfo fi;
                        try { fi = new FileInfo(cacheFile); } catch { continue; }
                        if (fi.Length > 8 * 1024 * 1024) continue;

                        string content;
                        try
                        {
                            using var fs = new FileStream(cacheFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs, Encoding.GetEncoding("ISO-8859-1"));
                            content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);
                        }
                        catch (IOException) { continue; }
                        catch (UnauthorizedAccessException) { continue; }

                        foreach (var keyword in DiscordChatSpamKeywords)
                        {
                            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            {
                                var fn = Path.GetFileName(cacheFile);
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Discord-Cache: FiveM Chat-Spam-Artefakt: {keyword}",
                                    Risk = RiskLevel.High,
                                    Location = cacheFile,
                                    FileName = fn,
                                    Reason = $"Discord-Cache-Datei '{fn}' des Clients '{client}' enthaelt das Chat-Spam-Schluesselwort " +
                                             $"'{keyword}'. Dies deutet auf Kommunikation ueber FiveM-Chat-Spam-Tools " +
                                             "in Discord hin (z.B. Bezug, Erwerb oder Nutzungskommunikation).",
                                    Detail = $"Client: {client} | Cache: {cacheDir} | Keyword: '{keyword}'"
                                });
                                break;
                            }
                        }
                    }
                }
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }, ct);

    private Task CheckFiveMDirLuaScripts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var fivemDirs = new[]
            {
                Path.Combine(LocalApp, "FiveM", "FiveM.app", "citizen", "scripting", "lua"),
                Path.Combine(LocalApp, "FiveM", "FiveM.app", "plugins"),
                Path.Combine(LocalApp, "FiveM", "FiveM.app", "resources"),
                Path.Combine(LocalApp, "FiveM", "FiveM.app", "data", "cache"),
                Path.Combine(LocalApp, "FiveM", "FiveM.app", "data", "scripts"),
                Path.Combine(LocalApp, "FiveM", "FiveM.app"),
                Path.Combine(LocalApp, "FiveM")
            };

            foreach (var dir in fivemDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                string[] luaFiles;
                try
                {
                    luaFiles = Directory.GetFiles(dir, "*.lua", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var luaFile in luaFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    FileInfo fi;
                    try { fi = new FileInfo(luaFile); } catch { continue; }
                    if (fi.Length > 2 * 1024 * 1024) continue;

                    string content;
                    try
                    {
                        using var fs = new FileStream(luaFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    var matches = LuaChatSpamPatterns
                        .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (matches.Count == 0) continue;

                    var risk = matches.Count >= 3 ? RiskLevel.Critical
                             : matches.Count >= 2 ? RiskLevel.High
                             : RiskLevel.Medium;

                    var fn = Path.GetFileName(luaFile);
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Lua Chat-Spam-Skript in FiveM: {fn}",
                        Risk = risk,
                        Location = luaFile,
                        FileName = fn,
                        Reason = $"Lua-Skript '{fn}' in FiveM-Verzeichnis enthaelt {matches.Count} Chat-Spam-Muster: " +
                                 string.Join(", ", matches.Take(3).Select(m => $"'{m}'")) +
                                 (matches.Count > 3 ? " ..." : "") +
                                 ". Diese Muster deuten auf ein Lua-Skript hin, das den FiveM-Chat flutet " +
                                 "oder automatisch Nachrichten sendet.",
                        Detail = $"Treffer ({matches.Count}): {string.Join(", ", matches.Take(5))}"
                    });
                }
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }, ct);

    private Task CheckFiveMDirJsScripts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var fivemJsDirs = new[]
            {
                Path.Combine(LocalApp, "FiveM", "FiveM.app", "citizen", "scripting", "js"),
                Path.Combine(LocalApp, "FiveM", "FiveM.app", "client_packages"),
                Path.Combine(LocalApp, "FiveM", "FiveM.app", "plugins"),
                Path.Combine(LocalApp, "FiveM", "FiveM.app", "resources"),
                Path.Combine(LocalApp, "FiveM", "FiveM.app", "data", "cache"),
                Path.Combine(LocalApp, "FiveM", "FiveM.app"),
                Path.Combine(LocalApp, "FiveM")
            };

            foreach (var dir in fivemJsDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                string[] jsFiles;
                try
                {
                    jsFiles = Directory.GetFiles(dir, "*.js", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var jsFile in jsFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    FileInfo fi;
                    try { fi = new FileInfo(jsFile); } catch { continue; }
                    if (fi.Length > 2 * 1024 * 1024) continue;

                    string content;
                    try
                    {
                        using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    var matches = JsChatSpamPatterns
                        .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (matches.Count == 0) continue;

                    var risk = matches.Count >= 3 ? RiskLevel.Critical
                             : matches.Count >= 2 ? RiskLevel.High
                             : RiskLevel.Medium;

                    var fn = Path.GetFileName(jsFile);
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"JS Chat-Spam-Skript in FiveM: {fn}",
                        Risk = risk,
                        Location = jsFile,
                        FileName = fn,
                        Reason = $"JavaScript-Datei '{fn}' in FiveM-Verzeichnis enthaelt {matches.Count} Chat-Spam-Muster: " +
                                 string.Join(", ", matches.Take(3).Select(m => $"'{m}'")) +
                                 (matches.Count > 3 ? " ..." : "") +
                                 ". Dies deutet auf ein clientseitiges Skript hin, das den FiveM-Chat automatisch " +
                                 "mit Nachrichten flutet.",
                        Detail = $"Treffer ({matches.Count}): {string.Join(", ", matches.Take(5))}"
                    });
                }
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }, ct);

    private Task CheckBatchPowerShellScripts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var scriptDirs = new[]
            {
                DesktopPath,
                Path.Combine(UserProfile, "Downloads"),
                Path.Combine(UserProfile, "Documents"),
                TempPath,
                LocalApp,
                RoamingApp
            };

            var scriptExtensions = new[] { "*.bat", "*.cmd", "*.ps1", "*.ahk", "*.vbs" };

            foreach (var dir in scriptDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                foreach (var ext in scriptExtensions)
                {
                    string[] scriptFiles;
                    try
                    {
                        scriptFiles = Directory.GetFiles(dir, ext, SearchOption.TopDirectoryOnly);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var scriptFile in scriptFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        FileInfo fi;
                        try { fi = new FileInfo(scriptFile); } catch { continue; }
                        if (fi.Length > 1 * 1024 * 1024) continue;

                        string content;
                        try
                        {
                            using var fs = new FileStream(scriptFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);
                        }
                        catch (IOException) { continue; }
                        catch (UnauthorizedAccessException) { continue; }

                        var matches = BatchPsChatSpamPatterns
                            .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        if (matches.Count < 2) continue;

                        var fn = Path.GetFileName(scriptFile);
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Batch/PS Chat-Spam-Skript: {fn}",
                            Risk = RiskLevel.High,
                            Location = scriptFile,
                            FileName = fn,
                            Reason = $"Skriptdatei '{fn}' ({Path.GetExtension(scriptFile).ToUpperInvariant()}) enthaelt {matches.Count} " +
                                     $"Chat-Spam-Muster: {string.Join(", ", matches.Take(3).Select(m => $"'{m}'"))}. " +
                                     "Batch- und PowerShell-Skripte werden oft verwendet, um FiveM-Chat-Spam-Tools " +
                                     "automatisch zu starten oder zu steuern.",
                            Detail = $"Erweiterung: {Path.GetExtension(scriptFile)} | " +
                                     $"Treffer ({matches.Count}): {string.Join(", ", matches.Take(4))}"
                        });
                    }
                }
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }, ct);

    private Task CheckCefBrowserCache(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var cefCacheDirs = new[]
            {
                Path.Combine(LocalApp, "FiveM", "FiveM.app", "cache", "browser"),
                Path.Combine(LocalApp, "FiveM", "FiveM.app", "CEF", "cache"),
                Path.Combine(LocalApp, "FiveM", "FiveM.app", "cache", "NUI"),
                Path.Combine(LocalApp, "FiveM", "FiveM.app", "nui-storage"),
                Path.Combine(LocalApp, "FiveM", "FiveM.app", "cache"),
                Path.Combine(LocalApp, "FiveM", "FiveM.app", "citizen", "nui"),
                Path.Combine(LocalApp, "FiveM", "FiveM.app", "data", "cache", "nui")
            };

            foreach (var cefDir in cefCacheDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(cefDir)) continue;

                string[] cacheFiles;
                try
                {
                    cacheFiles = Directory.GetFiles(cefDir, "*", SearchOption.AllDirectories)
                        .Take(80)
                        .ToArray();
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var cacheFile in cacheFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    FileInfo fi;
                    try { fi = new FileInfo(cacheFile); } catch { continue; }
                    if (fi.Length > 5 * 1024 * 1024 || fi.Length < 10) continue;

                    string content;
                    try
                    {
                        using var fs = new FileStream(cacheFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, Encoding.GetEncoding("ISO-8859-1"));
                        content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var pattern in CefCacheSpamPatterns)
                    {
                        if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            var fn = Path.GetFileName(cacheFile);
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"FiveM CEF-Cache: Chat-Spam-Skript-Artefakt: {fn}",
                                Risk = RiskLevel.High,
                                Location = cacheFile,
                                FileName = fn,
                                Reason = $"FiveM CEF-Browser-Cache-Datei '{fn}' enthaelt Chat-Spam-JavaScript-Muster '{pattern}'. " +
                                         "FiveM NUI/CEF-Browser-Cache kann JavaScript-Code von Chat-Spam-Exploits enthalten, " +
                                         "die ueber den NUI-Renderer des Spiels gefuehrt werden.",
                                Detail = $"CEF-Cache-Verzeichnis: {cefDir} | Muster: '{pattern}'"
                            });
                            break;
                        }
                    }
                }
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }, ct);

    private Task CheckTempSpamFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var tempDirs = new[]
            {
                TempPath,
                Path.Combine(LocalApp, "Temp"),
                Path.Combine(UserProfile, "AppData", "Local", "Temp"),
                Path.Combine(LocalApp, "FiveM", "FiveM.app", "data", "cache", "priv")
            };

            foreach (var dir in tempDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                foreach (var pattern in TempSpamFilePatterns)
                {
                    string[] tempFiles;
                    try
                    {
                        tempFiles = Directory.GetFiles(dir, pattern, SearchOption.TopDirectoryOnly);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var tempFile in tempFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        var fn = Path.GetFileName(tempFile);

                        FileInfo fi;
                        try { fi = new FileInfo(tempFile); } catch { continue; }

                        string previewContent = string.Empty;
                        if (fi.Length > 0 && fi.Length < 512 * 1024)
                        {
                            try
                            {
                                using var fs = new FileStream(tempFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                using var sr = new StreamReader(fs);
                                previewContent = await sr.ReadToEndAsync(ct).ConfigureAwait(false);
                            }
                            catch (IOException) { }
                            catch (UnauthorizedAccessException) { }
                        }

                        var hasSpamContent = !string.IsNullOrEmpty(previewContent) &&
                            ChatSpamLogKeywords.Any(k =>
                                previewContent.Contains(k, StringComparison.OrdinalIgnoreCase));

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Temp-Datei: FiveM Chat-Spam-Artefakt: {fn}",
                            Risk = hasSpamContent ? RiskLevel.High : RiskLevel.Medium,
                            Location = tempFile,
                            FileName = fn,
                            Reason = $"Temporaere Datei '{fn}' mit Chat-Spam-Muster in '{dir}' gefunden" +
                                     (hasSpamContent ? " mit Chat-Spam-Inhalt" : "") +
                                     ". Chat-Spam-Tools fuer FiveM erstellen oft temporaere Dateien " +
                                     "mit Nachrichtenlisten, Konfigurationen oder Skriptteilen.",
                            Detail = $"Groesse: {fi.Length} Bytes | Verzeichnis: {dir}" +
                                     (hasSpamContent ? " | Spam-Inhalt erkannt" : "")
                        });
                    }
                }
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }, ct);

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
