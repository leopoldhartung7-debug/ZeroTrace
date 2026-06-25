using System.Text.RegularExpressions;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class CheatDiscordC2ScanModule : IScanModule
{
    public string Name => "Cheat Discord C2 & Communication Detection";
    public double Weight => 3.7;
    public int ParallelGroup => 4;

    // ── Discord webhook URL pattern ───────────────────────────────────────────

    private const string DiscordWebhookUrlFragment = "discord.com/api/webhooks/";
    private const string DiscordWebhookAltFragment = "discordapp.com/api/webhooks/";
    private const string DiscordPtbWebhookFragment = "ptb.discord.com/api/webhooks/";
    private const string DiscordCanaryWebhookFragment = "canary.discord.com/api/webhooks/";

    // ── Discord token regex (standard and newer bot token formats) ────────────

    private static readonly Regex DiscordTokenRegex = new(
        @"[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex DiscordBotTokenRegex = new(
        @"Bot\s+[\w-]{24,28}\.[\w-]{6,10}\.[\w-]{27,38}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    // ── Discord invite URL pattern ────────────────────────────────────────────

    private static readonly Regex DiscordInviteRegex = new(
        @"discord(?:\.gg|\.com/invite)/([A-Za-z0-9]{2,20})",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    // ── Known Discord token grabber file names ────────────────────────────────

    private static readonly HashSet<string> KnownGrabberFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "discordgrabber.py",
        "token_grab.py",
        "dc_token.py",
        "grab_token.ps1",
        "grabtoken.ps1",
        "discord_grab.py",
        "discord_stealer.py",
        "discord_token_stealer.py",
        "token_stealer.py",
        "tokengrabber.py",
        "discord_token_grabber.py",
        "discordstealer.py",
        "dc_grabber.py",
        "token_logger.py",
        "steal_token.py",
        "grab_discord.py",
        "discord_logger.py",
        "discordlogger.py",
        "tokenlogger.py",
        "dcgrabber.py",
        "token_grab.js",
        "discordgrabber.js",
        "grab_token.js",
        "discord_token.js",
        "stealtoken.js",
        "grab_token.bat",
        "steal_token.bat",
        "discord_grab.bat",
        "token_grab.cmd",
        "discord_grabber.ahk",
        "token_stealer.ahk",
        "grab_token.au3",
        "discord_stealer.au3",
        "grabber.py",
        "stealer.py",
    };

    // ── Known Discord Nitro scam / generator file names ───────────────────────

    private static readonly HashSet<string> KnownNitroScamFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "nitro_gen.exe",
        "nitro_checker.exe",
        "discord_nitro.exe",
        "NitroGenerator.exe",
        "NitroChecker.exe",
        "DiscordNitro.exe",
        "nitrogen.exe",
        "nitro_generator.exe",
        "NitroGen.exe",
        "nitro_sniper.exe",
        "NitroSniper.exe",
        "discord_nitro_gen.py",
        "nitro_gen.py",
        "nitro_checker.py",
        "nitro_sniper.py",
        "nitro_claimer.py",
        "nitrochecker.py",
        "discord_gen.py",
        "gift_gen.py",
        "gift_checker.py",
        "nitro_spam.py",
        "nitro_spam.js",
        "nitro_gen.js",
        "nitro_checker.js",
        "nitrogenreator.bat",
        "generate_nitro.bat",
        "nitro_bot.py",
        "NitroBot.exe",
    };

    // ── Known Discord-invite related .txt cheat distribution file names ────────

    private static readonly HashSet<string> KnownInviteTxtFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "discord.txt",
        "join_discord.txt",
        "cheat_discord.txt",
        "discord_invite.txt",
        "invite.txt",
        "join.txt",
        "server.txt",
        "community.txt",
        "links.txt",
        "cheat_links.txt",
        "download.txt",
        "info.txt",
        "readme.txt",
        "READ_ME.txt",
        "IMPORTANT.txt",
        "discord_server.txt",
    };

    // ── Variable names in source code indicating webhook-based HWID exfiltration ──

    private static readonly string[] WebhookVariableNames =
    {
        "webhookUrl",
        "webhook_url",
        "discord_webhook",
        "webhookURL",
        "webhook_URL",
        "WEBHOOK_URL",
        "discordWebhook",
        "DiscordWebhook",
        "DISCORD_WEBHOOK",
        "hookUrl",
        "hook_url",
        "sendWebhook",
        "send_webhook",
        "notifyWebhook",
        "notify_webhook",
        "alertWebhook",
        "alert_webhook",
        "logWebhook",
        "log_webhook",
        "reportWebhook",
        "report_webhook",
        "hwidWebhook",
        "hwid_webhook",
    };

    // ── Config keys indicating Discord bot C2 usage ───────────────────────────

    private static readonly string[] BotC2ConfigKeys =
    {
        "bot_token",
        "discord_bot_token",
        "bot_secret",
        "discord_bot",
        "update_channel",
        "command_channel",
        "discord_bot_id",
        "bot_id",
        "bot_channel",
        "c2_channel",
        "c2_bot",
        "control_channel",
        "cmd_channel",
        "loader_channel",
        "cheat_channel",
        "payload_channel",
        "delivery_channel",
        "discord_c2",
        "discord_control",
        "discord_command",
    };

    // ── Config keys indicating Discord RPC abuse ──────────────────────────────

    private static readonly string[] RpcAbuseConfigKeys =
    {
        "discord_rpc",
        "enable_rpc",
        "rpc_enabled",
        "discord_rich_presence",
        "rich_presence",
        "rpc_status",
        "cheat_status_rpc",
        "show_cheat_rpc",
        "rpc_cheat_name",
        "discord_presence",
    };

    // ── Known Discord RPC DLL names in suspicious (non-game) locations ─────────

    private static readonly HashSet<string> KnownRpcDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "discord-rpc.dll",
        "DiscordRPC.dll",
        "discord_rpc.dll",
        "discordrpc.dll",
        "discord_game_sdk.dll",
        "discord-game-sdk.dll",
    };

    // ── Cheat invite file heuristic content keywords ──────────────────────────

    private static readonly string[] CheatInviteKeywords =
    {
        "discord.gg/",
        "discord.com/invite/",
        "download link",
        "cheat link",
        "loader link",
        "buy here",
        "purchase here",
        "free cheat",
        "paid cheat",
        "spoofer link",
        "bypass link",
        "free loader",
        "crack link",
        "cracked cheat",
        "cheat download",
    };

    // ── PowerShell / batch webhook delivery patterns ──────────────────────────

    private static readonly string[] WebhookDeliveryPatterns =
    {
        "Invoke-WebRequest",
        "Invoke-RestMethod",
        "curl.*discord",
        "curl.*webhook",
        "wget.*discord",
        "wget.*webhook",
        "discord.com/api/webhooks",
        "discordapp.com/api/webhooks",
        "Start-Process.*discord",
        "[Net.WebClient]",
        "WebClient",
        "HttpClient",
    };

    // ── Python / JS discord.py C2 import patterns ────────────────────────────

    private static readonly string[] DiscordBotImportPatterns =
    {
        "import discord",
        "from discord",
        "discord.ext.commands",
        "discord.Client",
        "discord.Bot",
        "discord.Intents",
        "bot.command",
        "@bot.command",
        "@client.event",
        "bot.run(",
        "client.run(",
        "discord.py",
        "require('discord.js')",
        "require(\"discord.js\")",
        "const { Client }",
        "new Client(",
        "DiscordJS",
        "Discord.js",
    };

    // ── File extensions to scan for webhook/C2 content ────────────────────────

    private static readonly HashSet<string> ScanExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".py", ".js", ".ts", ".bat", ".cmd", ".ps1", ".sh",
        ".cfg", ".config", ".ini", ".conf", ".json", ".xml", ".yaml", ".yml",
        ".txt", ".log", ".ahk", ".au3", ".rb", ".lua",
        ".cs", ".cpp", ".h", ".c",
    };

    // ── Directories where Discord token data lives ────────────────────────────

    private static readonly string[] DiscordLevelDbPaths =
    {
        "discord\\Local Storage\\leveldb",
        "discordptb\\Local Storage\\leveldb",
        "discordcanary\\Local Storage\\leveldb",
    };

    // =========================================================================
    // Entry point
    // =========================================================================

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting Discord C2 and communication detection");

        // Phase 1: Scan user filesystem for webhook URLs, token grabbers, Nitro scams
        await ScanUserFilesystemAsync(ctx, ct);
        ctx.Report(0.45, Name, "User filesystem scan complete");
        ct.ThrowIfCancellationRequested();

        // Phase 2: Scan Discord Local Storage access artifacts (token stealer traces)
        ScanDiscordLevelDbAccessArtifacts(ctx, ct);
        ctx.Report(0.60, Name, "Discord LevelDB access artifact scan complete");
        ct.ThrowIfCancellationRequested();

        // Phase 3: Scan for Discord RPC DLLs in non-game / suspicious locations
        await ScanDiscordRpcDllsAsync(ctx, ct);
        ctx.Report(0.72, Name, "Discord RPC DLL scan complete");
        ct.ThrowIfCancellationRequested();

        // Phase 4: Scan PowerShell history for webhook delivery commands
        await ScanPowerShellHistoryAsync(ctx, ct);
        ctx.Report(0.82, Name, "PowerShell history scan complete");
        ct.ThrowIfCancellationRequested();

        // Phase 5: Registry – Discord bot token entries, persistent C2 registration
        ScanRegistry(ctx, ct);
        ctx.Report(0.92, Name, "Registry scan complete");
        ct.ThrowIfCancellationRequested();

        // Phase 6: Cheat directory README/invite file inspection
        await ScanCheatDirectoryInviteFilesAsync(ctx, ct);
        ctx.Report(1.0, Name, "Discord C2 detection complete");
    }

    // =========================================================================
    // Phase 1 – User filesystem
    // =========================================================================

    private async Task ScanUserFilesystemAsync(ScanContext ctx, CancellationToken ct)
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var tempPath = Path.GetTempPath();

        var scanRoots = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            appData,
            localAppData,
            tempPath,
        };

        var allFiles = new List<string>();

        foreach (var root in scanRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;
            try { CollectFiles(root, allFiles, maxDepth: 5, ct); }
            catch (UnauthorizedAccessException) { }
        }

        int total = Math.Max(allFiles.Count, 1);
        int idx = 0;

        foreach (var file in allFiles)
        {
            ct.ThrowIfCancellationRequested();
            idx++;
            ctx.IncrementFiles();

            if (idx % 100 == 0)
                ctx.Report(0.01 + 0.43 * ((double)idx / total), file, $"{idx}/{allFiles.Count} files scanned");

            var fileName = Path.GetFileName(file);
            var ext = Path.GetExtension(file);

            // Check known Discord token grabber file names
            if (KnownGrabberFileNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Discord token grabber script detected: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason = $"File '{fileName}' is a known Discord token grabber script. " +
                             "These scripts are commonly bundled with cheat loaders and extract " +
                             "Discord authentication tokens from the local LevelDB cache, " +
                             "enabling account hijacking. Token grabbers are frequently used " +
                             "alongside cheat distribution as additional payload.",
                });
                continue;
            }

            // Check known Nitro scam file names
            if (KnownNitroScamFileNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Discord Nitro scam/generator file detected: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"File '{fileName}' is a known Discord Nitro generator, checker, " +
                             "or scam tool. These tools are frequently distributed alongside " +
                             "game cheats as additional monetization for cheat operators. " +
                             "They generate fake Nitro gift links or brute-force gift codes.",
                });
                continue;
            }

            // Check known invite .txt file names
            if (KnownInviteTxtFileNames.Contains(fileName))
            {
                try { await InspectInviteTxtFileAsync(ctx, file, fileName, ct); }
                catch (IOException) { }
                continue;
            }

            if (!ScanExtensions.Contains(ext)) continue;

            FileInfo fi;
            try { fi = new FileInfo(file); } catch { continue; }
            if (fi.Length > 4 * 1024 * 1024) continue;

            try
            {
                await InspectFileForDiscordC2Async(ctx, file, fileName, ext, ct);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private async Task InspectFileForDiscordC2Async(
        ScanContext ctx, string filePath, string fileName, string ext, CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }

        ct.ThrowIfCancellationRequested();

        // Check for Discord webhook URL
        bool hasWebhook = content.Contains(DiscordWebhookUrlFragment, StringComparison.OrdinalIgnoreCase) ||
                          content.Contains(DiscordWebhookAltFragment, StringComparison.OrdinalIgnoreCase) ||
                          content.Contains(DiscordPtbWebhookFragment, StringComparison.OrdinalIgnoreCase) ||
                          content.Contains(DiscordCanaryWebhookFragment, StringComparison.OrdinalIgnoreCase);

        if (hasWebhook)
        {
            // Determine if it's a HWID exfiltration context
            bool hasHwidContext = content.Contains("hwid", StringComparison.OrdinalIgnoreCase) ||
                                  content.Contains("hardware_id", StringComparison.OrdinalIgnoreCase) ||
                                  content.Contains("machine_id", StringComparison.OrdinalIgnoreCase) ||
                                  content.Contains("computer_name", StringComparison.OrdinalIgnoreCase) ||
                                  content.Contains("username", StringComparison.OrdinalIgnoreCase) ||
                                  content.Contains("serial", StringComparison.OrdinalIgnoreCase) ||
                                  content.Contains("volume_serial", StringComparison.OrdinalIgnoreCase);

            bool hasWebhookVar = WebhookVariableNames.Any(v =>
                content.Contains(v, StringComparison.OrdinalIgnoreCase));

            var fragment = content.Contains(DiscordWebhookUrlFragment, StringComparison.OrdinalIgnoreCase)
                ? DiscordWebhookUrlFragment : DiscordWebhookAltFragment;

            if (hasHwidContext && hasWebhookVar)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"HWID exfiltration via Discord webhook in: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = filePath,
                    FileName = fileName,
                    Reason = $"File '{fileName}' contains a Discord webhook URL alongside HWID " +
                             "and webhook variable references. This pattern is characteristic of " +
                             "cheat loaders that send machine identifiers to the cheat operator's " +
                             "Discord channel for license validation and user tracking.",
                    Detail = ExtractContext(content, fragment, 100),
                });
            }
            else if (hasWebhookVar)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Discord webhook variable in loader/cheat file: {fileName}",
                    Risk = RiskLevel.High,
                    Location = filePath,
                    FileName = fileName,
                    Reason = $"File '{fileName}' defines a Discord webhook URL variable " +
                             $"({WebhookVariableNames.FirstOrDefault(v => content.Contains(v, StringComparison.OrdinalIgnoreCase))}). " +
                             "Cheat loaders use webhook variables to send system information, " +
                             "activation events, and error reports to Discord channels.",
                    Detail = ExtractContext(content, fragment, 100),
                });
            }
            else
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Discord webhook URL in file: {fileName}",
                    Risk = RiskLevel.Medium,
                    Location = filePath,
                    FileName = fileName,
                    Reason = $"File '{fileName}' contains a Discord webhook URL. Cheat loaders, " +
                             "batch scripts, and AutoIt/AHK automation scripts use Discord webhooks " +
                             "as a lightweight C2 channel to send system info and cheat status.",
                    Detail = ExtractContext(content, fragment, 80),
                });
            }
            return;
        }

        // Check for Discord token regex match (raw token in file)
        if (DiscordTokenRegex.IsMatch(content))
        {
            bool isBotToken = content.Contains("bot_token", StringComparison.OrdinalIgnoreCase) ||
                              content.Contains("bot token", StringComparison.OrdinalIgnoreCase) ||
                              DiscordBotTokenRegex.IsMatch(content);

            var match = DiscordTokenRegex.Match(content);
            var tokenSnippet = match.Value.Length > 20
                ? match.Value[..8] + "..." + match.Value[^8..]
                : match.Value;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = isBotToken
                    ? $"Discord bot token (C2) in file: {fileName}"
                    : $"Discord token pattern in file: {fileName}",
                Risk = isBotToken ? RiskLevel.Critical : RiskLevel.High,
                Location = filePath,
                FileName = fileName,
                Reason = isBotToken
                    ? $"File '{fileName}' contains a Discord bot token. Cheat loaders use Discord " +
                      "bots as Command & Control channels to deliver updates, commands, and cheat " +
                      "configuration without requiring a dedicated server."
                    : $"File '{fileName}' contains a string matching the Discord authentication " +
                      "token format. Token grabbers embedded in cheat packages extract and store " +
                      "Discord tokens to hijack victim accounts.",
                Detail = $"Token fragment: {tokenSnippet}",
            });
            return;
        }

        // Check for Discord bot C2 config keys
        foreach (var key in BotC2ConfigKeys)
        {
            if (!content.Contains(key, StringComparison.OrdinalIgnoreCase)) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Discord bot C2 config key in: {fileName}",
                Risk = RiskLevel.High,
                Location = filePath,
                FileName = fileName,
                Reason = $"File '{fileName}' contains configuration key '{key}' associated with " +
                         "Discord bot Command & Control. Cheat loaders use Discord bots to receive " +
                         "commands, deliver payload updates, and manage cheat activation remotely.",
                Detail = ExtractContext(content, key, 100),
            });
            return;
        }

        // Check for Discord RPC abuse config keys
        foreach (var key in RpcAbuseConfigKeys)
        {
            if (!content.Contains(key, StringComparison.OrdinalIgnoreCase)) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Discord RPC cheat status config in: {fileName}",
                Risk = RiskLevel.Medium,
                Location = filePath,
                FileName = fileName,
                Reason = $"File '{fileName}' contains configuration key '{key}' enabling Discord " +
                         "Rich Presence for cheat status reporting. Some cheat menus use Discord " +
                         "RPC to signal to the cheat operator which users are running the cheat " +
                         "and in which game.",
                Detail = ExtractContext(content, key, 80),
            });
            return;
        }

        // Check for Python/JS discord bot import patterns (C2 bot source)
        int botImportHits = DiscordBotImportPatterns.Count(p =>
            content.Contains(p, StringComparison.OrdinalIgnoreCase));

        if (botImportHits >= 2)
        {
            // Determine if it's a C2 context by checking for cheat-related terms
            bool hasCheatContext = content.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                                   content.Contains("loader", StringComparison.OrdinalIgnoreCase) ||
                                   content.Contains("hwid", StringComparison.OrdinalIgnoreCase) ||
                                   content.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                                   content.Contains("inject", StringComparison.OrdinalIgnoreCase) ||
                                   content.Contains("payload", StringComparison.OrdinalIgnoreCase) ||
                                   content.Contains("download", StringComparison.OrdinalIgnoreCase) ||
                                   content.Contains("execute", StringComparison.OrdinalIgnoreCase) ||
                                   content.Contains("run_command", StringComparison.OrdinalIgnoreCase) ||
                                   content.Contains("shell", StringComparison.OrdinalIgnoreCase);

            var matched = DiscordBotImportPatterns
                .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                .Take(4)
                .ToList();

            if (hasCheatContext)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Discord bot C2 script with cheat context: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = filePath,
                    FileName = fileName,
                    Reason = $"File '{fileName}' is a Discord bot script with cheat-related " +
                             "functionality (loader/HWID/payload/execute keywords). Discord bots " +
                             "are used as C2 channels by cheat operators to issue commands, " +
                             "deliver updates, and manage cheat users remotely.",
                    Detail = $"Discord imports: {string.Join(", ", matched)}",
                });
            }
            else
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Discord bot script detected: {fileName}",
                    Risk = RiskLevel.Low,
                    Location = filePath,
                    FileName = fileName,
                    Reason = $"File '{fileName}' is a Discord bot script. When found alongside " +
                             "cheat-related files, Discord bots may serve as Command & Control " +
                             "infrastructure for cheat delivery and management.",
                    Detail = $"Discord imports: {string.Join(", ", matched)}",
                });
            }
            return;
        }

        // Check for webhook delivery in batch/PS files
        if (ext.Equals(".ps1", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".bat", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".cmd", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".sh", StringComparison.OrdinalIgnoreCase))
        {
            await InspectWebhookDeliveryScriptAsync(ctx, filePath, fileName, content, ct);
        }
    }

    private async Task InspectWebhookDeliveryScriptAsync(
        ScanContext ctx, string filePath, string fileName, string content, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        bool hasWebhookUrl = content.Contains(DiscordWebhookUrlFragment, StringComparison.OrdinalIgnoreCase) ||
                             content.Contains(DiscordWebhookAltFragment, StringComparison.OrdinalIgnoreCase);

        if (!hasWebhookUrl) return;

        // Count how many delivery patterns are present
        var matchedPatterns = WebhookDeliveryPatterns
            .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (matchedPatterns.Count == 0) return;

        bool hasSystemInfoTerms = content.Contains("systeminfo", StringComparison.OrdinalIgnoreCase) ||
                                  content.Contains("hostname", StringComparison.OrdinalIgnoreCase) ||
                                  content.Contains("username", StringComparison.OrdinalIgnoreCase) ||
                                  content.Contains("ipconfig", StringComparison.OrdinalIgnoreCase) ||
                                  content.Contains("whoami", StringComparison.OrdinalIgnoreCase) ||
                                  content.Contains("Get-ComputerInfo", StringComparison.OrdinalIgnoreCase) ||
                                  content.Contains("$env:COMPUTERNAME", StringComparison.OrdinalIgnoreCase) ||
                                  content.Contains("$env:USERNAME", StringComparison.OrdinalIgnoreCase);

        ctx.AddFinding(new Finding
        {
            Module = Name,
            Title = $"Discord webhook delivery script: {fileName}",
            Risk = hasSystemInfoTerms ? RiskLevel.Critical : RiskLevel.High,
            Location = filePath,
            FileName = fileName,
            Reason = hasSystemInfoTerms
                ? $"Script '{fileName}' sends system information (hostname, username, IP) " +
                  "to a Discord webhook URL. This is a classic cheat loader HWID exfiltration " +
                  "and system profiling pattern used to register users with cheat services."
                : $"Script '{fileName}' uses HTTP delivery functions (Invoke-WebRequest, curl) " +
                  "targeting a Discord webhook URL. Scripts using Discord webhooks for automated " +
                  "reporting are frequently embedded in cheat loaders and activation tools.",
            Detail = $"Delivery patterns: {string.Join(", ", matchedPatterns.Take(4))}",
        });

        await Task.CompletedTask;
    }

    private async Task InspectInviteTxtFileAsync(ScanContext ctx, string filePath, string fileName, CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }

        ct.ThrowIfCancellationRequested();

        bool hasDiscordInvite = DiscordInviteRegex.IsMatch(content);
        if (!hasDiscordInvite) return;

        bool hasCheatContext = CheatInviteKeywords.Any(k =>
            content.Contains(k, StringComparison.OrdinalIgnoreCase));

        if (!hasCheatContext) return;

        var inviteMatch = DiscordInviteRegex.Match(content);
        var inviteCode = inviteMatch.Success ? inviteMatch.Value : "unknown";

        ctx.AddFinding(new Finding
        {
            Module = Name,
            Title = $"Cheat Discord invite file detected: {fileName}",
            Risk = RiskLevel.High,
            Location = filePath,
            FileName = fileName,
            Reason = $"Text file '{fileName}' contains a Discord server invite link alongside " +
                     "cheat download or purchase keywords. Cheat distributions include these " +
                     "files to direct users to the cheat operator's Discord server for support, " +
                     "updates, and additional cheat purchases.",
            Detail = $"Discord invite: {inviteCode}",
        });
    }

    // =========================================================================
    // Phase 2 – Discord LevelDB access artifacts
    // =========================================================================

    private void ScanDiscordLevelDbAccessArtifacts(ScanContext ctx, CancellationToken ct)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        foreach (var ldbRelPath in DiscordLevelDbPaths)
        {
            ct.ThrowIfCancellationRequested();
            var ldbDir = Path.Combine(appData, ldbRelPath);
            if (!Directory.Exists(ldbDir)) continue;

            // Check for signs that the LevelDB was recently accessed by external processes
            // (token stealers leave behind partial/corrupted files or lock artifacts)
            string[] ldbFiles;
            try { ldbFiles = Directory.GetFiles(ldbDir); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            // If a .log file is very small but many .ldb files exist, it may indicate
            // the LDB was copied out (token stealer reads all files)
            int ldbCount = ldbFiles.Count(f => Path.GetExtension(f).Equals(".ldb", StringComparison.OrdinalIgnoreCase));
            int logCount = ldbFiles.Count(f => Path.GetExtension(f).Equals(".log", StringComparison.OrdinalIgnoreCase));

            ctx.IncrementFiles((long)ldbCount + logCount);

            // Look for lock files that are owned/held by an external process
            var lockFile = Path.Combine(ldbDir, "LOCK");
            if (File.Exists(lockFile))
            {
                // Check if the lock file has unusual modification time (recently accessed)
                try
                {
                    var lockInfo = new FileInfo(lockFile);
                    if ((DateTime.UtcNow - lockInfo.LastWriteTimeUtc).TotalHours < 24)
                    {
                        // Recent modification could mean a stealer ran recently
                        // This is a low-confidence signal on its own — report as Low
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Discord LevelDB LOCK file recently modified",
                            Risk = RiskLevel.Low,
                            Location = lockFile,
                            FileName = "LOCK",
                            Reason = "Discord Local Storage LevelDB LOCK file was modified within " +
                                     "the last 24 hours. While Discord normally manages this file, " +
                                     "external token stealers access the LevelDB directory to extract " +
                                     "authentication tokens. Review alongside other findings.",
                            Detail = $"Last write: {lockInfo.LastWriteTimeUtc:u} UTC | .ldb files: {ldbCount}",
                        });
                    }
                }
                catch { }
            }

            // Detect if there are extra files in the LevelDB directory that shouldn't be there
            var unexpectedFiles = ldbFiles
                .Where(f =>
                {
                    var ext = Path.GetExtension(f).ToLowerInvariant();
                    return ext != ".ldb" && ext != ".log" && ext != ".sst" && ext != ".tmp" &&
                           !Path.GetFileName(f).Equals("CURRENT", StringComparison.OrdinalIgnoreCase) &&
                           !Path.GetFileName(f).Equals("LOCK", StringComparison.OrdinalIgnoreCase) &&
                           !Path.GetFileName(f).Equals("MANIFEST-000001", StringComparison.OrdinalIgnoreCase) &&
                           !Path.GetFileName(f).StartsWith("MANIFEST-", StringComparison.OrdinalIgnoreCase) &&
                           !Path.GetFileName(f).StartsWith("LOG", StringComparison.OrdinalIgnoreCase);
                })
                .ToList();

            foreach (var unexpected in unexpectedFiles)
            {
                var unexpectedName = Path.GetFileName(unexpected);
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Unexpected file in Discord LevelDB directory: {unexpectedName}",
                    Risk = RiskLevel.High,
                    Location = unexpected,
                    FileName = unexpectedName,
                    Reason = $"File '{unexpectedName}' found inside the Discord Local Storage " +
                             "LevelDB directory where it should not exist. Token stealers sometimes " +
                             "drop output files or temporary extraction artifacts in the LevelDB " +
                             "directory during the token theft operation.",
                });
            }
        }
    }

    // =========================================================================
    // Phase 3 – Discord RPC DLLs in suspicious locations
    // =========================================================================

    private async Task ScanDiscordRpcDllsAsync(ScanContext ctx, CancellationToken ct)
    {
        // Legitimate game directories that may contain Discord RPC DLLs
        var legitimateGameRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var steamAppsCommon = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Steam", "steamapps", "common");
        if (Directory.Exists(steamAppsCommon)) legitimateGameRoots.Add(steamAppsCommon);

        var epicGames = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Epic Games");
        if (Directory.Exists(epicGames)) legitimateGameRoots.Add(epicGames);

        // Scan Downloads, Desktop, AppData, Temp for RPC DLLs (suspicious locations)
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var suspiciousRoots = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            Path.GetTempPath(),
        };

        foreach (var root in suspiciousRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            var files = new List<string>();
            try { CollectFiles(root, files, maxDepth: 4, ct); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);

                if (!KnownRpcDllNames.Contains(fileName)) continue;

                // Not in a legitimate game directory
                bool isInGameDir = legitimateGameRoots.Any(gr =>
                    file.StartsWith(gr, StringComparison.OrdinalIgnoreCase));
                if (isInGameDir) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Discord RPC DLL in suspicious location: {fileName}",
                    Risk = RiskLevel.Medium,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Discord RPC DLL '{fileName}' found in a non-game directory " +
                             $"('{Path.GetDirectoryName(file)}'). Legitimate uses appear inside " +
                             "game install directories. Cheat menus bundle Discord RPC DLLs to " +
                             "report cheat status via Rich Presence or to appear as a legitimate " +
                             "game process in Discord's activity monitor.",
                });
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // Phase 4 – PowerShell history
    // =========================================================================

    private async Task ScanPowerShellHistoryAsync(ScanContext ctx, CancellationToken ct)
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var histPaths = new[]
        {
            Path.Combine(userProfile, "AppData", "Roaming", "Microsoft", "Windows",
                "PowerShell", "PSReadLine", "ConsoleHost_history.txt"),
            Path.Combine(userProfile, "AppData", "Roaming", "Microsoft", "Windows",
                "PowerShell", "PSReadLine", "Visual Studio Code Host_history.txt"),
        };

        foreach (var histPath in histPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!File.Exists(histPath)) continue;

            string content;
            try
            {
                using var fs = new FileStream(histPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync();
            }
            catch (IOException) { continue; }
            catch (UnauthorizedAccessException) { continue; }

            ct.ThrowIfCancellationRequested();

            bool hasWebhook = content.Contains(DiscordWebhookUrlFragment, StringComparison.OrdinalIgnoreCase) ||
                              content.Contains(DiscordWebhookAltFragment, StringComparison.OrdinalIgnoreCase);

            if (!hasWebhook) continue;

            var matchedDelivery = WebhookDeliveryPatterns
                .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                .ToList();

            bool hasSystemInfo = content.Contains("$env:COMPUTERNAME", StringComparison.OrdinalIgnoreCase) ||
                                 content.Contains("$env:USERNAME", StringComparison.OrdinalIgnoreCase) ||
                                 content.Contains("Get-ComputerInfo", StringComparison.OrdinalIgnoreCase) ||
                                 content.Contains("systeminfo", StringComparison.OrdinalIgnoreCase) ||
                                 content.Contains("ipconfig", StringComparison.OrdinalIgnoreCase) ||
                                 content.Contains("whoami", StringComparison.OrdinalIgnoreCase);

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Discord webhook delivery in PowerShell history: {Path.GetFileName(histPath)}",
                Risk = hasSystemInfo ? RiskLevel.Critical : RiskLevel.High,
                Location = histPath,
                FileName = Path.GetFileName(histPath),
                Reason = hasSystemInfo
                    ? "PowerShell history contains commands that send system information " +
                      "(computer name, username, IP) to a Discord webhook URL. This is a " +
                      "textbook cheat loader HWID exfiltration pattern used to register the " +
                      "user's machine with a cheat service or log victim system data."
                    : "PowerShell history contains commands targeting a Discord webhook URL. " +
                      "Cheat loaders and their activation scripts frequently use PowerShell " +
                      "webhook delivery as a lightweight C2 reporting mechanism.",
                Detail = matchedDelivery.Count > 0
                    ? $"Delivery patterns found: {string.Join(", ", matchedDelivery.Take(4))}"
                    : ExtractContext(content, DiscordWebhookUrlFragment, 100),
            });
        }
    }

    // =========================================================================
    // Phase 5 – Registry
    // =========================================================================

    private void ScanRegistry(ScanContext ctx, CancellationToken ct)
    {
        // Check for Discord RPC SDK registered COM objects in suspicious contexts
        CheckDiscordRpcComRegistration(ctx, ct);

        // Check autostart entries that reference Discord webhook delivery
        CheckAutostartWebhookEntries(ctx, ct);
    }

    private void CheckDiscordRpcComRegistration(ScanContext ctx, CancellationToken ct)
    {
        // discord-rpc.dll COM class registration: legitimate when pointing to game dirs
        var clsidPaths = new[]
        {
            @"SOFTWARE\Classes\CLSID",
            @"SOFTWARE\WOW6432Node\Classes\CLSID",
        };

        foreach (var path in clsidPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path);
                if (key is null) continue;

                foreach (var clsidName in key.GetSubKeyNames().Take(500))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    try
                    {
                        using var clsidKey = key.OpenSubKey(clsidName);
                        if (clsidKey is null) continue;

                        var displayName = clsidKey.GetValue(null)?.ToString() ?? string.Empty;
                        if (!displayName.Contains("discord", StringComparison.OrdinalIgnoreCase)) continue;

                        using var inprocKey = clsidKey.OpenSubKey("InprocServer32");
                        if (inprocKey is null) continue;

                        var dllPath = inprocKey.GetValue(null)?.ToString() ?? string.Empty;
                        if (string.IsNullOrEmpty(dllPath)) continue;

                        // Flag if DLL path is outside Program Files / game directories
                        bool isSuspicious = !dllPath.Contains("Program Files", StringComparison.OrdinalIgnoreCase) &&
                                           !dllPath.Contains("steamapps", StringComparison.OrdinalIgnoreCase) &&
                                           !dllPath.Contains("Epic Games", StringComparison.OrdinalIgnoreCase) &&
                                           (dllPath.Contains("Temp", StringComparison.OrdinalIgnoreCase) ||
                                            dllPath.Contains("AppData", StringComparison.OrdinalIgnoreCase) ||
                                            dllPath.Contains("Downloads", StringComparison.OrdinalIgnoreCase) ||
                                            dllPath.Contains("Desktop", StringComparison.OrdinalIgnoreCase));

                        if (!isSuspicious) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Discord RPC COM class registered from suspicious path",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\{path}\{clsidName}\InprocServer32",
                            FileName = Path.GetFileName(dllPath),
                            Reason = $"Discord-related COM class registered with InprocServer32 " +
                                     $"pointing to '{dllPath}', which is outside expected game or " +
                                     "system directories. Cheat tools register Discord RPC COM objects " +
                                     "from AppData/Temp/Downloads to hook into Discord RPC calls.",
                            Detail = $"CLSID: {clsidName} | DLL: {dllPath}",
                        });
                    }
                    catch (UnauthorizedAccessException) { }
                    catch { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private void CheckAutostartWebhookEntries(ScanContext ctx, CancellationToken ct)
    {
        var runKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        };

        foreach (var keyPath in runKeys)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(keyPath)
                             ?? Registry.LocalMachine.OpenSubKey(keyPath);
                if (key is null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    var val = key.GetValue(valueName)?.ToString() ?? string.Empty;

                    if (!val.Contains(DiscordWebhookUrlFragment, StringComparison.OrdinalIgnoreCase) &&
                        !val.Contains(DiscordWebhookAltFragment, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Autostart entry with Discord webhook URL: {valueName}",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKCU\{keyPath}\{valueName}",
                        Reason = $"Autostart registry entry '{valueName}' contains a Discord webhook URL. " +
                                 "This means a script or executable that sends data to Discord is " +
                                 "configured to run at every Windows login. This is a persistence " +
                                 "mechanism used by cheat loaders to report system status to the " +
                                 "operator's Discord channel on each boot.",
                        Detail = $"Command: {Truncate(val, 200)}",
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    // =========================================================================
    // Phase 6 – Cheat directory invite files
    // =========================================================================

    private async Task ScanCheatDirectoryInviteFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        // Scan known cheat staging directories for README/invite .txt files
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var cheatStagingRoots = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            appData,
            localAppData,
        };

        foreach (var root in cheatStagingRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            string[] topDirs;
            try { topDirs = Directory.GetDirectories(root); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var dir in topDirs)
            {
                ct.ThrowIfCancellationRequested();

                // Look for txt files in the top-level directory that match invite file names
                string[] txtFiles;
                try { txtFiles = Directory.GetFiles(dir, "*.txt", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch { continue; }

                foreach (var txtFile in txtFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var txtFileName = Path.GetFileName(txtFile);

                    if (!KnownInviteTxtFileNames.Contains(txtFileName)) continue;

                    FileInfo fi;
                    try { fi = new FileInfo(txtFile); } catch { continue; }
                    if (fi.Length > 512 * 1024) continue;

                    try { await InspectInviteTxtFileAsync(ctx, txtFile, txtFileName, ct); }
                    catch (IOException) { }
                }

                // Also check if the directory itself has a cheat-sounding name alongside
                // any discord.txt / readme.txt style file
                var dirName = Path.GetFileName(dir).ToLowerInvariant();
                bool isCheatDir = dirName.Contains("cheat") || dirName.Contains("hack") ||
                                  dirName.Contains("menu") || dirName.Contains("loader") ||
                                  dirName.Contains("bypass") || dirName.Contains("spoofer") ||
                                  dirName.Contains("aimbot") || dirName.Contains("wallhack") ||
                                  dirName.Contains("esp") || dirName.Contains("inject") ||
                                  dirName.Contains("crack") || dirName.Contains("trainer");

                if (!isCheatDir) continue;

                // Scan all .txt files in this cheat directory
                string[] allTxts;
                try { allTxts = Directory.GetFiles(dir, "*.txt", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch { continue; }

                foreach (var txtFile in allTxts)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var txtFileName = Path.GetFileName(txtFile);

                    FileInfo fi;
                    try { fi = new FileInfo(txtFile); } catch { continue; }
                    if (fi.Length > 512 * 1024) continue;

                    string content;
                    try
                    {
                        using var fs = new FileStream(txtFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync();
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    ct.ThrowIfCancellationRequested();

                    bool hasDiscordInvite = DiscordInviteRegex.IsMatch(content);
                    if (!hasDiscordInvite) continue;

                    var inviteMatch = DiscordInviteRegex.Match(content);

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Discord invite in cheat directory README: {txtFileName}",
                        Risk = RiskLevel.High,
                        Location = txtFile,
                        FileName = txtFileName,
                        Reason = $"Text file '{txtFileName}' in cheat directory '{Path.GetFileName(dir)}' " +
                                 "contains a Discord server invite link. Cheat software packages " +
                                 "include Discord invite links to direct users to the operator's " +
                                 "server for download links, support, and cheat updates.",
                        Detail = $"Discord invite: {inviteMatch.Value} | Directory: {Path.GetFileName(dir)}",
                    });
                }
            }
        }
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private static void CollectFiles(string root, List<string> sink, int maxDepth, CancellationToken ct)
    {
        var stack = new Stack<(string dir, int depth)>();
        stack.Push((root, 0));

        while (stack.Count > 0)
        {
            if (ct.IsCancellationRequested) return;
            var (dir, depth) = stack.Pop();

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var f in files) sink.Add(f);

            if (depth >= maxDepth) continue;

            string[] subs = Array.Empty<string>();
            try { subs = Directory.GetDirectories(dir); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var s in subs) stack.Push((s, depth + 1));
        }
    }

    private static string ExtractContext(string content, string keyword, int maxLen)
    {
        var idx = content.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return string.Empty;
        var start = Math.Max(0, idx - 30);
        var end = Math.Min(content.Length, idx + keyword.Length + maxLen);
        var snippet = content[start..end].Replace('\n', ' ').Replace('\r', ' ');
        return snippet.Length > maxLen + 60 ? snippet[..(maxLen + 60)] + "..." : snippet;
    }

    private static string Truncate(string s, int maxLen) =>
        s.Length <= maxLen ? s : s[..maxLen] + "...";
}
