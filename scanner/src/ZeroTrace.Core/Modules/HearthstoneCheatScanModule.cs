using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class HearthstoneCheatScanModule : IScanModule
{
    public string Name => "Hearthstone Bot & Cheat Forensic Scan";
    public double Weight => 3.0;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string AppData =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string TempPath =
        Path.GetTempPath();
    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static readonly string Documents =
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    private static readonly string Desktop =
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    private static readonly string Downloads =
        Path.Combine(UserProfile, "Downloads");

    private static readonly string[] BotExecutableNames =
    {
        "hearthstone_bot.exe",
        "hs_bot.exe",
        "hsreplay_bot.exe",
        "hearth_bot.exe",
        "hearthstone_auto.exe",
        "hs_auto.exe",
        "hsfarmer.exe",
        "hs_farmer.exe",
        "hearthfarmer.exe",
        "innkeeper.exe",
        "stonebot.exe",
        "trackerbot.exe",
        "hearthbot.exe",
        "hs_grinder.exe",
        "hearthgrinder.exe",
        "hs_grinder64.exe",
        "hearthauto.exe",
        "hs_player.exe",
        "hearthplayer.exe",
        "silverfishbot.exe",
        "silverfish.exe",
        "hs_auto_player.exe",
        "hearthstone_afk.exe",
        "hs_afk_bot.exe",
        "hs_idle.exe",
        "hearthstone_idle.exe",
        "hearthautoplay.exe",
        "hs_autoplay.exe",
        "hs_rank_bot.exe",
        "hearthrank.exe",
        "hs_rank.exe",
        "hearthstone_rank_bot.exe",
        "hs_arena_bot.exe",
        "hearthstone_arena.exe",
        "hs_quest_bot.exe",
        "hearthstone_quest.exe",
        "hs_daily_bot.exe",
        "hearthstone_daily.exe",
        "hs_tavern_bot.exe",
        "hearthstone_tavern.exe",
        "hs_brawl_bot.exe",
        "hearthstone_brawl.exe",
        "hs_battlegrounds_bot.exe",
        "hearthstone_bg_bot.exe",
        "hearthstone_battlegrounds.exe",
        "hs_duels_bot.exe",
        "hearthstone_duels_bot.exe",
        "hs_mercenaries_bot.exe",
        "hearthstone_mercenaries.exe",
    };

    private static readonly string[] DeckTrackerExploitNames =
    {
        "hdtcheat.exe",
        "hdt_cheat.dll",
        "hs_tracker_exploit.exe",
        "hdt_exploit.exe",
        "hdtmod.exe",
        "hdt_mod.dll",
        "hdt_hack.exe",
        "hdt_bypass.dll",
        "hdt_reveal.exe",
        "hs_deck_reveal.exe",
        "hearthstone_reveal.exe",
        "hs_hand_reveal.exe",
        "hdt_full_reveal.dll",
        "hearthstone_tracker_hack.exe",
        "hdthack.exe",
        "hs_tracker_mod.dll",
        "hdt_cheat_plugin.dll",
        "hdt_plugin_cheat.dll",
    };

    private static readonly string[] PacketInjectionNames =
    {
        "hs_packet_inject.exe",
        "hs_mitm.exe",
        "hs_proxy.exe",
        "hearthstone_mitm.exe",
        "hearthstone_proxy.exe",
        "hs_intercept.exe",
        "hearthstone_intercept.exe",
        "hs_packet_edit.exe",
        "hs_packet_mod.exe",
        "hearthstone_packet_inject.exe",
        "hs_traffic_inject.exe",
        "hs_ssl_strip.exe",
        "hearthstone_ssl_strip.exe",
        "hs_net_inject.exe",
        "hearthstone_net_proxy.exe",
        "hs_network_inject.exe",
        "hs_bnet_mitm.exe",
        "hearthstone_bnet_proxy.exe",
        "hs_card_inject.exe",
        "hearthstone_card_inject.exe",
        "hs_game_proxy.exe",
    };

    private static readonly string[] CardUnlockHackNames =
    {
        "hs_unlocker.exe",
        "hs_dust.exe",
        "hearthstone_unlocker.exe",
        "hs_card_unlocker.exe",
        "hearthstone_card_unlock.exe",
        "hs_unlock_all.exe",
        "hearthstone_unlock.exe",
        "hs_dust_hack.exe",
        "hearthstone_dust_hack.exe",
        "hs_gold_hack.exe",
        "hearthstone_gold_hack.exe",
        "hs_resource_hack.exe",
        "hearthstone_resource.exe",
        "hs_pack_opener.exe",
        "hearthstone_pack_hack.exe",
        "hs_pack_open_all.exe",
        "hs_collection_unlocker.exe",
        "hearthstone_collection_hack.exe",
        "hs_free_cards.exe",
        "hearthstone_free_cards.exe",
        "hs_cheat_dust.exe",
        "hearthstone_cheat.exe",
        "hs_currency_hack.exe",
        "hearthstone_currency.exe",
    };

    private static readonly string[] ReplayManipulationNames =
    {
        "hs_replay_edit.exe",
        "hearthstone_replay_edit.exe",
        "hs_replay_hack.exe",
        "hearthstone_replay_hack.exe",
        "hs_replay_forge.exe",
        "hearthstone_replay_forge.exe",
        "hs_replay_spoof.exe",
        "hearthstone_replay_spoof.exe",
        "hs_replay_mod.exe",
        "hearthstone_replay_mod.exe",
        "hs_replay_inject.exe",
        "hearthstone_replay_inject.exe",
        "hs_rank_spoof.exe",
        "hearthstone_rank_spoof.exe",
        "hs_history_edit.exe",
        "hearthstone_history_edit.exe",
        "hs_match_spoof.exe",
        "hearthstone_match_spoof.exe",
    };

    private static readonly string[] FarmingScriptNames =
    {
        "hs_bot.py",
        "hearthbot.py",
        "hs_afk.py",
        "hs_farm.js",
        "hearthstone_bot.py",
        "hs_auto.py",
        "hs_grinder.py",
        "hearthgrinder.py",
        "hs_player.py",
        "hearthplayer.py",
        "hs_afk_bot.py",
        "hearthstone_afk.py",
        "hs_idle.py",
        "hearthstone_idle.py",
        "hs_farm.py",
        "hearthfarm.py",
        "hs_arena.py",
        "hearthstone_arena.py",
        "hs_quest.py",
        "hs_daily.py",
        "hs_tavern.py",
        "hs_battlegrounds.py",
        "hs_bg.py",
        "hs_bg_bot.py",
        "hearthstone_bg.py",
        "hs_mercenaries.py",
        "hs_mercs.py",
        "hs_duels.py",
        "hearthstone_duels.py",
        "hs_node.js",
        "hs_grinder.js",
        "hearthstone_farm.js",
        "hs_afk.js",
        "hs_idle.js",
        "hs_quest.js",
        "hs_daily.js",
        "hs_bot.ts",
        "hearthbot.ts",
    };

    private static readonly string[] FarmingScriptKeywords =
    {
        "hearthstone",
        "hs_bot",
        "hearthbot",
        "innkeeper",
        "stonebot",
        "auto_play",
        "autoplay",
        "auto_concede",
        "autoconcede",
        "end_turn",
        "play_card",
        "playcard",
        "attack_minion",
        "attackminion",
        "hs_client",
        "hearthauto",
        "find_button",
        "click_button",
        "click_end_turn",
        "mulligan",
        "auto_mulligan",
        "grind_gold",
        "grindgold",
        "quest_complete",
        "questcomplete",
        "win_rate",
        "daily_quest",
        "dailyquest",
        "tavern_brawl",
        "tavernbrawl",
        "battlegrounds_bot",
        "bgbot",
        "arena_bot",
        "arenabot",
        "card_image",
        "board_state",
        "game_state",
        "pyautogui",
        "win32api",
        "pynput",
    };

    private static readonly string[] BotConfigKeywords =
    {
        "innkeeper",
        "stonebot",
        "hs_bot",
        "hearthbot",
        "trackerbot",
        "hsfarmer",
        "silverfish",
        "auto_play=",
        "auto_play =",
        "autoplay=",
        "autoplay =",
        "grind_mode=",
        "farm_mode=",
        "afk_mode=",
        "concede_chance=",
        "mulligan_strategy=",
        "arena_draft=",
        "bot_deck=",
        "bot_class=",
        "target_wins=",
        "gold_target=",
        "dust_target=",
        "pack_target=",
        "daily_complete=",
        "quest_mode=",
        "battlegrounds_bot=",
        "bg_strategy=",
        "mercenaries_bot=",
        "bot_username=",
        "bot_password=",
    };

    private static readonly string[] HsLogBotSignatures =
    {
        "BOT:",
        "[BOT]",
        "AutoPlay",
        "BotAction",
        "BotDecision",
        "bot_play",
        "bot_mulligan",
        "bot_concede",
        "stonebot",
        "innkeeper_bot",
        "silverfishbot",
        "HearthBot",
        "auto_turn",
        "BotEnd",
        "BotStart",
        "BotAttack",
        "BotCard",
        "BotTarget",
        "FarmBot",
        "GrindBot",
        "trackerbot",
    };

    private static readonly string[] UserAssistCheatNames =
    {
        "hearthstone_bot",
        "hs_bot",
        "hsreplay_bot",
        "hearth_bot",
        "hearthstone_auto",
        "hs_auto",
        "hsfarmer",
        "hs_farmer",
        "hearthfarmer",
        "innkeeper",
        "stonebot",
        "trackerbot",
        "hearthbot",
        "silverfishbot",
        "hdtcheat",
        "hdt_cheat",
        "hs_tracker_exploit",
        "hs_packet_inject",
        "hs_mitm",
        "hs_proxy",
        "hs_unlocker",
        "hs_dust",
        "hearthstone_unlocker",
        "hs_replay_edit",
        "hearthstone_cheat",
        "hs_card_unlocker",
        "hs_gold_hack",
        "hs_dust_hack",
        "hs_pack_opener",
        "hs_rank_bot",
        "hearthgrinder",
        "hs_grinder",
        "hs_arena_bot",
        "hs_quest_bot",
        "hs_daily_bot",
        "hs_battlegrounds_bot",
    };

    private static readonly string[] MuiCacheCheatKeywords =
    {
        "hearthstone_bot",
        "hs_bot",
        "hearth_bot",
        "hearthbot",
        "hs_auto",
        "hsfarmer",
        "hs_farmer",
        "hearthfarmer",
        "innkeeper",
        "stonebot",
        "trackerbot",
        "silverfishbot",
        "hdtcheat",
        "hdt_cheat",
        "hs_tracker_exploit",
        "hs_packet_inject",
        "hs_mitm",
        "hs_proxy",
        "hs_unlocker",
        "hs_dust",
        "hearthstone_unlocker",
        "hs_replay_hack",
        "hearthstone_cheat",
        "hs_card_unlocker",
        "hs_gold_hack",
        "hs_dust_hack",
        "hs_grinder",
        "hearthgrinder",
        "hs_arena_bot",
        "hs_rank_bot",
    };

    private static readonly string[] RunKeyCheatNames =
    {
        "hearthstone_bot",
        "hs_bot",
        "hearth_bot",
        "hs_auto",
        "hsfarmer",
        "innkeeper",
        "stonebot",
        "trackerbot",
        "silverfishbot",
        "hdtcheat",
        "hs_packet_inject",
        "hs_mitm",
        "hs_proxy",
        "hs_unlocker",
        "hs_dust",
        "hs_grinder",
        "hs_arena_bot",
        "hs_rank_bot",
        "hs_quest_bot",
    };

    private const string UserAssistBase =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
    private const string MuiCacheKey =
        @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
    private const string RunKeyLm =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string RunKeyHkcu =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

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

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting Hearthstone bot & cheat forensic scan...");

        return Task.WhenAll(
            CheckBotExecutables(ctx, ct),
            CheckDeckTrackerExploitArtifacts(ctx, ct),
            CheckPacketInjectionArtifacts(ctx, ct),
            CheckCardUnlockHackArtifacts(ctx, ct),
            CheckReplayManipulationArtifacts(ctx, ct),
            CheckFarmingScripts(ctx, ct),
            CheckHearthstoneLocalDataCheatArtifacts(ctx, ct),
            CheckHearthstoneLogForBotSignatures(ctx, ct),
            CheckUserAssistRegistry(ctx, ct),
            CheckMuiCacheRegistry(ctx, ct),
            CheckRunKeyRegistry(ctx, ct),
            CheckBotConfigFiles(ctx, ct),
            CheckTempFolderArtifacts(ctx, ct),
            CheckHearthstoneDirectoryArtifacts(ctx, ct)
        );
    }

    private Task CheckBotExecutables(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.05, Name, "Scanning for Hearthstone bot executables...");

            var searchDirs = new[]
            {
                UserProfile,
                Desktop,
                Downloads,
                Documents,
                TempPath,
                Path.Combine(LocalAppData, "Temp"),
                Path.Combine(AppData, "Blizzard"),
                Path.Combine(AppData, "Blizzard Entertainment"),
                Path.Combine(LocalAppData, "Blizzard"),
                Path.Combine(LocalAppData, "Blizzard Entertainment"),
                Path.Combine(LocalAppData, "Blizzard Entertainment", "Hearthstone"),
                Path.Combine(AppData, "HearthstoneBot"),
                Path.Combine(AppData, "HSBot"),
                Path.Combine(UserProfile, "Bots"),
                Path.Combine(UserProfile, "HearthstoneBot"),
                Path.Combine(UserProfile, "HSBot"),
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);

                        var match = BotExecutableNames.FirstOrDefault(n =>
                            fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (match is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Hearthstone Bot Executable: {fileName}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Known Hearthstone bot executable '{fileName}' found at '{file}'. " +
                                       "Hearthstone bots automate gameplay to farm gold, complete quests, " +
                                       "grind ranked wins, or earn rewards without human input. This " +
                                       "constitutes a direct violation of Blizzard's Terms of Service " +
                                       "and Hearthstone's competitive integrity rules. Bot executables " +
                                       "of this name are well-known forensic artifacts of automated play.",
                            Detail   = $"Matched artifact: {match} | Path: {file}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }

            ctx.Report(0.1, Name, "Hearthstone bot executable check complete.");
        }, ct);

    private Task CheckDeckTrackerExploitArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.1, Name, "Checking for Hearthstone Deck Tracker exploit artifacts...");

            var searchDirs = new[]
            {
                UserProfile,
                Desktop,
                Downloads,
                Documents,
                TempPath,
                Path.Combine(LocalAppData, "Temp"),
                Path.Combine(AppData, "HearthstoneDeckTracker"),
                Path.Combine(LocalAppData, "HearthstoneDeckTracker"),
                Path.Combine(AppData, "HDT"),
                Path.Combine(UserProfile, "HDT"),
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);

                        var match = DeckTrackerExploitNames.FirstOrDefault(n =>
                            fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (match is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"HDT Exploit/Cheat Tool Artifact: {fileName}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Hearthstone Deck Tracker exploit tool '{fileName}' found at '{file}'. " +
                                       "These tools abuse or modify Hearthstone Deck Tracker (HDT) plugins " +
                                       "to reveal opponent's hand cards, predict future draws, expose " +
                                       "secrets, or provide full information on hidden game state that " +
                                       "would not normally be visible to a legitimate player. " +
                                       "This constitutes cheating by exploiting the game's network traffic " +
                                       "or memory to gain information advantage.",
                            Detail   = $"Matched artifact: {match} | Path: {file}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }

            ctx.Report(0.18, Name, "HDT exploit check complete.");
        }, ct);

    private Task CheckPacketInjectionArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.18, Name, "Checking for Hearthstone packet injection/MITM artifacts...");

            var searchDirs = new[]
            {
                UserProfile,
                Desktop,
                Downloads,
                Documents,
                TempPath,
                Path.Combine(LocalAppData, "Temp"),
                Path.Combine(UserProfile, "Tools"),
                Path.Combine(UserProfile, "Proxy"),
                Path.Combine(UserProfile, "MITM"),
                Path.Combine(UserProfile, "HSHack"),
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);

                        var match = PacketInjectionNames.FirstOrDefault(n =>
                            fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (match is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Hearthstone Packet Injection Tool: {fileName}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Hearthstone packet injection or MITM proxy tool '{fileName}' found " +
                                       $"at '{file}'. These tools intercept and modify the network traffic " +
                                       "between the Hearthstone client and Blizzard's servers, enabling " +
                                       "manipulation of game state, card draws, or outcomes. Packet " +
                                       "injection against Hearthstone constitutes a severe cheat that " +
                                       "bypasses all client-side protections and directly manipulates " +
                                       "server-side game data.",
                            Detail   = $"Matched artifact: {match} | Path: {file}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }

            ctx.Report(0.26, Name, "Packet injection check complete.");
        }, ct);

    private Task CheckCardUnlockHackArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.26, Name, "Checking for Hearthstone card unlock / dust hack artifacts...");

            var searchDirs = new[]
            {
                UserProfile,
                Desktop,
                Downloads,
                Documents,
                TempPath,
                Path.Combine(LocalAppData, "Temp"),
                Path.Combine(UserProfile, "Hacks"),
                Path.Combine(UserProfile, "Cheats"),
                Path.Combine(UserProfile, "HSHack"),
                Path.Combine(UserProfile, "HearthHack"),
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);

                        var match = CardUnlockHackNames.FirstOrDefault(n =>
                            fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (match is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Hearthstone Card Unlock / Dust Hack: {fileName}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Hearthstone card unlock or dust/currency hack tool '{fileName}' " +
                                       $"found at '{file}'. These tools attempt to modify the local " +
                                       "Hearthstone client state or intercept server responses to unlock " +
                                       "cards, generate dust, generate gold, or open packs without " +
                                       "legitimate purchases. While these may not affect other players " +
                                       "directly, they constitute fraud against Blizzard and violation " +
                                       "of the game's Terms of Service.",
                            Detail   = $"Matched artifact: {match} | Path: {file}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }

            ctx.Report(0.33, Name, "Card unlock hack check complete.");
        }, ct);

    private Task CheckReplayManipulationArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.33, Name, "Checking for Hearthstone replay manipulation artifacts...");

            var searchDirs = new[]
            {
                UserProfile,
                Desktop,
                Downloads,
                Documents,
                TempPath,
                Path.Combine(LocalAppData, "Temp"),
                Path.Combine(UserProfile, "HSHack"),
                Path.Combine(UserProfile, "HSReplay"),
                Path.Combine(AppData, "HSReplay"),
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);

                        var match = ReplayManipulationNames.FirstOrDefault(n =>
                            fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (match is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Hearthstone Replay Manipulation Tool: {fileName}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Hearthstone replay manipulation tool '{fileName}' found at '{file}'. " +
                                       "These tools modify Hearthstone game replay files or rank/match " +
                                       "history records to falsify win rates, fabricate high-rank " +
                                       "results, or manipulate statistical proof of game performance. " +
                                       "This constitutes record tampering used to fraudulently claim " +
                                       "tournament qualification, sponsorship, or social credibility.",
                            Detail   = $"Matched artifact: {match} | Path: {file}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }

            ctx.Report(0.4, Name, "Replay manipulation check complete.");
        }, ct);

    private Task CheckFarmingScripts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.4, Name, "Scanning for Hearthstone farming bot scripts...");

            var searchDirs = new[]
            {
                UserProfile,
                Desktop,
                Downloads,
                Documents,
                TempPath,
                Path.Combine(LocalAppData, "Temp"),
                Path.Combine(UserProfile, "Scripts"),
                Path.Combine(UserProfile, "Bots"),
                Path.Combine(UserProfile, "HearthBot"),
                Path.Combine(UserProfile, "HSBot"),
                Path.Combine(UserProfile, "HSFarm"),
                Path.Combine(UserProfile, "HSGrinder"),
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);

                        var match = FarmingScriptNames.FirstOrDefault(n =>
                            fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (match is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Hearthstone Farming Script: {fileName}",
                                Risk     = RiskLevel.Critical,
                                Location = file,
                                FileName = fileName,
                                Reason   = $"Known Hearthstone farming/bot script '{fileName}' found at '{file}'. " +
                                           "Python and Node.js farming scripts automate Hearthstone gameplay " +
                                           "through screen-scraping, log-parsing, or direct UI automation " +
                                           "to grind gold, complete daily quests, and run through ranked " +
                                           "games without human input. This is a known bot artifact.",
                                Detail   = $"Matched script: {match} | Path: {file}"
                            });
                            continue;
                        }

                        var ext = Path.GetExtension(fileName);
                        if (!ext.Equals(".py", StringComparison.OrdinalIgnoreCase) &&
                            !ext.Equals(".js", StringComparison.OrdinalIgnoreCase) &&
                            !ext.Equals(".ts", StringComparison.OrdinalIgnoreCase) &&
                            !ext.Equals(".ahk", StringComparison.OrdinalIgnoreCase)) continue;

                        if (!fileName.Contains("hs", StringComparison.OrdinalIgnoreCase) &&
                            !fileName.Contains("hearth", StringComparison.OrdinalIgnoreCase) &&
                            !fileName.Contains("bot", StringComparison.OrdinalIgnoreCase) &&
                            !fileName.Contains("farm", StringComparison.OrdinalIgnoreCase) &&
                            !fileName.Contains("grind", StringComparison.OrdinalIgnoreCase) &&
                            !fileName.Contains("auto", StringComparison.OrdinalIgnoreCase)) continue;

                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);

                            int keywordHits = FarmingScriptKeywords.Count(k =>
                                content.Contains(k, StringComparison.OrdinalIgnoreCase));

                            if (keywordHits < 4) continue;

                            var matchedKeywords = FarmingScriptKeywords
                                .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                                .Take(6)
                                .ToList();

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Hearthstone Bot Script Detected: {fileName}",
                                Risk     = RiskLevel.Critical,
                                Location = file,
                                FileName = fileName,
                                Reason   = $"Script '{fileName}' contains {keywordHits} Hearthstone bot " +
                                           "automation keywords including card play, turn management, " +
                                           "mulligan logic, and screen automation APIs. This pattern " +
                                           "is characteristic of automated Hearthstone farming bots " +
                                           "implemented in Python, JavaScript, or AutoHotkey.",
                                Detail   = $"Matched keywords: {string.Join(", ", matchedKeywords)} | Hits: {keywordHits} | Path: {file}"
                            });
                        }
                        catch (IOException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            ctx.Report(0.5, Name, "Farming script scan complete.");
        }, ct);

    private Task CheckHearthstoneLocalDataCheatArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.5, Name, "Scanning Hearthstone local app data for cheat artifacts...");

            var hsLocalDirs = new[]
            {
                Path.Combine(LocalAppData, "Blizzard", "Hearthstone"),
                Path.Combine(LocalAppData, "Blizzard Entertainment", "Hearthstone"),
                Path.Combine(LocalAppData, "Blizzard", "Hearthstone", "Cache"),
                Path.Combine(LocalAppData, "Blizzard Entertainment", "Hearthstone", "Cache"),
                Path.Combine(LocalAppData, "Blizzard", "Hearthstone", "Logs"),
                Path.Combine(LocalAppData, "Blizzard Entertainment", "Hearthstone", "Logs"),
                Path.Combine(AppData, "Blizzard", "Hearthstone"),
                Path.Combine(AppData, "Blizzard Entertainment", "Hearthstone"),
            };

            var cheatConfigExtensions = new[] { ".cfg", ".ini", ".json", ".yaml", ".yml", ".xml", ".conf" };
            var cheatConfigKeywords = new[]
            {
                "bot_mode",
                "botmode",
                "auto_play",
                "autoplay",
                "cheat_enabled",
                "hack_enabled",
                "reveal_hand",
                "reveal_opponent",
                "full_info",
                "packet_inject",
                "mitm_enabled",
                "proxy_enabled",
                "unlock_all",
                "free_cards",
                "unlimited_dust",
                "unlimited_gold",
                "bot_deck",
                "bot_class",
                "auto_concede",
                "auto_mulligan",
                "farming_mode",
                "grind_mode",
            };

            foreach (var hsDir in hsLocalDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(hsDir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(hsDir, "*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);
                        var ext = Path.GetExtension(fileName);

                        if (!cheatConfigExtensions.Any(e => e.Equals(ext, StringComparison.OrdinalIgnoreCase)))
                            continue;

                        if (BotExecutableNames.Any(n =>
                            Path.GetFileNameWithoutExtension(fileName).Equals(
                                Path.GetFileNameWithoutExtension(n), StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"HS Cheat Config in Game Directory: {fileName}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason   = $"Hearthstone cheat tool configuration file '{fileName}' found " +
                                           $"inside the Hearthstone application data directory '{hsDir}'. " +
                                           "Cheat tools and bots place their configuration files in the " +
                                           "game's own data directory to make them harder to detect and " +
                                           "to ensure the game process can load them at startup.",
                                Detail   = $"Path: {file}"
                            });
                            continue;
                        }

                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);

                            var keyword = cheatConfigKeywords.FirstOrDefault(k =>
                                content.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (keyword is null) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"HS Cheat Keyword in Game Data File: {fileName}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason   = $"File '{fileName}' in Hearthstone's local app data contains " +
                                           $"cheat/bot configuration keyword '{keyword}' that is not " +
                                           "part of any legitimate Hearthstone configuration. This " +
                                           "indicates a cheat tool or bot has injected configuration " +
                                           "data into the game's local data directory.",
                                Detail   = $"Keyword: {keyword} | Path: {file}"
                            });
                        }
                        catch (IOException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            ctx.Report(0.58, Name, "Hearthstone local data check complete.");
        }, ct);

    private Task CheckHearthstoneLogForBotSignatures(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.58, Name, "Scanning Hearthstone logs for bot activity signatures...");

            var hsLogDirs = new[]
            {
                Path.Combine(LocalAppData, "Blizzard", "Hearthstone", "Logs"),
                Path.Combine(LocalAppData, "Blizzard Entertainment", "Hearthstone", "Logs"),
                Path.Combine(AppData, "Blizzard", "Hearthstone", "Logs"),
                Path.Combine(AppData, "Blizzard Entertainment", "Hearthstone", "Logs"),
                Path.Combine(Documents, "Hearthstone"),
                Path.Combine(Documents, "Hearthstone", "Logs"),
                Path.Combine(AppData, "HearthstoneDeckTracker", "Logs"),
                Path.Combine(LocalAppData, "HearthstoneDeckTracker", "Logs"),
                Path.Combine(AppData, "HearthstoneDeckTracker"),
                Path.Combine(LocalAppData, "HearthstoneDeckTracker"),
            };

            foreach (var logDir in hsLogDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(logDir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(logDir, "*.log", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);

                            var sig = HsLogBotSignatures.FirstOrDefault(s =>
                                content.Contains(s, StringComparison.OrdinalIgnoreCase));
                            if (sig is null) continue;

                            int sigCount = HsLogBotSignatures.Count(s =>
                                content.Contains(s, StringComparison.OrdinalIgnoreCase));

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Bot Signature in Hearthstone Log: {Path.GetFileName(file)}",
                                Risk     = sigCount >= 3 ? RiskLevel.Critical : RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason   = $"Hearthstone log file '{Path.GetFileName(file)}' contains " +
                                           $"{sigCount} bot activity signatures including '{sig}'. " +
                                           "Bot frameworks (Stonebot, Innkeeper, SilverFishBot, HearthBot) " +
                                           "write characteristic log entries when they interact with the " +
                                           "Hearthstone client. These signatures persist in log files " +
                                           "even after the bot is stopped, providing forensic evidence " +
                                           "of automated play.",
                                Detail   = $"First sig: '{sig}' | Total sig count: {sigCount} | Log: {file}"
                            });
                        }
                        catch (IOException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            ctx.Report(0.65, Name, "Hearthstone log scan complete.");
        }, ct);

    private Task CheckUserAssistRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.65, Name, "Scanning UserAssist for Hearthstone cheat tool execution...");

            try
            {
                using var baseKey = Registry.CurrentUser.OpenSubKey(UserAssistBase, writable: false);
                if (baseKey is null) return;

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

                            var match = UserAssistCheatNames.FirstOrDefault(n =>
                                decoded.Contains(n, StringComparison.OrdinalIgnoreCase));
                            if (match is null) continue;

                            int runCount = 0;
                            DateTime? lastRun = null;
                            try
                            {
                                var data = countKey.GetValue(encodedName) as byte[];
                                if (data is { Length: >= 16 })
                                {
                                    runCount = BitConverter.ToInt32(data, 4);
                                    var ft = BitConverter.ToInt64(data, 8);
                                    if (ft > 0) lastRun = DateTime.FromFileTimeUtc(ft);
                                }
                            }
                            catch { }

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"UserAssist: Hearthstone Cheat/Bot Executed — {match}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKCU\{UserAssistBase}\{guidName}\Count",
                                FileName = Path.GetFileName(decoded),
                                Reason   = $"Windows UserAssist entry records execution of Hearthstone " +
                                           $"cheat/bot tool matching '{match}'. Decoded path: '{decoded}'. " +
                                           $"Execution count: {runCount}. " +
                                           (lastRun.HasValue ? $"Last executed: {lastRun.Value:yyyy-MM-dd HH:mm} UTC. " : "") +
                                           "UserAssist keys are ROT13-encoded entries that Windows creates " +
                                           "whenever a program is launched via Explorer or the Start Menu. " +
                                           "They persist after file deletion, providing reliable forensic " +
                                           "evidence of bot or cheat tool execution.",
                                Detail   = $"Decoded: {decoded} | Runs: {runCount} | " +
                                           $"Last: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unknown")}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }

            ctx.Report(0.72, Name, "UserAssist registry check complete.");
        }, ct);

    private Task CheckMuiCacheRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.72, Name, "Scanning MuiCache for Hearthstone cheat tool execution evidence...");

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(MuiCacheKey, writable: false);
                if (key is null) return;

                foreach (var valueName in key.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();

                    var path = valueName;
                    var dotIdx = valueName.LastIndexOf('.');
                    if (dotIdx > 0 && !valueName[dotIdx..].Contains('\\'))
                        path = valueName[..dotIdx];

                    var friendlyName = key.GetValue(valueName) as string ?? "";
                    var combined = path + " " + friendlyName;

                    var keyword = MuiCacheCheatKeywords.FirstOrDefault(k =>
                        combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (keyword is null) continue;

                    bool fileExists = File.Exists(path);
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"MuiCache: Hearthstone Cheat/Bot Executed: {Path.GetFileName(path)}",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKCU\{MuiCacheKey}",
                        FileName = Path.GetFileName(path),
                        Reason   = $"MuiCache registry entry confirms prior execution of Hearthstone " +
                                   $"cheat/bot tool matching keyword '{keyword}'. Recorded path: '{path}'. " +
                                   (fileExists
                                       ? "The tool file is still present on disk."
                                       : "The file has been deleted, but MuiCache preserves the execution forensic record.") +
                                   " MuiCache entries are created by Windows when displaying program " +
                                   "names in the UI and survive binary deletion.",
                        Detail   = $"Path: {path} | FriendlyName: {friendlyName} | Keyword: {keyword} | Exists: {fileExists}"
                    });
                }
            }
            catch { }

            ctx.Report(0.78, Name, "MuiCache check complete.");
        }, ct);

    private Task CheckRunKeyRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.78, Name, "Scanning Run/RunOnce keys for Hearthstone bot persistence...");

            var runKeys = new[]
            {
                (Registry.LocalMachine, RunKeyLm),
                (Registry.CurrentUser,  RunKeyHkcu),
                (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
            };

            foreach (var (hive, subKeyPath) in runKeys)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var key = hive.OpenSubKey(subKeyPath, writable: false);
                    if (key is null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        var value = key.GetValue(valueName) as string ?? "";
                        var combined = valueName + " " + value;

                        var keyword = RunKeyCheatNames.FirstOrDefault(k =>
                            combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (keyword is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Run Key: Hearthstone Bot Autostart — {valueName}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"{(hive == Registry.LocalMachine ? "HKLM" : "HKCU")}\{subKeyPath}",
                            Reason   = $"Registry Run key entry '{valueName}' references Hearthstone " +
                                       $"bot/cheat keyword '{keyword}'. Value: '{value}'. " +
                                       "This indicates the bot was configured for automatic startup " +
                                       "with Windows — bots require this to resume farming automatically " +
                                       "after reboots or client restarts without user intervention.",
                            Detail   = $"ValueName: {valueName} | Value: {value} | Keyword: {keyword}"
                        });
                    }
                }
                catch { }
            }

            ctx.Report(0.84, Name, "Run key check complete.");
        }, ct);

    private Task CheckBotConfigFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.84, Name, "Scanning for Hearthstone bot configuration files...");

            var configExtensions = new[] { ".cfg", ".ini", ".json", ".yaml", ".yml", ".xml", ".conf", ".txt" };

            var searchDirs = new[]
            {
                Desktop,
                Downloads,
                Documents,
                TempPath,
                Path.Combine(UserProfile, "HSBot"),
                Path.Combine(UserProfile, "HearthBot"),
                Path.Combine(UserProfile, "HSFarm"),
                Path.Combine(UserProfile, "HearthFarm"),
                Path.Combine(AppData, "Stonebot"),
                Path.Combine(AppData, "Innkeeper"),
                Path.Combine(AppData, "SilverFishBot"),
                Path.Combine(AppData, "HearthBot"),
                Path.Combine(AppData, "HSBot"),
                Path.Combine(LocalAppData, "Stonebot"),
                Path.Combine(LocalAppData, "Innkeeper"),
                Path.Combine(LocalAppData, "HearthBot"),
                Path.Combine(LocalAppData, "HSBot"),
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);
                        var ext = Path.GetExtension(fileName);

                        if (!configExtensions.Any(e => e.Equals(ext, StringComparison.OrdinalIgnoreCase)))
                            continue;

                        if (!fileName.Contains("hs", StringComparison.OrdinalIgnoreCase) &&
                            !fileName.Contains("hearth", StringComparison.OrdinalIgnoreCase) &&
                            !fileName.Contains("bot", StringComparison.OrdinalIgnoreCase) &&
                            !fileName.Contains("farm", StringComparison.OrdinalIgnoreCase) &&
                            !fileName.Contains("grind", StringComparison.OrdinalIgnoreCase) &&
                            !fileName.Contains("config", StringComparison.OrdinalIgnoreCase) &&
                            !fileName.Contains("settings", StringComparison.OrdinalIgnoreCase)) continue;

                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);

                            int keywordHits = BotConfigKeywords.Count(k =>
                                content.Contains(k, StringComparison.OrdinalIgnoreCase));

                            if (keywordHits < 2) continue;

                            var matchedKeywords = BotConfigKeywords
                                .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                                .Take(5)
                                .ToList();

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Hearthstone Bot Config File: {fileName}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason   = $"Configuration file '{fileName}' contains {keywordHits} known " +
                                           "Hearthstone bot configuration keywords including bot mode, " +
                                           "deck selection, class selection, auto-play, and farming mode " +
                                           "settings. This file is characteristic of Hearthstone bot " +
                                           "configuration from tools like Stonebot, Innkeeper, " +
                                           "SilverFishBot, or custom bot frameworks.",
                                Detail   = $"Keywords: {string.Join(", ", matchedKeywords)} | Hits: {keywordHits} | Path: {file}"
                            });
                        }
                        catch (IOException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            ctx.Report(0.9, Name, "Bot config file scan complete.");
        }, ct);

    private Task CheckTempFolderArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.9, Name, "Scanning temp folders for Hearthstone cheat artifacts...");

            var cheatTempKeywords = new[]
            {
                "hs_bot",
                "hsbot",
                "hearthbot",
                "hearth_bot",
                "hearthstone_bot",
                "innkeeper",
                "stonebot",
                "trackerbot",
                "silverfishbot",
                "hsfarmer",
                "hs_farmer",
                "hearthfarmer",
                "hdtcheat",
                "hdt_cheat",
                "hs_packet",
                "hs_mitm",
                "hs_proxy",
                "hs_unlocker",
                "hs_dust",
                "hearthstone_unlocker",
                "hs_replay_hack",
                "hearthstone_cheat",
                "hs_grinder",
                "hs_farm",
                "hs_afk",
                "hearthstone_afk",
                "hs_rank_bot",
                "hs_arena_bot",
                "hs_quest_bot",
            };

            var tempDirs = new[]
            {
                TempPath,
                Path.Combine(LocalAppData, "Temp"),
                Path.Combine(UserProfile, "AppData", "LocalLow", "Temp"),
            };

            foreach (var tempDir in tempDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(tempDir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(tempDir, "*", SearchOption.TopDirectoryOnly))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);

                        var keyword = cheatTempKeywords.FirstOrDefault(k =>
                            fileName.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (keyword is null) continue;

                        var ext = Path.GetExtension(fileName).ToLowerInvariant();
                        if (ext != ".exe" && ext != ".dll" && ext != ".zip" && ext != ".rar" &&
                            ext != ".7z" && ext != ".cfg" && ext != ".ini" && ext != ".log" &&
                            ext != ".py" && ext != ".js" && ext != ".ahk" && ext != ".bat" &&
                            ext != ".ps1" && ext != ".tmp" && ext != ".json") continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Hearthstone Cheat Artifact in Temp: {fileName}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"File '{fileName}' in temporary folder matches Hearthstone cheat " +
                                       $"or bot artifact keyword '{keyword}'. Bot tools frequently " +
                                       "extract temporary files, logs, or configuration to the system " +
                                       "temp directory during operation or installation. This artifact " +
                                       "indicates recent Hearthstone cheat or bot activity.",
                            Detail   = $"Keyword: {keyword} | Path: {file}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }

            ctx.Report(0.95, Name, "Temp folder scan complete.");
        }, ct);

    private Task CheckHearthstoneDirectoryArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.95, Name, "Checking for Hearthstone bot/cheat installation directories...");

            var suspiciousDirectoryNames = new[]
            {
                "stonebot",
                "stone_bot",
                "innkeeper_bot",
                "innkeeperbot",
                "silverfishbot",
                "silverfish_bot",
                "hearthbot",
                "hearth_bot",
                "hs_bot",
                "hsbot",
                "hearthfarm",
                "hearth_farm",
                "hs_farm",
                "hsfarm",
                "hearthgrinder",
                "hearth_grinder",
                "hs_grinder",
                "hsgrinder",
                "hearthstone_bot",
                "hearthstone_cheat",
                "hearthstone_hack",
                "hs_cheat",
                "hscheat",
                "hs_hack",
                "hshack",
                "hdt_cheat",
                "hdtcheat",
                "hs_mitm",
                "hsmitm",
                "hs_proxy",
                "hsproxy",
                "hs_packet_inject",
                "hs_unlocker",
                "hsunlocker",
                "hs_dust_hack",
                "hs_rank_bot",
                "hs_arena_bot",
                "hs_quest_bot",
                "hearthstone_afk",
                "hs_afk_bot",
                "trackerbot",
                "tracker_bot",
            };

            var searchRoots = new[]
            {
                UserProfile,
                "C:\\",
                "D:\\",
            };

            foreach (var root in searchRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                try
                {
                    foreach (var dir in Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly))
                    {
                        if (ct.IsCancellationRequested) return;
                        var dirName = Path.GetFileName(dir);

                        var match = suspiciousDirectoryNames.FirstOrDefault(n =>
                            dirName.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (match is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Hearthstone Bot/Cheat Directory Found: {dirName}",
                            Risk     = RiskLevel.Critical,
                            Location = dir,
                            FileName = dirName,
                            Reason   = $"Directory '{dirName}' at '{dir}' matches a known Hearthstone " +
                                       $"bot or cheat tool installation directory name '{match}'. " +
                                       "Hearthstone bots (Stonebot, Innkeeper, SilverFishBot, custom " +
                                       "Python/JS bots) install to named directories containing their " +
                                       "executable, configuration, and log files. The presence of such " +
                                       "a directory constitutes forensic evidence of bot installation.",
                            Detail   = $"Directory: {dir} | Matched: {match}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            var appDataRoots = new[] { AppData, LocalAppData };
            var appDataBotDirs = new[]
            {
                "Stonebot", "Innkeeper", "SilverFishBot", "HearthBot", "HSBot",
                "HearthFarm", "HSFarm", "HearthGrinder", "HSGrinder",
                "HearthstoneBot", "HearthstoneCheat", "HearthstoneHack",
                "HDTCheat", "HSProxy", "HSMitm", "HSUnlocker",
            };

            foreach (var baseDir in appDataRoots)
            {
                foreach (var botDir in appDataBotDirs)
                {
                    if (ct.IsCancellationRequested) return;
                    var fullPath = Path.Combine(baseDir, botDir);
                    if (!Directory.Exists(fullPath)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Hearthstone Bot AppData Directory: {botDir}",
                        Risk     = RiskLevel.Critical,
                        Location = fullPath,
                        FileName = botDir,
                        Reason   = $"Hearthstone bot/cheat application data directory '{botDir}' found " +
                                   $"at '{fullPath}'. Bots and cheat tools commonly use the Windows " +
                                   "AppData folder to store persistent configuration, state, and logs " +
                                   "across sessions. Discovery of this directory indicates that a " +
                                   "Hearthstone bot or cheat tool was installed and configured on this system.",
                        Detail   = $"Directory: {fullPath} | Bot: {botDir}"
                    });
                }
            }

            ctx.Report(1.0, Name, "Hearthstone bot & cheat forensic scan complete.");
        }, ct);
}
