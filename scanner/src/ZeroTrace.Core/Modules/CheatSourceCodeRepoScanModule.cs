using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using System.Text.RegularExpressions;

namespace ZeroTrace.Core.Modules;

public sealed class CheatSourceCodeRepoScanModule : IScanModule
{
    public string Name => "Cheat Source Code Repository Detection";
    public double Weight => 3.8;
    public int ParallelGroup => 4;

    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static readonly string AppData =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string CommonAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

    private static readonly string[] GitRemoteCheatPatterns =
    {
        "cheat", "hack", "aimbot", "esp", "wallhack", "bypass", "inject",
        "trainer", "spoofer", "hwid", "undetected", "ud-", "internal",
        "external", "triggerbot", "bhop", "bunnyhop", "noclip", "godmode",
        "speedhack", "radar_hack", "radar-hack", "chams", "glow",
        "aimware", "skeet", "cs2-cheat", "cs2-internal", "cs2-external",
        "apex-cheat", "apex_cheat", "rust-cheat", "rust_cheat",
        "valorant-cheat", "valorant_cheat", "fivem-cheat", "fivem_cheat",
        "gta5-cheat", "gta5_cheat", "gta-cheat", "gta_cheat",
        "fortnite-cheat", "fortnite_cheat", "pubg-cheat", "pubg_cheat",
        "overwatch-cheat", "overwatch_cheat", "r6-cheat", "r6_cheat",
        "tarkov-cheat", "tarkov_cheat", "dayz-cheat", "dayz_cheat",
        "arma-cheat", "arma_cheat", "warzone-cheat", "warzone_cheat",
        "xdefiant-cheat", "deadlock-cheat", "marvel-rivals-cheat",
        "aimassist", "aim-assist", "aim_assist", "recoil_control",
        "triggerbot", "trigger_bot", "silent_aim", "silentaim",
        "bone_aimbot", "memory_read", "memread", "memhack",
        "no_recoil", "no-recoil", "anti_aim", "anti-aim", "antiaim",
        "ragebot", "legitbot", "vischeck", "vicheck",
        "unlock_all", "unlock-all", "god_mode", "god-mode",
        "skin_changer", "skin-changer", "knife_changer",
        "rank_booster", "rank-boost", "stat_manipulate",
        "packet_cheat", "lagswitch", "lag_switch",
        "knifebot", "rapidfire", "bunnybot",
    };

    private static readonly string[] KnownCheatRepoNames =
    {
        "cs2-cheat", "cs2-internal", "cs2-external", "cs2-esp", "cs2-aimbot",
        "csgo-cheat", "csgo-internal", "csgo-external", "csgo-esp",
        "apex-cheat", "apex-legends-cheat", "apex-internal", "apex-external",
        "rust-cheat", "rust-internal", "rust-external", "rust-esp",
        "valorant-cheat", "valorant-internal", "valorant-external",
        "fivem-cheat", "fivem-internal", "fivem-external",
        "gta5-cheat", "gta-v-cheat", "gtav-cheat",
        "fortnite-cheat", "fortnite-internal", "fortnite-external",
        "pubg-cheat", "pubg-external",
        "tarkov-cheat", "tarkov-esp",
        "overwatch-cheat", "ow-cheat",
        "warzone-cheat", "warzone-esp",
        "battlefront-cheat", "bf2042-cheat",
        "dayz-cheat", "dayz-esp",
        "r6-cheat", "r6s-cheat", "rainbow-six-cheat",
        "deadlock-cheat", "deadlock-esp",
        "marvel-rivals-cheat",
        "aimbot-source", "esp-source", "wallhack-source",
        "internal-cheat", "external-cheat",
        "game-hack", "game-cheat",
        "ud-hack", "undetected-hack",
        "hwid-spoofer", "hwid-ban-bypass",
        "eac-bypass", "easyanticheat-bypass",
        "be-bypass", "battleye-bypass",
        "vac-bypass", "vacnet-bypass",
        "ricochet-bypass",
        "anticheat-bypass",
        "driver-cheat", "kernel-cheat",
    };

    private static readonly string[] CheatIncludeHeaders =
    {
        "minhook.h",
        "MinHook.h",
        "cheat_headers",
        "game_sdk",
        "offsets.h",
        "offsets.hpp",
        "sdk.h",
        "game_offsets.h",
        "game_offsets.hpp",
        "entity.h",
        "entity_list.h",
        "c_baseentity.h",
        "c_baseplayer.h",
        "c_basecombatcharacter.h",
        "input.h",
        "bones.h",
        "bone_setup.h",
        "renderer.h",
        "imgui_impl_dx",
        "esp.h",
        "aimbot.h",
        "features.h",
        "triggerbot.h",
        "bhop.h",
        "visuals.h",
        "aim.h",
        "weapon_data.h",
        "game_data.h",
        "interfaces.h",
        "netvars.h",
        "networkvars.h",
        "hazedumper",
        "cs2dumper",
        "mempattern.h",
        "pattern.h",
        "scanner.hpp",
        "read_write.h",
        "process.h",
        "memory.hpp",
        "reclass",
        "INetChannelInfo",
        "CEngineClient",
        "IBaseClientDLL",
        "IClientEntity",
        "ICvar",
    };

    private static readonly string[] GameSdkDirectoryPatterns =
    {
        "csgo_sdk", "cs2_sdk", "cs_sdk",
        "apex_sdk", "apex-sdk",
        "valorant_sdk", "valorant-sdk",
        "rust_sdk", "rust-sdk",
        "gta5_sdk", "gtav_sdk", "gta_sdk",
        "fortnite_sdk", "fn_sdk",
        "pubg_sdk",
        "game_sdk", "game-sdk",
        "cheat_sdk", "hack_sdk",
        "offsetdumper", "offset_dumper",
        "cs2dumper", "hazedumper",
        "game_offsets",
    };

    private static readonly string[] OffsetFileNames =
    {
        "offsets.hpp", "offsets.h", "offsets.cs", "offsets.py",
        "offsets.json", "offsets.js", "offsets.lua", "offsets.txt",
        "game_offsets.h", "game_offsets.hpp",
        "client.dll.json", "server.dll.json",
        "output.json",
        "buttons.json", "interfaces.json",
        "netvars.json", "networkvars.json",
        "cs2_offsets.json", "csgo_offsets.json",
        "apex_offsets.h", "valorant_offsets.h",
        "offsets_generated.h",
        "hazedumper.json",
        "dumper_output.json",
    };

    private static readonly string[] PdbCheatPatterns =
    {
        "cheat.pdb", "hack.pdb", "aimbot.pdb", "esp.pdb",
        "internal.pdb", "external.pdb", "wallhack.pdb",
        "triggerbot.pdb", "bhop.pdb", "spoofer.pdb",
        "loader.pdb", "injector.pdb", "bypass.pdb",
        "trainer.pdb", "radar.pdb", "chams.pdb",
        "silentaim.pdb", "ragebot.pdb", "legitbot.pdb",
        "hwid.pdb", "unlocker.pdb", "skinhack.pdb",
    };

    private static readonly string[] ProtectionToolProjectFiles =
    {
        "themida",
        "vmprotect",
        "enigma_protector",
        "enigmaprotector",
        "obsidium",
        "asprotect",
        "pecompact",
        "mpress",
        "upx_loader",
        "molebox",
        "armadillo",
    };

    private static readonly Regex HexAddressRegex =
        new(@"0x[0-9A-Fa-f]{4,}", RegexOptions.Compiled);

    private static readonly Regex DiscordWebhookRegex =
        new(@"discord\.com/api/webhooks/\d+/", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex AuthServerRegex =
        new(@"https?://[a-z0-9\-\.]+/(?:auth|login|verify|validate|hwid|license|check)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ScanGitRepositoriesAsync(ctx, ct);
        ctx.Report(0.30, "Git repos", "Git repository cheat source scan complete");

        await ScanVisualStudioProjectsAsync(ctx, ct);
        ctx.Report(0.52, "VS projects", "Visual Studio project cheat scan complete");

        await ScanOffsetFilesAsync(ctx, ct);
        ctx.Report(0.66, "Offset files", "Game offset file scan complete");

        await ScanPdbFilesAsync(ctx, ct);
        ctx.Report(0.76, "PDB files", "Cheat PDB symbol file scan complete");

        ScanGameSdkDirectories(ctx, ct);
        ctx.Report(0.86, "Game SDKs", "Game SDK directory scan complete");

        await ScanCompiledCheatBuildOutputAsync(ctx, ct);
        ctx.Report(0.94, "Build output", "Cheat build output artifact scan complete");

        await ScanCheatLoaderSourceAsync(ctx, ct);
        ctx.Report(1.00, "Loader source", "Cheat loader source artifact scan complete");
    }

    private async Task ScanGitRepositoriesAsync(ScanContext ctx, CancellationToken ct)
    {
        var gitSearchRoots = BuildSearchRoots();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var root in gitSearchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;
            if (!visited.Add(root)) continue;

            await FindAndScanGitReposAsync(root, ctx, ct, depth: 0, maxDepth: 6);
        }
    }

    private static IEnumerable<string> BuildSearchRoots()
    {
        var roots = new List<string>
        {
            Path.Combine(UserProfile, "Desktop"),
            Path.Combine(UserProfile, "Documents"),
            Path.Combine(UserProfile, "Downloads"),
            Path.Combine(UserProfile, "source"),
            Path.Combine(UserProfile, "repos"),
            Path.Combine(UserProfile, "projects"),
            Path.Combine(UserProfile, "dev"),
            Path.Combine(UserProfile, "code"),
            Path.Combine(UserProfile, "git"),
            Path.Combine(UserProfile, "GitHub"),
            Path.Combine(UserProfile, "GitLab"),
            AppData,
            LocalAppData,
            CommonAppData,
        };

        foreach (var drive in DriveInfo.GetDrives()
            .Where(d => d.DriveType == DriveType.Fixed && d.IsReady))
        {
            roots.Add(drive.RootDirectory.FullName);
        }

        return roots.Where(r => !string.IsNullOrEmpty(r)).Distinct(StringComparer.OrdinalIgnoreCase);
    }

    private async Task FindAndScanGitReposAsync(
        string dir, ScanContext ctx, CancellationToken ct, int depth, int maxDepth)
    {
        if (depth > maxDepth) return;
        ct.ThrowIfCancellationRequested();

        var gitDir = Path.Combine(dir, ".git");
        if (Directory.Exists(gitDir))
        {
            ctx.IncrementFiles();
            await CheckGitRepoForCheatSourceAsync(dir, gitDir, ctx, ct);
            return;
        }

        IEnumerable<string> subdirs;
        try { subdirs = Directory.EnumerateDirectories(dir); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var sub in subdirs)
        {
            ct.ThrowIfCancellationRequested();
            await FindAndScanGitReposAsync(sub, ctx, ct, depth + 1, maxDepth);
        }
    }

    private async Task CheckGitRepoForCheatSourceAsync(
        string repoRoot, string gitDir, ScanContext ctx, CancellationToken ct)
    {
        var repoName = Path.GetFileName(repoRoot).ToLowerInvariant();

        var repoNameMatch = KnownCheatRepoNames.FirstOrDefault(r =>
            repoName.Equals(r, StringComparison.OrdinalIgnoreCase) ||
            repoName.Contains(r, StringComparison.OrdinalIgnoreCase));

        if (repoNameMatch is not null)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Known cheat repository directory: {Path.GetFileName(repoRoot)}",
                Risk = RiskLevel.Critical,
                Location = repoRoot,
                FileName = repoName,
                Reason = "The directory name matches a known cheat repository naming pattern. " +
                         "These repositories are commonly found on GitHub/GitLab containing " +
                         "cheat source code, compiled cheats, or cheat loaders.",
                Detail = $"Matched repo pattern: '{repoNameMatch}'"
            });
        }

        var configPath = Path.Combine(gitDir, "config");
        if (File.Exists(configPath))
        {
            await CheckGitConfigForCheatRemotesAsync(configPath, repoRoot, ctx, ct);
        }

        var commitMsgPath = Path.Combine(gitDir, "COMMIT_EDITMSG");
        if (File.Exists(commitMsgPath))
        {
            await CheckGitCommitMessageAsync(commitMsgPath, repoRoot, ctx, ct);
        }

        var descriptionPath = Path.Combine(gitDir, "description");
        if (File.Exists(descriptionPath))
        {
            await CheckGitDescriptionAsync(descriptionPath, repoRoot, ctx, ct);
        }
    }

    private async Task CheckGitConfigForCheatRemotesAsync(
        string configPath, string repoRoot, ScanContext ctx, CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(configPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException) { return; }

        if (string.IsNullOrWhiteSpace(content)) return;

        var lower = content.ToLowerInvariant();

        var matchedPattern = GitRemoteCheatPatterns.FirstOrDefault(p =>
            lower.Contains(p, StringComparison.OrdinalIgnoreCase));

        if (matchedPattern is null) return;

        var urlLine = content
            .Split('\n')
            .FirstOrDefault(l => l.TrimStart().StartsWith("url", StringComparison.OrdinalIgnoreCase) &&
                                  l.ToLowerInvariant().Contains(matchedPattern));

        ctx.AddFinding(new Finding
        {
            Module = Name,
            Title = $"Cheat source code git remote: {Path.GetFileName(repoRoot)}",
            Risk = RiskLevel.Critical,
            Location = repoRoot,
            FileName = ".git/config",
            Reason = "The git repository's remote URL contains cheat-related keywords. " +
                     "This indicates the repository was cloned from a cheat source code host " +
                     "(GitHub, GitLab, Gitea, or private server). Pattern matched: '" + matchedPattern + "'.",
            Detail = string.IsNullOrEmpty(urlLine)
                ? $"Matched pattern: '{matchedPattern}'"
                : $"Remote URL line: {Truncate(urlLine.Trim(), 200)}"
        });
    }

    private static async Task CheckGitCommitMessageAsync(
        string commitMsgPath, string repoRoot, ScanContext ctx, CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(commitMsgPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException) { return; }

        if (string.IsNullOrWhiteSpace(content) || content.Length < 5) return;

        var lower = content.ToLowerInvariant();

        var matchedPattern = GitRemoteCheatPatterns.FirstOrDefault(p =>
            lower.Contains(p, StringComparison.OrdinalIgnoreCase));

        if (matchedPattern is null) return;

        ctx.AddFinding(new Finding
        {
            Module = "Cheat Source Code Repository Detection",
            Title = $"Cheat development commit message: {Path.GetFileName(repoRoot)}",
            Risk = RiskLevel.High,
            Location = repoRoot,
            FileName = "COMMIT_EDITMSG",
            Reason = "The most recent git commit message in this repository contains keywords " +
                     "associated with cheat development. Suggests active cheat source modification.",
            Detail = $"Commit: {Truncate(content.Trim(), 200)} | Matched: '{matchedPattern}'"
        });
    }

    private static async Task CheckGitDescriptionAsync(
        string descPath, string repoRoot, ScanContext ctx, CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(descPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException) { return; }

        if (string.IsNullOrWhiteSpace(content)) return;

        if (content.Contains("Unnamed repository", StringComparison.OrdinalIgnoreCase)) return;

        var lower = content.ToLowerInvariant();
        var matchedPattern = GitRemoteCheatPatterns.FirstOrDefault(p =>
            lower.Contains(p, StringComparison.OrdinalIgnoreCase));

        if (matchedPattern is null) return;

        ctx.AddFinding(new Finding
        {
            Module = "Cheat Source Code Repository Detection",
            Title = $"Cheat repository description: {Path.GetFileName(repoRoot)}",
            Risk = RiskLevel.High,
            Location = repoRoot,
            FileName = ".git/description",
            Reason = "The git repository description file describes cheat-related content.",
            Detail = $"Description: {Truncate(content.Trim(), 200)}"
        });
    }

    private async Task ScanVisualStudioProjectsAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = BuildSearchRoots();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int projectsScanned = 0;
        const int MaxProjects = 500;

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;
            if (!visited.Add(root)) continue;
            if (projectsScanned >= MaxProjects) break;

            IEnumerable<string> projectFiles;
            try
            {
                projectFiles = Directory.EnumerateFiles(root, "*.sln", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(root, "*.vcxproj", SearchOption.AllDirectories))
                    .Concat(Directory.EnumerateFiles(root, "*.csproj", SearchOption.AllDirectories))
                    .Concat(Directory.EnumerateFiles(root, "*.rcnet", SearchOption.AllDirectories));
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var projectFile in projectFiles)
            {
                ct.ThrowIfCancellationRequested();
                if (++projectsScanned > MaxProjects) break;

                ctx.IncrementFiles();
                await CheckVisualStudioProjectFileAsync(projectFile, ctx, ct);
            }
        }
    }

    private async Task CheckVisualStudioProjectFileAsync(string path, ScanContext ctx, CancellationToken ct)
    {
        var fileName = Path.GetFileName(path);
        var fileNameLow = fileName.ToLowerInvariant();
        var ext = Path.GetExtension(path).ToLowerInvariant();

        if (ext == ".rcnet")
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"ReClass.NET project file: {fileName}",
                Risk = RiskLevel.High,
                Location = path,
                FileName = fileName,
                Reason = "A ReClass.NET project file was found. ReClass.NET is a game memory " +
                         "reverse engineering tool used to map game structures (entities, players, " +
                         "weapons) for cheat development. Its presence alongside other cheat artifacts " +
                         "indicates active cheat reverse engineering work.",
                Detail = $"Path: {path}"
            });
            return;
        }

        var cheatNameMatch = GitRemoteCheatPatterns.FirstOrDefault(p =>
            fileNameLow.Contains(p, StringComparison.OrdinalIgnoreCase));

        bool hasSuspiciousName = cheatNameMatch is not null;

        string content;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException) { return; }

        if (string.IsNullOrWhiteSpace(content)) return;

        var matchedIncludes = CheatIncludeHeaders
            .Where(h => content.Contains(h, StringComparison.OrdinalIgnoreCase))
            .Take(6)
            .ToList();

        var matchedProtectionTools = ProtectionToolProjectFiles
            .Where(t => content.Contains(t, StringComparison.OrdinalIgnoreCase))
            .Take(3)
            .ToList();

        bool hasDiscordWebhook = DiscordWebhookRegex.IsMatch(content);
        bool hasAuthServer = AuthServerRegex.IsMatch(content);

        if (hasSuspiciousName && matchedIncludes.Count == 0 && matchedProtectionTools.Count == 0
            && !hasDiscordWebhook && !hasAuthServer) return;

        if (matchedIncludes.Count >= 2)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Cheat project file with game SDK headers: {fileName}",
                Risk = RiskLevel.Critical,
                Location = path,
                FileName = fileName,
                Reason = "A Visual Studio project file references multiple cheat-related header files " +
                         "(game SDK, hook libraries, offset headers). These headers are used in cheat " +
                         "development to interface with game internals via memory reading/writing.",
                Detail = "Matched includes: " + string.Join(", ", matchedIncludes)
            });
        }
        else if (hasSuspiciousName)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Cheat-named Visual Studio project: {fileName}",
                Risk = RiskLevel.High,
                Location = path,
                FileName = fileName,
                Reason = "A Visual Studio project or solution file has a name matching cheat-related " +
                         "patterns. Project names like 'aimbot.vcxproj' or 'cs2-cheat.sln' directly " +
                         "indicate cheat source code development.",
                Detail = $"Matched name pattern: '{cheatNameMatch}'"
            });
        }

        if (matchedProtectionTools.Count > 0)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Obfuscation/protection tool in project: {fileName}",
                Risk = RiskLevel.High,
                Location = path,
                FileName = fileName,
                Reason = "A Visual Studio project references commercial obfuscation tools " +
                         "(Themida, VMProtect, Enigma Protector) in a context with cheat-related content. " +
                         "Cheat sellers use these tools to protect their software from reverse engineering " +
                         "and signature detection.",
                Detail = "Protection tools referenced: " + string.Join(", ", matchedProtectionTools)
            });
        }

        if (hasDiscordWebhook)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Discord webhook exfiltration in project source: {fileName}",
                Risk = RiskLevel.Critical,
                Location = path,
                FileName = fileName,
                Reason = "A project file or source contains a Discord webhook URL. Cheat loaders and " +
                         "sellers embed Discord webhooks to exfiltrate buyer HWID, system information, " +
                         "and usage telemetry. This is a common pattern in commercial cheat software.",
                Detail = "Discord webhook URL pattern detected in project content"
            });
        }

        if (hasAuthServer)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Authentication server URL in cheat project: {fileName}",
                Risk = RiskLevel.High,
                Location = path,
                FileName = fileName,
                Reason = "A project file references an authentication, HWID-check, or license " +
                         "validation server URL. Cheat software commonly implements HWID-based " +
                         "authentication to prevent sharing and to collect user system fingerprints.",
                Detail = "Auth server URL pattern detected in project content"
            });
        }
    }

    private async Task ScanOffsetFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = BuildSearchRoots();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int filesScanned = 0;
        const int MaxFiles = 500;

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;
            if (!visited.Add(root)) continue;
            if (filesScanned >= MaxFiles) break;

            foreach (var offsetFileName in OffsetFileNames)
            {
                IEnumerable<string> found;
                try
                {
                    found = Directory.EnumerateFiles(root, offsetFileName, SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var filePath in found)
                {
                    ct.ThrowIfCancellationRequested();
                    if (++filesScanned > MaxFiles) break;
                    ctx.IncrementFiles();

                    await CheckOffsetFileAsync(filePath, ctx, ct);
                }
            }
        }
    }

    private static async Task CheckOffsetFileAsync(string path, ScanContext ctx, CancellationToken ct)
    {
        var fileName = Path.GetFileName(path);

        if (path.Contains("\\node_modules\\", StringComparison.OrdinalIgnoreCase)) return;
        if (path.Contains("\\vendor\\", StringComparison.OrdinalIgnoreCase)) return;

        string content;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException) { return; }

        if (string.IsNullOrWhiteSpace(content)) return;

        var hexMatches = HexAddressRegex.Matches(content);

        bool isClientDll = fileName.Equals("client.dll.json", StringComparison.OrdinalIgnoreCase) ||
                           fileName.Equals("server.dll.json", StringComparison.OrdinalIgnoreCase);
        bool isHazedumper = fileName.Equals("output.json", StringComparison.OrdinalIgnoreCase) &&
                            (content.Contains("\"netvars\"", StringComparison.OrdinalIgnoreCase) ||
                             content.Contains("\"signatures\"", StringComparison.OrdinalIgnoreCase));
        bool isOffsetsJson = fileName.EndsWith("offsets.json", StringComparison.OrdinalIgnoreCase) ||
                             fileName.Equals("hazedumper.json", StringComparison.OrdinalIgnoreCase);

        if (isClientDll || isHazedumper)
        {
            ctx.AddFinding(new Finding
            {
                Module = "Cheat Source Code Repository Detection",
                Title = $"Game binary analysis dump: {fileName}",
                Risk = RiskLevel.Critical,
                Location = path,
                FileName = fileName,
                Reason = isClientDll
                    ? "A game binary JSON dump (client.dll.json/server.dll.json) was found. These " +
                      "files are output from IDA Pro, Ghidra, or cs2dumper/hazedumper game analysis " +
                      "tools and contain memory offsets for every game class and netvar. They are " +
                      "the primary input for writing game-specific cheats."
                    : "A hazedumper/cs2dumper output file was found containing game memory signatures " +
                      "and netvars. This is direct evidence of game binary analysis for cheat development.",
                Detail = $"File size: {content.Length} chars · Hex addresses found: {hexMatches.Count}"
            });
            return;
        }

        if (hexMatches.Count >= 15)
        {
            ctx.AddFinding(new Finding
            {
                Module = "Cheat Source Code Repository Detection",
                Title = $"Game memory offset file with {hexMatches.Count} addresses: {fileName}",
                Risk = RiskLevel.High,
                Location = path,
                FileName = fileName,
                Reason = $"An offset file was found containing {hexMatches.Count} hexadecimal memory " +
                         "addresses. Files named 'offsets.h', 'offsets.json' etc. that contain large " +
                         "numbers of hex addresses are the output of game memory analysis tools and " +
                         "are required for writing game-specific memory cheats.",
                Detail = $"Hex address count: {hexMatches.Count} · " +
                         $"First few: {string.Join(", ", hexMatches.Cast<Match>().Take(5).Select(m => m.Value))}"
            });
        }
    }

    private async Task ScanPdbFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = BuildSearchRoots();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int scanned = 0;
        const int Max = 1000;

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;
            if (!visited.Add(root)) continue;
            if (scanned >= Max) break;

            IEnumerable<string> pdbFiles;
            try
            {
                pdbFiles = Directory.EnumerateFiles(root, "*.pdb", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var pdbPath in pdbFiles)
            {
                ct.ThrowIfCancellationRequested();
                if (++scanned > Max) break;
                ctx.IncrementFiles();

                var pdbName = Path.GetFileName(pdbPath);
                var pdbNameLow = pdbName.ToLowerInvariant();

                var exactPdbMatch = PdbCheatPatterns.FirstOrDefault(p =>
                    pdbNameLow.Equals(p, StringComparison.OrdinalIgnoreCase));

                if (exactPdbMatch is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cheat PDB symbol file: {pdbName}",
                        Risk = RiskLevel.Critical,
                        Location = pdbPath,
                        FileName = pdbName,
                        Reason = "A PDB debug symbol file with a name matching a known cheat binary was " +
                                 "found. PDB files are generated during compilation and contain debug " +
                                 "symbols for the compiled binary. Their presence proves local compilation " +
                                 "of the cheat rather than just downloading it.",
                        Detail = $"PDB file: {pdbPath}"
                    });
                    continue;
                }

                var fragMatch = GitRemoteCheatPatterns.FirstOrDefault(p =>
                    pdbNameLow.Contains(p, StringComparison.OrdinalIgnoreCase));

                if (fragMatch is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cheat-named PDB symbol file: {pdbName}",
                        Risk = RiskLevel.High,
                        Location = pdbPath,
                        FileName = pdbName,
                        Reason = "A PDB debug symbol file has a name matching cheat-related patterns. " +
                                 "This suggests local compilation of cheat source code.",
                        Detail = $"Matched pattern: '{fragMatch}' · Path: {pdbPath}"
                    });
                }
            }
        }
    }

    private void ScanGameSdkDirectories(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = BuildSearchRoots();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;
            if (!visited.Add(root)) continue;

            IEnumerable<string> dirs;
            try
            {
                dirs = Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var dir in dirs)
            {
                ct.ThrowIfCancellationRequested();

                var dirName = Path.GetFileName(dir).ToLowerInvariant();

                var sdkMatch = GameSdkDirectoryPatterns.FirstOrDefault(p =>
                    dirName.Equals(p, StringComparison.OrdinalIgnoreCase) ||
                    dirName.Contains(p, StringComparison.OrdinalIgnoreCase));

                if (sdkMatch is null) continue;

                bool isUnderGameInstall =
                    dir.Contains("\\steamapps\\", StringComparison.OrdinalIgnoreCase) ||
                    dir.Contains("\\EpicGames\\", StringComparison.OrdinalIgnoreCase) ||
                    dir.Contains("\\Ubisoft Game Launcher\\", StringComparison.OrdinalIgnoreCase);

                if (isUnderGameInstall) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Game SDK/offset directory: {Path.GetFileName(dir)}",
                    Risk = RiskLevel.High,
                    Location = dir,
                    FileName = Path.GetFileName(dir),
                    Reason = "A directory matching a game SDK or offset dumper naming pattern was found " +
                             "outside the game's installation directory. Game SDK directories contain " +
                             "game class headers, memory offset definitions, and interface declarations " +
                             "that are used as the foundation for writing game-specific cheats.",
                    Detail = $"Matched SDK pattern: '{sdkMatch}'"
                });
            }
        }
    }

    private async Task ScanCompiledCheatBuildOutputAsync(ScanContext ctx, CancellationToken ct)
    {
        var buildOutputPatterns = new[]
        {
            Path.Combine("build", "Release"),
            Path.Combine("build", "Debug"),
            Path.Combine("x64", "Release"),
            Path.Combine("x64", "Debug"),
            Path.Combine("x86", "Release"),
            Path.Combine("Release"),
            Path.Combine("bin", "Release"),
            Path.Combine("bin", "x64"),
            Path.Combine("out", "Release"),
        };

        var searchRoots = BuildSearchRoots();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int dirsScanned = 0;
        const int MaxDirs = 300;

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;
            if (!visited.Add(root)) continue;
            if (dirsScanned >= MaxDirs) break;

            foreach (var buildPattern in buildOutputPatterns)
            {
                IEnumerable<string> buildDirs;
                try
                {
                    buildDirs = Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories)
                        .Where(d =>
                        {
                            var rel = d[root.Length..].TrimStart(Path.DirectorySeparatorChar);
                            return rel.EndsWith(buildPattern, StringComparison.OrdinalIgnoreCase);
                        });
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var buildDir in buildDirs)
                {
                    ct.ThrowIfCancellationRequested();
                    if (++dirsScanned > MaxDirs) break;

                    var parentDir = Path.GetDirectoryName(Path.GetDirectoryName(buildDir)) ?? buildDir;
                    var parentName = Path.GetFileName(parentDir).ToLowerInvariant();

                    bool parentIsCheatProject = GitRemoteCheatPatterns.Any(p =>
                        parentName.Contains(p, StringComparison.OrdinalIgnoreCase));

                    if (!parentIsCheatProject) continue;

                    IEnumerable<string> outputFiles;
                    try
                    {
                        outputFiles = Directory.EnumerateFiles(buildDir)
                            .Where(f =>
                            {
                                var ext = Path.GetExtension(f).ToLowerInvariant();
                                return ext == ".exe" || ext == ".dll" || ext == ".sys";
                            });
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var outputFile in outputFiles)
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();

                        var outputFileName = Path.GetFileName(outputFile);
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Compiled cheat binary in build output: {outputFileName}",
                            Risk = RiskLevel.Critical,
                            Location = outputFile,
                            FileName = outputFileName,
                            Reason = "A compiled binary (EXE/DLL/SYS) was found in a build output " +
                                     "directory of a project with a cheat-related name. Build output " +
                                     "directories in cheat project folders are a direct artifact of " +
                                     "local cheat compilation.",
                            Detail = $"Build directory: {buildDir} · Parent project: {Path.GetFileName(parentDir)}"
                        });
                    }

                    IEnumerable<string> objFiles;
                    try
                    {
                        objFiles = Directory.EnumerateFiles(buildDir, "*.obj")
                            .Take(5);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    var objList = objFiles.ToList();
                    if (objList.Count > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Intermediate object files in cheat build dir: {Path.GetFileName(buildDir)}",
                            Risk = RiskLevel.High,
                            Location = buildDir,
                            FileName = Path.GetFileName(buildDir),
                            Reason = "Intermediate compiler object files (.obj) were found in a build " +
                                     "directory of a cheat-named project. These files are produced during " +
                                     "local compilation and confirm active cheat source code development.",
                            Detail = $"Example .obj: {Path.GetFileName(objList[0])} · Count found: {objList.Count}"
                        });
                    }
                }
            }
        }
    }

    private async Task ScanCheatLoaderSourceAsync(ScanContext ctx, CancellationToken ct)
    {
        var sourceExtensions = new[] { ".cpp", ".c", ".cs", ".h", ".hpp", ".rs", ".py", ".lua" };
        var searchRoots = BuildSearchRoots();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int filesScanned = 0;
        const int MaxFiles = 600;

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;
            if (!visited.Add(root)) continue;
            if (filesScanned >= MaxFiles) break;

            IEnumerable<string> sourceFiles;
            try
            {
                sourceFiles = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
                    .Where(f => sourceExtensions.Any(ext =>
                        f.EndsWith(ext, StringComparison.OrdinalIgnoreCase)));
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var sourceFile in sourceFiles)
            {
                ct.ThrowIfCancellationRequested();
                if (++filesScanned > MaxFiles) break;

                var dirPath = Path.GetDirectoryName(sourceFile) ?? "";
                bool inSteamApps = dirPath.Contains("\\steamapps\\", StringComparison.OrdinalIgnoreCase);
                bool inProgramFiles = dirPath.StartsWith(
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    StringComparison.OrdinalIgnoreCase);
                if (inSteamApps || inProgramFiles) continue;

                ctx.IncrementFiles();
                await CheckCheatSourceFileAsync(sourceFile, ctx, ct);
            }
        }
    }

    private async Task CheckCheatSourceFileAsync(string path, ScanContext ctx, CancellationToken ct)
    {
        var fileName = Path.GetFileName(path);
        var fileNameLow = fileName.ToLowerInvariant();

        var licenseCheckerNames = new[]
        {
            "license_check", "hwid_check", "auth.cpp", "auth.h",
            "hwid.cpp", "hwid.h", "keysystem.cpp", "keysystem.h",
            "keyauth.cpp", "keyauth.h", "loader.cpp", "injector.cpp",
            "bypass.cpp", "bypass.h",
        };

        bool isLicenseFile = licenseCheckerNames.Any(n =>
            fileNameLow.Equals(n, StringComparison.OrdinalIgnoreCase));

        string content;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException) { return; }

        if (string.IsNullOrWhiteSpace(content) || content.Length < 50) return;

        bool hasDiscordWebhook = DiscordWebhookRegex.IsMatch(content);
        bool hasAuthServer = AuthServerRegex.IsMatch(content);

        var matchedIncludes = CheatIncludeHeaders
            .Where(h => content.Contains(h, StringComparison.OrdinalIgnoreCase))
            .Take(5)
            .ToList();

        var matchedProtectionRefs = ProtectionToolProjectFiles
            .Where(t => content.Contains(t, StringComparison.OrdinalIgnoreCase))
            .Take(3)
            .ToList();

        var hexAddressCount = HexAddressRegex.Matches(content).Count;

        bool isCheatSource = matchedIncludes.Count >= 2 ||
                             (matchedIncludes.Count >= 1 && hexAddressCount >= 5) ||
                             (isLicenseFile && (hasDiscordWebhook || hasAuthServer));

        if (!isCheatSource) return;

        if (hasDiscordWebhook)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Discord webhook data exfiltration in source: {fileName}",
                Risk = RiskLevel.Critical,
                Location = path,
                FileName = fileName,
                Reason = "Source code file contains a Discord webhook URL. Cheat loaders and " +
                         "authentication systems embed Discord webhooks to silently report buyer HWIDs, " +
                         "system fingerprints, and usage statistics back to the cheat seller. " +
                         "This constitutes spyware behavior in commercial cheat software.",
                Detail = "discord.com/api/webhooks URL detected in source file content"
            });
        }

        if (hasAuthServer && isLicenseFile)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"HWID authentication server in cheat loader source: {fileName}",
                Risk = RiskLevel.High,
                Location = path,
                FileName = fileName,
                Reason = "A source file implementing HWID checking or license validation contains " +
                         "authentication server URLs. This is the authentication component of " +
                         "commercial cheat software that validates the buyer's hardware ID against " +
                         "a remote server before allowing cheat functionality.",
                Detail = "Auth/HWID server URL detected in source file"
            });
        }

        if (matchedIncludes.Count >= 2)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Cheat source file with game SDK references: {fileName}",
                Risk = RiskLevel.Critical,
                Location = path,
                FileName = fileName,
                Reason = "A source code file contains multiple references to cheat development headers " +
                         "and SDK files. These include game-specific class definitions, hook libraries, " +
                         "and memory offset headers that together constitute a cheat implementation.",
                Detail = "Matched SDK/cheat headers: " + string.Join(", ", matchedIncludes) +
                         (hexAddressCount > 0 ? $" · Hex addresses: {hexAddressCount}" : "")
            });
        }

        if (matchedProtectionRefs.Count > 0)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Obfuscation tool referenced in cheat source: {fileName}",
                Risk = RiskLevel.High,
                Location = path,
                FileName = fileName,
                Reason = "A source file references commercial obfuscation/protection tools (Themida, " +
                         "VMProtect, Enigma) in a cheat development context. Cheat sellers use these " +
                         "tools to protect their binaries from AV signature detection and reverse engineering.",
                Detail = "Protection tools: " + string.Join(", ", matchedProtectionRefs)
            });
        }
    }

    private static string Truncate(string s, int max)
        => s.Length <= max ? s : s[..max] + "…";
}
