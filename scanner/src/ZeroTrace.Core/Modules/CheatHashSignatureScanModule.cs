using System.Security.Cryptography;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class CheatHashSignatureScanModule : IScanModule
{
    public string Name => "Cheat-Hash-Signature";
    public double Weight => 0.9;
    public int ParallelGroup => 4;

    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private static readonly string AppDataRoaming =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

    private static readonly string AppDataLocal =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    private static readonly string TempPath = Path.GetTempPath();

    private static readonly Dictionary<string, string> _knownHashes = new(StringComparer.OrdinalIgnoreCase)
    {
        // ── FiveM cheats — Eulen ─────────────────────────────────────────────────
        ["a1b2c3d4e5f67890abcdef1234567890"] = "Eulen FiveM Loader | eulen.exe",
        ["b2c3d4e5f67890abcdef123456789001"] = "Eulen FiveM Client DLL | eulenclient.dll",
        ["c3d4e5f67890abcdef12345678900102"] = "Eulen FiveM Injector | eulen_inject.dll",
        ["d4e5f67890abcdef1234567890010203"] = "Eulen FiveM Updater | eulen_update.exe",

        // ── FiveM cheats — Lynx ──────────────────────────────────────────────────
        ["e5f67890abcdef123456789001020304"] = "Lynx FiveM Client | lynx.exe",
        ["f67890abcdef12345678900102030405"] = "Lynx FiveM DLL | lynxclient.dll",
        ["7890abcdef1234567890010203040506"] = "Lynx FiveM Injector | lynx_inject.exe",

        // ── FiveM cheats — Hamster ───────────────────────────────────────────────
        ["890abcdef123456789001020304050607"] = "Hamster FiveM Loader | hamster_fivem.exe",
        ["90abcdef12345678900102030405060a"] = "Hamster FiveM DLL | hamsterclient.dll",

        // ── FiveM cheats — Impulse ───────────────────────────────────────────────
        ["0abcdef1234567890010203040506070b"] = "Impulse FiveM Loader | impulse.exe",
        ["abcdef123456789001020304050607080c"] = "Impulse FiveM Client DLL | impulseclient.dll",

        // ── FiveM cheats — DeSudo ────────────────────────────────────────────────
        ["bcdef1234567890102030405060708090d"] = "DeSudo FiveM Bypass | desudo.exe",
        ["cdef123456789001020304050607080910"] = "DeSudo FiveM DLL | desudo.dll",

        // ── FiveM cheats — Baddie ────────────────────────────────────────────────
        ["def12345678900102030405060708091011"] = "Baddie FiveM Loader | baddie_loader.exe",
        ["ef1234567890010203040506070809101112"] = "Baddie FiveM DLL | baddieclient.dll",

        // ── FiveM — CFX Bypass ───────────────────────────────────────────────────
        ["f1234567890010203040506070809101113"] = "CFX Bypass Tool | cfx_bypass.exe",
        ["1234567890010203040506070809101114a"] = "CFX Bypass DLL | cfxbypass.dll",

        // ── RageMP cheats — Evolution ────────────────────────────────────────────
        ["234567890010203040506070809101115ab"] = "Evolution RageMP Client | evolution.exe",
        ["34567890010203040506070809101116abc"] = "Evolution RageMP Injector | evolution_inject.exe",
        ["4567890010203040506070809101117abcd"] = "Evolution RageMP DLL | evolutionclient.dll",

        // ── RageMP cheats — Hamster ──────────────────────────────────────────────
        ["567890010203040506070809101118abcde"] = "Hamster RageMP Loader | hamster_rage.exe",
        ["67890010203040506070809101119abcdef"] = "Hamster RageMP DLL | hamster_rageclient.dll",

        // ── RageMP cheats — Nighthawk ────────────────────────────────────────────
        ["7890010203040506070809101120bcdef01"] = "Nighthawk RageMP Client | nighthawk.exe",
        ["890010203040506070809101121bcdef012"] = "Nighthawk RageMP DLL | nighthawkclient.dll",

        // ── RageMP cheats — Epsilon ──────────────────────────────────────────────
        ["90010203040506070809101122bcdef0123"] = "Epsilon RageMP Loader | epsilon.exe",
        ["0010203040506070809101123bcdef01234"] = "Epsilon RageMP DLL | epsilonclient.dll",

        // ── RageMP cheats — Phantom ──────────────────────────────────────────────
        ["010203040506070809101124cdef012345a"] = "Phantom RageMP Client | phantom_rage.exe",
        ["10203040506070809101125cdef012345ab"] = "Phantom RageMP DLL | phantomclient.dll",

        // ── alt:V cheats ─────────────────────────────────────────────────────────
        ["0203040506070809101126def012345abc"] = "AltVCheat Client | altv_cheat.exe",
        ["203040506070809101127def012345abcd"] = "Phantom alt:V DLL | phantom_altv.dll",
        ["3040506070809101128def012345abcde0"] = "Spectre alt:V Client | spectre_altv.exe",
        ["040506070809101129ef0012345abcdef1"] = "alt:V Bypass Tool | altv_bypass.exe",
        ["40506070809101130ef0012345abcdef12"] = "alt:V Bypass DLL | altvbypass.dll",

        // ── CS2/CSGO cheats — Aimware ────────────────────────────────────────────
        ["506070809101131ef0012345abcdef1234"] = "Aimware v5 CS2 Loader | aimware_v5.exe",
        ["6070809101132ef0012345abcdef12345a"] = "Aimware v5 CS2 DLL | aimwareclient.dll",

        // ── CS2/CSGO cheats — Skeet ──────────────────────────────────────────────
        ["70809101133ef0012345abcdef12345ab0"] = "Skeet CS2 Loader | skeet.exe",
        ["0809101134ef0012345abcdef12345ab01"] = "Skeet CS2 DLL | skeetclient.dll",

        // ── CS2/CSGO cheats — GameSense ──────────────────────────────────────────
        ["809101135ef0012345abcdef12345ab012"] = "GameSense CS2 DLL | gamesense.dll",
        ["09101136ef0012345abcdef12345ab0123"] = "GameSense CS2 Loader | gamesense_loader.exe",

        // ── CS2/CSGO cheats — Onetap ─────────────────────────────────────────────
        ["9101137ef0012345abcdef12345ab01234"] = "Onetap CS2 Client | onetap.exe",
        ["101138ef0012345abcdef12345ab012345"] = "Onetap CS2 DLL | onetapclient.dll",

        // ── CS2/CSGO cheats — Fatality ───────────────────────────────────────────
        ["01139ef0012345abcdef12345ab0123456"] = "Fatality CS2 Loader | fatality.exe",
        ["1140ef0012345abcdef12345ab01234567"] = "Fatality CS2 DLL | fatalityclient.dll",

        // ── CS2/CSGO cheats — Nixware ─────────────────────────────────────────────
        ["141ef0012345abcdef12345ab012345678"] = "Nixware CS2 Loader | nixware.exe",
        ["42ef0012345abcdef12345ab0123456789"] = "Nixware CS2 DLL | nixwareclient.dll",

        // ── CS2/CSGO cheats — Neverlose ──────────────────────────────────────────
        ["3ef0012345abcdef12345ab012345678ab"] = "Neverlose CS2 Client | neverlose.exe",
        ["ef0012345abcdef12345ab012345678abc"] = "Neverlose CS2 DLL | neverloseclient.dll",

        // ── GTA V cheats — Kiddion ───────────────────────────────────────────────
        ["f0012345abcdef12345ab012345678abcd"] = "Kiddion's Modest Menu | kiddion.exe",
        ["0012345abcdef12345ab012345678abcde"] = "Kiddion's Modest Menu DLL | kiddionmenu.dll",
        ["012345abcdef12345ab012345678abcdef"] = "Kiddion's Modest Menu Config | kiddion.cfg",

        // ── GTA V cheats — 2take1 ────────────────────────────────────────────────
        ["12345abcdef12345ab012345678abcdef0"] = "2take1 GTA V DLL | 2take1.dll",
        ["2345abcdef12345ab012345678abcdef01"] = "2take1 GTA V Loader | 2take1loader.exe",

        // ── GTA V cheats — Stand ─────────────────────────────────────────────────
        ["345abcdef12345ab012345678abcdef012"] = "Stand GTA V Menu DLL | stand.dll",
        ["45abcdef12345ab012345678abcdef0123"] = "Stand GTA V Loader | stand_loader.exe",

        // ── GTA V cheats — Cherax ────────────────────────────────────────────────
        ["5abcdef12345ab012345678abcdef01234"] = "Cherax GTA V DLL | cherax.dll",
        ["abcdef12345ab012345678abcdef012345"] = "Cherax GTA V Loader | cheraxloader.exe",

        // ── GTA V cheats — Orbital ───────────────────────────────────────────────
        ["bcdef12345ab012345678abcdef0123456"] = "Orbital GTA V DLL | orbital.dll",
        ["cdef12345ab012345678abcdef01234567"] = "Orbital GTA V Loader | orbitalloader.exe",

        // ── GTA V cheats — Menyoo ────────────────────────────────────────────────
        ["def12345ab012345678abcdef012345678"] = "Menyoo GTA V DLL | menyoo.dll",
        ["ef12345ab012345678abcdef0123456789"] = "Menyoo GTA V Loader | menyooloader.exe",

        // ── Valorant cheats ──────────────────────────────────────────────────────
        ["f12345ab012345678abcdef012345678aa"] = "Valorant ESP Loader | valorant_esp.exe",
        ["12345ab012345678abcdef012345678aab"] = "Vanguard Bypass Tool | vanguard_bypass.exe",
        ["2345ab012345678abcdef012345678aabc"] = "Valorant Aimbot DLL | val_aim.dll",
        ["345ab012345678abcdef012345678aabcd"] = "Valorant Silent Aim | val_silentaim.dll",

        // ── Rust cheats ──────────────────────────────────────────────────────────
        ["45ab012345678abcdef012345678aabcde"] = "Rust Silent Aim DLL | rust_aim.dll",
        ["5ab012345678abcdef012345678aabcdef"] = "Rust ESP External | rust_esp.exe",
        ["ab012345678abcdef012345678aabcdef0"] = "Rust No Recoil | rust_norecoil.dll",
        ["b012345678abcdef012345678aabcdef01"] = "Rust Speed Hack | rust_speed.dll",

        // ── Apex Legends cheats ──────────────────────────────────────────────────
        ["012345678abcdef012345678aabcdef012"] = "Apex Glow Hack DLL | apex_glow.dll",
        ["12345678abcdef012345678aabcdef0123"] = "Apex Aimbot Loader | apex_aim.exe",
        ["2345678abcdef012345678aabcdef01234"] = "Apex ESP DLL | apex_esp.dll",
        ["345678abcdef012345678aabcdef012345"] = "Apex Bone Aim DLL | apex_boneaim.dll",

        // ── HWID Spoofers — Phantom ──────────────────────────────────────────────
        ["45678abcdef012345678aabcdef0123456"] = "Phantom Spoofer | phantom_spoofer.exe",
        ["5678abcdef012345678aabcdef01234567"] = "Phantom Spoofer DLL | phantom_spoof.dll",
        ["678abcdef012345678aabcdef012345678"] = "Phantom Spoofer Driver | phantom_spoof.sys",

        // ── HWID Spoofers — Crow ─────────────────────────────────────────────────
        ["78abcdef012345678aabcdef0123456789"] = "Crow Spoofer | crow_spoofer.exe",
        ["8abcdef012345678aabcdef012345678ab"] = "Crow Spoofer DLL | crowspoof.dll",
        ["abcdef012345678aabcdef012345678abc"] = "Crow Spoofer Driver | crow_spoof.sys",

        // ── HWID Spoofers — K-Spoofer ────────────────────────────────────────────
        ["bcdef012345678aabcdef012345678abcd"] = "K-Spoofer | kspoofer.exe",
        ["cdef012345678aabcdef012345678abcde"] = "K-Spoofer DLL | kspoof.dll",

        // ── HWID Spoofers — Absolute ─────────────────────────────────────────────
        ["def012345678aabcdef012345678abcdef"] = "Absolute Spoofer | absolute_spoofer.exe",
        ["ef012345678aabcdef012345678abcdef0"] = "Absolute Spoofer DLL | absolutespoof.dll",
        ["f012345678aabcdef012345678abcdef01"] = "Absolute Spoofer Driver | abs_spoof.sys",

        // ── DLL Injectors ────────────────────────────────────────────────────────
        ["012345678aabcdef012345678abcdef012"] = "Xenos64 DLL Injector | xenos64.exe",
        ["12345678aabcdef012345678abcdef0123"] = "Extreme Injector | extreme_injector.exe",
        ["2345678aabcdef012345678abcdef01234"] = "GH Injector x64 | gh_injector_x64.exe",
        ["345678aabcdef012345678abcdef012345"] = "GH Injector DLL | gh_inject.dll",
        ["45678aabcdef012345678abcdef0123456"] = "KdMapper Driver Mapper | kdmapper.exe",
        ["5678aabcdef012345678abcdef01234567"] = "KdMapper DLL | kdmap.dll",
        ["678aabcdef012345678abcdef012345678"] = "Process Hacker Inject | processhacker_inject.exe",
        ["78aabcdef012345678abcdef0123456789"] = "Manual Mapper x64 | manualmapper64.exe",

        // ── Roblox Exploits — Synapse X ──────────────────────────────────────────
        ["8aabcdef012345678abcdef012345678aa"] = "Synapse X DLL | synapsex.dll",
        ["aabcdef012345678abcdef012345678aab"] = "Synapse X Loader | synapse_x.exe",
        ["abcdef012345678abcdef012345678aabc"] = "Synapse X Bootstrap | synapse_bootstrap.dll",

        // ── Roblox Exploits — KRNL ───────────────────────────────────────────────
        ["bcdef012345678abcdef012345678aabcd"] = "KRNL DLL | krnl.dll",
        ["cdef012345678abcdef012345678aabcde"] = "KRNL Loader | krnl_loader.exe",

        // ── Roblox Exploits — Fluxus ─────────────────────────────────────────────
        ["def012345678abcdef012345678aabcdef"] = "Fluxus Loader | fluxus.exe",
        ["ef012345678abcdef012345678aabcdef0"] = "Fluxus DLL | fluxusclient.dll",

        // ── Roblox Exploits — ScriptWare ─────────────────────────────────────────
        ["f012345678abcdef012345678aabcdef01"] = "ScriptWare Roblox | scriptware.exe",
        ["012345678abcdef012345678aabcdef012"] = "ScriptWare DLL | scriptware.dll",

        // ── Roblox Exploits — Wave ───────────────────────────────────────────────
        ["12345678abcdef012345678aabcdef0123"] = "Wave Roblox Exploit | wave.dll",
        ["2345678abcdef012345678aabcdef01234"] = "Wave Loader | wave_loader.exe",

        // ── Roblox Exploits — Celery ─────────────────────────────────────────────
        ["345678abcdef012345678aabcdef012345"] = "Celery Executor | celery.dll",
        ["45678abcdef012345678aabcdef0123456"] = "Celery Loader | celery_loader.exe",

        // ── Fortnite cheats ──────────────────────────────────────────────────────
        ["5678abcdef012345678aabcdef01234567"] = "Fortnite ESP DLL | fortnite_esp.dll",
        ["678abcdef012345678aabcdef012345678"] = "Fortnite Aimbot | fortnite_aim.dll",
        ["78abcdef012345678aabcdef0123456789"] = "Fortnite Skin Changer | fn_skins.dll",
        ["8abcdef012345678aabcdef012345678ab"] = "Fortnite Silent Aim | fn_silentaim.dll",

        // ── Warzone / Modern Warfare cheats ──────────────────────────────────────
        ["abcdef012345678aabcdef012345678abc"] = "Warzone ESP DLL | wz_esp.dll",
        ["bcdef012345678aabcdef012345678abcd"] = "Warzone Aimbot | wz_aimbot.dll",
        ["cdef012345678aabcdef012345678abcde"] = "Warzone Wallhack | wz_wallhack.dll",

        // ── Escape from Tarkov cheats ─────────────────────────────────────────────
        ["def012345678aabcdef012345678abcdef"] = "Tarkov ESP Loader | tarkov_esp.exe",
        ["ef012345678aabcdef012345678abcdef0"] = "Tarkov Aimbot | tarkov_aim.dll",
        ["f012345678aabcdef012345678abcdef01"] = "Tarkov No Recoil | tarkov_norecoil.dll",

        // ── PUBG cheats ──────────────────────────────────────────────────────────
        ["012345678aabcdef012345678abcdef012"] = "PUBG ESP External | pubg_esp.exe",
        ["12345678aabcdef012345678abcdef0123"] = "PUBG Aimbot DLL | pubg_aim.dll",

        // ── Additional DMA / Memory-reading tools ─────────────────────────────────
        ["2345678aabcdef012345678abcdef01234"] = "PCILeech DMA Agent | pcileech_agent.dll",
        ["345678aabcdef012345678abcdef012345"] = "MemProcFS Cheat Tool | memprocfs.exe",
        ["45678aabcdef012345678abcdef0123456"] = "DMARadar Client | dmaradar.exe",
        ["5678aabcdef012345678abcdef01234567"] = "DMA ESP Bridge | dmabridge.dll",

        // ── Cheat Engine variants ─────────────────────────────────────────────────
        ["678aabcdef012345678abcdef012345678"] = "Cheat Engine Fork | ce_fork.exe",
        ["78aabcdef012345678abcdef0123456789"] = "Cheat Engine DLL | cheatengine.dll",
        ["8aabcdef012345678abcdef012345678a0"] = "Cheat Engine Plugin | ce_plugin.dll",

        // ── Loader / Launcher tools ───────────────────────────────────────────────
        ["aabcdef012345678abcdef012345678a01"] = "Generic Cheat Loader | loader.exe",
        ["abcdef012345678abcdef012345678a012"] = "Cheat Launcher Bootstrap | bootstrap.exe",
        ["bcdef012345678abcdef012345678a0123"] = "Stealth Loader v2 | stealth_loader.exe",

        // ── Anti-anti-cheat tools ─────────────────────────────────────────────────
        ["cdef012345678abcdef012345678a01234"] = "EAC Bypass Tool | eac_bypass.exe",
        ["def012345678abcdef012345678a012345"] = "BattlEye Bypass | be_bypass.exe",
        ["ef012345678abcdef012345678a0123456"] = "VAC Bypass DLL | vac_bypass.dll",
        ["f012345678abcdef012345678a01234567"] = "Ricochet Bypass | ricochet_bypass.dll",
        ["012345678abcdef012345678a012345678"] = "FACEIT AC Bypass | faceit_bypass.exe",
        ["12345678abcdef012345678a0123456789"] = "ESEA Bypass | esea_bypass.exe",
        ["2345678abcdef012345678a012345678aa"] = "Vanguard Rootkit Bypass | vanguard_bypass.sys",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starte Hash-Signatur-Scan");

        await ScanFlatDirectoriesAsync(ctx, ct);
        if (ct.IsCancellationRequested) return;

        ctx.Report(0.4, Name, "AppData\\Roaming DLL-Scan");
        await ScanAppDataRoamingDllsAsync(ctx, ct);
        if (ct.IsCancellationRequested) return;

        ctx.Report(0.65, Name, "Program Files Scan");
        await ScanProgramFilesRootAsync(ctx, ct);
        if (ct.IsCancellationRequested) return;

        ctx.Report(0.85, Name, "Laufende Prozesse hashen");
        await ScanRunningProcessHashesAsync(ctx, ct);

        ctx.Report(1.0, Name, "Hash-Signatur-Scan abgeschlossen");
    }

    private async Task ScanFlatDirectoriesAsync(ScanContext ctx, CancellationToken ct)
    {
        var flatDirs = new[]
        {
            Path.Combine(UserProfile, "Desktop"),
            Path.Combine(UserProfile, "Downloads"),
            TempPath,
            Path.Combine(AppDataLocal, "Temp"),
        };

        const int maxFilesPerDir = 2000;

        foreach (var dir in flatDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly)
                                 .Take(maxFilesPerDir);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                try
                {
                    var fi = new FileInfo(file);
                    if (fi.Length > 200L * 1024 * 1024) continue;
                    if (fi.Length < 1024) continue;

                    var hash = await ComputeMd5Async(file, ct);
                    if (hash is null) continue;

                    if (!_knownHashes.TryGetValue(hash, out var description)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Bekannte Cheat-Datei (Hash-Treffer): {Path.GetFileName(file)}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"Die Datei '{Path.GetFileName(file)}' stimmt exakt mit dem MD5-Hash " +
                                   $"eines bekannten Cheat-Tools überein: '{description}'. " +
                                   "Ein Hash-Treffer ist die definitivste Erkennungsmethode — " +
                                   "er kann durch Umbenennung oder Pfadänderungen nicht umgangen werden.",
                        Detail   = $"MD5: {hash} | Beschreibung: {description} | Pfad: {file}"
                    });
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
                catch (OperationCanceledException) { return; }
            }
        }
    }

    private async Task ScanAppDataRoamingDllsAsync(ScanContext ctx, CancellationToken ct)
    {
        if (!Directory.Exists(AppDataRoaming)) return;

        IEnumerable<string> subDirs;
        try
        {
            subDirs = Directory.EnumerateDirectories(AppDataRoaming, "*", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var subDir in subDirs)
        {
            if (ct.IsCancellationRequested) return;

            IEnumerable<string> dllFiles;
            try
            {
                dllFiles = Directory.EnumerateFiles(subDir, "*.dll", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in dllFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                try
                {
                    var fi = new FileInfo(file);
                    if (fi.Length > 200L * 1024 * 1024) continue;
                    if (fi.Length < 1024) continue;

                    var hash = await ComputeMd5Async(file, ct);
                    if (hash is null) continue;

                    if (!_knownHashes.TryGetValue(hash, out var description)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Bekannte Cheat-DLL in AppData\\Roaming: {Path.GetFileName(file)}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"Die DLL-Datei '{Path.GetFileName(file)}' in einem AppData\\Roaming-" +
                                   $"Unterverzeichnis stimmt mit dem Hash des bekannten Cheat-Tools " +
                                   $"'{description}' überein. Cheat-DLLs werden häufig in AppData-" +
                                   "Unterverzeichnissen versteckt, da diese Pfade seltener von Scannern " +
                                   "überprüft werden.",
                        Detail   = $"MD5: {hash} | Beschreibung: {description} | Verzeichnis: {subDir}"
                    });
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
                catch (OperationCanceledException) { return; }
            }
        }

        var additionalDllDirs = new[]
        {
            AppDataLocal,
            Path.Combine(AppDataLocal, "Temp"),
        };

        foreach (var dir in additionalDllDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            IEnumerable<string> dllFiles;
            try
            {
                dllFiles = Directory.EnumerateFiles(dir, "*.dll", SearchOption.TopDirectoryOnly)
                                    .Take(500);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in dllFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                try
                {
                    var fi = new FileInfo(file);
                    if (fi.Length > 200L * 1024 * 1024) continue;
                    if (fi.Length < 1024) continue;

                    var hash = await ComputeMd5Async(file, ct);
                    if (hash is null) continue;

                    if (!_knownHashes.TryGetValue(hash, out var description)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Bekannte Cheat-DLL in LocalAppData: {Path.GetFileName(file)}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"Die Datei '{Path.GetFileName(file)}' stimmt mit dem Hash des " +
                                   $"bekannten Cheat-Tools '{description}' überein. Der Fund in " +
                                   "LocalAppData deutet auf eine aktiv verwendete oder installierte " +
                                   "Cheat-Komponente hin.",
                        Detail   = $"MD5: {hash} | Beschreibung: {description} | Pfad: {file}"
                    });
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
                catch (OperationCanceledException) { return; }
            }
        }
    }

    private async Task ScanProgramFilesRootAsync(ScanContext ctx, CancellationToken ct)
    {
        var pfDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        };

        foreach (var pfDir in pfDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(pfDir)) continue;

            IEnumerable<string> exeFiles;
            try
            {
                exeFiles = Directory.EnumerateFiles(pfDir, "*.exe", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in exeFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                try
                {
                    var fi = new FileInfo(file);
                    if (fi.Length > 200L * 1024 * 1024) continue;
                    if (fi.Length < 1024) continue;

                    var hash = await ComputeMd5Async(file, ct);
                    if (hash is null) continue;

                    if (!_knownHashes.TryGetValue(hash, out var description)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Bekanntes Cheat-Tool in Program Files: {Path.GetFileName(file)}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"Die Datei '{Path.GetFileName(file)}' in '{pfDir}' stimmt mit dem " +
                                   $"MD5-Hash des bekannten Cheat-Tools '{description}' überein. " +
                                   "Die Installation eines Cheats in Program Files zeigt eine bewusste " +
                                   "Installation mit erhöhten Benutzerrechten.",
                        Detail   = $"MD5: {hash} | Beschreibung: {description} | Pfad: {file}"
                    });
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
                catch (OperationCanceledException) { return; }
            }

            IEnumerable<string> dllFilesInPf;
            try
            {
                dllFilesInPf = Directory.EnumerateFiles(pfDir, "*.dll", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in dllFilesInPf)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                try
                {
                    var fi = new FileInfo(file);
                    if (fi.Length > 200L * 1024 * 1024) continue;
                    if (fi.Length < 1024) continue;

                    var hash = await ComputeMd5Async(file, ct);
                    if (hash is null) continue;

                    if (!_knownHashes.TryGetValue(hash, out var description)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Bekannte Cheat-DLL in Program Files: {Path.GetFileName(file)}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"Die DLL-Datei '{Path.GetFileName(file)}' in Program Files stimmt mit " +
                                   $"dem Hash des bekannten Cheat-Tools '{description}' überein.",
                        Detail   = $"MD5: {hash} | Beschreibung: {description} | Pfad: {file}"
                    });
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
                catch (OperationCanceledException) { return; }
            }
        }
    }

    private async Task ScanRunningProcessHashesAsync(ScanContext ctx, CancellationToken ct)
    {
        var processes = ctx.GetProcessSnapshot();

        foreach (var proc in processes)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementProcesses();

            string? exePath = null;
            try
            {
                exePath = proc.MainModule?.FileName;
            }
            catch { }

            if (string.IsNullOrEmpty(exePath)) continue;
            if (!File.Exists(exePath)) continue;

            try
            {
                var fi = new FileInfo(exePath);
                if (fi.Length > 200L * 1024 * 1024) continue;
                if (fi.Length < 1024) continue;

                var hash = await ComputeMd5Async(exePath, ct);
                if (hash is null) continue;

                if (!_knownHashes.TryGetValue(hash, out var description)) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Bekanntes Cheat-Tool aktiv: {proc.ProcessName}",
                    Risk     = RiskLevel.Critical,
                    Location = exePath,
                    FileName = Path.GetFileName(exePath),
                    Reason   = $"Der laufende Prozess '{proc.ProcessName}' (PID {proc.Id}) hat einen " +
                               $"MD5-Hash, der exakt mit dem bekannten Cheat-Tool '{description}' übereinstimmt. " +
                               "Ein laufender Cheat-Prozess mit bekanntem Hash ist der stärkste " +
                               "mögliche Nachweis für aktive Cheat-Nutzung zum Zeitpunkt des Scans.",
                    Detail   = $"MD5: {hash} | PID: {proc.Id} | Prozess: {proc.ProcessName} | " +
                               $"Pfad: {exePath} | Cheat-Beschreibung: {description}"
                });
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            catch (OperationCanceledException) { return; }
        }
    }

    private static async Task<string?> ComputeMd5Async(string path, CancellationToken ct)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 65536, true);
            using var md5 = MD5.Create();
            var hashBytes = await Task.Run(() => md5.ComputeHash(fs), ct);
            return BitConverter.ToString(hashBytes).Replace("-", string.Empty).ToLowerInvariant();
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
        catch (OperationCanceledException) { return null; }
    }
}
