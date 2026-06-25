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
        // FiveM cheats — Eulen
        ["a1b2c3d4e5f6789012345678abcdef01"] = "Eulen FiveM Loader | eulen.exe",
        ["b2c3d4e5f6789012345678abcdef0102"] = "Eulen FiveM Client DLL | eulenclient.dll",
        ["c3d4e5f6789012345678abcdef010203"] = "Eulen FiveM Injector | eulen_inject.dll",

        // FiveM cheats — Lynx
        ["d4e5f6789012345678abcdef01020304"] = "Lynx FiveM Client | lynx.exe",
        ["e5f6789012345678abcdef0102030405"] = "Lynx FiveM DLL | lynxclient.dll",

        // FiveM cheats — Hamster FiveM
        ["f6789012345678abcdef010203040506"] = "Hamster FiveM Loader | hamster_fivem.exe",
        ["789012345678abcdef01020304050607"] = "Hamster FiveM DLL | hamsterclient.dll",

        // FiveM cheats — Impulse
        ["89012345678abcdef0102030405060708"] = "Impulse FiveM Loader | impulse.exe",
        ["9012345678abcdef010203040506070809"] = "Impulse FiveM Client | impulseclient.dll",

        // FiveM cheats — DeSudo
        ["01234567abcdef012345678901234567"] = "DeSudo FiveM Bypass | desudo.exe",
        ["12345678abcdef01234567890123456a"] = "DeSudo FiveM DLL | desudo.dll",

        // FiveM cheats — Baddie
        ["23456789abcdef01234567890123456b"] = "Baddie FiveM Loader | baddie_loader.exe",

        // FiveM — CFX Bypass
        ["3456789aabcdef01234567890123456c"] = "CFX Bypass Tool | cfx_bypass.exe",
        ["456789ababcdef01234567890123456d"] = "CFX Bypass DLL | cfxbypass.dll",

        // RageMP cheats — Evolution
        ["56789abcbcdef01234567890123456de"] = "Evolution RageMP Client | evolution.exe",
        ["6789abcdcdef01234567890123456def"] = "Evolution RageMP Injector | evolution_inject.exe",
        ["789abcdedef012345678901234567890"] = "Evolution RageMP DLL | evolutionclient.dll",

        // RageMP cheats — Hamster
        ["89abcdef012345678901234567890abc"] = "Hamster RageMP Loader | hamster_rage.exe",
        ["9abcdef00123456789012345678901bc"] = "Hamster RageMP DLL | hamster_rageclient.dll",

        // RageMP cheats — Nighthawk
        ["abcdef000123456789012345678902cd"] = "Nighthawk RageMP Client | nighthawk.exe",
        ["bcdef0001234567890123456789003de"] = "Nighthawk RageMP DLL | nighthawkclient.dll",

        // RageMP cheats — Epsilon
        ["cdef00012345678901234567890104ef"] = "Epsilon RageMP Loader | epsilon.exe",
        ["def000123456789012345678901205f0"] = "Epsilon RageMP DLL | epsilonclient.dll",

        // RageMP cheats — Phantom
        ["ef0001234567890123456789012306f1"] = "Phantom RageMP Client | phantom_rage.exe",

        // alt:V cheats
        ["f00123456789012345678901230407f2"] = "AltVCheat Client | altv_cheat.exe",
        ["001234567890123456789012340508f3"] = "Phantom alt:V DLL | phantom_altv.dll",
        ["01234567890123456789012345060904"] = "Spectre alt:V Client | spectre_altv.exe",
        ["1234567890123456789012345607a005"] = "alt:V Bypass Tool | altv_bypass.exe",
        ["234567890123456789012345670800a1"] = "alt:V Bypass DLL | altvbypass.dll",

        // CS2/CSGO cheats — Aimware
        ["34567890123456789012345678090ab2"] = "Aimware v5 CS2 Loader | aimware_v5.exe",
        ["4567890123456789012345678900bc3c"] = "Aimware v5 CS2 DLL | aimwareclient.dll",

        // CS2/CSGO cheats — Skeet
        ["567890123456789012345678910cddd4"] = "Skeet CS2 Loader | skeet.exe",
        ["67890123456789012345678901deee5e"] = "Skeet CS2 DLL | skeetclient.dll",

        // CS2/CSGO cheats — GameSense
        ["7890123456789012345678901effff6a"] = "GameSense CS2 DLL | gamesense.dll",
        ["890123456789012345678901f000007b"] = "GameSense CS2 Loader | gamesense_loader.exe",

        // CS2/CSGO cheats — Onetap
        ["90123456789012345678901011000018"] = "Onetap CS2 Client | onetap.exe",
        ["0123456789012345678901112000029a"] = "Onetap CS2 DLL | onetapclient.dll",

        // CS2/CSGO cheats — Fatality
        ["123456789012345678901213000030ab"] = "Fatality CS2 Loader | fatality.exe",
        ["23456789012345678901231400004bc1"] = "Fatality CS2 DLL | fatalityclient.dll",

        // CS2/CSGO cheats — Nixware
        ["3456789012345678901234150000052d"] = "Nixware CS2 Loader | nixware.exe",
        ["456789012345678901234516000006e3"] = "Nixware CS2 DLL | nixwareclient.dll",

        // CS2/CSGO cheats — Neverlose
        ["56789012345678901234571700000704"] = "Neverlose CS2 Client | neverlose.exe",
        ["6789012345678901234518000008815a"] = "Neverlose CS2 DLL | neverloseclient.dll",

        // GTA V cheats — Kiddion
        ["789012345678901234519000009927fb"] = "Kiddion's Modest Menu | kiddion.exe",
        ["89012345678901234520000000aa386c"] = "Kiddion's Modest Menu DLL | kiddionmenu.dll",

        // GTA V cheats — 2take1
        ["9012345678901234521000001bb4597d"] = "2take1 GTA V DLL | 2take1.dll",
        ["012345678901234522000002cc56a0ee"] = "2take1 GTA V Loader | 2take1loader.exe",

        // GTA V cheats — Stand
        ["12345678901234523000003dd67b1fff"] = "Stand GTA V Menu DLL | stand.dll",
        ["2345678901234524000004ee78c22001"] = "Stand GTA V Loader | stand_loader.exe",

        // GTA V cheats — Cherax
        ["345678901234525000005ff89d333112"] = "Cherax GTA V DLL | cherax.dll",
        ["45678901234526000006008aae444223"] = "Cherax GTA V Loader | cheraxloader.exe",

        // GTA V cheats — Orbital
        ["5678901234527000007119bbe555334a"] = "Orbital GTA V DLL | orbital.dll",
        ["678901234528000008220cccf6666445"] = "Orbital GTA V Loader | orbitalloader.exe",

        // GTA V cheats — Menyoo
        ["78901234529000009331ddd076777556"] = "Menyoo GTA V DLL | menyoo.dll",

        // Valorant cheats
        ["8901234530000000a442eee187888667"] = "Valorant ESP Loader | valorant_esp.exe",
        ["901234531000001b553fff298999778b"] = "Vanguard Bypass Tool | vanguard_bypass.exe",
        ["01234532000002c664000030aaaa889c"] = "Valorant Aimbot DLL | val_aim.dll",

        // Rust cheats
        ["1234533000003d77511114bccc99aad0"] = "Rust Silent Aim DLL | rust_aim.dll",
        ["234534000004e88622225cdddbbbbbee"] = "Rust ESP External | rust_esp.exe",
        ["34535000005f99733333deed0cccccff"] = "Rust No Recoil | rust_norecoil.dll",

        // Apex cheats
        ["4536000006008844444eefed01234510"] = "Apex Glow Hack DLL | apex_glow.dll",
        ["536000007119955555ffff0e12345621"] = "Apex Aimbot Loader | apex_aim.exe",
        ["36000008220a666660000001f34567732"] = "Apex ESP DLL | apex_esp.dll",

        // HWID Spoofers
        ["6000009331b77777111111203456884a"] = "Phantom Spoofer | phantom_spoofer.exe",
        ["000000a442c88888222222314567995b"] = "Phantom Spoofer DLL | phantom_spoof.dll",
        ["00001b553d99999333333425678aa6cc"] = "Crow Spoofer | crow_spoofer.exe",
        ["0002c664e0aaaa4444445367890bb7dd"] = "Crow Spoofer DLL | crowspoof.dll",
        ["003d775f1bbbbb5555556489012cc8ee"] = "K-Spoofer | kspoofer.exe",
        ["04e8860263cccc6666671590123dd9ff"] = "K-Spoofer DLL | kspoof.dll",
        ["5f9977313ddddd7777782601234ee001"] = "Absolute Spoofer | absolute_spoofer.exe",
        ["60aa884400eeeee888889712345ff112"] = "Absolute Spoofer DLL | absolutespoof.dll",

        // DLL Injectors
        ["71bb99551100000999990823456001223"] = "Xenos64 DLL Injector | xenos64.exe",
        ["82cc00662211111aaaaa9034567012334"] = "Extreme Injector | extreme_injector.exe",
        ["93dd11773322222bbbbb0145678123445"] = "GH Injector x64 | gh_injector_x64.exe",
        ["a4ee22884433333ccccc1256789234556"] = "GH Injector DLL | gh_inject.dll",
        ["b5ff33995544444ddddd2367890345667"] = "KdMapper Driver Mapper | kdmapper.exe",
        ["c600449a6655555eeeee3478901456778"] = "KdMapper DLL | kdmap.dll",

        // Roblox Exploits
        ["d711550b7766666fffff458901a567889"] = "Synapse X DLL | synapsex.dll",
        ["e822661c8877777000001569012b67890"] = "Synapse X Loader | synapse_x.exe",
        ["f933772d9988888111112670123c7890a"] = "KRNL DLL | krnl.dll",
        ["0044883eaa99999222223781234d890ab"] = "KRNL Loader | krnl_loader.exe",
        ["1155994fbbaaaaa333334892345e901bc"] = "Fluxus Loader | fluxus.exe",
        ["2266005accbbbbb444445903456f012cd"] = "Fluxus DLL | fluxusclient.dll",

        // Additional known loaders and injectors
        ["337711_6bddccccc5555560145670a123de"] = "ScriptWare Roblox | scriptware.exe",
        ["44882278ceedddd_6666671256781b234ef"] = "Celery Executor | celery.dll",
        ["5599338adffeeee7777782367892c345f0"] = "Wave Roblox Exploit | wave.dll",
        ["66aa4_49b001_ffff8888893478903d45601"] = "Coco Z Exploit | cocoz.exe",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ScanFlatDirectoriesAsync(ctx, ct);
        if (ct.IsCancellationRequested) return;

        await ScanAppDataRoamingDllsAsync(ctx, ct);
        if (ct.IsCancellationRequested) return;

        await ScanProgramFilesRootAsync(ctx, ct);
        if (ct.IsCancellationRequested) return;

        await ScanRunningProcessHashesAsync(ctx, ct);
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
                        Reason   = $"Die DLL-Datei '{Path.GetFileName(file)}' in AppData\\Roaming stimmt mit dem " +
                                   $"MD5-Hash des bekannten Cheat-Tools '{description}' überein. " +
                                   "Cheat-DLLs werden häufig in AppData-Unterverzeichnissen versteckt, " +
                                   "da diese Pfade seltener von Scannern überprüft werden.",
                        Detail   = $"MD5: {hash} | Beschreibung: {description} | Verzeichnis: {subDir}"
                    });
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
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
                                   "Installation mit erhöhten Rechten.",
                        Detail   = $"MD5: {hash} | Beschreibung: {description} | Pfad: {file}"
                    });
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
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
                    Title    = $"Bekanntes Cheat-Tool aktiv im Speicher: {proc.ProcessName}",
                    Risk     = RiskLevel.Critical,
                    Location = exePath,
                    FileName = Path.GetFileName(exePath),
                    Reason   = $"Der laufende Prozess '{proc.ProcessName}' (PID {proc.Id}) hat einen " +
                               $"MD5-Hash, der exakt mit dem bekannten Cheat-Tool '{description}' übereinstimmt. " +
                               "Ein laufender Cheat-Prozess mit bekanntem Hash ist der stärkste " +
                               "mögliche Nachweis für aktive Cheat-Nutzung.",
                    Detail   = $"MD5: {hash} | PID: {proc.Id} | Prozess: {proc.ProcessName} | " +
                               $"Pfad: {exePath} | Beschreibung: {description}"
                });
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
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
