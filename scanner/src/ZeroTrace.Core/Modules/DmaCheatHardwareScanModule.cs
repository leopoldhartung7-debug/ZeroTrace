using Microsoft.Win32;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class DmaCheatHardwareScanModule : IScanModule
{
    public string Name => "DMA Hardware Cheat Detection";
    public double Weight => 4.5;
    public int ParallelGroup => 4;

    private static readonly string[] DmaSoftwareExecutables =
    {
        "pcileech.exe", "pcileech_wifi.exe", "dma_read.exe", "dma_cheat.exe",
        "dma_esp.exe", "dma_aimbot.exe", "dma_radar.exe", "scatter_read.exe",
        "mem_access.exe", "fpga_cheat.exe", "fpga_read.exe", "fpga_memread.exe",
        "squirrel_cheat.exe", "enigma_dma.exe", "memflow.exe", "memflow_cheat.exe",
        "MemProcFS.exe", "memprocfs.exe", "leechcore.exe", "vmm.exe",
        "dma_tool.exe", "dma_mem.exe", "pciscream.exe", "screamer.exe",
        "dma_loader.exe", "dma_inject.exe", "fpga_inject.exe",
        "dma_scan.exe", "mem_reader.exe", "phys_mem.exe",
        "physical_mem.exe", "pcie_mem.exe", "dma_overlay.exe",
        "dma_hack.exe", "dma_driver.exe", "dma_software.exe",
        "pcileech_tool.exe", "pcileech_fpga.exe",
        "ac_bypass_dma.exe", "dma_bypass.exe",
        "squirrel.exe", "zdma.exe", "screamerM2.exe",
    };

    private static readonly string[] DmaLibraryFiles =
    {
        "leechcore.dll", "vmm.dll", "FTD2XX.dll", "ftd2xx.dll",
        "leechcoredll.dll", "vmmdll.dll", "ftdi.dll",
        "libusb-1.0.dll", "cyusb3.dll", "CyUSB3.dll",
        "mpsse.dll", "ftdibus.dll",
    };

    private static readonly string[] DmaFirmwareFiles =
    {
        "pcileech.bat", "dma_connect.bat", "fpga_connect.bat",
        "pcileech_connect.bat", "squirrel_connect.bat", "zdma_connect.bat",
        "screamer_connect.bat", "pcileech_run.bat", "dma_start.bat",
        "connect_dma.bat", "run_dma.bat", "fpga_start.bat",
    };

    private static readonly string[] DmaRadarExecutables =
    {
        "radar_server.exe", "radar_client.exe", "web_radar.exe",
        "dma_radar.exe", "esp_radar.exe", "game_radar.exe",
        "radar_overlay.exe", "radar_esp.exe", "map_radar.exe",
        "radar.exe", "webradar.exe", "radarserver.exe",
    };

    private static readonly int[] DmaRadarPorts =
    {
        3000, 8080, 28003, 28004, 7000, 7001, 7777,
        8000, 8081, 8443, 9000, 28000, 28001, 28002,
    };

    private static readonly string[] TargetGameProcesses =
    {
        "r5apex.exe", "r5apex_dx12.exe",
        "cs2.exe", "csgo.exe",
        "TslGame-Win64-Shipping.exe", "TslGame.exe",
        "cod.exe", "ModernWarfare.exe", "cod2mp_s.exe",
        "VALORANT-Win64-Shipping.exe",
        "EscapeFromTarkov.exe",
        "RainbowSix.exe", "RainbowSix_BE.exe",
        "bf2042.exe", "bf1.exe", "bfv.exe",
        "Rust.exe", "rustclient.exe",
        "GTA5.exe", "GTA5_Enhanced.exe",
        "RDR2.exe",
        "Fortnite-Win64-Shipping.exe",
        "ac_client.exe",
        "quake3.exe",
        "Overwatch.exe",
        "destiny2.exe",
    };

    private static readonly string[] DmaConfigOffsetKeywords =
    {
        "\"offset\"", "\"offsets\"", "\"base_address\"", "\"game_base\"",
        "\"entity_list\"", "\"local_player\"", "\"view_matrix\"",
        "\"bone_matrix\"", "\"health\"", "\"ammo\"", "\"weapon\"",
        "\"aimbot\"", "\"esp\"", "\"wallhack\"", "\"radar\"",
        "scatter_read", "scatter_write", "vmm", "leechcore",
        "pcileech", "fpga", "dma_read", "mem_read",
        "physical_read", "phys_mem", "pcie_read",
    };

    private static readonly string[] RadarConfigKeywords =
    {
        "\"ip\"", "\"port\"", "\"game\"", "\"players\"", "\"enemies\"",
        "\"websocket\"", "\"ws://\"", "\"radar\"", "\"minimap\"",
        "radar_port", "radar_server", "radar_host", "radar_url",
        "\"team\"", "\"bombs\"", "\"loot\"", "\"position\"",
        "\"x\"", "\"y\"", "\"z\"", "coordinates",
    };

    private static readonly string[] PcileechDirectoryNames =
    {
        "PCILeech", "pcileech", "pcileech-fpga", "pcileech-webrec",
        "LeechCore", "leechcore", "MemProcFS", "memprocfs",
        "DMA", "dma", "DMA_Cheat", "dma_cheat",
        "FPGA", "fpga", "Squirrel", "squirrel",
        "ZDMA", "zdma", "Screamer", "screamer",
        "enigma_dma", "EnigmaDMA",
        "memflow", "Memflow",
    };

    private static readonly string[] FtdiDriverPaths =
    {
        "ftdibus.sys", "ftdiport.sys", "ftd2xx.sys",
        "ftdibus64.sys", "ftdiport64.sys",
    };

    private static readonly string[] DmaRegistryServiceFragments =
    {
        "pcileech", "leechcore", "memprocfs", "memflow",
        "zdma", "screamer", "ftdibus", "ftdiport",
        "cyusb3", "ftd2xx",
    };

    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static readonly string AppDataRoaming =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string AppDataLocal =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string Desktop =
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    private static readonly string Downloads =
        Path.Combine(UserProfile, "Downloads");
    private static readonly string Documents =
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    private static readonly string System32 =
        Environment.GetFolderPath(Environment.SpecialFolder.System);

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Scanning for DMA software executables...");
        await ScanDmaSoftwareExecutablesAsync(ctx, ct);

        ctx.Report(0.15, Name, "Scanning for DMA library files in user directories...");
        await ScanDmaLibraryFilesAsync(ctx, ct);

        ctx.Report(0.25, Name, "Scanning for PCILeech directories and firmware artifacts...");
        await ScanPcileechDirectoriesAsync(ctx, ct);

        ctx.Report(0.38, Name, "Scanning DMA config files for game process targets...");
        await ScanDmaConfigFilesAsync(ctx, ct);

        ctx.Report(0.52, Name, "Scanning for DMA radar infrastructure...");
        await ScanRadarInfrastructureAsync(ctx, ct);

        ctx.Report(0.65, Name, "Checking registry for DMA driver service artifacts...");
        ScanDmaRegistryArtifacts(ctx, ct);

        ctx.Report(0.77, Name, "Scanning for FTDI/USB DMA hardware driver artifacts...");
        await ScanFtdiDriverArtifactsAsync(ctx, ct);

        ctx.Report(0.88, Name, "Checking for DMA radar port listeners...");
        CheckRadarPortListeners(ctx, ct);

        ctx.Report(1.0, Name, "DMA hardware cheat scan complete");
    }

    private async Task ScanDmaSoftwareExecutablesAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            UserProfile,
            Desktop,
            Downloads,
            Documents,
            AppDataRoaming,
            AppDataLocal,
            Path.GetTempPath(),
        };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                await ScanDirForDmaExecutablesAsync(ctx, dir, SearchOption.TopDirectoryOnly, ct);
            }
            catch (UnauthorizedAccessException) { }
        }

        await ScanUserDriveRootsForDmaAsync(ctx, ct);
    }

    private async Task ScanDirForDmaExecutablesAsync(
        ScanContext ctx, string directory, SearchOption option, CancellationToken ct)
    {
        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(directory, "*.exe", option)
                .Concat(Directory.EnumerateFiles(directory, "*.dll", option));
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var filePath in files)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(filePath);

            var exeMatch = DmaSoftwareExecutables.FirstOrDefault(n =>
                n.Equals(fileName, StringComparison.OrdinalIgnoreCase));
            if (exeMatch is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"DMA cheat software executable: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = filePath,
                    FileName = fileName,
                    Reason = $"Executable '{fileName}' matches a known DMA cheat software tool. " +
                             "DMA (Direct Memory Access) cheat software reads game memory over the " +
                             "PCIe bus from a hardware device (FPGA card like PCIe Squirrel, ZDMA, " +
                             "or Screamer M2), completely bypassing all software-based anti-cheats " +
                             "because the cheat runs on separate hardware. Finding this software " +
                             "confirms a DMA cheat setup on this machine.",
                    Detail = $"Path: {filePath}"
                });
                continue;
            }

            var libMatch = DmaLibraryFiles.FirstOrDefault(n =>
                n.Equals(fileName, StringComparison.OrdinalIgnoreCase));
            if (libMatch is not null)
            {
                bool inSystem32 = filePath.StartsWith(System32, StringComparison.OrdinalIgnoreCase);
                if (!inSystem32)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"DMA library in non-system directory: {fileName}",
                        Risk = RiskLevel.High,
                        Location = filePath,
                        FileName = fileName,
                        Reason = $"DMA-related library '{fileName}' found outside system directories. " +
                                 "LeechCore and VMM are the core libraries of the PCILeech DMA framework. " +
                                 "FTD2XX.dll is the FTDI USB driver library required by DMA boards " +
                                 "(PCIe Squirrel, ZDMA) to communicate over USB to the host PC. " +
                                 "These files in user directories strongly suggest DMA cheat software " +
                                 "has been installed.",
                        Detail = $"Path: {filePath}"
                    });
                }
            }
        }

        await Task.Yield();
    }

    private async Task ScanUserDriveRootsForDmaAsync(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType != DriveType.Fixed) continue;
                ct.ThrowIfCancellationRequested();

                foreach (var dirName in PcileechDirectoryNames)
                {
                    var dmaDir = Path.Combine(drive.RootDirectory.FullName, dirName);
                    if (!Directory.Exists(dmaDir)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"DMA tool directory at drive root: {dirName}",
                        Risk = RiskLevel.Critical,
                        Location = dmaDir,
                        FileName = dirName,
                        Reason = $"DMA cheat tool directory '{dirName}' found at the root of drive " +
                                 $"'{drive.RootDirectory.FullName}'. Users frequently extract PCILeech, " +
                                 "MemProcFS, or ZDMA tools to drive roots. The presence of this " +
                                 "directory confirms DMA cheat infrastructure was deployed on this machine.",
                        Detail = $"Directory: {dmaDir}"
                    });

                    try
                    {
                        await ScanDirForDmaExecutablesAsync(ctx, dmaDir, SearchOption.AllDirectories, ct);
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
        }
        catch (IOException) { }
    }

    private async Task ScanDmaLibraryFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            UserProfile,
            Desktop,
            Downloads,
            Documents,
            AppDataRoaming,
            AppDataLocal,
        };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                IEnumerable<string> dlls;
                try
                {
                    dlls = Directory.EnumerateFiles(dir, "*.dll", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var filePath in dlls)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(filePath);
                    var libMatch = DmaLibraryFiles.FirstOrDefault(n =>
                        n.Equals(fileName, StringComparison.OrdinalIgnoreCase));

                    if (libMatch is null) continue;

                    bool inSystem32 = filePath.StartsWith(System32, StringComparison.OrdinalIgnoreCase);
                    if (inSystem32) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"DMA framework library in user directory: {fileName}",
                        Risk = RiskLevel.High,
                        Location = filePath,
                        FileName = fileName,
                        Reason = $"DMA framework library '{fileName}' found in a user-accessible " +
                                 $"directory: '{dir}'. {GetLibraryDescription(fileName)} " +
                                 "These libraries only serve a purpose when DMA hardware is connected " +
                                 "and DMA cheat software is in use.",
                        Detail = $"Path: {filePath}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }

            await Task.Yield();
        }
    }

    private async Task ScanPcileechDirectoriesAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchBases = new[]
        {
            UserProfile,
            Desktop,
            Downloads,
            Documents,
            AppDataRoaming,
            AppDataLocal,
            Path.GetTempPath(),
        };

        foreach (var baseDir in searchBases)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(baseDir)) continue;

            try
            {
                IEnumerable<string> subdirs;
                try
                {
                    subdirs = Directory.EnumerateDirectories(baseDir, "*", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var subdir in subdirs)
                {
                    ct.ThrowIfCancellationRequested();
                    var dirName = Path.GetFileName(subdir);

                    var dirMatch = PcileechDirectoryNames.FirstOrDefault(n =>
                        n.Equals(dirName, StringComparison.OrdinalIgnoreCase)
                        || dirName.Contains(n, StringComparison.OrdinalIgnoreCase));

                    if (dirMatch is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"DMA tool directory found: {dirName}",
                            Risk = RiskLevel.Critical,
                            Location = subdir,
                            FileName = dirName,
                            Reason = $"Directory '{dirName}' matches a known DMA cheat tool package " +
                                     $"name (pattern: '{dirMatch}'). PCILeech, MemProcFS, ZDMA, " +
                                     "and Screamer are the primary software components of FPGA-based " +
                                     "DMA cheat systems. Their directory presence confirms the software " +
                                     "was extracted and likely used on this machine.",
                            Detail = $"Directory path: {subdir}"
                        });
                    }

                    try
                    {
                        foreach (var batFile in DmaFirmwareFiles)
                        {
                            var batPath = Path.Combine(subdir, batFile);
                            if (!File.Exists(batPath)) continue;

                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"DMA connection script: {batFile}",
                                Risk = RiskLevel.Critical,
                                Location = batPath,
                                FileName = batFile,
                                Reason = $"DMA connection batch script '{batFile}' found in '{dirName}'. " +
                                         "These scripts automate the connection between the host PC and " +
                                         "the DMA hardware card, configuring the FPGA device and " +
                                         "launching the memory access framework. This file is " +
                                         "definitive evidence of DMA cheat infrastructure.",
                                Detail = $"Script: {batPath}"
                            });
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }

                    await Task.Yield();
                }
            }
            catch (UnauthorizedAccessException) { }
        }

        await ScanForFirmwareBatFilesAsync(ctx, ct);
    }

    private async Task ScanForFirmwareBatFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            Desktop,
            Downloads,
            Documents,
            UserProfile,
        };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var batName in DmaFirmwareFiles)
                {
                    var batPath = Path.Combine(dir, batName);
                    if (!File.Exists(batPath)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"DMA firmware connection script at top level: {batName}",
                        Risk = RiskLevel.Critical,
                        Location = batPath,
                        FileName = batName,
                        Reason = $"DMA connection batch script '{batName}' found directly in " +
                                 $"'{dir}'. This script establishes the link between DMA cheat " +
                                 "software and the FPGA hardware card over USB. Its presence at " +
                                 "a prominent location indicates regular use.",
                        Detail = $"Path: {batPath}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        await Task.Yield();
    }

    private async Task ScanDmaConfigFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            UserProfile,
            Desktop,
            Downloads,
            Documents,
            AppDataRoaming,
            AppDataLocal,
            Path.GetTempPath(),
        };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                await ScanDirForDmaConfigsAsync(ctx, dir, SearchOption.TopDirectoryOnly, ct);
            }
            catch (UnauthorizedAccessException) { }
        }

        foreach (var baseDir in new[] { AppDataRoaming, AppDataLocal })
        {
            if (!Directory.Exists(baseDir)) continue;
            IEnumerable<string> subdirs;
            try
            {
                subdirs = Directory.EnumerateDirectories(baseDir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var subdir in subdirs)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    await ScanDirForDmaConfigsAsync(ctx, subdir, SearchOption.TopDirectoryOnly, ct);
                }
                catch (UnauthorizedAccessException) { }
                await Task.Yield();
            }
        }
    }

    private async Task ScanDirForDmaConfigsAsync(
        ScanContext ctx, string directory, SearchOption option, CancellationToken ct)
    {
        IEnumerable<string> jsonFiles;
        try
        {
            jsonFiles = Directory.EnumerateFiles(directory, "*.json", option)
                .Concat(Directory.EnumerateFiles(directory, "*.cfg", option));
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var filePath in jsonFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync();
            }
            catch (IOException) { continue; }
            catch (UnauthorizedAccessException) { continue; }

            var lowerContent = content.ToLowerInvariant();

            var matchedGame = TargetGameProcesses.FirstOrDefault(g =>
                content.Contains(g, StringComparison.OrdinalIgnoreCase));

            var matchedOffsets = DmaConfigOffsetKeywords
                .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (matchedGame is null && matchedOffsets.Count < 4) continue;

            var fileName = Path.GetFileName(filePath);

            if (matchedGame is not null && matchedOffsets.Count >= 3)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"DMA cheat configuration file: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = filePath,
                    FileName = fileName,
                    Reason = $"Config file '{fileName}' targets game process '{matchedGame}' and " +
                             $"contains {matchedOffsets.Count} DMA/cheat offset keywords: " +
                             $"{string.Join(", ", matchedOffsets.Take(5))}. " +
                             "DMA cheats require game-specific memory offset configs to locate " +
                             "entity lists, view matrices, and player positions via direct " +
                             "physical memory reads. This file is DMA cheat configuration.",
                    Detail = $"Target game: {matchedGame} | Offset keywords: {string.Join(", ", matchedOffsets)}"
                });
            }
            else if (matchedOffsets.Count >= 5)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Suspected DMA offset config file: {fileName}",
                    Risk = RiskLevel.High,
                    Location = filePath,
                    FileName = fileName,
                    Reason = $"Config file '{fileName}' contains {matchedOffsets.Count} keywords " +
                             $"consistent with DMA cheat memory offset configuration: " +
                             $"{string.Join(", ", matchedOffsets.Take(6))}. " +
                             "DMA cheats use JSON configs to store memory offsets for reading " +
                             "game data over PCIe without a game process injection.",
                    Detail = $"Matched: {string.Join(", ", matchedOffsets)}"
                });
            }
        }
    }

    private async Task ScanRadarInfrastructureAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            UserProfile,
            Desktop,
            Downloads,
            Documents,
            AppDataRoaming,
            AppDataLocal,
            Path.GetTempPath(),
        };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(dir, "*.exe", SearchOption.TopDirectoryOnly)
                        .Concat(Directory.EnumerateFiles(dir, "*.html", SearchOption.TopDirectoryOnly))
                        .Concat(Directory.EnumerateFiles(dir, "*.json", SearchOption.TopDirectoryOnly));
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var filePath in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(filePath);

                    var radarExeMatch = DmaRadarExecutables.FirstOrDefault(n =>
                        n.Equals(fileName, StringComparison.OrdinalIgnoreCase));
                    if (radarExeMatch is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"DMA radar server/client executable: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = filePath,
                            FileName = fileName,
                            Reason = $"Executable '{fileName}' is a known DMA radar tool. " +
                                     "DMA radar systems transmit game state (player positions, " +
                                     "loot, enemies) from the DMA reading PC to a second device " +
                                     "over WebSocket or local network. The second device displays " +
                                     "a radar overlay. This component is part of a two-PC DMA " +
                                     "cheat setup.",
                            Detail = $"Path: {filePath}"
                        });
                        continue;
                    }

                    if (fileName.Equals("radar.html", StringComparison.OrdinalIgnoreCase))
                    {
                        string content = string.Empty;
                        try
                        {
                            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync();
                        }
                        catch (IOException) { continue; }

                        var matchedRadarKw = RadarConfigKeywords
                            .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        if (matchedRadarKw.Count >= 4)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "DMA web radar HTML page: radar.html",
                                Risk = RiskLevel.Critical,
                                Location = filePath,
                                FileName = "radar.html",
                                Reason = $"radar.html contains {matchedRadarKw.Count} radar-related " +
                                         $"keywords: {string.Join(", ", matchedRadarKw.Take(6))}. " +
                                         "DMA web radars display game data received from the DMA " +
                                         "reading process in a browser, showing enemy positions " +
                                         "and loot on a minimap without game injection.",
                                Detail = $"Radar keywords: {string.Join(", ", matchedRadarKw)}"
                            });
                        }
                        continue;
                    }

                    if (fileName.Equals("config.json", StringComparison.OrdinalIgnoreCase)
                        || fileName.Equals("radar_config.json", StringComparison.OrdinalIgnoreCase)
                        || fileName.Equals("settings.json", StringComparison.OrdinalIgnoreCase))
                    {
                        string content = string.Empty;
                        try
                        {
                            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync();
                        }
                        catch (IOException) { continue; }

                        bool hasIp = content.Contains("\"ip\"", StringComparison.OrdinalIgnoreCase)
                                  || content.Contains("\"host\"", StringComparison.OrdinalIgnoreCase);
                        bool hasPort = content.Contains("\"port\"", StringComparison.OrdinalIgnoreCase);
                        bool hasGame = TargetGameProcesses.Any(g =>
                            content.Contains(g, StringComparison.OrdinalIgnoreCase));

                        var matchedRadarKw = RadarConfigKeywords
                            .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        if (hasIp && hasPort && (hasGame || matchedRadarKw.Count >= 4))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"DMA radar server config: {fileName}",
                                Risk = RiskLevel.High,
                                Location = filePath,
                                FileName = fileName,
                                Reason = $"Config file '{fileName}' has ip/port fields and " +
                                         (hasGame ? $"targets a game process" : $"{matchedRadarKw.Count} radar keywords") +
                                         ". DMA radar systems use network configs to specify " +
                                         "the IP and port of the receiving radar client on a " +
                                         "second PC or phone. This is a DMA radar configuration.",
                                Detail = $"Radar config keywords: {string.Join(", ", matchedRadarKw.Take(6))}"
                            });
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }

            await Task.Yield();
        }
    }

    private void ScanDmaRegistryArtifacts(ScanContext ctx, CancellationToken ct)
    {
        const string servicesKey = @"SYSTEM\CurrentControlSet\Services";
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var svcRoot = baseKey.OpenSubKey(servicesKey, writable: false);
            if (svcRoot is null) return;

            foreach (var svcName in svcRoot.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                var matched = DmaRegistryServiceFragments.FirstOrDefault(f =>
                    svcName.Contains(f, StringComparison.OrdinalIgnoreCase));
                if (matched is null) continue;

                string? imagePath = null;
                try
                {
                    using var svcKey = svcRoot.OpenSubKey(svcName, writable: false);
                    imagePath = svcKey?.GetValue("ImagePath")?.ToString();
                }
                catch { }

                bool isHighConfidence = new[] { "pcileech", "leechcore", "memprocfs", "memflow", "zdma", "screamer" }
                    .Any(f => svcName.Contains(f, StringComparison.OrdinalIgnoreCase));

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = isHighConfidence
                        ? $"DMA cheat software service: {svcName}"
                        : $"DMA hardware driver service: {svcName}",
                    Risk = isHighConfidence ? RiskLevel.Critical : RiskLevel.High,
                    Location = $@"HKLM\{servicesKey}\{svcName}",
                    Reason = isHighConfidence
                        ? $"Windows service '{svcName}' matches DMA cheat software (pattern: '{matched}'). " +
                          "PCILeech, LeechCore, MemProcFS, and MemFlow are the core libraries of " +
                          "FPGA-based DMA cheat frameworks. A service registration confirms this " +
                          "software was installed and configured for persistence."
                        : $"Windows service '{svcName}' matches DMA hardware driver (pattern: '{matched}'). " +
                          "FTDI FT600/FT601 and Cypress USB3 drivers are used by DMA cheat boards " +
                          "(PCIe Squirrel, ZDMA, Screamer M2) to communicate with the host PC. " +
                          "This driver may belong to legitimate hardware but is worth reviewing " +
                          "in the context of other DMA indicators.",
                    Detail = imagePath is null ? null : $"ImagePath: {imagePath}"
                });
            }
        }
        catch { }
    }

    private async Task ScanFtdiDriverArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var nonStandardPaths = new[]
        {
            UserProfile,
            Desktop,
            Downloads,
            Documents,
            AppDataRoaming,
            AppDataLocal,
            Path.GetTempPath(),
        };

        foreach (var dir in nonStandardPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                IEnumerable<string> sysFiles;
                try
                {
                    sysFiles = Directory.EnumerateFiles(dir, "*.sys", SearchOption.TopDirectoryOnly)
                        .Concat(Directory.EnumerateFiles(dir, "*.inf", SearchOption.TopDirectoryOnly));
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var filePath in sysFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(filePath);
                    var driverMatch = FtdiDriverPaths.FirstOrDefault(d =>
                        d.Equals(fileName, StringComparison.OrdinalIgnoreCase));

                    if (driverMatch is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FTDI DMA hardware driver in non-standard path: {fileName}",
                        Risk = RiskLevel.High,
                        Location = filePath,
                        FileName = fileName,
                        Reason = $"FTDI driver file '{fileName}' found outside standard Windows driver " +
                                 "directories. FTDI bus and port drivers are required by DMA cheat " +
                                 "hardware boards (PCIe Squirrel, ZDMA, Screamer M2) that use FTDI " +
                                 "FT600/FT601 chips as the USB interface between the FPGA and the host. " +
                                 "Driver files in user directories suggest manual DMA hardware setup.",
                        Detail = $"Path: {filePath}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }

            await Task.Yield();
        }

        ScanFtdiRegistryArtifacts(ctx, ct);
    }

    private static void ScanFtdiRegistryArtifacts(ScanContext ctx, CancellationToken ct)
    {
        var ftdiRegistryKeys = new[]
        {
            @"SYSTEM\CurrentControlSet\Enum\USB\VID_0403&PID_601E",
            @"SYSTEM\CurrentControlSet\Enum\USB\VID_0403&PID_601F",
            @"SYSTEM\CurrentControlSet\Enum\USB\VID_04B4&PID_00F3",
            @"SYSTEM\CurrentControlSet\Enum\USB\VID_04B4&PID_4720",
            @"SOFTWARE\FTDI",
            @"SOFTWARE\WOW6432Node\FTDI",
        };

        foreach (var regPath in ftdiRegistryKeys)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementRegistryKeys();
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                using var key = baseKey.OpenSubKey(regPath, writable: false);
                if (key is null) continue;

                bool isFtdiUsbDevice = regPath.Contains("VID_0403", StringComparison.OrdinalIgnoreCase)
                                    || regPath.Contains("VID_04B4", StringComparison.OrdinalIgnoreCase);

                ctx.AddFinding(new Finding
                {
                    Module = "DMA Hardware Cheat Detection",
                    Title = isFtdiUsbDevice
                        ? $"DMA board USB device registry entry: {regPath.Split('\\').Last()}"
                        : "FTDI driver registry presence",
                    Risk = isFtdiUsbDevice ? RiskLevel.High : RiskLevel.Medium,
                    Location = $@"HKLM\{regPath}",
                    Reason = isFtdiUsbDevice
                        ? $"USB device registry entry '{regPath}' corresponds to FTDI FT600/FT601 or " +
                          "Cypress FX3 chips. These USB chips are used almost exclusively in DMA " +
                          "cheat hardware boards (PCIe Squirrel uses VID_0403&PID_601F, ZDMA uses " +
                          "FT601). This entry shows a DMA-capable device was connected to this machine."
                        : "FTDI software registry key found. FTDI provides drivers for DMA cheat " +
                          "hardware. Combined with other DMA indicators this increases confidence.",
                    Detail = $"Registry key: HKLM\\{regPath}"
                });
            }
            catch { }
        }
    }

    private static void CheckRadarPortListeners(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            var ipGlobalProperties = IPGlobalProperties.GetIPGlobalProperties();

            var tcpListeners = ipGlobalProperties.GetActiveTcpListeners();
            var udpListeners = ipGlobalProperties.GetActiveUdpListeners();

            foreach (var radarPort in DmaRadarPorts)
            {
                ct.ThrowIfCancellationRequested();

                var tcpMatch = tcpListeners.FirstOrDefault(ep =>
                    ep.Port == radarPort &&
                    (ep.Address.Equals(IPAddress.Any) ||
                     ep.Address.Equals(IPAddress.Loopback) ||
                     ep.Address.Equals(IPAddress.IPv6Any) ||
                     ep.Address.Equals(IPAddress.IPv6Loopback)));

                if (tcpMatch is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "DMA Hardware Cheat Detection",
                        Title = $"DMA radar server port active: TCP {radarPort}",
                        Risk = RiskLevel.High,
                        Location = $"TCP:{radarPort} (listener: {tcpMatch.Address})",
                        Reason = $"A process is actively listening on TCP port {radarPort}, which is " +
                                 "a known DMA radar server port. DMA radar systems run a local " +
                                 "WebSocket server on known ports to stream game data (player positions, " +
                                 "enemies, loot) to a radar display on a second device. An active " +
                                 "listener on this port during a game session indicates a DMA radar " +
                                 "is running.",
                        Detail = $"TCP listener: {tcpMatch.Address}:{tcpMatch.Port}"
                    });
                }

                var udpMatch = udpListeners.FirstOrDefault(ep => ep.Port == radarPort);
                if (udpMatch is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "DMA Hardware Cheat Detection",
                        Title = $"DMA radar UDP port active: UDP {radarPort}",
                        Risk = RiskLevel.High,
                        Location = $"UDP:{radarPort} (listener: {udpMatch.Address})",
                        Reason = $"A process is listening on UDP port {radarPort}, a known DMA radar " +
                                 "data transmission port. Some DMA radar implementations use UDP " +
                                 "datagrams to broadcast game state to clients. This listener during " +
                                 "gameplay is a strong indicator of active DMA radar usage.",
                        Detail = $"UDP listener: {udpMatch.Address}:{udpMatch.Port}"
                    });
                }
            }

            CheckLoopbackDmaConnections(ctx, ct, ipGlobalProperties);
        }
        catch (NetworkInformationException) { }
        catch { }
    }

    private static void CheckLoopbackDmaConnections(
        ScanContext ctx, CancellationToken ct, IPGlobalProperties props)
    {
        try
        {
            var tcpConnections = props.GetActiveTcpConnections();

            foreach (var radarPort in DmaRadarPorts)
            {
                ct.ThrowIfCancellationRequested();

                var loopbackConn = tcpConnections.FirstOrDefault(conn =>
                    conn.LocalEndPoint.Port == radarPort &&
                    conn.RemoteEndPoint.Address.Equals(IPAddress.Loopback) &&
                    conn.State == TcpState.Established);

                if (loopbackConn is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "DMA Hardware Cheat Detection",
                    Title = $"DMA loopback connection on radar port: {radarPort}",
                    Risk = RiskLevel.High,
                    Location = $"TCP loopback {loopbackConn.LocalEndPoint} -> {loopbackConn.RemoteEndPoint}",
                    Reason = $"Established TCP loopback connection on port {radarPort} detected. " +
                             "This pattern is consistent with a DMA memory reader process sending " +
                             "game data over loopback to a local radar overlay client. Some DMA " +
                             "radar setups split the memory reader and display into separate " +
                             "processes communicating over loopback.",
                    Detail = $"Local: {loopbackConn.LocalEndPoint} | Remote: {loopbackConn.RemoteEndPoint} | State: Established"
                });
            }
        }
        catch { }
    }

    private static string GetLibraryDescription(string fileName)
    {
        if (fileName.Equals("leechcore.dll", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("leechcoredll.dll", StringComparison.OrdinalIgnoreCase))
            return "LeechCore.dll is the core hardware abstraction library of PCILeech, " +
                   "providing direct DMA read/write access over FPGA or USB3380. ";

        if (fileName.Equals("vmm.dll", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("vmmdll.dll", StringComparison.OrdinalIgnoreCase))
            return "VMM.dll is the Virtual Memory Manager of MemProcFS, which translates " +
                   "physical DMA reads into virtual memory addresses for game process inspection. ";

        if (fileName.Equals("FTD2XX.dll", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("ftd2xx.dll", StringComparison.OrdinalIgnoreCase))
            return "FTD2XX.dll is the FTDI USB driver library required to communicate with " +
                   "DMA hardware boards using FTDI FT600/FT601 USB chips (PCIe Squirrel, ZDMA). ";

        if (fileName.Equals("cyusb3.dll", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("CyUSB3.dll", StringComparison.OrdinalIgnoreCase))
            return "CyUSB3.dll is the Cypress FX3 USB3 driver library used in some DMA boards. ";

        return string.Empty;
    }
}
