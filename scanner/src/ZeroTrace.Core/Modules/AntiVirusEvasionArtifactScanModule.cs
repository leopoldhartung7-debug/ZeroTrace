using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class AntiVirusEvasionArtifactScanModule : IScanModule
{
    public string Name => "Anti-Virus / EDR Evasion Artifact Detection";
    public double Weight => 4.1;
    public int ParallelGroup => 4;

    private static readonly string[] EvasionToolNames =
    [
        "edrhook_bypass.exe", "edr_bypass.dll", "edrunhook.exe",
        "blindside.exe", "ppldump.exe", "edr_silencer.exe",
        "edr_killer.exe", "edr_disable.exe", "av_killer.exe",
        "av_bypass.exe", "av_disable.exe", "antivirus_bypass.exe",
        "defender_bypass.exe", "windefend_bypass.exe", "mde_bypass.exe",
        "mde_kill.exe", "defender_kill.exe", "tamper_disable.exe",
        "tamper_bypass.exe", "wdtamper.exe", "wdbypass.exe",
        "processprotect_bypass.exe", "ppl_bypass.exe", "ppl_dump.exe",
        "lsass_bypass.exe", "mimikatz_bypass.exe", "procdump_bypass.exe",
        "runpe.exe", "process_hollow.exe", "ghost_process.exe",
        "hollow_loader.exe", "process_ghost.exe", "phantom_loader.exe",
        "doppelganger.exe", "atom_bombing.exe", "heavens_gate.exe",
        "stackbomber.exe", "manual_syscall.exe", "unhook_ntdll.exe",
        "ntdll_unhook.exe", "ntdll_patch.exe", "edr_unhook.exe",
        "amsi_bypass.exe", "amsibypass.exe", "amsi_patch.exe",
        "amsi_kill.exe", "clm_bypass.exe", "applocker_bypass.exe",
        "wdac_bypass.exe", "wdac_bypass.dll", "wdac_bypass.sys",
        "obfuscated_bypass.exe", "encrypted_loader.exe", "packed_cheat.exe",
        "payload_loader.exe", "stage1_loader.exe", "stage2_loader.exe",
        "shellcode_loader.exe", "reflective_loader.exe", "pe_inject.exe",
        "pe_hollow.exe", "thread_hijack.exe", "apc_inject.exe",
        "setwindowshook.exe", "queueapc_inject.exe", "create_remote_thread.exe",
        "virtual_alloc_inject.exe", "heap_spray.exe", "rop_chain.exe",
    ];

    private static readonly string[] SuspiciousPayloadNames =
    [
        "payload.bin", "loader.bin", "cheat.bin", "inject.bin",
        "shellcode.bin", "stage1.bin", "stage2.bin", "stage3.bin",
        "packed.bin", "encrypted.bin", "obfuscated.bin", "bypass.bin",
        "payload.dat", "loader.dat", "cheat.dat", "inject.dat",
        "shellcode.dat", "encrypted.dat", "obfuscated.dat",
        "cheat_loader.bin", "cheat_payload.bin", "rootkit.bin",
        "driver_payload.bin", "kernel_payload.bin",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var tasks = new List<Task>
        {
            ScanDefenderExclusionsAsync(ctx, ct),
            ScanDefenderDisabledAsync(ctx, ct),
            ScanThirdPartyAvExclusionsAsync(ctx, ct),
            ScanEvasionToolsAsync(ctx, ct),
            ScanEdRBypassArtifactsAsync(ctx, ct),
            ScanPayloadBlobsAsync(ctx, ct),
            ScanObfuscatedFilesAsync(ctx, ct),
            ScanAmsiArtifactsAsync(ctx, ct),
        };
        await Task.WhenAll(tasks);
    }

    private async Task ScanDefenderExclusionsAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            var exclusionKeys = new Dictionary<string, string>
            {
                { @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths", "Excluded path" },
                { @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes", "Excluded process" },
                { @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions", "Excluded extension" },
                { @"SOFTWARE\Microsoft\Windows Defender\Exclusions\TemporaryPaths", "Excluded temp path" },
            };

            var suspiciousPathPatterns = new[]
            {
                "temp", "tmp", "appdata", "downloads", "desktop",
                "cheat", "hack", "aimbot", "bypass", "inject",
                "loader", "exploit", "crack", "keygen",
            };

            var suspiciousExtensions = new[] { ".sys", ".dll", ".drv" };
            var suspiciousProcesses = new[] { "cheat", "hack", "aimbot", "bypass", "inject", "exploit", "loader" };

            foreach (var (keyPath, description) in exclusionKeys)
            {
                foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
                {
                    try
                    {
                        using var key = hive.OpenSubKey(keyPath);
                        if (key == null) continue;

                        foreach (var valName in key.GetValueNames())
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementRegistryKeys();
                            var valLower = valName.ToLowerInvariant();

                            bool isSuspicious = false;
                            string reason = string.Empty;

                            if (keyPath.Contains("Paths"))
                            {
                                if (suspiciousPathPatterns.Any(p => valLower.Contains(p)))
                                {
                                    isSuspicious = true;
                                    reason = $"Defender path exclusion pointing to suspicious directory: {valName}";
                                }
                            }
                            else if (keyPath.Contains("Processes"))
                            {
                                if (suspiciousProcesses.Any(p => valLower.Contains(p)))
                                {
                                    isSuspicious = true;
                                    reason = $"Defender process exclusion for suspicious process: {valName}";
                                }
                            }
                            else if (keyPath.Contains("Extensions"))
                            {
                                if (suspiciousExtensions.Any(e => valLower.Contains(e)))
                                {
                                    isSuspicious = true;
                                    reason = $"Defender file extension exclusion for executable type: {valName}";
                                }
                            }

                            if (isSuspicious)
                            {
                                var hiveName = hive == Registry.LocalMachine ? "HKLM" : "HKCU";
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Suspicious Windows Defender Exclusion",
                                    Risk = Risk.High,
                                    Location = $@"{hiveName}\{keyPath}",
                                    FileName = "Registry",
                                    Reason = reason,
                                    Detail = $"Exclusion value: {valName} — cheats often add Defender exclusions to avoid detection"
                                });
                            }
                        }
                    }
                    catch { }
                }
            }
        }, ct);
    }

    private async Task ScanDefenderDisabledAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            var disableChecks = new[]
            {
                (@"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", 1, "Defender Anti-Spyware disabled by policy"),
                (@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", 1, "Defender real-time monitoring disabled"),
                (@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableBehaviorMonitoring", 1, "Defender behavior monitoring disabled"),
                (@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableOnAccessProtection", 1, "Defender on-access protection disabled"),
                (@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableIOAVProtection", 1, "Defender download scanning disabled"),
                (@"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection", 0, "Defender tamper protection disabled"),
                (@"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection", 4, "Defender tamper protection disabled (value=4)"),
                (@"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "SpyNetReporting", 0, "Defender cloud reporting disabled"),
            };

            foreach (var (keyPath, valueName, badValue, description) in disableChecks)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();
                    var val = key.GetValue(valueName);
                    if (val is int v && v == badValue)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Windows Defender Disabled",
                            Risk = Risk.Critical,
                            Location = $@"HKLM\{keyPath}",
                            FileName = "Registry",
                            Reason = description,
                            Detail = $"Registry: {keyPath}\\{valueName}={badValue}"
                        });
                    }
                }
                catch { }
            }

            // Check WinDefend service status
            try
            {
                using var winDefend = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\WinDefend");
                if (winDefend != null)
                {
                    ctx.IncrementRegistryKeys();
                    var start = winDefend.GetValue("Start");
                    if (start is int s && s == 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Windows Defender Service Disabled",
                            Risk = Risk.Critical,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Services\WinDefend",
                            FileName = "Registry",
                            Reason = "WinDefend service Start=4 (Disabled) — Defender engine not running",
                            Detail = "Cheats disable Defender service to avoid real-time detection"
                        });
                    }
                }
            }
            catch { }

            // Sense service (MDE Advanced Threat Protection)
            try
            {
                using var sense = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Sense");
                if (sense != null)
                {
                    ctx.IncrementRegistryKeys();
                    var start = sense.GetValue("Start");
                    if (start is int s && s == 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Microsoft Defender for Endpoint (Sense) Service Disabled",
                            Risk = Risk.High,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Services\Sense",
                            FileName = "Registry",
                            Reason = "MDE Sense service disabled — enterprise EDR detection bypassed",
                            Detail = "Disabling Sense prevents Microsoft Defender for Endpoint from monitoring"
                        });
                    }
                }
            }
            catch { }
        }, ct);
    }

    private async Task ScanThirdPartyAvExclusionsAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // Common third-party AV exclusion registry paths
            var avExclusionKeys = new[]
            {
                @"SOFTWARE\Kaspersky Lab\AVP",
                @"SOFTWARE\WOW6432Node\Kaspersky Lab\AVP",
                @"SOFTWARE\AVAST Software\Avast",
                @"SOFTWARE\WOW6432Node\AVAST Software\Avast",
                @"SOFTWARE\NortonLifeLock\Norton Security",
                @"SOFTWARE\Bitdefender",
                @"SOFTWARE\WOW6432Node\Bitdefender",
                @"SOFTWARE\ESET\ESET Security",
                @"SOFTWARE\Malwarebytes",
                @"SOFTWARE\WOW6432Node\Malwarebytes",
            };

            foreach (var avKey in avExclusionKeys)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(avKey);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();

                    // Check for exclusion subkeys
                    foreach (var subName in key.GetSubKeyNames())
                    {
                        if (!subName.Contains("exclusion", StringComparison.OrdinalIgnoreCase) &&
                            !subName.Contains("whitelist", StringComparison.OrdinalIgnoreCase) &&
                            !subName.Contains("exception", StringComparison.OrdinalIgnoreCase)) continue;

                        try
                        {
                            using var subKey = key.OpenSubKey(subName);
                            if (subKey == null) continue;
                            ctx.IncrementRegistryKeys();

                            foreach (var valName in subKey.GetValueNames())
                            {
                                ct.ThrowIfCancellationRequested();
                                var valLower = valName.ToLowerInvariant();
                                if (valLower.Contains("cheat") || valLower.Contains("hack") ||
                                    valLower.Contains("aimbot") || valLower.Contains("bypass") ||
                                    valLower.Contains("inject") || valLower.Contains("exploit"))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "Third-Party AV Exclusion for Suspicious Path",
                                        Risk = Risk.High,
                                        Location = $@"HKLM\{avKey}\{subName}",
                                        FileName = "Registry",
                                        Reason = $"AV exclusion with suspicious keyword: {valName}",
                                        Detail = $"Third-party AV ({Path.GetFileName(avKey)}) exclusion may protect cheat tool"
                                    });
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }, ct);
    }

    private async Task ScanEvasionToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                if (EvasionToolNames.Any(t => fn.Equals(t, StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "AV/EDR Evasion Tool Detected",
                        Risk = Risk.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Known AV/EDR evasion tool '{fn}' found",
                        Detail = "Cheat loaders use AV/EDR evasion to prevent detection during injection"
                    });
                }
            }
        }
    }

    private async Task ScanEdRBypassArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // Check for PPL (Protected Process Light) bypass indicators
            var pplBypassKeys = new[]
            {
                @"SYSTEM\CurrentControlSet\Services\lsass",
            };

            foreach (var pplKey in pplBypassKeys)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(pplKey);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();
                    var protection = key.GetValue("Start");
                    // If lsass Start is manually changed — suspicious
                    if (protection is int p && p != 2 && p != 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "LSASS Service Start Value Modified",
                            Risk = Risk.High,
                            Location = $@"HKLM\{pplKey}",
                            FileName = "Registry",
                            Reason = $"LSASS service Start={p} — unexpected value may indicate manipulation",
                            Detail = "Modified LSASS service settings may indicate credential dumping or PPL bypass"
                        });
                    }
                }
                catch { }
            }

            // ETW session manipulation — check for autologger tampering
            try
            {
                using var etw = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\WMI\Autologger");
                if (etw != null)
                {
                    ctx.IncrementRegistryKeys();
                    foreach (var session in etw.GetSubKeyNames())
                    {
                        try
                        {
                            using var s = etw.OpenSubKey(session);
                            if (s == null) continue;
                            ctx.IncrementRegistryKeys();
                            var enabled = s.GetValue("Start");
                            if (enabled is int e && e == 0 &&
                                (session.Contains("Defender", StringComparison.OrdinalIgnoreCase) ||
                                 session.Contains("Security", StringComparison.OrdinalIgnoreCase) ||
                                 session.Contains("Audit", StringComparison.OrdinalIgnoreCase)))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Security ETW Autologger Disabled",
                                    Risk = Risk.High,
                                    Location = $@"HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\{session}",
                                    FileName = "Registry",
                                    Reason = $"Security ETW autologger session '{session}' disabled (Start=0)",
                                    Detail = "Disabling security ETW sessions blinds AV/EDR behavioral monitoring"
                                });
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }, ct);
    }

    private async Task ScanPayloadBlobsAsync(ScanContext ctx, CancellationToken ct)
    {
        const long MinSuspiciousSizeBytes = 1_048_576; // 1 MB
        const long MaxSuspiciousSizeBytes = 500_000_000; // 500 MB upper sanity

        var searchDirs = new[]
        {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var fn = Path.GetFileName(file);
                var ext = Path.GetExtension(fn).ToLowerInvariant();

                // Check named payload files
                if (SuspiciousPayloadNames.Any(p => fn.Equals(p, StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Suspicious Payload Blob",
                        Risk = Risk.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Suspicious payload file '{fn}' found in temp/AppData directory",
                        Detail = "Cheat loaders store encrypted/packed payloads as .bin/.dat files"
                    });
                    continue;
                }

                // Large .bin or .dat files in temp
                if ((ext == ".bin" || ext == ".dat") && dir == Path.GetTempPath())
                {
                    try
                    {
                        ctx.IncrementFiles();
                        var info = new FileInfo(file);
                        if (info.Length >= MinSuspiciousSizeBytes && info.Length <= MaxSuspiciousSizeBytes)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Large Binary Blob in Temp Directory",
                                Risk = Risk.Medium,
                                Location = file,
                                FileName = fn,
                                Reason = $"Large binary file ({info.Length / 1024 / 1024} MB) in temp — possible cheat payload",
                                Detail = $"Extension: {ext}, Size: {info.Length} bytes"
                            });
                        }
                    }
                    catch (IOException) { }
                }
            }
        }
    }

    private async Task ScanObfuscatedFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        // Base64-encoded loader files — large .txt files in AppData
        const long MinBase64SizeBytes = 100_000; // 100 KB

        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(dir, "*.txt", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    var info = new FileInfo(file);
                    if (info.Length < MinBase64SizeBytes) continue;

                    ctx.IncrementFiles();
                    // Read first 512 bytes to check for base64 content
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    var buf = new byte[512];
                    var read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    var sample = System.Text.Encoding.ASCII.GetString(buf, 0, read);

                    // Base64 detection: mostly alphanumeric + /+=
                    var base64Chars = sample.Count(c =>
                        (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' || c == '\n' || c == '\r');
                    var ratio = (double)base64Chars / Math.Max(read, 1);

                    if (ratio > 0.95)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Possible Base64-Encoded Loader in AppData",
                            Risk = Risk.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Large text file ({info.Length / 1024} KB) appears to be Base64-encoded — possible cheat payload",
                            Detail = "Cheat loaders store Base64-encoded payloads as .txt files to evade AV scanning"
                        });
                    }
                }
                catch (IOException) { }
                catch (OperationCanceledException) { throw; }
            }
        }
    }

    private async Task ScanAmsiArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        // AMSI bypass tools and DLL replacement
        var sys32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var amsiPath = Path.Combine(sys32, "amsi.dll");

        if (File.Exists(amsiPath))
        {
            try
            {
                ctx.IncrementFiles();
                var info = new FileInfo(amsiPath);
                // Legitimate amsi.dll is ~60–150 KB
                if (info.Length < 40_000 || info.Length > 300_000)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "amsi.dll Size Anomaly",
                        Risk = Risk.Critical,
                        Location = amsiPath,
                        FileName = "amsi.dll",
                        Reason = $"amsi.dll has unexpected size: {info.Length / 1024} KB (expected 40–300 KB)",
                        Detail = "amsi.dll replacement is a common cheat loader technique to disable AMSI scanning"
                    });
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        // AMSI bypass PS scripts in AppData/temp
        var amsiBypassDirs = new[]
        {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };

        foreach (var dir in amsiBypassDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] psFiles;
            try { psFiles = Directory.GetFiles(dir, "*.ps1", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var psFile in psFiles)
            {
                ct.ThrowIfCancellationRequested();
                string content;
                try
                {
                    ctx.IncrementFiles();
                    using var fs = new FileStream(psFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                if (content.Contains("amsi", StringComparison.OrdinalIgnoreCase) &&
                    (content.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                     content.Contains("patch", StringComparison.OrdinalIgnoreCase) ||
                     content.Contains("disable", StringComparison.OrdinalIgnoreCase) ||
                     content.Contains("0xc3", StringComparison.OrdinalIgnoreCase) ||
                     content.Contains("AmsiScanBuffer", StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "AMSI Bypass PowerShell Script",
                        Risk = Risk.Critical,
                        Location = psFile,
                        FileName = Path.GetFileName(psFile),
                        Reason = "PowerShell script contains AMSI bypass code",
                        Detail = "AMSI bypass scripts patch AmsiScanBuffer to disable AV scanning of PS scripts"
                    });
                }
            }
        }
        await Task.CompletedTask;
    }
}
