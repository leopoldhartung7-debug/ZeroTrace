using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans game process private memory for cheat-related strings and C2 indicators.
///
/// Cheat software typically contains hardcoded strings that serve as strong indicators:
///
///   1. License server URLs and domain names:
///      Many external cheats use a license/authentication server to prevent unauthorized
///      use. The URL or domain is embedded in the cheat DLL or injected shellcode.
///      Examples: "auth.cheatprovider.com", "api.megacheat.gg", "license.hacktools.net"
///
///   2. Telegram bot API strings:
///      Some cheats communicate with their C2 via Telegram:
///      "https://api.telegram.org/bot" — bot API base URL
///      "chat_id" — target chat identifier
///      Telegram tokens format: 10-digit number + colon + 35-char alphanumeric string
///
///   3. Discord webhook URLs:
///      "https://discord.com/api/webhooks/" — Discord webhook for C2 or crash reporting
///      "https://discordapp.com/api/webhooks/" — legacy Discord webhook URL
///
///   4. Known cheat tool identifier strings:
///      Cheat executables often contain their own name or version strings
///      Examples: "aimware", "skeet.cc", "fatality", "otc", "gamesense",
///      "neverlose", "primordial", "knifebot", "legitbot", "hvh"
///
///   5. Kernel driver communication strings:
///      "\\\\.\\\\" (device path prefix) — kernel driver DeviceIoControl access
///      "\\Device\\", "\\BaseNamedObjects\\" — NT object path references
///      Known cheat driver names: "iqvw64e", "dbutil_2_3", "mhyprot2"
///
///   6. Anti-analysis indicator strings (the cheat tries to detect analysis):
///      "vmware", "vbox", "virtualbox", "wireshark", "processhacker", "x64dbg",
///      "cheatengine", "ida pro", "ollydbg" — cheat's own detection blacklist strings
///
///   7. DMA (Direct Memory Access) tool strings:
///      "PCILeech", "MEM_MAP", "LeechCore", "FPGA", "DMA_READ"
///      "vmmdll", "FTD2XX", "FTDI"
///
/// Scanning approach:
///   1. Walk all private non-image memory regions in game processes
///   2. Read the region content
///   3. Extract both ASCII and Unicode strings (minimum length 8 characters)
///   4. Match against the cheat indicator string database
///   5. Flag regions containing ≥1 strong indicator OR ≥2 medium indicators
///   6. Report the specific matched strings for forensic evidence
/// </summary>
public sealed class ProcessMemoryStringsScanModule : IScanModule
{
    public string Name => "Prozessspeicher-String-Analyse";
    public double Weight => 1.0;
    public int ParallelGroup => 0;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint   AllocationProtect;
        public IntPtr RegionSize;
        public uint   State;
        public uint   Protect;
        public uint   Type;
    }

    private const uint PROCESS_VM_READ          = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint MEM_COMMIT               = 0x1000;
    private const uint MEM_IMAGE                = 0x1000000;

    // Maximum region size to scan per region
    private const long MaxRegionScanBytes = 2 * 1024 * 1024; // 2 MB
    // Minimum string length to extract
    private const int MinStringLength = 8;

    // HIGH confidence indicators (single match = Critical finding)
    private static readonly string[] HighConfidenceIndicators =
    {
        "https://api.telegram.org/bot",
        "https://discord.com/api/webhooks/",
        "https://discordapp.com/api/webhooks/",
        "aimware.net", "skeet.cc", "fatality.win", "gamesense.pub",
        "neverlose.cc", "primordial.gg", "otc.gg", "kiddion",
        "2take1", "cherax", "eulen.cc", "ufccheat", "iniuria",
        "cheatautomation.com", "ring-1.io", "lucid-cheats",
        "mhyprot2.sys", "dbutil_2_3.sys", "iqvw64e.sys",
        "PCILeech", "LeechCore", "vmmdll.dll", "FTD2XX.dll",
        "DirectMem", "FPGA_DMA", "DMA_read_scatter",
        "silentaim", "triggerbot_key", "bhop_key", "esp_enabled",
        "aimbot_enabled", "wallhack", "spinbot",
    };

    // MEDIUM confidence indicators (2+ matches = High finding)
    private static readonly string[] MediumConfidenceIndicators =
    {
        "auth.php?key=", "license_key", "hwid_ban", "hwid_check",
        "api/getlicense", "api/verify", "api/auth",
        "vmware", "virtualbox", "vbox", "qemu",
        "wireshark", "processhacker", "x64dbg", "cheatengine",
        "\\Device\\", "\\BaseNamedObjects\\",
        "NtOpenProcess failed", "inject_success", "inject_failed",
        "hook_installed", "module_injected",
        "aimbot", "norecoil", "rapidfire", "autofire",
        "legit_bot", "rage_bot", "resolver", "antiaim",
        "backtrack", "doubletap", "fakelag",
        "kernel_mode", "ring0", "um2km", "user_to_kernel",
        "BYOVD", "vulnerable_driver",
    };

    private static readonly HashSet<string> TargetProcesses =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "csgo.exe", "cs2.exe", "valorant.exe", "VALORANT-Win64-Shipping.exe",
            "r5apex.exe", "FortniteClient-Win64-Shipping.exe",
            "GTA5.exe", "EFT.exe", "pubg.exe",
            "overwatch.exe", "Overwatch.exe",
            "RainbowSix.exe", "dota2.exe",
        };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                string procExe = proc.ProcessName + ".exe";
                if (!TargetProcesses.Contains(procExe))
                {
                    proc.Dispose();
                    continue;
                }

                ctx.IncrementProcesses();
                IntPtr hProcess = IntPtr.Zero;
                try
                {
                    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                        false, proc.Id);
                    if (hProcess == IntPtr.Zero) continue;

                    hits += ScanProcessStrings(proc, hProcess, procExe, ctx, ct);
                }
                catch { }
                finally
                {
                    if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
                    proc.Dispose();
                }
            }
        }
        catch { }

        ctx.Report(1.0, Name, $"Prozessspeicher-Strings analysiert, {hits} Indikatoren");
        return Task.CompletedTask;
    }

    private static int ScanProcessStrings(Process proc, IntPtr hProcess, string procExe,
        ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            var mbi = new MEMORY_BASIC_INFORMATION();
            uint mbiSize = (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
            IntPtr addr = IntPtr.Zero;

            while (!ct.IsCancellationRequested)
            {
                if (!VirtualQueryEx(hProcess, addr, out mbi, mbiSize)) break;
                if (mbi.RegionSize == IntPtr.Zero) break;

                long regionBase = mbi.BaseAddress.ToInt64();
                long regionSize = mbi.RegionSize.ToInt64();

                try { addr = new IntPtr(regionBase + regionSize); } catch { break; }

                // Only private committed memory (not MEM_IMAGE = modules)
                if (mbi.State != MEM_COMMIT) continue;
                if (mbi.Type == MEM_IMAGE) continue;
                if (regionSize < MinStringLength) continue;

                int readSize = (int)Math.Min(regionSize, MaxRegionScanBytes);
                var buf = new byte[readSize];
                if (!ReadProcessMemory(hProcess, mbi.BaseAddress, buf, readSize, out int nRead)
                    || nRead < MinStringLength) continue;

                // Extract all printable ASCII strings and check against indicators
                var highMatches = new List<string>();
                var medMatches  = new List<string>();

                // ASCII strings
                int strStart = -1;
                for (int i = 0; i <= nRead; i++)
                {
                    bool printable = i < nRead && buf[i] >= 0x20 && buf[i] < 0x7F;
                    if (printable)
                    {
                        if (strStart < 0) strStart = i;
                    }
                    else if (strStart >= 0)
                    {
                        int len = i - strStart;
                        if (len >= MinStringLength)
                        {
                            string s = Encoding.ASCII.GetString(buf, strStart, len);
                            CheckString(s, highMatches, medMatches);
                        }
                        strStart = -1;
                    }
                }

                // Unicode (UTF-16 LE) strings — scan 2-byte aligned
                strStart = -1;
                for (int i = 0; i <= nRead - 1; i += 2)
                {
                    bool printable = i + 1 < nRead && buf[i] >= 0x20 && buf[i] < 0x7F && buf[i + 1] == 0;
                    if (printable)
                    {
                        if (strStart < 0) strStart = i;
                    }
                    else if (strStart >= 0)
                    {
                        int charCount = (i - strStart) / 2;
                        if (charCount >= MinStringLength)
                        {
                            string s = Encoding.Unicode.GetString(buf, strStart, i - strStart);
                            CheckString(s, highMatches, medMatches);
                        }
                        strStart = -1;
                    }
                }

                if (highMatches.Count == 0 && medMatches.Count < 2) continue;

                RiskLevel risk = highMatches.Count > 0 ? RiskLevel.Critical :
                                 medMatches.Count >= 3 ? RiskLevel.High : RiskLevel.Medium;

                string matchStr = highMatches.Count > 0
                    ? string.Join(", ", highMatches.Take(5))
                    : string.Join(", ", medMatches.Take(5));

                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "Prozessspeicher-String-Analyse",
                    Title    = $"Cheat-Indikatoren im Prozessspeicher: {procExe}",
                    Risk     = risk,
                    Location = $"PID {proc.Id}: 0x{regionBase:X} ({nRead / 1024}KB)",
                    Reason   = $"Privater Speicher von '{procExe}' (PID {proc.Id}) " +
                               $"bei 0x{regionBase:X} enthält " +
                               (highMatches.Count > 0
                                   ? $"{highMatches.Count} starke Cheat-Indikatoren"
                                   : $"{medMatches.Count} mittlere Cheat-Indikatoren") +
                               $": [{matchStr}]. " +
                               "Diese Strings sind im Speicher eines Spielprozesses " +
                               "nicht zu erwarten und deuten auf injizierte Cheat-Software hin. " +
                               "Starke Indikatoren: Cheat-Provider-Domains, Telegram/Discord-C2-URLs, " +
                               "DMA-Tool-Strings. Mittlere Indikatoren: Kernel-Treiberstrings, " +
                               "Anti-Debug-Blacklists, Cheat-Feature-Namen.",
                    Detail   = $"Addr=0x{regionBase:X} | Größe={nRead / 1024}KB | " +
                               $"Hochwertig=[{string.Join(", ", highMatches.Take(3))}] | " +
                               $"Mittel=[{string.Join(", ", medMatches.Take(3))}] | " +
                               $"Prozess={procExe} PID={proc.Id}"
                });

                if (hits >= 8) break; // Cap per process
            }
        }
        catch { }
        return hits;
    }

    private static void CheckString(string s, List<string> high, List<string> medium)
    {
        foreach (string indicator in HighConfidenceIndicators)
        {
            if (s.Contains(indicator, StringComparison.OrdinalIgnoreCase) &&
                !high.Any(h => h.Equals(indicator, StringComparison.OrdinalIgnoreCase)))
            {
                high.Add(indicator);
                return;
            }
        }
        foreach (string indicator in MediumConfidenceIndicators)
        {
            if (s.Contains(indicator, StringComparison.OrdinalIgnoreCase) &&
                !medium.Any(m => m.Equals(indicator, StringComparison.OrdinalIgnoreCase)))
            {
                medium.Add(indicator);
                return;
            }
        }
    }
}
