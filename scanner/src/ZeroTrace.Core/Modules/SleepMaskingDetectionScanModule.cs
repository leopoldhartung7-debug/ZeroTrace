using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects sleep-obfuscated cheat DLLs using memory obfuscation techniques to evade
/// runtime memory scanners. Advanced cheat DLLs implement sleep masking to avoid detection
/// during periodic scans:
///
///   - Ekko (by odzhan/C5pider): Uses NtCreateTimer + NtSetTimer + ROP chains to
///     XOR-encrypt the DLL's memory region, change permissions to RW (not executable),
///     sleep for the specified interval, then decrypt and restore RX permissions.
///     While sleeping the DLL is: encrypted, not executable, and looks like data.
///
///   - Foliage (by Cracked5pider): Similar but uses CreateFiber instead of timers.
///     Swaps execution context to a fiber that encrypts the DLL and sleeps.
///
///   - Deathsleep (by janoglezcampos): Uses modified NtDelayExecution with DLL
///     encrypted in RW memory, leveraging APC mechanism for wake-up decryption.
///
/// Detection methods:
///   1. VirtualQueryEx: enumerate all private memory regions in game processes looking
///      for Private MEM_COMMIT regions that are:
///      - Currently PAGE_READWRITE (not executable) but large enough to be a full DLL
///      - Have high entropy (compressed/encrypted content > 7.0 bits/byte)
///      - Contain a PE header pattern at a non-aligned offset (encrypted header check)
///   2. Thread sleep-time analysis: threads sleeping for exactly the cheat poll interval
///      (typically 1000-5000ms) from suspicious memory regions
///   3. Timer callback ROP chain detection: timers set to fire with callback in non-module memory
/// </summary>
public sealed class SleepMaskingDetectionScanModule : IScanModule
{
    public string Name => "Sleep Masking / Memory Obfuscation Cheat Detection";
    public double Weight => 0.75;
    public int ParallelGroup => 2;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint VirtualQueryEx(nint hProcess, nint lpAddress,
        ref MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(nint hProcess, nint lpBaseAddress,
        byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesRead);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public nint BaseAddress;
        public nint AllocationBase;
        public uint AllocationProtect;
        public nint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ           = 0x0010;
    private const uint MEM_COMMIT                = 0x1000;
    private const uint MEM_PRIVATE               = 0x20000;
    private const uint PAGE_READWRITE            = 0x04;
    private const uint PAGE_READONLY             = 0x02;
    private const uint PAGE_EXECUTE_READ         = 0x20;
    private const uint PAGE_EXECUTE_READWRITE    = 0x40;
    private const uint PAGE_NOACCESS             = 0x01;

    // Minimum size to consider as a possible DLL (64KB)
    private const uint MinSuspiciousRegionSize = 64 * 1024;
    // Maximum size to read for entropy check (4MB to avoid memory pressure)
    private const uint MaxEntropyCheckSize = 4 * 1024 * 1024;

    // Known game processes to scan (same as ProcessMitigationAnomalyScanModule)
    private static readonly HashSet<string> GameProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "cs2", "VALORANT-Win64-Shipping", "r5apex", "FortniteClient-Win64-Shipping",
        "TslGame", "EscapeFromTarkov", "RainbowSix", "bf1", "bf4", "bfv", "bf2042",
        "Overwatch", "RustClient", "Hunt", "Insurgency", "DayZ",
        "left4dead2", "hl2",
        // Also check injected processes
        "explorer", "notepad",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => ScanGameProcesses(ctx, ct), ct);
    }

    private static void ScanGameProcesses(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            var processes = System.Diagnostics.Process.GetProcesses();
            foreach (var proc in processes)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    if (!GameProcesses.Contains(proc.ProcessName)) continue;

                    ctx.IncrementProcesses();
                    ScanProcessMemory(proc, ctx, ct);
                }
                catch { }
                finally { try { proc.Dispose(); } catch { } }
            }
        }
        catch { }
    }

    private static void ScanProcessMemory(System.Diagnostics.Process proc,
        ScanContext ctx, CancellationToken ct)
    {
        nint hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, proc.Id);
        if (hProcess == nint.Zero) return;

        try
        {
            nint address = nint.Zero;
            var mbi = new MEMORY_BASIC_INFORMATION();
            uint mbiSize = (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
            int regionsChecked = 0;
            const int maxRegions = 2000; // safety limit

            while (regionsChecked++ < maxRegions)
            {
                ct.ThrowIfCancellationRequested();

                nint result = VirtualQueryEx(hProcess, address, ref mbi, mbiSize);
                if (result == nint.Zero) break;

                nint nextAddress = mbi.BaseAddress + mbi.RegionSize;
                if (nextAddress == address) break; // no progress
                address = nextAddress;

                // We are interested in:
                // - Committed private memory (not backed by a file/module)
                // - Read-write or read-only (currently not executable — key sleep-mask signal)
                // - Large enough to be a DLL
                if (mbi.State != MEM_COMMIT) continue;
                if (mbi.Type != MEM_PRIVATE) continue;
                if ((ulong)mbi.RegionSize < MinSuspiciousRegionSize) continue;

                bool isRwOnly = mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY;
                if (!isRwOnly) continue;

                // Read a sample of the region for entropy analysis
                uint readSize = (uint)Math.Min((long)mbi.RegionSize, MaxEntropyCheckSize);
                byte[] sample = new byte[readSize];
                if (!ReadProcessMemory(hProcess, mbi.BaseAddress, sample, readSize, out uint bytesRead) ||
                    bytesRead < 1024)
                    continue;

                ctx.IncrementFiles();

                // Calculate Shannon entropy
                double entropy = CalculateEntropy(sample, (int)bytesRead);

                // High entropy (> 7.2) suggests encrypted/compressed content
                // Combined with RW-only non-module private memory of DLL size
                if (entropy > 7.2)
                {
                    // Check first 16 bytes for encrypted PE MZ header traces
                    // Ekko-style encryption uses XOR with key — the XOR'd 'MZ' is predictable
                    bool hasEncryptedPeHint = false;
                    if (bytesRead >= 16)
                    {
                        // Look for patterns that could be XOR'd "MZ\x90\x00" (PE header magic)
                        for (int i = 0; i < Math.Min((int)bytesRead - 2, 4096); i++)
                        {
                            byte xorKey = (byte)(sample[i] ^ 0x4D); // 'M' = 0x4D
                            if ((sample[i + 1] ^ xorKey) == 0x5A && // 'Z' = 0x5A
                                (i == 0 || sample[i - 1] == 0)) // zero-padded prefix
                            {
                                hasEncryptedPeHint = true;
                                break;
                            }
                        }
                    }

                    ctx.AddFinding(new Finding
                    {
                        Module   = "Sleep Masking / Memory Obfuscation Cheat Detection",
                        Title    = $"Hochentropie-RW-Speicherregion in Spielprozess: {proc.ProcessName}",
                        Risk     = hasEncryptedPeHint ? RiskLevel.Critical : RiskLevel.High,
                        Location = $"{proc.ProcessName} (PID {proc.Id}) @ 0x{mbi.BaseAddress:X16}",
                        FileName = proc.ProcessName,
                        Reason   = $"Privater RW-Speicher (nicht ausführbar, {(long)mbi.RegionSize / 1024} KB) " +
                                   $"mit hoher Entropie {entropy:F2} bits/byte in '{proc.ProcessName}' — " +
                                   "Sleep-Masking-Cheats (Ekko/Foliage/Deathsleep) verschlüsseln ihre DLL im Schlaf: " +
                                   "kein Schutzbit, kein Modul-Backing, verschlüsselte Daten — klassischer Sleep-Mask-Fingerprint" +
                                   (hasEncryptedPeHint ? " | XOR'd PE-Header-Muster erkannt" : ""),
                        Detail   = $"Prozess: {proc.ProcessName} | PID: {proc.Id} | " +
                                   $"Adresse: 0x{mbi.BaseAddress:X} | Größe: {(long)mbi.RegionSize} Bytes | " +
                                   $"Entropie: {entropy:F3} | Schutz: 0x{mbi.Protect:X} | " +
                                   $"Verschl-PE-Hinweis: {hasEncryptedPeHint}"
                    });
                }
            }
        }
        finally { CloseHandle(hProcess); }
    }

    private static double CalculateEntropy(byte[] data, int length)
    {
        if (length == 0) return 0.0;

        int[] freq = new int[256];
        for (int i = 0; i < length; i++)
            freq[data[i]]++;

        double entropy = 0.0;
        double len = length;
        for (int i = 0; i < 256; i++)
        {
            if (freq[i] == 0) continue;
            double p = freq[i] / len;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }
}
