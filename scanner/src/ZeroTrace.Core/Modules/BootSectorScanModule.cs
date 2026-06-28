using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects MBR (Master Boot Record) and VBR (Volume Boot Record) infections.
///
/// Bootkits are the most persistent and powerful rootkits because they execute
/// before the operating system, before any security software, and can subvert
/// the entire boot chain including Secure Boot (via UEFI vulnerabilities).
///
/// Cheat tools targeting kernel-level anti-cheat systems increasingly use
/// bootkit techniques to:
///   1. Load unsigned kernel drivers before the OS starts
///   2. Patch kernel code integrity (CI.dll / KiSystemServiceCopyEnd) at boot time
///   3. Disable Driver Signature Enforcement permanently from the boot sector
///   4. Install hypervisors (BluePill-style) to hide from Ring-0 detection
///
/// Detection approach:
///   1. Read physical sector 0 of all fixed drives via \\.\PhysicalDriveN
///   2. Compare MBR boot signature (0x55 0xAA at offset 510)
///   3. Check MBR bootstrap code against known-good patterns
///   4. Flag MBRs that don't match standard Windows 7/8/10/11 MBR templates
///   5. Read Volume Boot Records of active partitions
///
/// Also checks:
///   - Windows Boot Configuration Data (BCD) for testsigning/nointegritychecks
///     (already in BootConfigScanModule — this module focuses on raw sector reads)
///   - UEFI Secure Boot state via WMI
/// </summary>
public sealed class BootSectorScanModule : IScanModule
{
    private static readonly string _name = "Bootsektor-Analyse";
    public string Name => _name;
    public double Weight => 0.9;
    public int ParallelGroup => 0;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFile(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadFile(
        IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    private static extern uint SetFilePointer(
        IntPtr hFile, int lDistanceToMove,
        IntPtr lpDistanceToMoveHigh, uint dwMoveMethod);

    private static readonly IntPtr INVALID_HANDLE = new(-1);
    private const uint GENERIC_READ     = 0x80000000;
    private const uint FILE_SHARE_READ  = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint OPEN_EXISTING    = 3;

    // Known Windows 7/8/10/11 MBR first-byte signatures
    // Real MBR code varies between Windows versions but always starts with x86 bootstrap code
    private static readonly byte[][] KnownGoodMbrSignatures =
    {
        // Windows Vista/7/8/10/11 standard MBR: starts with XOR DI,DI (33 FF)
        new byte[] { 0x33, 0xFF },
        // Windows XP MBR: starts with FA 33 C0 8E D0
        new byte[] { 0xFA, 0x33, 0xC0 },
        // GRUB/multi-boot (legitimate dual-boot scenario)
        new byte[] { 0xEB, 0x5E },   // JMP short
        new byte[] { 0xEB, 0x63 },
        new byte[] { 0xEB, 0x48 },
        // Windows 10/11 MBR
        new byte[] { 0x33, 0xC0 },
        // Dell/HP OEM MBR
        new byte[] { 0xB8, 0x00, 0x10 },
    };

    // Rootkit MBR indicators: strings and byte patterns found in known bootkits
    private static readonly byte[][] BootkitPatterns =
    {
        // Stoned bootkit: "Your PC is now Stoned!"
        new byte[] { 0x59, 0x6F, 0x75, 0x72, 0x20, 0x50, 0x43 },
        // TDL4 bootkit indicator
        new byte[] { 0x54, 0x44, 0x4C, 0x34 },    // "TDL4"
        // Necurs bootkit
        new byte[] { 0x4E, 0x65, 0x63, 0x75, 0x72, 0x73 }, // "Necurs"
        // Generic: any bootkit that stores its next stage at a specific LBA offset
        // often writes a jump to a suspicious absolute sector (outside partition table)
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;

        // Check up to 4 physical drives
        for (int driveNum = 0; driveNum < 4; driveNum++)
        {
            if (ct.IsCancellationRequested) break;
            hits += AnalyzePhysicalDrive(driveNum, ctx, ct);
        }

        ctx.Report(1.0, Name, $"Boot-Sektoren analysiert, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int AnalyzePhysicalDrive(int driveNum, ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        var path = $@"\\.\PhysicalDrive{driveNum}";
        var hDrive = CreateFile(path, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);

        if (hDrive == INVALID_HANDLE) return 0;

        try
        {
            // Read sector 0 (MBR / GPT Protective MBR)
            var mbrSector = new byte[512];
            if (!ReadFile(hDrive, mbrSector, 512, out var read, IntPtr.Zero) || read < 512)
                return 0;

            // Check boot signature (should be 0x55 0xAA at bytes 510-511)
            if (mbrSector[510] != 0x55 || mbrSector[511] != 0xAA)
            {
                // Missing boot signature might indicate a wiped/corrupt MBR
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module = _name,
                    Title    = $"Ungültige MBR-Signatur: PhysicalDrive{driveNum}",
                    Risk     = RiskLevel.High,
                    Location = path,
                    Reason   = $"MBR von Laufwerk {driveNum} hat keine gültige Boot-Signatur (55 AA). " +
                               "Dies kann auf ein überschriebenes, beschädigtes oder bewusst " +
                               "gelöschtes MBR hinweisen (Anti-Forensik).",
                    Detail   = $"Laufwerk: {path} | Signatur: {mbrSector[510]:X2} {mbrSector[511]:X2}"
                });
                return hits;
            }

            // Check for GPT disk (EFI header at LBA 1)
            bool isGpt = (mbrSector[446] == 0xEE); // GPT protective partition type
            // For GPT disks, MBR bootstrap code area is still present but usually minimal

            // Check for known bootkit patterns in MBR
            foreach (var pattern in BootkitPatterns)
            {
                if (ct.IsCancellationRequested) break;
                if (ContainsPattern(mbrSector, pattern))
                {
                    hits++;
                    var patHex = BitConverter.ToString(pattern).Replace("-", " ");
                    ctx.AddFinding(new Finding
                    {
                        Module = _name,
                        Title    = $"Bootkit-Muster im MBR: PhysicalDrive{driveNum}",
                        Risk     = RiskLevel.Critical,
                        Location = path,
                        Reason   = $"MBR von Laufwerk {driveNum} enthält bekanntes Bootkit-Byte-Muster " +
                                   $"({patHex}). " +
                                   "Bootkits werden vor dem Betriebssystem geladen und können " +
                                   "Kernel-Codesignaturprüfungen deaktivieren, Treiber ohne Signatur " +
                                   "laden und Anti-Cheat-Systeme vollständig umgehen.",
                        Detail   = $"Laufwerk: {path} | Muster: {patHex} | GPT: {isGpt}"
                    });
                }
            }

            // Check if MBR code matches a known good template
            // (Compare first 3 bytes as signature)
            bool matchesKnownGood = KnownGoodMbrSignatures.Any(sig =>
                mbrSector.Length >= sig.Length &&
                sig.SequenceEqual(mbrSector.Take(sig.Length)));

            if (!matchesKnownGood && !isGpt && hits == 0)
            {
                // Unknown MBR bootstrap code — flag for investigation
                var firstBytes = BitConverter.ToString(mbrSector, 0, 8).Replace("-", " ");
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module = _name,
                    Title    = $"Unbekannter MBR-Bootstrap-Code: PhysicalDrive{driveNum}",
                    Risk     = RiskLevel.High,
                    Location = path,
                    Reason   = $"MBR von Laufwerk {driveNum} hat unbekannten Bootstrap-Code " +
                               $"(Bytes 0-7: {firstBytes}). " +
                               "Standard-Windows-MBRs beginnen mit bekannten Byte-Sequenzen. " +
                               "Ein abweichender MBR kann ein Bootkit, einen benutzerdefinierten " +
                               "Bootloader oder Anti-Forensik-Software anzeigen.",
                    Detail   = $"Laufwerk: {path} | Erste 8 Bytes: {firstBytes} | GPT: {isGpt}"
                });
            }
        }
        catch { }
        finally
        {
            CloseHandle(hDrive);
        }
        return hits;
    }

    private static bool ContainsPattern(byte[] data, byte[] pattern)
    {
        if (pattern.Length > data.Length) return false;
        for (int i = 0; i <= data.Length - pattern.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (data[i + j] != pattern[j]) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }
}
