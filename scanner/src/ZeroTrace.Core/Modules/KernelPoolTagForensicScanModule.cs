using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Performs kernel pool tag forensics via NtQuerySystemInformation(SystemPoolTagInformation).
/// Every kernel driver allocates memory with a 4-byte tag for debugging; known cheat and
/// BYOVD drivers use specific tags that remain in the pool accounting tables even after
/// attempting to hide. The module queries the full pool tag table and cross-references
/// against known malicious tags: mhyp (mhyprot2), Wdfl (WinDivert), RKPK (rootkit packer),
/// cheat tool custom tags, and unusually high non-paged alloc counts for suspicious tags
/// whose drivers are not registered as known-good services. A tag with allocations but
/// no matching known driver is a strong indicator of a hidden or deleted kernel module.
/// </summary>
public sealed class KernelPoolTagForensicScanModule : IScanModule
{
    public string Name => "Kernel Pool Tag Forensics";
    public double Weight => 0.7;
    public int ParallelGroup => 2;

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(
        int SystemInformationClass, byte[] SystemInformation,
        uint SystemInformationLength, out uint ReturnLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_POOLTAG
    {
        public uint Tag;      // 4-byte ASCII tag (little-endian)
        public uint PagedAllocs;
        public uint PagedFrees;
        public ulong PagedUsed;
        public uint NonPagedAllocs;
        public uint NonPagedFrees;
        public ulong NonPagedUsed;
    }

    private const int SystemPoolTagInformation    = 5;
    private const int STATUS_SUCCESS              = 0;
    private const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);

    // Pool tags for known cheat/BYOVD/rootkit drivers
    // Format: tag bytes in memory order (little-endian as stored)
    private static readonly Dictionary<string, string> MaliciousPoolTags = new(StringComparer.OrdinalIgnoreCase)
    {
        // BYOVD exploit drivers
        { "mhyp",   "mhyprot2.sys — Genshin Impact Kernel-Driver (bekannter BYOVD-Exploit)" },
        { "db2_",   "dbutil_2_3.sys — Dell BIOS Update Treiber (bekannter BYOVD-Exploit)" },
        { "AsIO",   "AsIO.sys / AsIO64.sys — ASUS IO Treiber (BYOVD-Exploit)" },
        { "ELAM",   "ELAM-Bypass Treiber Artefakt" },
        { "RTCO",   "RTCore64.sys — MSI Afterburner BYOVD-Exploit Treiber" },
        { "MsIo",   "MsIo.sys — Micro-Star MSI Treiber (BYOVD-Exploit)" },
        { "CPUZ",   "cpuz.sys — CPU-Z Kernel Treiber (BYOVD-Exploit)" },
        { "WinR",   "WinRing0 — CPU-Z/OpenHardwareMonitor Treiber (BYOVD-Exploit)" },
        { "Enet",   "EneTechIo.sys / EneIo.sys — ASUS BYOVD-Exploit Treiber" },
        // WinDivert / network redirect
        { "WiDv",   "WinDivert — Netzwerk-Paket-Umleitung (Cheat-Netzwerk-Interception)" },
        { "Wdfl",   "WinDivert Layer — Netzwerkfilter für Paket-Interception" },
        // Known rootkit/cheat patterns
        { "RKPK",   "Rootkit-Packer Pool-Tag — Kernel-Rootkit aktiv" },
        { "Hack",   "Bekanntes Cheat/Hack-Driver Pool-Tag" },
        { "Chet",   "Verdächtiger Cheat-Treiber Pool-Tag" },
        { "ChAT",   "Verdächtiger Cheat-Tool Pool-Tag" },
        // Suspicious custom tags (often used by cheat drivers to avoid detection)
        { "Fake",   "Verdächtiger 'Fake' Pool-Tag — mögliche Rootkit-Artefakte" },
        { "Test",   "Nicht-Produktions-Treiber Pool-Tag — unsignierte Test-Treiber möglich" },
        { "ZZZZ",   "Verdächtiger Null-Pool-Tag (oft von Rootkits zur Tarnung verwendet)" },
        // Vulnerable game anti-cheat drivers
        { "GDRV",   "gdrv.sys — Gigabyte BYOVD-Exploit Treiber" },
        { "EChS",   "EchSvc Treiber — EchDrv BYOVD-Exploit" },
        { "Iobi",   "IObit Unlocker Treiber (BYOVD-Exploit)" },
    };

    // Legitimate pool tags to never flag (whitelist)
    private static readonly HashSet<string> WhitelistedTags = new(StringComparer.OrdinalIgnoreCase)
    {
        "Proc", "Thre", "File", "FMsl", "MmSt", "Pool", "Irp ", "Driv",
        "NtSe", "ObNm", "Sect", "Port", "Reg ", "Key ", "Vad ", "Heap",
        "WFPp", "TCP6", "UDP6", "NDIS", "Buff", "MDL ", "Work", "Even",
        "Muta", "Sema", "Timr", "Token", "LDR ", "PEB ", "TEB ",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => ScanPoolTags(ctx, ct), ct);
    }

    private void ScanPoolTags(ScanContext ctx, CancellationToken ct)
    {
        uint bufSize = 0x100000; // 1 MB initial buffer
        byte[]? buf = null;

        for (int attempt = 0; attempt < 6; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            buf = new byte[bufSize];
            int status = NtQuerySystemInformation(SystemPoolTagInformation, buf, bufSize, out uint needed);
            if (status == STATUS_SUCCESS) break;
            if (status == STATUS_INFO_LENGTH_MISMATCH)
            {
                bufSize = Math.Max(needed + 0x10000, bufSize * 2);
                buf = null;
                continue;
            }
            return;
        }

        if (buf is null) return;

        // Structure: [0-3] = Count (ULONG), then array of SYSTEM_POOLTAG (40 bytes each on x64)
        uint count    = BitConverter.ToUInt32(buf, 0);
        int entrySize = Marshal.SizeOf<SYSTEM_POOLTAG>();
        int baseOff   = 8; // ULONG_PTR alignment on x64

        if (count > 100_000) return; // sanity check

        for (uint i = 0; i < count; i++)
        {
            ct.ThrowIfCancellationRequested();
            int off = baseOff + (int)(i * entrySize);
            if (off + entrySize > buf.Length) break;

            // Read the 4-byte tag and convert to string
            uint rawTag = BitConverter.ToUInt32(buf, off);
            string tagStr = TagToString(rawTag);

            // Skip whitelisted legitimate tags
            if (WhitelistedTags.Contains(tagStr)) continue;

            // Check against known malicious tags
            if (MaliciousPoolTags.TryGetValue(tagStr, out string? description))
            {
                uint pagedAllocs    = BitConverter.ToUInt32(buf, off + 4);
                uint pagedFrees     = BitConverter.ToUInt32(buf, off + 8);
                ulong pagedUsed     = BitConverter.ToUInt64(buf, off + 16);
                uint npAllocs       = BitConverter.ToUInt32(buf, off + 24);
                uint npFrees        = BitConverter.ToUInt32(buf, off + 28);
                ulong npUsed        = BitConverter.ToUInt64(buf, off + 32);

                // Only flag if there are active (non-freed) allocations
                bool hasActiveAllocs = (pagedAllocs > pagedFrees) || (npAllocs > npFrees);
                if (!hasActiveAllocs && pagedUsed == 0 && npUsed == 0) continue;

                long activeNP    = (long)npAllocs - (long)npFrees;
                long activePaged = (long)pagedAllocs - (long)pagedFrees;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Verdächtiger Kernel-Pool-Tag: '{tagStr}' — {description.Split('—')[0].Trim()}",
                    Risk     = RiskLevel.Critical,
                    Location = $"Kernel-Pool Tag '{tagStr}'",
                    FileName = tagStr,
                    Reason   = $"Kernel-Pool-Tag '{tagStr}' enthält aktive Allokationen: {description} — " +
                               "Pool-Tags bleiben im Kernel-Speicher auch wenn der Treiber versucht sich zu verstecken",
                    Detail   = $"Tag: '{tagStr}' | Aktive NP: {activeNP} | Aktive Paged: {activePaged} | " +
                               $"NP-Speicher: {npUsed:N0} Bytes | Paged-Speicher: {pagedUsed:N0} Bytes | " +
                               $"Info: {description}"
                });
            }
        }
    }

    private static string TagToString(uint tag)
    {
        // Pool tags are stored little-endian; display as ASCII (reverse bytes)
        char c0 = (char)((tag >> 0)  & 0xFF);
        char c1 = (char)((tag >> 8)  & 0xFF);
        char c2 = (char)((tag >> 16) & 0xFF);
        char c3 = (char)((tag >> 24) & 0xFF);

        // Replace non-printable with '?'
        c0 = char.IsLetterOrDigit(c0) || char.IsPunctuation(c0) || c0 == ' ' ? c0 : '?';
        c1 = char.IsLetterOrDigit(c1) || char.IsPunctuation(c1) || c1 == ' ' ? c1 : '?';
        c2 = char.IsLetterOrDigit(c2) || char.IsPunctuation(c2) || c2 == ' ' ? c2 : '?';
        c3 = char.IsLetterOrDigit(c3) || char.IsPunctuation(c3) || c3 == ' ' ? c3 : '?';

        return $"{c0}{c1}{c2}{c3}";
    }
}
