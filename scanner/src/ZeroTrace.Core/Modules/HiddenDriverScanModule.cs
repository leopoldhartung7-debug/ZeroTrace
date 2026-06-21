using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Looks for kernel drivers that are LOADED in the kernel (visible via the
/// undocumented NtQuerySystemInformation SystemModuleInformation call) but are
/// NOT registered as a Windows service (invisible to WMI Win32_SystemDriver).
/// Rootkit-style cheats often load their driver kernel-mode without creating a
/// service entry, because DKOM (Direct Kernel Object Manipulation) or custom
/// loaders bypass the normal SCM path. A driver that is truly loaded but absent
/// from the WMI list AND is outside the Windows system driver directories is a
/// strong indicator. Requires admin rights; degrades gracefully without them.
/// Read-only.
/// </summary>
public sealed class HiddenDriverScanModule : IScanModule
{
    public string Name => "Versteckte Treiber";
    public double Weight => 0.5;

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(
        int SystemInformationClass,
        byte[] SystemInformation,
        int SystemInformationLength,
        out int ReturnLength);

    private const int SystemModuleInformation = 11;

    private static readonly string WinDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();

    // Standard kernel module locations: anything outside these is unusual.
    private static readonly string[] KnownGoodRoots =
    {
        Path.Combine(WinDir, "system32"),
        Path.Combine(WinDir, "syswow64"),
        Path.Combine(WinDir, "sysarm32"),
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            var ntModules = GetNtLoadedModules();
            if (ntModules.Count == 0)
            {
                ctx.Report(1.0, "Versteckte Treiber", "NtQuerySystemInformation nicht verfuegbar");
                return Task.CompletedTask;
            }

            var wmiPaths = GetWmiDriverPaths();

            int found = 0;
            foreach (var ntPath in ntModules)
            {
                if (ct.IsCancellationRequested || found >= 20) break;

                // Skip modules inside the Windows directory (ntoskrnl, hal, system DLLs, etc.)
                if (IsUnderKnownRoot(ntPath)) continue;

                // Check if any WMI entry matches this path (same file name at minimum)
                var ntFile = Path.GetFileName(ntPath).ToLowerInvariant();
                bool foundInWmi = wmiPaths.Any(w =>
                    Path.GetFileName(w).Equals(ntFile, StringComparison.OrdinalIgnoreCase));

                if (foundInWmi) continue;

                // Loaded outside Windows dirs but not in WMI service list = suspicious
                found++;
                var ind = ctx.Matcher.MatchFileName(Path.GetFileName(ntPath))
                          ?? ctx.Matcher.MatchFileNameKeyword(Path.GetFileName(ntPath))
                          ?? ctx.Matcher.MatchPathKeyword(ntPath);

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = ind is null
                        ? $"Geladener Treiber ohne Service-Eintrag: {Path.GetFileName(ntPath)}"
                        : $"Verdaechtiger versteckter Treiber ({ind.Category}): {Path.GetFileName(ntPath)}",
                    Risk = ind?.Risk ?? RiskLevel.High,
                    Location = ntPath,
                    FileName = Path.GetFileName(ntPath),
                    Reason = $"Der Kernel-Treiber '{Path.GetFileName(ntPath)}' ist geladen " +
                             "(sichtbar per NtQuerySystemInformation), hat aber keinen " +
                             "entsprechenden Windows-Service-Eintrag (nicht in WMI " +
                             "Win32_SystemDriver). Das deutet auf einen manuell geladenen " +
                             "oder per DKOM versteckten Rootkit-/Cheat-Treiber hin." +
                             (ind is null ? "" : $" Indikator '{ind.Pattern}': {ind.Description}"),
                    Detail = $"NT-Pfad: {ntPath}"
                });
            }
        }
        catch { }

        ctx.Report(1.0, "Versteckte Treiber", "Treiber-Vergleich abgeschlossen");
        return Task.CompletedTask;
    }

    /// <summary>
    /// Returns loaded kernel module paths via NtQuerySystemInformation
    /// (SystemModuleInformation = 11). Paths are normalized to lowercase
    /// absolute Windows paths.
    /// </summary>
    private static HashSet<string> GetNtLoadedModules()
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // First call to determine required buffer size.
        NtQuerySystemInformation(SystemModuleInformation, Array.Empty<byte>(), 0, out int needed);
        if (needed <= 0) needed = 1024 * 1024;

        var buf = new byte[needed + 8192]; // margin for concurrent additions
        int status = NtQuerySystemInformation(SystemModuleInformation, buf, buf.Length, out _);
        if (status != 0) return result; // non-zero = error (e.g. access denied)

        // Buffer layout (x64):
        //   [0..3]  ULONG Count
        //   [4..7]  padding (alignment to pointer size)
        //   [8..]   SYSTEM_MODULE[Count]
        //
        // SYSTEM_MODULE (x64 = 296 bytes, x86 = 284 bytes):
        //   3 × PVOID  (24 bytes on x64)
        //   2 × ULONG  (8 bytes)
        //   4 × USHORT (8 bytes)
        //   CHAR[256]  (256 bytes)  <- FullPathName
        int ptrSize     = IntPtr.Size;
        int moduleSize  = 3 * ptrSize + 272;        // 296 on x64
        int pathOffset  = 3 * ptrSize + 16;          // 40 on x64
        int firstOffset = ptrSize;                   // 8 on x64 (after Count + padding)

        uint count = BitConverter.ToUInt32(buf, 0);
        for (uint i = 0; i < count; i++)
        {
            int off = firstOffset + (int)(i * moduleSize);
            if (off + pathOffset + 256 > buf.Length) break;

            var raw = Encoding.ASCII.GetString(buf, off + pathOffset, 256).TrimEnd('\0');
            if (string.IsNullOrEmpty(raw)) continue;

            // Normalize NT-style paths
            var norm = raw;
            if (norm.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
                norm = WinDir + norm[@"\SystemRoot".Length..].Replace('/', '\\');
            else if (norm.StartsWith(@"\WINDOWS\", StringComparison.OrdinalIgnoreCase))
                norm = WinDir + norm[@"\WINDOWS".Length..].Replace('/', '\\');

            try { norm = Path.GetFullPath(norm).ToLowerInvariant(); } catch { }
            result.Add(norm);
        }

        return result;
    }

    private static HashSet<string> GetWmiDriverPaths()
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT PathName FROM Win32_SystemDriver");
            foreach (ManagementObject mo in searcher.Get())
            {
                var p = mo["PathName"]?.ToString();
                if (!string.IsNullOrWhiteSpace(p))
                    result.Add(p.Trim().ToLowerInvariant());
            }
        }
        catch { }
        return result;
    }

    private static bool IsUnderKnownRoot(string path)
    {
        var lower = path.ToLowerInvariant();
        return KnownGoodRoots.Any(r => lower.StartsWith(r, StringComparison.OrdinalIgnoreCase));
    }
}
