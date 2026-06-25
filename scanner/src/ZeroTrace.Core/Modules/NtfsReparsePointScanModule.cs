using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects malicious NTFS reparse points (directory junctions and symlinks) in critical
/// system directories. Cheat tools and BYOVD loaders use NTFS junctions to redirect:
///   - \Windows\System32\drivers\someName.sys → cheat driver staging area
///   - Game directory DLL paths → cheat DLL without modifying game files
///   - Anti-cheat update directories → empty/fake paths to prevent AC updates
/// The module checks for unexpected reparse points in: System32, SysWOW64, Windows\Temp,
/// and Steam game directories. Also scans the game process working directories for symlinks
/// pointing outside expected game paths. Uses DeviceIoControl(FSCTL_GET_REPARSE_POINT)
/// to read reparse point data and extract junction targets for analysis.
/// </summary>
public sealed class NtfsReparsePointScanModule : IScanModule
{
    public string Name => "NTFS Reparse Point / Junction Hijack Detection";
    public double Weight => 0.65;
    public int ParallelGroup => 4;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern nint CreateFile(string lpFileName, uint dwAccess, uint dwShareMode,
        nint lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes,
        nint hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(nint hDevice, uint dwIoControlCode,
        nint lpInBuffer, uint nInBufferSize,
        nint lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, nint lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    private const uint FILE_FLAG_BACKUP_SEMANTICS       = 0x02000000;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT     = 0x00200000;
    private const uint OPEN_EXISTING                    = 3;
    private const uint FILE_READ_EA                     = 0x0008;
    private const uint FILE_SHARE_READ                  = 0x00000001;
    private const uint FILE_SHARE_WRITE                 = 0x00000002;
    private const uint FILE_SHARE_DELETE                = 0x00000004;
    private const uint FSCTL_GET_REPARSE_POINT          = 0x000900A8;
    private const uint IO_REPARSE_TAG_MOUNT_POINT       = 0xA0000003;
    private const uint IO_REPARSE_TAG_SYMLINK           = 0xA000000C;

    private static readonly string[] ScanDirectories =
    {
        @"C:\Windows\System32",
        @"C:\Windows\SysWOW64",
        @"C:\Windows\Temp",
        @"C:\Windows\System32\drivers",
    };

    private static readonly string[] SafeJunctionTargets =
    {
        @"c:\windows\",
        @"c:\program files\",
        @"c:\program files (x86)\",
        @"c:\users\",
        @"c:\programdata\",
    };

    private static readonly string[] SuspiciousTargetPatterns =
    {
        @"\temp\", @"\tmp\", @"\appdata\local\temp\",
        @"\downloads\", @"\desktop\",
        // Paths outside of Windows installation
        @"\users\public\",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            CheckSystemDirectories(ctx, ct);
            CheckSteamGameDirectories(ctx, ct);
        }, ct);
    }

    private void CheckSystemDirectories(ScanContext ctx, CancellationToken ct)
    {
        foreach (var dir in ScanDirectories)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                // Check directory itself for reparse point
                CheckPath(dir, ctx, ct, isSystemCritical: true);

                // Check subdirectories (one level deep to avoid huge scan)
                foreach (var sub in Directory.EnumerateFileSystemEntries(dir))
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        var attrs = File.GetAttributes(sub);
                        if ((attrs & FileAttributes.ReparsePoint) == 0) continue;
                        ctx.IncrementFiles();
                        CheckPath(sub, ctx, ct, isSystemCritical: true);
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    private void CheckSteamGameDirectories(ScanContext ctx, CancellationToken ct)
    {
        string[] steamRoots =
        {
            @"C:\Program Files\Steam\steamapps\common",
            @"C:\Program Files (x86)\Steam\steamapps\common",
            @"D:\Steam\steamapps\common",
            @"D:\Games\steamapps\common",
        };

        foreach (var root in steamRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            try
            {
                foreach (var gameDir in Directory.EnumerateDirectories(root))
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        // Check top-level game directory entries
                        foreach (var entry in Directory.EnumerateFileSystemEntries(gameDir))
                        {
                            ct.ThrowIfCancellationRequested();
                            try
                            {
                                var attrs = File.GetAttributes(entry);
                                if ((attrs & FileAttributes.ReparsePoint) == 0) continue;
                                ctx.IncrementFiles();
                                CheckPath(entry, ctx, ct, isSystemCritical: false);
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    private void CheckPath(string path, ScanContext ctx, CancellationToken ct, bool isSystemCritical)
    {
        try
        {
            var attrs = File.GetAttributes(path);
            if ((attrs & FileAttributes.ReparsePoint) == 0) return;

            // Read the reparse point target
            string? target = ReadReparsePointTarget(path);
            if (target is null) return;

            string targetLower = target.ToLowerInvariant();
            string pathLower   = path.ToLowerInvariant();
            string fileName    = Path.GetFileName(path);

            // For system directories, any unexpected junction is suspicious
            bool isSuspiciousTarget = isSystemCritical
                ? !Array.Exists(SafeJunctionTargets, t => targetLower.StartsWith(t))
                : Array.Exists(SuspiciousTargetPatterns, t => targetLower.Contains(t));

            if (!isSuspiciousTarget && !isSystemCritical) return;

            // Extra: check if target contains cheat-related keywords
            string[] cheatKeywords = { "cheat", "hack", "inject", "bypass", "spoof", "loader" };
            bool targetHasCheatKw = Array.Exists(cheatKeywords,
                kw => targetLower.Contains(kw));

            bool targetExists = Directory.Exists(target) || File.Exists(target);

            RiskLevel risk = (targetHasCheatKw || (isSystemCritical && !targetExists))
                ? RiskLevel.Critical
                : isSystemCritical ? RiskLevel.High : RiskLevel.Medium;

            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"NTFS-{(isSystemCritical ? "System-Verzeichnis" : "Spiel-Verzeichnis")}-Reparse-Point: {fileName}",
                Risk     = risk,
                Location = path,
                FileName = fileName,
                Reason   = isSystemCritical
                    ? $"NTFS-Reparse-Point '{path}' in kritischem System-Verzeichnis zeigt auf " +
                      $"'{target}' — Cheat-Tools können System32-DLL-Pfade auf eigene Implementierungen " +
                      "umleiten oder AC-Treiber-Verzeichnisse auf leere Pfade (AC-Update-Blockierung)"
                    : $"NTFS-Reparse-Point '{path}' in Spiel-Verzeichnis zeigt auf verdächtigen " +
                      $"Pfad '{target}' — kann genutzt werden um Spieldateien durch Cheat-DLLs " +
                      "zu ersetzen ohne die Originaldateien zu verändern",
                Detail   = $"Pfad: {path} | Ziel: {target} | " +
                           $"Ziel-Existiert: {targetExists} | " +
                           $"System-Kritisch: {isSystemCritical} | Cheat-Keyword: {targetHasCheatKw}"
            });
        }
        catch { }
    }

    private static string? ReadReparsePointTarget(string path)
    {
        nint hFile = CreateFile(path,
            FILE_READ_EA,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nint.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            nint.Zero);

        if (hFile == new nint(-1)) return null;

        try
        {
            uint bufSize = 16 * 1024;
            nint buf = Marshal.AllocHGlobal((int)bufSize);
            try
            {
                if (!DeviceIoControl(hFile, FSCTL_GET_REPARSE_POINT,
                    nint.Zero, 0, buf, bufSize, out _, nint.Zero))
                    return null;

                // REPARSE_DATA_BUFFER layout:
                // uint  ReparseTag         (4)
                // ushort DataLength        (2)
                // ushort Reserved          (2)
                // Then: MountPointReparseBuffer or SymbolicLinkReparseBuffer
                uint tag = (uint)Marshal.ReadInt32(buf, 0);

                if (tag == IO_REPARSE_TAG_MOUNT_POINT)
                {
                    // MountPointReparseBuffer:
                    // ushort SubstituteNameOffset (8)
                    // ushort SubstituteNameLength (10)
                    // ushort PrintNameOffset      (12)
                    // ushort PrintNameLength      (14)
                    // WCHAR PathBuffer[]          (16)
                    ushort subOffset = (ushort)Marshal.ReadInt16(buf, 8);
                    ushort subLen    = (ushort)Marshal.ReadInt16(buf, 10);
                    if (subLen > 0 && subLen < 512 * 2)
                    {
                        string raw = Marshal.PtrToStringUni(buf + 16 + subOffset, subLen / 2);
                        // Strip \??\ prefix
                        return raw.StartsWith(@"\??\") ? raw[4..] : raw;
                    }
                }
                else if (tag == IO_REPARSE_TAG_SYMLINK)
                {
                    // SymbolicLinkReparseBuffer:
                    // ushort SubstituteNameOffset (8)
                    // ushort SubstituteNameLength (10)
                    // ushort PrintNameOffset      (12)
                    // ushort PrintNameLength      (14)
                    // uint Flags                  (16)
                    // WCHAR PathBuffer[]          (20)
                    ushort subOffset = (ushort)Marshal.ReadInt16(buf, 8);
                    ushort subLen    = (ushort)Marshal.ReadInt16(buf, 10);
                    if (subLen > 0 && subLen < 512 * 2)
                    {
                        string raw = Marshal.PtrToStringUni(buf + 20 + subOffset, subLen / 2);
                        return raw.StartsWith(@"\??\") ? raw[4..] : raw;
                    }
                }

                return null;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        finally { CloseHandle(hFile); }
    }
}
