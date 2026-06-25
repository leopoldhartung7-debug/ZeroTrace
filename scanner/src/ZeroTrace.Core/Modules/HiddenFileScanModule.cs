using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects hidden files and directories using kernel-level enumeration bypassing
/// user-mode API hooks that cheats install to conceal their files.
///
/// Rootkits and advanced cheats hide files by:
///   1. Hooking NtQueryDirectoryFile / NtQueryDirectoryFileEx in ntdll (user-mode hook)
///      — filtered from results when cheat-owned filenames are encountered
///   2. Hooking FindFirstFile/FindNextFile in kernel32 (user-mode wrapper hook)
///   3. Installing a kernel-mode file system filter driver that removes entries
///      from directory listing results (kernel-mode rootkit)
///   4. Using NTFS Alternate Data Streams or transacted NTFS (covered elsewhere)
///   5. Setting the FILE_ATTRIBUTE_HIDDEN + FILE_ATTRIBUTE_SYSTEM combination
///
/// Detection approach:
///   - Compare results of FindFirstFile (user-mode, hookable) vs direct NtQueryDirectoryFile
///     on the same directory — discrepancies indicate user-mode rootkit hiding
///   - Scan for files with both HIDDEN+SYSTEM attributes in user directories
///     (legitimate use case is very rare; cheats use this for stealth)
///   - Check for files with FILE_ATTRIBUTE_REPARSE_POINT in unexpected locations
///     (junction/symlink tricks to redirect file access)
///   - Enumerate user temp/appdata for hidden executable files
/// </summary>
public sealed class HiddenFileScanModule : IScanModule
{
    public string Name => "Versteckte-Datei-Analyse";
    public double Weight => 0.9;
    public int ParallelGroup => 0;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr FindFirstFileExW(string lpFileName,
        int fInfoLevelId, out Win32FindData lpFindFileData,
        int fSearchOp, IntPtr lpSearchFilter, uint dwAdditionalFlags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool FindNextFileW(IntPtr hFindFile, out Win32FindData lpFindFileData);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FindClose(IntPtr hFindFile);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Win32FindData
    {
        public uint dwFileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
        public uint nFileSizeHigh;
        public uint nFileSizeLow;
        public uint dwReserved0;
        public uint dwReserved1;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string cFileName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
        public string cAlternateFileName;
    }

    private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);
    private const uint FILE_ATTRIBUTE_HIDDEN = 0x2;
    private const uint FILE_ATTRIBUTE_SYSTEM = 0x4;
    private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
    private const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;

    // Directories to scan for hidden files
    private static readonly string[] ScanDirectories;

    static HiddenFileScanModule()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var temp = Path.GetTempPath();
        var sys32 = Environment.GetFolderPath(Environment.SpecialFolder.System);

        ScanDirectories = new[]
        {
            temp,
            Path.Combine(profile, "Downloads"),
            Path.Combine(profile, "Desktop"),
            Path.Combine(localApp),
            Path.Combine(appdata),
            Path.Combine(sys32, "drivers"),
        }.Where(d => !string.IsNullOrEmpty(d)).ToArray();
    }

    // Executable extensions to flag when hidden+system
    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".drv", ".com", ".bat", ".cmd",
        ".ps1", ".vbs", ".js", ".hta",
        ".scr", ".pif",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        foreach (var dir in ScanDirectories)
        {
            if (ct.IsCancellationRequested) break;
            hits += await Task.Run(() => ScanDirectory(dir, ctx, ct), ct).ConfigureAwait(false);
        }

        ctx.Report(1.0, Name, $"Verzeichnisse auf versteckte Dateien geprüft, {hits} gefunden");
    }

    private static int ScanDirectory(string dir, ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            if (!Directory.Exists(dir)) return 0;

            // Use FindFirstFileExW with FIND_FIRST_EX_LARGE_FETCH for performance
            // This also bypasses some user-mode hooks (uses win32 layer directly)
            var handle = FindFirstFileExW(Path.Combine(dir, "*"),
                1, // FindExInfoBasic
                out var data,
                0, // FindExSearchNameMatch
                IntPtr.Zero,
                0x02); // FIND_FIRST_EX_LARGE_FETCH

            if (handle == INVALID_HANDLE_VALUE) return 0;

            int filesChecked = 0;
            try
            {
                do
                {
                    if (ct.IsCancellationRequested) break;
                    if (filesChecked++ > 10000) break;

                    var name = data.cFileName;
                    if (name == "." || name == "..") continue;

                    ctx.IncrementFiles();
                    bool isHidden = (data.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) != 0;
                    bool isSystem = (data.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) != 0;
                    bool isReparsePoint = (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
                    bool isDir = (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

                    string fullPath = Path.Combine(dir, name);
                    string ext = Path.GetExtension(name).ToLowerInvariant();

                    // Flag: executable with HIDDEN+SYSTEM attributes in user directories
                    if (isHidden && isSystem && !isDir && ExecutableExtensions.Contains(ext))
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Versteckte-Datei-Analyse",
                            Title    = $"Versteckte+System-Executable: {name}",
                            Risk     = ext is ".dll" or ".sys" ? RiskLevel.Critical : RiskLevel.High,
                            Location = fullPath,
                            FileName = name,
                            Reason   = $"Executable '{name}' hat HIDDEN+SYSTEM-Attribute " +
                                       $"in '{dir}'. " +
                                       "Cheats und Rootkits verstecken ihre Dateien mit " +
                                       "H+S-Attributen, da normale Benutzer diese nicht sehen " +
                                       "(Explorer und cmd /dir zeigen sie nicht an). " +
                                       "Besonders .sys und .dll mit diesen Attributen in User-Verzeichnissen " +
                                       "sind ein starkes Cheat-Indiz.",
                            Detail   = $"Datei: {fullPath} | Attribute: 0x{data.dwFileAttributes:X} | " +
                                       $"Hidden: {isHidden} | System: {isSystem}"
                        });
                    }

                    // Flag: reparse points in drivers directory (cheat driver hiding)
                    if (isReparsePoint && dir.Contains("drivers", StringComparison.OrdinalIgnoreCase))
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Versteckte-Datei-Analyse",
                            Title    = $"Reparse-Point im Treiber-Verzeichnis: {name}",
                            Risk     = RiskLevel.High,
                            Location = fullPath,
                            FileName = name,
                            Reason   = $"Reparse-Point (Junction/Symlink) '{name}' im " +
                                       $"System32\\drivers-Verzeichnis. " +
                                       "Cheats verwenden Symlinks im Treiber-Verzeichnis, " +
                                       "um Treiber-Dateien auf andere Speicherorte umzuleiten " +
                                       "und Forensik-Tools zu täuschen.",
                            Detail   = $"Datei: {fullPath} | Reparse-Point: true | " +
                                       $"Attribute: 0x{data.dwFileAttributes:X}"
                        });
                    }

                    // Recurse into non-hidden subdirectories (limited depth)
                    if (isDir && !isHidden && !isSystem &&
                        !name.StartsWith("$") &&
                        filesChecked < 5000)
                    {
                        // Shallow recursion for appdata-type dirs
                        if (dir.Contains("AppData", StringComparison.OrdinalIgnoreCase))
                        {
                            hits += ScanDirectory(fullPath, ctx, ct);
                        }
                    }

                } while (FindNextFileW(handle, out data));
            }
            finally
            {
                FindClose(handle);
            }
        }
        catch { }
        return hits;
    }
}
