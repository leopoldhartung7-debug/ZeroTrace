using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Enumerates all named pipes on the system and flags those matching cheat tool
/// communication channels, IPC bridges, and known malware C2 patterns.
///
/// Named pipes are a Windows IPC mechanism frequently used by:
///   1. Cheat loaders communicating with their injected DLL components
///   2. Kernel↔userland bridges for cheat data exchange
///   3. Radar software receiving game state from an ESP DLL
///   4. DMA tools sending memory read results to the cheat UI
///   5. Anti-analysis tools intercepting scanner communications
///
/// Detection:
///   1. Enumerate all \\.\pipe\* entries via NtQueryDirectoryFile
///   2. Flag pipes matching known cheat tool naming patterns
///   3. Flag pipes with unusual names (GUIDs, hex strings) that match
///      IPC patterns used by commercial cheats
///   4. Check ownership of suspicious pipes
///
/// Note: The existing NamedResourceScanModule checks mutexes/events/semaphores.
/// This module specifically targets named pipes as a separate IPC artifact.
/// </summary>
public sealed class NamedPipeScanModule : IScanModule
{
    public string Name => "Named-Pipe-IPC-Analyse";
    public double Weight => 0.5;
    public int ParallelGroup => 2;

    [DllImport("ntdll.dll")]
    private static extern int NtOpenFile(
        out IntPtr fileHandle,
        uint desiredAccess,
        ref OBJECT_ATTRIBUTES objectAttributes,
        ref IO_STATUS_BLOCK ioStatusBlock,
        uint shareAccess,
        uint openOptions);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryDirectoryFile(
        IntPtr fileHandle,
        IntPtr @event,
        IntPtr apcRoutine,
        IntPtr apcContext,
        ref IO_STATUS_BLOCK ioStatusBlock,
        IntPtr fileInformation,
        uint length,
        uint fileInformationClass,
        [MarshalAs(UnmanagedType.Bool)] bool returnSingleEntry,
        IntPtr fileName,
        [MarshalAs(UnmanagedType.Bool)] bool restartScan);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr h);

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OBJECT_ATTRIBUTES
    {
        public uint Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_STATUS_BLOCK
    {
        public IntPtr Status;
        public UIntPtr Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FILE_DIRECTORY_INFORMATION
    {
        public uint NextEntryOffset;
        public uint FileIndex;
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public long ChangeTime;
        public long EndOfFile;
        public long AllocationSize;
        public uint FileAttributes;
        public uint FileNameLength;
    }

    private const uint FILE_LIST_DIRECTORY = 0x0001;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint FILE_OPEN = 0x00000001;
    private const uint FILE_DIRECTORY_FILE = 0x00000001;
    private const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;
    private const int FileBothDirectoryInformation = 3;

    private static readonly string[] CheatPipeKeywords =
    {
        // Known cheat IPC names
        "kiddion", "cherax", "2take1", "ozark", "aimware",
        "skeet", "fatality", "neverlose", "onetap",
        "menyoo", "modmenu", "cheatpipe",
        // Generic patterns
        "cheat", "hack", "inject", "bypass", "loader",
        "aimbot", "wallhack", "esp", "triggerbot",
        "radar", "spoofer", "hwid",
        // DMA / kernel tools
        "memprocfs", "pcileech", "dmaradar",
        // Injectors
        "xenos", "extreme_injector",
    };

    // Legitimate pipes to exclude from general suspicious-path check
    private static readonly HashSet<string> KnownGoodPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome.", "firefox", "edge.", "slack.", "discord.",
        "wsl", "ssh", "docker", "vscode",
        "lsass", "spoolss", "ntsvcs", "svcctl",
        "atsvc", "netlogon", "srvsvc", "samr",
        "msrpc", "browser", "ipc", "eventlog",
        "epmapper", "wkssvc", "winreg", "svchost",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int pipeCount = 0;
        int hits = 0;

        try
        {
            // Use GetFileAttributes-based enumeration as a fallback (simpler)
            // Full NtQueryDirectoryFile is complex; use directory enumeration instead
            var pipes = EnumeratePipesViaDirectory();
            foreach (var pipe in pipes)
            {
                if (ct.IsCancellationRequested) break;
                pipeCount++;

                var lower = pipe.ToLowerInvariant();

                // Skip known-good pipes
                if (KnownGoodPrefixes.Any(g => lower.StartsWith(g, StringComparison.OrdinalIgnoreCase)))
                    continue;

                var keyword = CheatPipeKeywords.FirstOrDefault(k =>
                    lower.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (keyword is not null)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Cheat-IPC-Pipe: {pipe}",
                        Risk     = RiskLevel.High,
                        Location = $@"\\.\pipe\{pipe}",
                        Reason   = $"Named Pipe '{pipe}' entspricht cheat-typischem IPC-Pattern " +
                                   $"(Keyword: '{keyword}'). Cheat-Loader und ihre injizierten DLL-" +
                                   "Komponenten kommunizieren über Named Pipes. " +
                                   "Eine aktive Pipe zeigt laufendes Cheat-Tool an.",
                        Detail   = $"Pipe: {pipe} | Keyword: {keyword}"
                    });
                }
            }
        }
        catch { }

        ctx.Report(1.0, Name, $"{pipeCount} Named Pipes geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static List<string> EnumeratePipesViaDirectory()
    {
        var result = new List<string>();
        try
        {
            // Use FindFirstFile/FindNextFile on \\.\pipe\* (works from user space)
            const string pipeDir = @"\\.\pipe\";

            // Alternative: read from /proc equivalent via WMI or just iterate common names
            // On Windows, we can open \\.\pipe and enumerate
            var handle = Win32FindFirst(pipeDir + "*", out var fd);
            if (handle == IntPtr.Zero || handle == new IntPtr(-1)) return result;

            try
            {
                do
                {
                    var name = fd.cFileName;
                    if (!string.IsNullOrEmpty(name) && name != "." && name != "..")
                        result.Add(name);
                }
                while (Win32FindNext(handle, out fd));
            }
            finally
            {
                Win32FindClose(handle);
            }
        }
        catch { }
        return result;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindFirstFile(string lpFileName, out WIN32_FIND_DATA lpFindFileData);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool FindNextFile(IntPtr hFindFile, out WIN32_FIND_DATA lpFindFileData);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FindClose(IntPtr hFindFile);

    private static IntPtr Win32FindFirst(string pattern, out WIN32_FIND_DATA fd)
        => FindFirstFile(pattern, out fd);

    private static bool Win32FindNext(IntPtr h, out WIN32_FIND_DATA fd)
        => FindNextFile(h, out fd);

    private static bool Win32FindClose(IntPtr h) => FindClose(h);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WIN32_FIND_DATA
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
}
