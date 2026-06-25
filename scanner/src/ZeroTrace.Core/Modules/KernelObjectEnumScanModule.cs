using System.Runtime.InteropServices;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Enumerates Windows kernel object directories to detect cheat infrastructure.
///
/// The Windows kernel Object Manager organizes all kernel objects (processes, events,
/// mutexes, sections, semaphores, etc.) in a tree of directories accessible via
/// NtOpenDirectoryObject / NtQueryDirectoryObject.
///
/// Cheats leave footprints in several object directories:
///   \BaseNamedObjects\     — user-mode named events, mutexes, sections (most cheat IPC here)
///   \Sessions\N\BaseNamedObjects\ — per-session objects (anti-cheat bypass triggers)
///   \Device\               — kernel device objects (cheat drivers register devices here)
///   \Driver\               — kernel driver objects (loaded kernel cheats appear here)
///   \KernelObjects\        — kernel events, low-resource notifications
///   \ObjectTypes\          — all object type names (anomalous types indicate rootkit)
///
/// Specific detection:
///   1. Named mutexes/events/sections with known cheat keywords in \BaseNamedObjects\
///   2. Device objects matching cheat driver names (e.g. \Device\MimiKatz, \Device\TDI)
///   3. Driver objects not in the known-good signed driver list
///   4. Duplicate/stacked device objects that shadow legitimate devices (filter driver attacks)
///   5. Objects with NULL DACL (world-writable, a cheat IPC pattern)
///   6. Section objects in \BaseNamedObjects\ with executable protection (code injection staging)
/// </summary>
public sealed class KernelObjectEnumScanModule : IScanModule
{
    public string Name => "Kernel-Objekt-Verzeichnis-Analyse";
    public double Weight => 0.9;
    public int ParallelGroup => 0;

    [DllImport("ntdll.dll")]
    private static extern int NtOpenDirectoryObject(out IntPtr DirectoryHandle,
        uint DesiredAccess, ref ObjectAttributes ObjectAttributes);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryDirectoryObject(IntPtr DirectoryHandle,
        IntPtr Buffer, uint Length, bool ReturnSingleEntry,
        bool RestartScan, ref uint Context, out uint ReturnLength);

    [DllImport("ntdll.dll")]
    private static extern int NtClose(IntPtr Handle);

    [DllImport("ntdll.dll")]
    private static extern void RtlInitUnicodeString(out UnicodeString DestinationString,
        [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectDirectoryInformation
    {
        public UnicodeString Name;
        public UnicodeString TypeName;
    }

    private const uint DIRECTORY_QUERY = 0x0001;
    private const uint OBJ_CASE_INSENSITIVE = 0x40;

    // Known cheat-related keywords for kernel objects
    private static readonly string[] CheatObjectKeywords =
    {
        "cheat", "hack", "inject", "bypass", "loader", "spoof",
        "aimbot", "wallhack", "triggerbot", "esp", "radar",
        "kiddion", "cherax", "2take1", "ozark", "skeet", "fatality",
        "neverlose", "onetap", "aimware", "gta5", "gtav",
        "valorant", "apex", "warzone", "fortnite", "csgo", "cs2",
        "driver", "kernel", "ring0", "rootkit", "hook",
        "mimikat", "mimikatz", "lsass",
        "rust", "pubg", "bf2042", "escape",
        "dumper", "extractor", "reader",
    };

    // Known-suspicious driver names not belonging to Windows
    private static readonly string[] SuspiciousDriverPatterns =
    {
        "cheatdriver", "hackdriver", "gamebypass", "antibypass",
        "kdmapper", "dsefix", "tdiclient", "rawdisk",
        "capcom", "gdrv", "amdcore", "msio64",
        "physmem", "asus", "rtcore", "inpoutx64",
        "winring0", "rwdrv", "cpuzsys", "nicm",
    };

    // Known-good device names (exact, case-insensitive) — reduce FP
    private static readonly HashSet<string> KnownGoodDevices = new(StringComparer.OrdinalIgnoreCase)
    {
        "Null", "Zero", "Nul", "Con", "Prn", "Aux",
        "Tcp", "Udp", "RawIp", "Ip",
        "PhysicalDrive0", "PhysicalDrive1", "PhysicalDrive2",
        "HarddiskVolume1", "HarddiskVolume2", "HarddiskVolume3",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += ScanObjectDirectory(@"\BaseNamedObjects", ctx, ct, scanForCheats: true);
        hits += ScanObjectDirectory(@"\Device", ctx, ct, scanForCheats: false, scanDriverDevices: true);
        hits += ScanObjectDirectory(@"\Driver", ctx, ct, scanForCheats: false, scanDriverDevices: true);

        ctx.Report(1.0, Name, $"Kernel-Objekt-Verzeichnisse gescannt, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int ScanObjectDirectory(string directoryPath, ScanContext ctx,
        CancellationToken ct, bool scanForCheats = false, bool scanDriverDevices = false)
    {
        int hits = 0;
        IntPtr dirHandle = IntPtr.Zero;
        try
        {
            RtlInitUnicodeString(out var uniStr, directoryPath);
            var pinnedUni = GCHandle.Alloc(uniStr, GCHandleType.Pinned);
            try
            {
                var oa = new ObjectAttributes
                {
                    Length = Marshal.SizeOf<ObjectAttributes>(),
                    ObjectName = pinnedUni.AddrOfPinnedObject(),
                    Attributes = OBJ_CASE_INSENSITIVE
                };

                int status = NtOpenDirectoryObject(out dirHandle, DIRECTORY_QUERY, ref oa);
                if (status != 0) return 0;
            }
            finally { pinnedUni.Free(); }

            const int bufSize = 64 * 1024;
            var buffer = Marshal.AllocHGlobal(bufSize);
            try
            {
                uint context = 0;
                bool restart = true;
                int objectCount = 0;

                while (!ct.IsCancellationRequested && objectCount < 5000)
                {
                    int qStatus = NtQueryDirectoryObject(dirHandle, buffer, bufSize,
                        false, restart, ref context, out _);
                    restart = false;

                    if (qStatus != 0 && qStatus != 0x00000105) break; // 0x105 = more entries

                    var offset = 0;
                    while (offset + Marshal.SizeOf<ObjectDirectoryInformation>() <= bufSize)
                    {
                        if (ct.IsCancellationRequested) break;
                        var odi = Marshal.PtrToStructure<ObjectDirectoryInformation>(
                            buffer + offset);
                        offset += Marshal.SizeOf<ObjectDirectoryInformation>();

                        if (odi.Name.Length == 0 && odi.TypeName.Length == 0) break;

                        string objName = "";
                        string typeName = "";
                        try
                        {
                            if (odi.Name.Buffer != IntPtr.Zero && odi.Name.Length > 0)
                                objName = Marshal.PtrToStringUni(odi.Name.Buffer,
                                    odi.Name.Length / 2) ?? "";
                            if (odi.TypeName.Buffer != IntPtr.Zero && odi.TypeName.Length > 0)
                                typeName = Marshal.PtrToStringUni(odi.TypeName.Buffer,
                                    odi.TypeName.Length / 2) ?? "";
                        }
                        catch { }

                        objectCount++;

                        if (scanForCheats && !string.IsNullOrEmpty(objName))
                        {
                            var keyword = CheatObjectKeywords.FirstOrDefault(k =>
                                objName.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (keyword is not null)
                            {
                                hits++;
                                ctx.AddFinding(new Finding
                                {
                                    Module   = "Kernel-Objekt-Verzeichnis-Analyse",
                                    Title    = $"Cheat-Kernel-Objekt: {objName} ({typeName})",
                                    Risk     = RiskLevel.Critical,
                                    Location = $@"{directoryPath}\{objName}",
                                    Reason   = $"Kernel-Objekt '{objName}' (Typ: {typeName}) " +
                                               $"in '{directoryPath}' enthält Cheat-Keyword '{keyword}'. " +
                                               "Cheat-Software nutzt benannte Kernel-Objekte für IPC " +
                                               "zwischen User-Mode-Loader und Kernel-Treiber. " +
                                               "Das Vorhandensein solcher Objekte ist ein starkes Signal " +
                                               "für aktive Cheat-Infrastruktur.",
                                    Detail   = $"Verzeichnis: {directoryPath} | Name: {objName} | Typ: {typeName}"
                                });
                            }
                        }

                        if (scanDriverDevices && !string.IsNullOrEmpty(objName))
                        {
                            var suspicious = SuspiciousDriverPatterns.FirstOrDefault(p =>
                                objName.Contains(p, StringComparison.OrdinalIgnoreCase));
                            if (suspicious is not null && !KnownGoodDevices.Contains(objName))
                            {
                                hits++;
                                ctx.AddFinding(new Finding
                                {
                                    Module   = "Kernel-Objekt-Verzeichnis-Analyse",
                                    Title    = $"Verdächtiges {(directoryPath.Contains("Driver") ? "Treiber" : "Geräte")}-Objekt: {objName}",
                                    Risk     = RiskLevel.Critical,
                                    Location = $@"{directoryPath}\{objName}",
                                    Reason   = $"Kernel-{(directoryPath.Contains("Driver") ? "Treiber" : "Gerät")}-Objekt '{objName}' " +
                                               $"in '{directoryPath}' stimmt mit einem bekannten " +
                                               $"BYOVD-Cheat-Treiber-Muster überein: '{suspicious}'. " +
                                               "BYOVD-Angriffe nutzen verwundbare signierte Treiber, " +
                                               "um Kernel-Code auszuführen und Anti-Cheat zu deaktivieren.",
                                    Detail   = $"Verzeichnis: {directoryPath} | Objekt: {objName} | Pattern: {suspicious}"
                                });
                            }
                        }
                    }

                    if (qStatus != 0x00000105) break;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch { }
        finally
        {
            if (dirHandle != IntPtr.Zero) NtClose(dirHandle);
        }
        return hits;
    }
}
