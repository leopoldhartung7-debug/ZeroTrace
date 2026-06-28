using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans for suspicious memory-mapped files and shared memory sections used
/// by cheat tools for inter-process communication and data sharing.
///
/// Memory-mapped files (MMF) / shared sections are used by cheats for:
///   1. DMA radar: game process data shared with external radar application
///   2. ESP overlay: entity list shared between game-side DLL and overlay renderer
///   3. Cheat config: settings shared between loader and injected DLL
///   4. Kernel↔user bridge: kernel driver shares detected players with user-mode UI
///
/// Detection via NtQuerySystemInformation (SystemHandleInformation = 16) or
/// the Object Manager namespace enumeration:
///   1. Enumerate named section objects in \BaseNamedObjects\
///   2. Flag sections with cheat-keyword names
///   3. Look for sections shared between game processes and unknown processes
///
/// Also checks the Windows object manager for named events and semaphores
/// that cheat tools use as synchronization primitives.
/// </summary>
public sealed class MemoryMappedFileScanModule : IScanModule
{
    private static readonly string _name = "Memory-Mapped-File-Analyse";
    public string Name => _name;
    public double Weight => 0.6;
    public int ParallelGroup => 2;

    [DllImport("ntdll.dll")]
    private static extern int NtOpenDirectoryObject(
        out IntPtr directoryHandle, uint desiredAccess, ref OBJECT_ATTRIBUTES oa);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryDirectoryObject(
        IntPtr directoryHandle, IntPtr buffer, uint bufLen,
        bool returnSingleEntry, bool restartScan, ref uint context, out uint returnLen);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr h);

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
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OBJECT_DIRECTORY_INFORMATION
    {
        public UNICODE_STRING Name;
        public UNICODE_STRING TypeName;
    }

    private const uint DIRECTORY_QUERY = 0x0001;
    private const uint OBJ_CASE_INSENSITIVE = 0x00000040;
    private const int STATUS_NO_MORE_ENTRIES = unchecked((int)0x8000001A);

    private static readonly string[] CheatSectionKeywords =
    {
        "cheat", "hack", "radar", "esp", "aimbot",
        "kiddion", "cherax", "2take1", "ozark", "skeet",
        "fatality", "neverlose", "onetap", "aimware",
        "inject", "bypass", "loader", "memprocfs",
        "dma", "pcileech", "entitylist", "players",
        "gta5", "fivem", "tarkov", "apex", "valorant",
        "wallhack", "triggerbot", "bhop",
    };

    // Known legitimate section names to skip
    private static readonly HashSet<string> KnownGoodSections = new(StringComparer.OrdinalIgnoreCase)
    {
        "windows", "microsoft", "steam", "nvidia", "amd", "intel",
        "discord", "chrome", "firefox", "edge",
        "clrjit", "mscorlib",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int objectsChecked = 0;
        int hits = 0;

        // Enumerate \BaseNamedObjects\ directory
        hits += EnumerateNamedObjects(@"\BaseNamedObjects", ctx, ref objectsChecked, ct);
        hits += EnumerateNamedObjects(@"\Sessions\1\BaseNamedObjects", ctx, ref objectsChecked, ct);

        ctx.Report(1.0, Name, $"{objectsChecked} Kernel-Objekte geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int EnumerateNamedObjects(string dirPath, ScanContext ctx,
        ref int objectsChecked, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Encode the directory path as UNICODE_STRING
            var dirNameBytes = System.Text.Encoding.Unicode.GetBytes(dirPath);
            var namePtr = Marshal.AllocHGlobal(dirNameBytes.Length + 2);
            try
            {
                Marshal.Copy(dirNameBytes, 0, namePtr, dirNameBytes.Length);
                Marshal.WriteInt16(namePtr, dirNameBytes.Length, 0);

                var us = new UNICODE_STRING
                {
                    Length = (ushort)dirNameBytes.Length,
                    MaximumLength = (ushort)(dirNameBytes.Length + 2),
                    Buffer = namePtr
                };

                var usPtr = Marshal.AllocHGlobal(Marshal.SizeOf<UNICODE_STRING>());
                try
                {
                    Marshal.StructureToPtr(us, usPtr, false);
                    var oa = new OBJECT_ATTRIBUTES
                    {
                        Length = (uint)Marshal.SizeOf<OBJECT_ATTRIBUTES>(),
                        ObjectName = usPtr,
                        Attributes = OBJ_CASE_INSENSITIVE
                    };

                    int status = NtOpenDirectoryObject(out var hDir, DIRECTORY_QUERY, ref oa);
                    if (status != 0 || hDir == IntPtr.Zero) return 0;

                    try
                    {
                        uint ctx2 = 0;
                        uint bufSize = 1024 * 64;
                        var buf = Marshal.AllocHGlobal((int)bufSize);

                        try
                        {
                            while (true)
                            {
                                if (ct.IsCancellationRequested) break;
                                int qStatus = NtQueryDirectoryObject(hDir, buf, bufSize,
                                    false, false, ref ctx2, out _);

                                if (qStatus == STATUS_NO_MORE_ENTRIES) break;
                                if (qStatus != 0 && qStatus != 0x104) break; // 0x104 = more entries

                                int offset = 0;
                                while (offset < bufSize)
                                {
                                    if (ct.IsCancellationRequested) break;

                                    var info = Marshal.PtrToStructure<OBJECT_DIRECTORY_INFORMATION>(
                                        IntPtr.Add(buf, offset));

                                    if (info.Name.Length == 0 && info.TypeName.Length == 0) break;

                                    var name = info.Name.Buffer != IntPtr.Zero && info.Name.Length > 0
                                        ? Marshal.PtrToStringUni(info.Name.Buffer, info.Name.Length / 2)
                                        : "";
                                    var typeName = info.TypeName.Buffer != IntPtr.Zero && info.TypeName.Length > 0
                                        ? Marshal.PtrToStringUni(info.TypeName.Buffer, info.TypeName.Length / 2)
                                        : "";

                                    offset += Marshal.SizeOf<OBJECT_DIRECTORY_INFORMATION>();

                                    if (string.IsNullOrEmpty(name)) continue;
                                    objectsChecked++;

                                    // Only care about Sections, Events, Semaphores
                                    if (typeName != "Section" && typeName != "Event" &&
                                        typeName != "Semaphore" && typeName != "Mutant")
                                        continue;

                                    var nameLower = name.ToLowerInvariant();

                                    if (KnownGoodSections.Any(g =>
                                        nameLower.StartsWith(g, StringComparison.OrdinalIgnoreCase)))
                                        continue;

                                    var keyword = CheatSectionKeywords.FirstOrDefault(k =>
                                        nameLower.Contains(k, StringComparison.OrdinalIgnoreCase));

                                    if (keyword is not null)
                                    {
                                        hits++;
                                        ctx.AddFinding(new Finding
                                        {
                                            Module = _name,
                                            Title    = $"Cheat-IPC-Objekt: {typeName} '{name}'",
                                            Risk     = typeName == "Section" ? RiskLevel.High : RiskLevel.Medium,
                                            Location = $@"{dirPath}\{name}",
                                            Reason   = $"Kernel-Objekt '{name}' (Typ: {typeName}) im " +
                                                       $"Object Manager Namespace mit Cheat-Keyword '{keyword}'. " +
                                                       (typeName == "Section" ?
                                                           "Shared-Memory-Sections werden für Radar-IPC, " +
                                                           "Entity-List-Sharing und DMA-Datenübertragung genutzt." :
                                                           "Events/Semaphoren werden für Synchronisation zwischen " +
                                                           "Cheat-Loader und injizierten DLLs genutzt."),
                                            Detail   = $"Objekt: {dirPath}\\{name} | Typ: {typeName} | Keyword: {keyword}"
                                        });
                                    }
                                }

                                if (qStatus == STATUS_NO_MORE_ENTRIES) break;
                            }
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(buf);
                        }
                    }
                    finally
                    {
                        CloseHandle(hDir);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(usPtr);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(namePtr);
            }
        }
        catch { }
        return hits;
    }
}
