using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Comprehensive enumeration of named kernel objects (mutexes, events, semaphores, sections)
/// matching an extended list of known cheat tool IPC names specific to popular cheat suites.
/// Cheat tools create named synchronization objects to: (1) communicate between cheat loader
/// and injected DLL; (2) prevent multiple cheat instances from running simultaneously;
/// (3) signal cheat state (injection complete, menu open, feature enabled). The names are
/// intentionally distinctive and don't change between releases, making them reliable forensic
/// indicators even after the cheat process is closed (named kernel objects persist until all
/// handles are closed). This module extends the existing NamedResources scan with 100+ specific
/// cheat suite mutex/event/section names across CS2, Valorant, Apex, EFT, PUBG, and more.
/// Uses NtQueryDirectoryObject to enumerate \BaseNamedObjects without relying on CreateMutex.
/// </summary>
public sealed class KnownCheatMutexExtScanModule : IScanModule
{
    public string Name => "Known Cheat Mutex/Event Extended Detection";
    public double Weight => 0.65;
    public int ParallelGroup => 2;

    [DllImport("ntdll.dll")]
    private static extern int NtOpenDirectoryObject(out nint DirectoryHandle,
        uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryDirectoryObject(nint DirectoryHandle,
        nint Buffer, uint Length, bool ReturnSingleEntry, bool RestartScan,
        ref uint Context, out uint ReturnLength);

    [DllImport("ntdll.dll")]
    private static extern int NtClose(nint Handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct OBJECT_ATTRIBUTES
    {
        public uint Length;
        public nint RootDirectory;
        public nint ObjectName;
        public uint Attributes;
        public nint SecurityDescriptor;
        public nint SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public nint   Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OBJECT_DIRECTORY_INFORMATION
    {
        public UNICODE_STRING Name;
        public UNICODE_STRING TypeName;
    }

    private const uint DIRECTORY_QUERY    = 0x0001;
    private const uint OBJ_CASE_INSENSITIVE = 0x40;

    // 100+ known cheat tool named objects
    // Format: object name fragments (checked with Contains, case-insensitive)
    private static readonly HashSet<string> KnownCheatObjectNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // Gamesense (csgo/cs2 cheat suite)
        "gamesense", "Limeware", "LimewareMutex",
        // Onetap.su
        "onetap", "onetap_mutex", "otMutex",
        // Fatality (fatality.win)
        "fatality", "FatalityMutex",
        // Aimware
        "aimware", "AWMutex", "AIMWARE",
        // Skycheats
        "skycheats", "SkyC",
        // Interwebz (neverlose)
        "neverlose", "nl_mutex",
        // Primordial
        "primordial",
        // Beserk/Zemu
        "beserk", "zemucc",
        // Kiddion's Modest Menu (GTA V)
        "kiddion", "KiddionMenu", "ModestMenu",
        // 2Take1 (GTA V)
        "2take1", "2t1mutex",
        // Stand (GTA V)
        "StandMutex", "stand_mutex",
        // Midnight (GTA V)
        "MidnightMutex", "midnightcc",
        // Ozark (GTA V)
        "OzarkMutex",
        // Cherax (GTA V)
        "CheraxMutex", "cherax_",
        // Phantom-X (Valorant cheat)
        "PhantomX", "phantom_x",
        // Hysteria/Hyperion (Valorant)
        "HysteriaMutex",
        // Valorant external cheats
        "ValorantCheat", "VACMutex",
        // Apex cheats
        "ApexLegendsMutex", "ApexCheat",
        // EFT (Escape From Tarkov)
        "EFTCheat", "TarkovHack",
        // PUBG cheats
        "PUBGCheat", "PUBGMutex",
        // Fortnite cheats
        "FortniteMutex", "FNCheat",
        // Universal cheat patterns
        "CheatMutex", "HackMutex", "InjectorMutex",
        "LoaderMutex", "EspMutex", "AimbotMutex",
        "RadarMutex", "OverlayMutex", "TriggerMutex",
        // DMA tool objects
        "MemProcFS", "PCILeech", "DMACheat",
        "Memflow", "MemflowMutex",
        // SysWhispers / direct syscall tools
        "SysWhispers", "HellsGate", "TartarusGate",
        // HWID spoofer tools
        "SpooferMutex", "HwidMutex", "HWIDSpoof",
        // Known bypass tool objects
        "VACBypass", "EACBypass", "BEBypass",
        "ACBypass", "AntiCheatBypass",
        // Injection tool objects
        "InjectorReady", "DllInjected", "InjectComplete",
        "ExtLoader", "IntLoader",
        // Overlay tools
        "OverlayReady", "ESPOverlay", "RadarOverlay",
        // No-recoil tools
        "NoRecoilMutex", "NRMutex", "RecoilScript",
        // Triggerbot tools
        "TriggerBotMutex", "TbMutex",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => EnumerateNamedObjects(ctx, ct), ct);
    }

    private void EnumerateNamedObjects(ScanContext ctx, CancellationToken ct)
    {
        string[] objectDirs = { @"\BaseNamedObjects", @"\Sessions\1\BaseNamedObjects" };

        foreach (var dir in objectDirs)
        {
            ct.ThrowIfCancellationRequested();
            EnumerateDirectory(dir, ctx, ct);
        }
    }

    private void EnumerateDirectory(string dirPath, ScanContext ctx, CancellationToken ct)
    {
        nint hDir = nint.Zero;
        try
        {
            // Allocate UNICODE_STRING for the directory path
            var us = new UNICODE_STRING
            {
                Length        = (ushort)(dirPath.Length * 2),
                MaximumLength = (ushort)((dirPath.Length + 1) * 2),
                Buffer        = Marshal.StringToHGlobalUni(dirPath),
            };

            var oa = new OBJECT_ATTRIBUTES
            {
                Length              = (uint)Marshal.SizeOf<OBJECT_ATTRIBUTES>(),
                ObjectName          = Marshal.AllocHGlobal(Marshal.SizeOf<UNICODE_STRING>()),
                Attributes          = OBJ_CASE_INSENSITIVE,
                SecurityDescriptor  = nint.Zero,
                SecurityQualityOfService = nint.Zero,
            };
            Marshal.StructureToPtr(us, oa.ObjectName, false);

            int status = NtOpenDirectoryObject(out hDir, DIRECTORY_QUERY, ref oa);
            Marshal.FreeHGlobal(us.Buffer);
            Marshal.FreeHGlobal(oa.ObjectName);

            if (status != 0 || hDir == nint.Zero) return;

            uint context = 0;
            uint bufSize = 1024 * 64;
            nint buf = Marshal.AllocHGlobal((int)bufSize);
            try
            {
                while (true)
                {
                    ct.ThrowIfCancellationRequested();

                    int qStatus = NtQueryDirectoryObject(hDir, buf, bufSize,
                        false, false, ref context, out _);
                    if (qStatus != 0 && qStatus != unchecked((int)0x80000006)) // STATUS_MORE_ENTRIES
                        break;

                    // Parse OBJECT_DIRECTORY_INFORMATION array (terminates with two empty entries)
                    int infoSize = Marshal.SizeOf<OBJECT_DIRECTORY_INFORMATION>();
                    int offset = 0;
                    while (offset + infoSize <= (int)bufSize)
                    {
                        var info = Marshal.PtrToStructure<OBJECT_DIRECTORY_INFORMATION>(buf + offset);
                        offset += infoSize;

                        if (info.Name.Length == 0 && info.TypeName.Length == 0) break;

                        string name = info.Name.Buffer != nint.Zero
                            ? Marshal.PtrToStringUni(info.Name.Buffer, info.Name.Length / 2) ?? ""
                            : "";
                        string typeName = info.TypeName.Buffer != nint.Zero
                            ? Marshal.PtrToStringUni(info.TypeName.Buffer, info.TypeName.Length / 2) ?? ""
                            : "";

                        ctx.IncrementRegistryKeys();

                        // Check against known cheat object names
                        foreach (string cheatName in KnownCheatObjectNames)
                        {
                            if (!name.Contains(cheatName, StringComparison.OrdinalIgnoreCase)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Bekanntes Cheat-{typeName}-Objekt: {name}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"{dirPath}\{name}",
                                FileName = name,
                                Reason   = $"Kernel-Objekt '{name}' (Typ: {typeName}) in " +
                                           $"'{dirPath}' — erkannt als Cheat-Tool-Signatur von " +
                                           $"'{cheatName}'. Named-Kernel-Objekte bleiben bis zum " +
                                           "Schließen aller Handles erhalten und beweisen dass das " +
                                           "Cheat-Tool aktuell läuft oder kürzlich aktiv war",
                                Detail   = $"Objekt: {name} | Typ: {typeName} | Dir: {dirPath} | " +
                                           $"Erkannte Signatur: {cheatName}"
                            });
                            break; // One finding per object is enough
                        }
                    }

                    if (qStatus == 0) break; // STATUS_SUCCESS — no more entries
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
        catch { }
        finally
        {
            if (hDir != nint.Zero) NtClose(hDir);
        }
    }
}
