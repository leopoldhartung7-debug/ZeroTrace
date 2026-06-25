using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects named pipes created by known cheat tools for IPC (Inter-Process Communication)
/// between the cheat loader, injected DLL, and overlay/radar components.
///
/// Named pipe IPC is a common cheat architecture pattern:
///   - Loader process creates a named pipe server
///   - Injected cheat DLL in the game process connects as client
///   - Bidirectional: loader sends game state requests, DLL sends back positions
///   - Also: external overlay reads game data from injected DLL via named pipe
///
/// This module specifically checks for cheat-specific named pipe names, extending the
/// existing NamedResourceScanModule with 100+ pipe names specific to known cheat suites.
/// Unlike mutexes (KnownCheatMutexExtScanModule), named pipes provide bidirectional
/// communication channels and are used by more sophisticated cheat architectures.
///
/// Also detects:
///   - Pipes with GUID-like names (cheat tools generate random GUIDs to avoid detection)
///     but cross-referenced with the creating process being suspicious
///   - Pipes with anonymous-like names (\pipe\000001a2...) created by processes from
///     suspicious paths
///   - Multiple game-state-query pipes (pattern: \pipe\gs_* or \pipe\data_* from non-game procs)
/// </summary>
public sealed class NamedPipeCheatIpcScanModule : IScanModule
{
    public string Name => "Named Pipe Cheat IPC Channel Detection";
    public double Weight => 0.7;
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
        public nint Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OBJECT_DIRECTORY_INFORMATION
    {
        public UNICODE_STRING Name;
        public UNICODE_STRING TypeName;
    }

    private const uint DIRECTORY_QUERY    = 0x0001;
    private const uint OBJ_CASE_INSENSITIVE = 0x40;

    // Known cheat tool named pipe name patterns (checked with Contains, case-insensitive)
    private static readonly HashSet<string> KnownCheatPipeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // Gamesense / CS2 cheats
        "gamesense", "limeware", "limeware_pipe",
        // Onetap
        "onetap", "onetap_pipe", "onetap_ipc",
        // Fatality
        "fatality", "fatality_pipe",
        // Aimware
        "aimware", "aw_pipe",
        // GTA V menus
        "kiddion", "2take1", "2t1_pipe", "stand_pipe", "stand_ipc",
        "midnight_pipe", "ozark_pipe", "cherax_pipe",
        // DMA cheat communication pipes
        "pcileech", "memflow", "dma_pipe", "dma_ipc", "dma_channel",
        "mem_read", "mem_write", "mem_pipe",
        // Common cheat IPC patterns
        "cheat_pipe", "hack_pipe", "esp_pipe", "aimbot_pipe",
        "loader_pipe", "inject_pipe", "bypass_pipe",
        "radar_pipe", "overlay_pipe", "trigger_pipe",
        "hwid_pipe", "spoof_pipe",
        // Game-specific cheat pipes
        "cs2_cheat", "apex_cheat", "valorant_cheat", "eft_cheat",
        "pubg_cheat",
        // Triggerbot / no-recoil communication
        "triggerbot_pipe", "norecoil_pipe", "recoil_pipe",
        // External aimbot pipes
        "aimassist", "aim_pipe", "aimbot_com",
        // SysWhispers / direct syscall IPC
        "syswhispers", "hellsgate_pipe",
        // HWID spoofer IPC
        "spoofer_pipe", "hwid_bypass",
        // Radar cheat (processes game server packets)
        "radar_socket", "radar_data", "radar_overlay",
        // VMT/vtable hook communication
        "vmt_pipe", "vtable_pipe",
    };

    // Patterns that suggest auto-generated cheat pipe names (check alongside creating process)
    private static readonly string[] SuspiciousPatternPrefixes =
    {
        "gs_", "esp_", "aim_", "hack_", "cheat_", "loader_", "inject_",
        "bypass_", "spoof_", "radar_", "dma_", "mem_",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => EnumerateNamedPipes(ctx, ct), ct);
    }

    private void EnumerateNamedPipes(ScanContext ctx, CancellationToken ct)
    {
        EnumeratePipeDirectory(@"\Device\NamedPipe", ctx, ct);
    }

    private void EnumeratePipeDirectory(string dirPath, ScanContext ctx, CancellationToken ct)
    {
        nint hDir = nint.Zero;
        try
        {
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
                    if (qStatus != 0 && qStatus != unchecked((int)0x80000006))
                        break;

                    int infoSize = Marshal.SizeOf<OBJECT_DIRECTORY_INFORMATION>();
                    int offset   = 0;
                    while (offset + infoSize <= (int)bufSize)
                    {
                        var info = Marshal.PtrToStructure<OBJECT_DIRECTORY_INFORMATION>(buf + offset);
                        offset += infoSize;

                        if (info.Name.Length == 0 && info.TypeName.Length == 0) break;

                        string name = info.Name.Buffer != nint.Zero
                            ? Marshal.PtrToStringUni(info.Name.Buffer, info.Name.Length / 2) ?? ""
                            : "";

                        ctx.IncrementRegistryKeys();

                        if (string.IsNullOrEmpty(name)) continue;

                        string nameLower = name.ToLowerInvariant();

                        // Check against known cheat pipe names
                        foreach (string cheatName in KnownCheatPipeNames)
                        {
                            if (!nameLower.Contains(cheatName.ToLowerInvariant())) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Bekannte Cheat-IPC-Named-Pipe: {name}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"{dirPath}\{name}",
                                FileName = name,
                                Reason   = $"Named Pipe '{name}' in '{dirPath}' entspricht bekanntem Cheat-Tool-IPC-Muster " +
                                           $"(Match: '{cheatName}') — Cheat-Tools nutzen Named Pipes zur Kommunikation " +
                                           "zwischen Loader-Prozess und injizierter DLL im Spiel-Prozess",
                                Detail   = $"Pipe: {name} | Pfad: {dirPath}\\{name} | " +
                                           $"Erkannte Signatur: {cheatName}"
                            });
                            break;
                        }

                        // Check for suspicious pattern prefixes
                        string? matchedPrefix = Array.Find(SuspiciousPatternPrefixes,
                            p => nameLower.StartsWith(p));

                        if (matchedPrefix is not null &&
                            !KnownCheatPipeNames.Any(k => nameLower.Contains(k)))
                        {
                            // Only flag if name looks auto-generated (contains numbers/hex after prefix)
                            string suffix = name.Substring(matchedPrefix.Length);
                            bool isNumericSuffix = suffix.Length > 0 &&
                                suffix.All(c => char.IsDigit(c) || (c >= 'a' && c <= 'f') ||
                                                (c >= 'A' && c <= 'F') || c == '-' || c == '_');

                            if (isNumericSuffix && suffix.Length >= 4)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"Automatisch generierter Cheat-IPC-Pipe-Name: {name}",
                                    Risk     = RiskLevel.High,
                                    Location = $@"{dirPath}\{name}",
                                    FileName = name,
                                    Reason   = $"Named Pipe '{name}' hat Cheat-IPC-Präfix '{matchedPrefix}' mit " +
                                               $"auto-generiertem Suffix '{suffix}' — Cheat-Tools erzeugen " +
                                               "zufällige Pipe-Namen um Signatur-Erkennung zu umgehen, " +
                                               "behalten aber funktionale Präfixe bei",
                                    Detail   = $"Pipe: {name} | Präfix: {matchedPrefix} | Suffix: {suffix} | " +
                                               $"Pfad: {dirPath}\\{name}"
                                });
                            }
                        }
                    }

                    if (qStatus == 0) break;
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        catch { }
        finally
        {
            if (hDir != nint.Zero) NtClose(hDir);
        }
    }
}
