using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects ETW (Event Tracing for Windows) tampering used by cheat software.
///
/// ETW is Windows's built-in telemetry and logging framework. Security products,
/// anti-cheat systems, and Windows Defender all rely on ETW for:
///   - Process creation/termination events (kernel ETW provider)
///   - Memory allocation events (NtAllocateVirtualMemory trace)
///   - DLL load events (LdrLoadDll trace)
///   - Thread creation events (NtCreateThreadEx trace)
///   - Network connection events (WFP ETW provider)
///   - PowerShell script execution (AMSI + ETW combined)
///
/// How cheats tamper with ETW:
///
///   1. Patching EtwEventWrite in ntdll.dll (most common):
///      - Overwrite first 2 bytes with: XOR EAX,EAX; RET (33 C0 C3)
///        or: MOV EAX,0; RET (B8 00 00 00 00 C3)
///        or simply: RET (C3)
///      - This makes ALL ETW events from this process completely silent
///      - Advanced cheats only patch for specific provider GUIDs
///
///   2. Patching EtwEventWriteFull (deeper ETW stack):
///      - Same technique on the underlying implementation
///
///   3. Patching NtTraceEvent syscall stub in ntdll:
///      - The NT-level function that delivers events to the kernel ETW consumer
///      - Patching this is stealthier than EtwEventWrite because fewer tools monitor it
///
///   4. Modifying ETW provider registration:
///      - Remove a provider GUID from the session's active provider list
///      - The provider thinks it's registered but events are silently dropped
///
///   5. Stopping ETW sessions via ControlTrace(EVENT_TRACE_CONTROL_STOP):
///      - Stop the NT Kernel Logger → no kernel-mode ETW events delivered
///      - Stop Microsoft-Windows-Security-Auditing → no 4688/4697 events
///      - Requires administrative privileges
///
///   6. EtwpLogKernelEvent patch in ntoskrnl.exe (kernel-mode, BYOVD):
///      - Most advanced — patches the kernel ETW dispatcher directly
///      - Stops ALL ETW events system-wide regardless of provider registration
///
/// Detection (user-mode, this module):
///   1. Compare EtwEventWrite prologue in our ntdll vs on-disk ntdll:
///      - Read ntdll base (GetModuleHandle) + EtwEventWrite offset (GetProcAddress)
///      - Read bytes from live ntdll memory vs the on-disk ntdll.dll file
///      - Flag if memory bytes start with RET/XOR EAX/NOP — indicates patch
///   2. Check EtwEventWriteFull and NtTraceEvent for the same pattern
///   3. Verify that key ETW-consuming sessions are still running:
///      - Microsoft-Windows-Kernel-Process provider (GUID: {22FB2CD6-...})
///      - NT Kernel Logger ({9E814AAD-3204-11D2-9A82-006008A86939})
///      via QueryTrace / EnumerateTraceGuids
///   4. Check EtwEventWrite in known-good ntdll.dll and report discrepancies
///   5. Also check EtwNotificationRegister for removal of security provider registrations
/// </summary>
public sealed class EtwTamperScanModule : IScanModule
{
    public string Name => "ETW-Tamper-Erkennung";
    public double Weight => 0.9;
    public int ParallelGroup => 0;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetCurrentProcess();

    // ETW session management — detect stopped sessions
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int QueryTrace(ulong TraceHandle, string InstanceName,
        ref EVENT_TRACE_PROPERTIES Properties);

    [StructLayout(LayoutKind.Sequential)]
    private struct EVENT_TRACE_PROPERTIES
    {
        public int Wnode_BufferSize;
        public uint Wnode_Flags;
        public Guid Wnode_Guid;
        public uint Wnode_ClientContext;
        public uint BufferSize;
        public uint MinimumBuffers;
        public uint MaximumBuffers;
        public uint MaximumFileSize;
        public uint LogFileMode;
        public uint FlushTimer;
        public uint EnableFlags;
        public int AgeLimit;
        public uint NumberOfBuffers;
        public uint FreeBuffers;
        public uint EventsLost;
        public uint BuffersWritten;
        public uint LogBuffersLost;
        public uint RealTimeBuffersLost;
        public IntPtr LoggerThreadId;
        public uint LogFileNameOffset;
        public uint LoggerNameOffset;
    }

    // ETW patch detection patterns
    private static readonly (string Name, byte FirstByte, string Description)[] PatchPatterns =
    [
        ("RET", 0xC3, "Direkte Rücksprung-Patch (C3) — Funktion gibt sofort zurück"),
        ("XOR EAX,EAX / RET", 0x33, "XOR EAX,EAX (33 C0) — Nullwert-Rückgabe vor RET"),
        ("MOV EAX,0", 0xB8, "MOV EAX,0 (B8 00...) — Nullwert-Rückgabe vor RET"),
        ("NOP sled", 0x90, "NOP-Sled (90 90...) — Funktionskörper überschrieben"),
        ("INT3 Breakpoint", 0xCC, "INT3 (CC) — Breakpoint als Hook-Trampolin"),
        ("JMP rel32", 0xE9, "JMP rel32 (E9 ...) — Umleitung zu Cheat-Handler"),
        ("JMP [mem]", 0xFF, "JMP [mem] (FF 25 ...) — Absoluter Sprung zu Cheat-Handler"),
        ("XOR RAX,RAX", 0x48, "XOR RAX,RAX (48 33 C0) — x64 Nullwert-Rückgabe"),
    ];

    // Functions to check for ETW patches (in ntdll.dll)
    private static readonly string[] EtwFunctions =
    {
        "EtwEventWrite",
        "EtwEventWriteFull",
        "EtwEventWriteEx",
        "EtwEventWriteString",
        "EtwEventWriteTransfer",
        "NtTraceEvent",
        "EtwNotificationRegister",
    };

    // Known ETW session names for active-session verification
    private static readonly string[] EtwSessionNames =
    {
        "NT Kernel Logger",
        "Microsoft-Windows-Security-Auditing",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Check ETW function patches in our own process (if cheats are active,
            // they likely patched ntdll globally or at least in our process too)
            hits += CheckEtwPatches(ctx);

            // Check critical ETW session status
            hits += CheckEtwSessions(ctx);
        }
        catch { }

        ctx.Report(1.0, Name, $"ETW-Integrität geprüft, {hits} Manipulationen erkannt");
        return Task.CompletedTask;
    }

    private static int CheckEtwPatches(ScanContext ctx)
    {
        int hits = 0;
        try
        {
            IntPtr ntdllBase = GetModuleHandle("ntdll.dll");
            if (ntdllBase == IntPtr.Zero) return 0;

            // Find ntdll.dll path on disk
            string ntdllPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), "ntdll.dll");
            if (!File.Exists(ntdllPath)) return 0;

            // Read on-disk ntdll PE header to find function RVAs
            byte[] diskBytes;
            try { diskBytes = File.ReadAllBytes(ntdllPath); }
            catch { return 0; }

            // Parse disk PE to build export table lookup
            if (diskBytes.Length < 0x200) return 0;
            if (diskBytes[0] != 'M' || diskBytes[1] != 'Z') return 0;

            int e_lfanew = BitConverter.ToInt32(diskBytes, 0x3C);
            if (e_lfanew < 0 || e_lfanew + 0x100 > diskBytes.Length) return 0;

            ushort machine = BitConverter.ToUInt16(diskBytes, e_lfanew + 4);
            bool is64 = machine == 0x8664;
            int optOff = e_lfanew + 24;
            int ddOffset = optOff + (is64 ? 0x70 : 0x60); // DataDirectory[0] = EXPORT

            if (ddOffset + 8 > diskBytes.Length) return 0;
            uint expRva  = BitConverter.ToUInt32(diskBytes, ddOffset);
            if (expRva == 0) return 0;

            // Resolve RVA to file offset
            int numSec = BitConverter.ToUInt16(diskBytes, e_lfanew + 6);
            int secStart = optOff + BitConverter.ToUInt16(diskBytes, e_lfanew + 20);

            static int RvaToOff(byte[] pe, int secBase, int secCnt, uint rva)
            {
                for (int s = 0; s < secCnt; s++)
                {
                    int off = secBase + s * 40;
                    if (off + 40 > pe.Length) break;
                    uint virt = BitConverter.ToUInt32(pe, off + 12);
                    uint raw  = BitConverter.ToUInt32(pe, off + 20);
                    uint vsz  = BitConverter.ToUInt32(pe, off + 8);
                    if (rva >= virt && rva < virt + vsz) return (int)(raw + (rva - virt));
                }
                return -1;
            }

            int expOff = RvaToOff(diskBytes, secStart, numSec, expRva);
            if (expOff < 0 || expOff + 40 > diskBytes.Length) return 0;

            uint numNames    = BitConverter.ToUInt32(diskBytes, expOff + 16);
            uint addrOfNames = BitConverter.ToUInt32(diskBytes, expOff + 28);
            uint addrOfOrds  = BitConverter.ToUInt32(diskBytes, expOff + 32);
            uint addrOfFuncs = BitConverter.ToUInt32(diskBytes, expOff + 24);
            uint numFuncs    = BitConverter.ToUInt32(diskBytes, expOff + 20);

            if (numNames > 10000 || numFuncs > 10000) return 0;

            // Build name → disk-file-offset mapping for ETW functions
            var funcDiskOffsets = new Dictionary<string, (int diskOff, uint rva)>(
                StringComparer.OrdinalIgnoreCase);

            for (uint i = 0; i < numNames && i < 10000; i++)
            {
                int nameRvaOff = RvaToOff(diskBytes, secStart, numSec, addrOfNames + i * 4);
                if (nameRvaOff < 0 || nameRvaOff + 4 > diskBytes.Length) continue;
                uint nameRva = BitConverter.ToUInt32(diskBytes, nameRvaOff);
                int nameOff  = RvaToOff(diskBytes, secStart, numSec, nameRva);
                if (nameOff < 0 || nameOff >= diskBytes.Length) continue;

                int end = nameOff;
                while (end < diskBytes.Length && diskBytes[end] != 0) end++;
                string name = System.Text.Encoding.ASCII.GetString(diskBytes, nameOff, end - nameOff);

                if (!EtwFunctions.Any(f => f.Equals(name, StringComparison.OrdinalIgnoreCase)))
                    continue;

                int ordOff = RvaToOff(diskBytes, secStart, numSec, addrOfOrds + i * 2);
                if (ordOff < 0 || ordOff + 2 > diskBytes.Length) continue;
                ushort ord = BitConverter.ToUInt16(diskBytes, ordOff);

                int funcRvaOff = RvaToOff(diskBytes, secStart, numSec, addrOfFuncs + ord * 4);
                if (funcRvaOff < 0 || funcRvaOff + 4 > diskBytes.Length) continue;
                uint funcRva = BitConverter.ToUInt32(diskBytes, funcRvaOff);
                if (funcRva == 0) continue;

                int funcDiskOff = RvaToOff(diskBytes, secStart, numSec, funcRva);
                if (funcDiskOff < 0 || funcDiskOff + 16 > diskBytes.Length) continue;

                funcDiskOffsets[name] = (funcDiskOff, funcRva);
            }

            // Now check live memory for each ETW function
            IntPtr hSelf = GetCurrentProcess();
            foreach (string funcName in EtwFunctions)
            {
                if (!funcDiskOffsets.TryGetValue(funcName, out var info)) continue;

                IntPtr funcAddr = GetProcAddress(ntdllBase, funcName);
                if (funcAddr == IntPtr.Zero) continue;

                var memBytes = new byte[16];
                if (!ReadProcessMemory(hSelf, funcAddr, memBytes, 16, out int mr) || mr < 4)
                    continue;

                // Compare first 8 bytes with disk
                var diskFirst = new byte[8];
                Buffer.BlockCopy(diskBytes, info.diskOff, diskFirst, 0, 8);

                bool differs = false;
                for (int j = 0; j < Math.Min(mr, 8); j++)
                {
                    if (memBytes[j] != diskFirst[j]) { differs = true; break; }
                }
                if (!differs) continue;

                // Is the first byte a known patch pattern?
                var pattern = PatchPatterns.FirstOrDefault(p => p.FirstByte == memBytes[0]);
                if (pattern == default) continue;

                string memHex  = BitConverter.ToString(memBytes, 0, Math.Min(mr, 8)).Replace("-", " ");
                string diskHex = BitConverter.ToString(diskFirst, 0, 8).Replace("-", " ");

                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "ETW-Tamper-Erkennung",
                    Title    = $"ETW-Funktion gepatch: ntdll!{funcName}",
                    Risk     = RiskLevel.Critical,
                    Location = $"ntdll!{funcName} @ 0x{funcAddr.ToInt64():X}",
                    Reason   = $"ntdll!{funcName} wurde im Speicher modifiziert: " +
                               $"{pattern.Description}. " +
                               $"Speicher: [{memHex}] | Disk: [{diskHex}]. " +
                               "ETW-Patches deaktivieren Windows-Telemetrie und Event-Logs. " +
                               "Cheat-Software verwendet diese Technik, um " +
                               "Prozesserstellungs-Events (4688), DLL-Load-Events, " +
                               "und Anti-Cheat-Monitoring-Callbacks zu unterdrücken. " +
                               "Betroffen: Windows Defender, EDR-Lösungen, und " +
                               "alle Tools die auf ETW-Ereignisse angewiesen sind.",
                    Detail   = $"Funktion=ntdll!{funcName} | " +
                               $"VA=0x{funcAddr.ToInt64():X} | " +
                               $"Speicher=[{memHex}] | Disk=[{diskHex}] | " +
                               $"Patch-Typ={pattern.Description}"
                });
            }
        }
        catch { }
        return hits;
    }

    private static int CheckEtwSessions(ScanContext ctx)
    {
        int hits = 0;
        try
        {
            foreach (string sessionName in EtwSessionNames)
            {
                try
                {
                    int propSize = Marshal.SizeOf<EVENT_TRACE_PROPERTIES>() + 512;
                    var props = new EVENT_TRACE_PROPERTIES { Wnode_BufferSize = propSize };

                    int result = QueryTrace(0UL, sessionName, ref props);
                    // ERROR_SUCCESS = 0, ERROR_WMI_INSTANCE_NOT_FOUND = 4201 (session stopped)
                    if (result == 4201 || result == 0x1069)
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = "ETW-Tamper-Erkennung",
                            Title    = $"ETW-Kernsitzung beendet: '{sessionName}'",
                            Risk     = RiskLevel.High,
                            Location = $"ETW-Sitzung: {sessionName}",
                            Reason   = $"Die ETW-Sitzung '{sessionName}' ist nicht aktiv. " +
                                       "Diese Sitzung sammelt kritische Windows-Sicherheitsereignisse. " +
                                       "Cheat-Software und Angreifer beenden ETW-Sitzungen via " +
                                       "ControlTrace(EVENT_TRACE_CONTROL_STOP) um " +
                                       "Prozesserstellungs-Logs (4688), Kernel-Events, und " +
                                       "Sicherheits-Auditing zu deaktivieren.",
                            Detail   = $"ETW-Sitzung='{sessionName}' | " +
                                       $"QueryTrace-Ergebnis=0x{result:X}"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
        return hits;
    }
}
