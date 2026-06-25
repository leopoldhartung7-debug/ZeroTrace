using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Verifies Steam API DLL integrity in game processes: compares steam_api64.dll and
/// steam_api.dll export function prologue bytes in process memory against the on-disk
/// PE file. Detects patched SteamInit, SteamEncryptedAppTicket, SteamApps, and VAC/DRM
/// check functions indicating Steam DRM bypass, version spoofing, or offline crackers.
/// Also checks for known Steam emulator DLLs (Goldberg Emulator, CreamAPI, Koaloader,
/// SteamStub) loaded in game processes instead of the legitimate Steam API.
/// </summary>
public sealed class SteamApiIntegrityScanModule : IScanModule
{
    public string Name => "Steam API Integrity";
    public double Weight => 0.7;
    public int ParallelGroup => 0;

    // High-value Steam API exports to verify
    private static readonly string[] SteamExportsToCheck =
    {
        "SteamAPI_Init",
        "SteamAPI_RunCallbacks",
        "SteamAPI_Shutdown",
        "SteamEncryptedAppTicket_BDecryptTicket",
        "SteamAPI_ISteamApps_BIsSubscribed",
        "SteamAPI_ISteamApps_GetAppBuildId",
        "SteamAPI_ISteamUser_GetAuthTicketForWebApi",
        "SteamAPI_ISteamUser_GetSteamID",
        "SteamAPI_RestartAppIfNecessary",
    };

    // Known Steam emulator / crack DLL names
    private static readonly (string FileName, string Description)[] EmuDlls =
    {
        ("steam_api64.dll",     ""), // legit — detect by content, not name
        ("steam_api.dll",       ""), // legit — detect by content, not name
        // Actual emulator DLL names that replace the legit steam_api
        ("steamclient64.dll",   ""), // can be legit — flag only from wrong path
        ("goldberg_steam_emu",  "Goldberg Steam Emulator (VAC/DRM Bypass)"),
        ("creamapi",            "CreamAPI DLC Unlocker (Steam DRM Bypass)"),
        ("koaloader",           "Koaloader (Steam DLC Bypass)"),
        ("smokeapi",            "SmokeAPI (Steam DLC Unlocker)"),
        ("steamemu",            "Steam Emulator (veraltete Crack-Library)"),
        ("skidrow",             "Skidrow Crack DLL (Piracy Indicator)"),
        ("ali213",              "Ali213 Steam Emulator"),
        ("valve_ds",            ""), // legit Valve dedicated server
        ("codex",               "CODEX Crack DLL (Piracy Indicator)"),
        ("flt",                 "FLT Crack DLL (Piracy Indicator)"),
        ("razor1911",           "Razor1911 Crack (Piracy Indicator)"),
    };

    // Tells us it's a fake steam_api based on string presence in the file
    private static readonly string[] EmuStringMarkers =
    {
        "Goldberg SteamEmulator",
        "CreamAPI",
        "SmokeAPI",
        "Koaloader",
        "ALI213",
        "STEAMEMU",
        "FAKE STEAM",
        "Steam Emulator",
        "SmartSteamEmu",
        "SSE Revision",
    };

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        nint hProcess, nint lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll")]
    private static extern bool Module32First(nint hSnapshot, ref MODULEENTRY32 lpme);

    [DllImport("kernel32.dll")]
    private static extern bool Module32Next(nint hSnapshot, ref MODULEENTRY32 lpme);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    private struct MODULEENTRY32
    {
        public uint dwSize;
        public uint th32ModuleID, th32ProcessID, GlblcntUsage, ProccntUsage;
        public nint modBaseAddr;
        public uint modBaseSize;
        public nint hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExePath;
    }

    private const uint TH32CS_SNAPMODULE        = 0x00000008;
    private const uint TH32CS_SNAPMODULE32       = 0x00000010;
    private const uint PROCESS_VM_READ           = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private static readonly nint InvalidHandle   = new nint(-1);

    private static readonly string[] GameProcessNames =
    {
        "cs2", "csgo", "hl2", "game", "r5apex", "pubg", "rust", "fortnite",
        "apex", "eft", "destiny", "warzone", "overwatch", "cod", "dota2", "tf2",
        "hll", "battlefront", "paladins", "rocketleague", "insurgency", "l4d2"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var targets = GetTargetProcesses();
        if (targets.Count == 0) return;

        await Task.Run(() =>
        {
            foreach (var proc in targets)
            {
                ct.ThrowIfCancellationRequested();
                try { ScanProcess(proc, ctx, ct); }
                catch { /* skip */ }
                finally { proc.Dispose(); }
                ctx.IncrementProcesses();
            }
        }, ct);
    }

    private void ScanProcess(Process proc, ScanContext ctx, CancellationToken ct)
    {
        nint hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (uint)proc.Id);
        if (hSnap == InvalidHandle) return;

        try
        {
            var me = new MODULEENTRY32 { dwSize = (uint)Marshal.SizeOf<MODULEENTRY32>() };
            if (!Module32First(hSnap, ref me)) return;

            do
            {
                ct.ThrowIfCancellationRequested();
                string modName = me.szModule.ToLowerInvariant();
                string modPath = me.szExePath;

                // Check for known emulator DLL names
                foreach (var (emu, desc) in EmuDlls)
                {
                    if (string.IsNullOrEmpty(desc)) continue; // skip legit ones here
                    if (modName.Contains(emu.ToLowerInvariant()))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Steam API Integrity",
                            Title = $"Steam Emulator DLL in {proc.ProcessName}: {me.szModule}",
                            Risk = RiskLevel.Critical,
                            Location = modPath,
                            FileName = me.szModule,
                            Reason = $"Bekannte Steam Emulator DLL '{me.szModule}' in Spielprozess — " +
                                     "ersetzt echte Steam API um Kopierschutz/VAC zu umgehen",
                            Detail = $"{desc} | Pfad: {modPath}"
                        });
                    }
                }

                // Check steam_api DLLs specifically
                if (modName == "steam_api64.dll" || modName == "steam_api.dll")
                {
                    CheckSteamApiDll(proc, me, ctx, ct);
                }
            }
            while (Module32Next(hSnap, ref me));
        }
        finally { CloseHandle(hSnap); }
    }

    private void CheckSteamApiDll(Process proc, MODULEENTRY32 me, ScanContext ctx, CancellationToken ct)
    {
        string diskPath = me.szExePath;
        if (!File.Exists(diskPath)) return;

        nint hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, proc.Id);
        if (hProc == nint.Zero) return;

        try
        {
            // Check 1: Scan DLL file for emulator string markers
            try
            {
                long fileSize = new FileInfo(diskPath).Length;
                if (fileSize < 50L * 1024 * 1024) // only scan small DLLs
                {
                    using var fs = File.Open(diskPath, FileMode.Open, FileAccess.Read,
                        FileShare.ReadWrite | FileShare.Delete);
                    using var sr = new StreamReader(fs, System.Text.Encoding.Latin1);
                    string content = sr.ReadToEnd();

                    foreach (var marker in EmuStringMarkers)
                    {
                        if (content.Contains(marker, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Steam API Integrity",
                                Title = $"Steam Emulator String in {me.szModule}: '{marker}'",
                                Risk = RiskLevel.Critical,
                                Location = diskPath,
                                FileName = me.szModule,
                                Reason = $"Datei '{me.szModule}' enthaelt Steam-Emulator Bezeichnung '{marker}' — " +
                                         "gefaelschte Steam API ersetzt die echte Valve-Bibliothek",
                                Detail = $"Marker: {marker} | Pfad: {diskPath} | " +
                                         "Diese Datei ist keine offizielle Valve Steam API"
                            });
                            break;
                        }
                    }
                }
            }
            catch { }

            // Check 2: Compare key export function prologue bytes (memory vs disk)
            var memHeader = new byte[0x1000];
            if (!ReadProcessMemory(hProc, me.modBaseAddr, memHeader, memHeader.Length, out _))
                return;

            if (memHeader[0] != 'M' || memHeader[1] != 'Z') return;

            int e_lfanew = BitConverter.ToInt32(memHeader, 0x3C);
            if (e_lfanew < 0 || e_lfanew + 24 > memHeader.Length) return;
            if (memHeader[e_lfanew] != 'P' || memHeader[e_lfanew + 1] != 'E') return;

            ushort machine = BitConverter.ToUInt16(memHeader, e_lfanew + 4);
            bool is64 = machine == 0x8664;

            // Get export directory RVA
            int ddBase = e_lfanew + 24 + (is64 ? 0x70 : 0x60);
            if (ddBase + 8 > memHeader.Length) return;

            uint exportRva  = BitConverter.ToUInt32(memHeader, ddBase);
            if (exportRva == 0) return;

            // Read export directory from process memory
            var exportDir = new byte[40];
            if (!ReadProcessMemory(hProc, me.modBaseAddr + (nint)exportRva, exportDir, exportDir.Length, out _))
                return;

            // IMAGE_EXPORT_DIRECTORY: [0]=Characteristics [4]=TimeDateStamp [8]=MajorVersion [10]=MinorVersion
            // [12]=Name [16]=Base [20]=NumberOfFunctions [24]=NumberOfNames [28]=AddressOfFunctions
            // [32]=AddressOfNames [36]=AddressOfNameOrdinals
            uint numNames     = BitConverter.ToUInt32(exportDir, 24);
            uint addrOfNames  = BitConverter.ToUInt32(exportDir, 32);
            uint addrOfFuncs  = BitConverter.ToUInt32(exportDir, 28);
            uint addrOfOrds   = BitConverter.ToUInt32(exportDir, 36);

            if (numNames == 0 || addrOfNames == 0 || addrOfFuncs == 0) return;

            // Read name array (up to 1000 exports)
            uint nameCount = Math.Min(numNames, 1000u);
            var nameRvas   = new byte[nameCount * 4];
            var ordRvas    = new byte[nameCount * 2];
            var funcRvas   = new byte[Math.Min(numNames + 16u, 2000u) * 4];

            if (!ReadProcessMemory(hProc, me.modBaseAddr + (nint)addrOfNames, nameRvas, nameRvas.Length, out _))
                return;
            if (!ReadProcessMemory(hProc, me.modBaseAddr + (nint)addrOfOrds, ordRvas, ordRvas.Length, out _))
                return;
            if (!ReadProcessMemory(hProc, me.modBaseAddr + (nint)addrOfFuncs, funcRvas, funcRvas.Length, out _))
                return;

            // Build export name → function RVA map
            var exportMap = new Dictionary<string, uint>(StringComparer.Ordinal);
            for (uint i = 0; i < nameCount; i++)
            {
                uint nameRva = BitConverter.ToUInt32(nameRvas, (int)(i * 4));
                if (nameRva == 0) continue;
                var nameBuf = new byte[128];
                if (!ReadProcessMemory(hProc, me.modBaseAddr + (nint)nameRva, nameBuf, nameBuf.Length, out _))
                    continue;
                int nl = Array.IndexOf(nameBuf, (byte)0);
                if (nl <= 0) continue;
                string expName = System.Text.Encoding.ASCII.GetString(nameBuf, 0, nl);

                ushort ordOff = BitConverter.ToUInt16(ordRvas, (int)(i * 2));
                if (ordOff * 4 + 4 > funcRvas.Length) continue;
                uint funcRva = BitConverter.ToUInt32(funcRvas, ordOff * 4);
                exportMap[expName] = funcRva;
            }

            // For each target export, compare memory bytes vs disk
            byte[] diskBytes;
            try
            {
                diskBytes = File.ReadAllBytes(diskPath);
            }
            catch { return; }

            foreach (var exportName in SteamExportsToCheck)
            {
                ct.ThrowIfCancellationRequested();
                if (!exportMap.TryGetValue(exportName, out uint funcRva)) continue;
                if (funcRva == 0 || funcRva > me.modBaseSize) continue;

                // Read 16 bytes from process memory at this export
                var memBytes = new byte[16];
                if (!ReadProcessMemory(hProc, me.modBaseAddr + (nint)funcRva, memBytes, memBytes.Length, out _))
                    continue;

                // Compare with disk at same file offset
                // Need to resolve RVA to file offset via section table
                uint fileOff = RvaToFileOffset(memHeader, funcRva, e_lfanew, is64);
                if (fileOff == 0 || fileOff + 16 > diskBytes.Length) continue;

                int mismatch = 0;
                for (int b = 0; b < 16; b++)
                    if (memBytes[b] != diskBytes[fileOff + b]) mismatch++;

                // Flag JMP or other hook opcodes at the start
                bool hasJmp = memBytes[0] == 0xE9 || memBytes[0] == 0xEB ||
                              (memBytes[0] == 0xFF && (memBytes[1] == 0x25 || memBytes[1] == 0x15)) ||
                              memBytes[0] == 0xB8 && memBytes[5] == 0xFF; // MOV RAX+JMP

                if (mismatch >= 4 || hasJmp)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "Steam API Integrity",
                        Title = $"Steam API Funktion gepatcht: {exportName}",
                        Risk = RiskLevel.Critical,
                        Location = diskPath,
                        FileName = me.szModule,
                        Reason = $"Steam API Export '{exportName}' in Prozess {proc.ProcessName} " +
                                 $"hat {mismatch}/16 Bytes abweichend von Disk-PE — Hook oder Crack-Patch",
                        Detail = $"Speicher[0..3]: {memBytes[0]:X2} {memBytes[1]:X2} {memBytes[2]:X2} {memBytes[3]:X2} | " +
                                 $"Disk[0..3]: {diskBytes[fileOff]:X2} {diskBytes[fileOff+1]:X2} {diskBytes[fileOff+2]:X2} {diskBytes[fileOff+3]:X2} | " +
                                 (hasJmp ? "JMP/HOOK erkannt" : $"{mismatch} Byte-Abweichungen")
                    });
                }
            }
        }
        finally { CloseHandle(hProc); }
    }

    private static uint RvaToFileOffset(byte[] header, uint rva, int e_lfanew, bool is64)
    {
        int sectionCount = BitConverter.ToUInt16(header, e_lfanew + 6);
        int optHdrSize   = BitConverter.ToUInt16(header, e_lfanew + 20);
        int firstSection = e_lfanew + 24 + optHdrSize;

        for (int i = 0; i < sectionCount; i++)
        {
            int off = firstSection + i * 40;
            if (off + 40 > header.Length) break;
            uint va  = BitConverter.ToUInt32(header, off + 12);
            uint sz  = BitConverter.ToUInt32(header, off + 8);
            uint raw = BitConverter.ToUInt32(header, off + 20);
            if (rva >= va && rva < va + sz)
                return raw + (rva - va);
        }
        return 0;
    }

    private static List<Process> GetTargetProcesses()
    {
        var result = new List<Process>();
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    string name = proc.ProcessName.ToLowerInvariant();
                    if (Array.Exists(GameProcessNames, n => name.Contains(n)))
                        result.Add(proc);
                    else
                        proc.Dispose();
                }
                catch { proc.Dispose(); }
            }
        }
        catch { }
        return result;
    }
}
