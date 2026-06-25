using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects DirectInput 8 virtual function table (vtable) hooks in game processes.
///
/// Aimbot and no-recoil cheats hook IDirectInputDevice8::GetDeviceState (vtable slot 9)
/// and IDirectInputDevice8::GetDeviceData (vtable slot 10) to intercept raw mouse and
/// keyboard input before the game can read it. This allows:
///   - Subtracting recoil pattern from mouse deltas (no-recoil cheat)
///   - Smoothing aim toward target (aimbot with "human-like" movement)
///   - Injecting synthetic key/button presses (triggerbot)
///
/// Different from DirectXVtableHookScanModule (checks IDXGISwapChain::Present for ESP/overlay)
/// and InputDeviceFilterScanModule (checks HID kernel-level filter drivers).
/// This specifically targets the userland DirectInput COM vtable in game processes.
///
/// Detection:
///   1. Find game processes
///   2. Locate dinput8.dll base in target process via EnumProcessModulesEx
///   3. Read dinput8.dll module range (start + SizeOfImage)
///   4. Read the first 64 KB of dinput8.dll in target process looking for vtable patterns
///   5. For each vtable entry found: check if the function pointer falls inside dinput8.dll
///      — any pointer outside the DLL's mapped range = hook pointing to injected code
///
/// Elevation required for PROCESS_VM_READ.
/// </summary>
public sealed class DirectInputVtableHookScanModule : IScanModule
{
    public string Name => "DirectInput vtable Hook Detection (Aimbot/No-Recoil Input Hook)";
    public double Weight => 0.75;
    public int ParallelGroup => 2;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(nint hProcess, nint lpBaseAddress,
        nint lpBuffer, nint nSize, out nint lpNumberOfBytesRead);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcessModulesEx(nint hProcess, nint[] lphModule,
        uint cb, out uint lpcbNeeded, uint dwFilterFlag);

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetModuleFileNameExW(nint hProcess, nint hModule,
        [Out] char[] lpFilename, uint nSize);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool GetModuleInformation(nint hProcess, nint hModule,
        out MODULEINFO lpmodinfo, uint cb);

    [StructLayout(LayoutKind.Sequential)]
    private struct MODULEINFO
    {
        public nint lpBaseOfDll;
        public uint SizeOfImage;
        public nint EntryPoint;
    }

    private const uint PROCESS_VM_READ             = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION   = 0x0400;
    private const uint LIST_MODULES_ALL            = 0x03;

    // DirectInput vtable slot indices in IDirectInputDevice8
    // Slot  0: QueryInterface, 1: AddRef, 2: Release
    // Slot  3: GetCapabilities, 4: EnumObjects, 5: GetProperty, 6: SetProperty
    // Slot  7: Acquire, 8: Unacquire
    // Slot  9: GetDeviceState  ← primary aimbot/no-recoil hook target
    // Slot 10: GetDeviceData   ← secondary hook target
    // Slot 11: SetDataFormat, 12: SetEventNotification, 13: SetCooperativeLevel
    // Slot 14: GetObjectInfo, 15: GetDeviceInfo, 16: RunControlPanel
    // Slot 17: Initialize
    private static readonly int[] HighValueSlots = { 9, 10 };
    private const int VtableCheckSlots = 18;

    private static readonly HashSet<string> GameProcessNames =
        new(StringComparer.OrdinalIgnoreCase)
    {
        "cs2", "csgo", "valorant-win64-shipping", "r5apex", "dota2",
        "payday3-win64-shipping", "eft", "escapefromtarkov",
        "destiny2", "warzone", "cod", "fortnite",
        "pubg", "tslgame", "rust", "bf2042",
        "overwatch", "overwatch2", "rainbow6", "r6", "siege",
        "gta5", "gtav", "rdr2", "eldenring",
        "dayz", "squad", "arma3", "hunt", "battlebit",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        if (!ZeroTrace.Core.Util.PrivilegeChecker.IsElevated()) return;

        var gameProcs = Process.GetProcesses()
            .Where(p => GameProcessNames.Any(g =>
                p.ProcessName.Contains(g, StringComparison.OrdinalIgnoreCase)))
            .ToArray();

        foreach (var proc in gameProcs)
        {
            ct.ThrowIfCancellationRequested();
            await Task.Run(() => AnalyzeProcess(ctx, proc, ct), ct);
            try { proc.Dispose(); } catch { }
        }
    }

    private void AnalyzeProcess(ScanContext ctx, Process proc, CancellationToken ct)
    {
        nint hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, proc.Id);
        if (hProc == nint.Zero) return;

        try
        {
            ctx.IncrementProcesses();

            // Find dinput8.dll in the target process
            nint dinput8Base = nint.Zero;
            nint dinput8End  = nint.Zero;
            string? dinput8Path = null;

            var moduleRanges = new List<(nint Start, nint End, string Name)>();

            uint needed = 0;
            nint[] dummy = new nint[1];
            EnumProcessModulesEx(hProc, dummy, (uint)nint.Size, out needed, LIST_MODULES_ALL);
            if (needed == 0) return;

            int count = (int)(needed / (uint)nint.Size);
            nint[] mods = new nint[count];
            if (!EnumProcessModulesEx(hProc, mods, (uint)(count * nint.Size), out _, LIST_MODULES_ALL))
                return;

            char[] nameBuf = new char[512];
            foreach (nint mod in mods)
            {
                if (mod == nint.Zero) continue;
                uint len = GetModuleFileNameExW(hProc, mod, nameBuf, (uint)nameBuf.Length);
                if (len == 0) continue;
                string path = new string(nameBuf, 0, (int)len);
                string baseName = System.IO.Path.GetFileName(path).ToLowerInvariant();

                if (!GetModuleInformation(hProc, mod, out MODULEINFO mi, (uint)Marshal.SizeOf<MODULEINFO>()))
                    continue;

                nint start = mi.lpBaseOfDll;
                nint end   = start + (int)mi.SizeOfImage;
                moduleRanges.Add((start, end, path));

                if (baseName == "dinput8.dll")
                {
                    dinput8Base = start;
                    dinput8End  = end;
                    dinput8Path = path;
                }
            }

            if (dinput8Base == nint.Zero) return; // dinput8 not loaded in this process

            // Scan the first 64 KB of dinput8.dll for vtable patterns
            // A vtable is an array of function pointers; we look for arrays of N
            // consecutive valid function pointers where some may point outside dinput8.
            int scanBytes = (int)Math.Min(0x10000, (long)(dinput8End - dinput8Base));
            if (scanBytes <= 0) return;

            nint scanBuf = Marshal.AllocHGlobal(scanBytes);
            try
            {
                if (!ReadProcessMemory(hProc, dinput8Base, scanBuf, scanBytes, out nint read))
                    return;

                int ptrSize = nint.Size; // 8 bytes on x64

                // Slide through buffer looking for vtable-like arrays
                for (int off = 0; off <= (int)read - VtableCheckSlots * ptrSize; off += ptrSize)
                {
                    ct.ThrowIfCancellationRequested();

                    // Check if this could be the start of IDirectInputDevice8 vtable
                    // Heuristic: first 3 slots (QI/AddRef/Release) should all be inside dinput8
                    bool isVtable = true;
                    for (int s = 0; s < 3; s++)
                    {
                        nint fptr = Marshal.ReadIntPtr(scanBuf + off + s * ptrSize);
                        if (fptr < dinput8Base || fptr >= dinput8End) { isVtable = false; break; }
                    }
                    if (!isVtable) continue;

                    // Check high-value hook slots (9 and 10)
                    foreach (int slot in HighValueSlots)
                    {
                        if (off + (slot + 1) * ptrSize > (int)read) continue;
                        nint fnPtr = Marshal.ReadIntPtr(scanBuf + off + slot * ptrSize);
                        if (fnPtr == nint.Zero) continue;

                        // Is this pointer inside dinput8?
                        if (fnPtr >= dinput8Base && fnPtr < dinput8End) continue;

                        // Is it inside any known loaded module?
                        bool inModule = moduleRanges.Any(r => fnPtr >= r.Start && fnPtr < r.End);

                        if (!inModule)
                        {
                            string slotName = slot == 9 ? "GetDeviceState" : "GetDeviceData";
                            nint vtableRva  = dinput8Base + off;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"DirectInput8 vtable-Hook in {proc.ProcessName}: IDirectInputDevice8::{slotName}",
                                Risk     = RiskLevel.Critical,
                                Location = $"Prozess: {proc.ProcessName} (PID {proc.Id}) | dinput8.dll+0x{off:X}",
                                FileName = "dinput8.dll",
                                Reason   = $"IDirectInputDevice8::{slotName} (vtable-Slot {slot}) in " +
                                           $"Prozess '{proc.ProcessName}' (PID {proc.Id}) zeigt auf " +
                                           $"Adresse 0x{fnPtr:X} — außerhalb aller geladenen Module " +
                                           "(privater, ausführbarer Speicher = injizierter Stub). " +
                                           $"Aimbot- und No-Recoil-Cheats hooken {slotName} um " +
                                           "Mausbewegungen abzufangen und Rückstoßmuster zu subtrahieren " +
                                           "bevor der Spielprozess den Input erhält.",
                                Detail   = $"Prozess: {proc.ProcessName} | PID: {proc.Id} | " +
                                           $"dinput8.dll Basis: 0x{dinput8Base:X} | " +
                                           $"vtable-Adresse: 0x{vtableRva:X} | " +
                                           $"Hook-Slot: {slot} ({slotName}) | " +
                                           $"Hook-Ziel: 0x{fnPtr:X} (kein Modul)"
                            });
                        }
                    }
                }
            }
            finally { Marshal.FreeHGlobal(scanBuf); }
        }
        catch { }
        finally { CloseHandle(hProc); }
    }
}
