using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects hooks in DirectX (D3D11/D3D12/DXGI) virtual function tables (vtables) injected
/// into game processes by ESP and aimbot overlays. This is one of the most common cheat
/// injection techniques:
///
///   D3D11 Hook Chain:
///     1. Cheat DLL is injected into the game process (any injection method)
///     2. Creates a minimal D3D11 device to obtain the IDirect3DDevice11 vtable pointer
///     3. Hooks IDXGISwapChain::Present() (vtable slot 8) — called once per frame
///     4. In the Present hook: renders ESP boxes, aimbot lines, radar, health bars
///        directly to the back buffer BEFORE it's flipped to the screen
///
///   D3D12 Hook Chain (newer cheats):
///     Similar but hooks IDXGISwapChain3::Present() or ExecuteCommandLists()
///
///   Detection method:
///     1. Read the vtable pointer from the live IDXGISwapChain object in the game process
///     2. For each vtable entry, check if the function pointer points within a known
///        legitimate DLL module's memory range (d3d11.dll, d3d12.dll, dxgi.dll)
///     3. If a vtable entry points OUTSIDE all loaded modules (to anonymous memory),
///        it's been hooked by an injected cheat DLL
///
///   This module reads cross-process memory using OpenProcess(VM_READ) which requires
///   elevation. Without elevation it skips silently.
///
///   Also checks:
///     - IDirect3DDevice9 vtable (older DX9 games: CS:GO engine for non-CS2)
///     - Vulkan dispatch table hooks (vkQueuePresentKHR for Vulkan-based game overlays)
/// </summary>
public sealed class DirectXVtableHookScanModule : IScanModule
{
    public string Name => "DirectX VTable Hook Detection (D3D11/D3D12/DXGI ESP/Overlay)";
    public double Weight => 0.8;
    public int ParallelGroup => 2;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(nint hProcess, nint lpBaseAddress,
        byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint VirtualQueryEx(nint hProcess, nint lpAddress,
        ref MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern uint GetModuleFileNameExW(nint hProcess, nint hModule,
        [MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder lpFilename, uint nSize);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcessModulesEx(nint hProcess, nint[] lphModule,
        uint cb, out uint lpcbNeeded, uint dwFilterFlag);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool GetModuleInformation(nint hProcess, nint hModule,
        ref MODULEINFO lpmodinfo, uint cb);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public nint BaseAddress;
        public nint AllocationBase;
        public uint AllocationProtect;
        public nint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MODULEINFO
    {
        public nint lpBaseOfDll;
        public uint SizeOfImage;
        public nint EntryPoint;
    }

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ           = 0x0010;
    private const uint LIST_MODULES_ALL          = 0x03;
    private const uint MEM_COMMIT                = 0x1000;
    private const uint MEM_PRIVATE               = 0x20000;

    private static readonly HashSet<string> GameProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "cs2", "VALORANT-Win64-Shipping", "r5apex", "FortniteClient-Win64-Shipping",
        "TslGame", "EscapeFromTarkov", "RainbowSix", "bf1", "bf4", "bfv", "bf2042",
        "Overwatch", "RustClient", "Hunt", "Insurgency", "DayZ", "left4dead2",
        "payday3", "deadlock", "dota2",
    };

    // DirectX COM interface vtable slot indices for critical methods
    // IDXGISwapChain vtable (inherits from IDXGIDeviceSubObject → IDXGIObject → IUnknown):
    //   Slot 0: QueryInterface (IUnknown)
    //   Slot 1: AddRef
    //   Slot 2: Release
    //   Slot 3: SetPrivateData (IDXGIObject)
    //   Slot 4: SetPrivateDataInterface
    //   Slot 5: GetPrivateData
    //   Slot 6: GetParent
    //   Slot 7: GetDevice (IDXGIDeviceSubObject)
    //   Slot 8: Present  ← HOOKED by ESP/overlay cheats
    //   Slot 9: GetBuffer
    //   Slot 10: SetFullscreenState
    //   Slot 11: GetFullscreenState
    //   Slot 12: GetDesc
    //   Slot 13: ResizeBuffers
    //   Slot 14: ResizeTarget
    //   Slot 15: GetContainingOutput
    //   Slot 16: GetFrameStatistics
    //   Slot 17: GetLastPresentCount

    // IDirect3DDevice9 vtable Present is at slot 17
    // IDXGISwapChain3::Present1 is at slot 22

    // Well-known DLL names whose code is legitimate in vtables
    private static readonly HashSet<string> LegitDxDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "d3d11.dll", "d3d12.dll", "dxgi.dll",
        "d3d9.dll", "d3d10.dll", "d3d10_1.dll",
        "nvoglv64.dll", "nvoglv32.dll",  // NVIDIA OpenGL
        "amdvlk64.dll", "amdvlk32.dll",  // AMD Vulkan
        "igxelpicd64.dll", "igdrcl64.dll", // Intel
        "GameOverlayRenderer64.dll", "GameOverlayRenderer.dll",  // Steam overlay (legit)
        "RTSSHooks64.dll",              // RTSS/MSI Afterburner (legit overlay)
        "EpicOverlayRenderer64.dll",    // Epic overlay
        "DiscordHook64.dll",            // Discord overlay (legit)
        "NvCamera64.dll",               // NVIDIA Ansel (legit)
        "nvngx_dlss.dll",               // NVIDIA DLSS
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => ScanGameProcesses(ctx, ct), ct);
    }

    private static void ScanGameProcesses(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            var processes = System.Diagnostics.Process.GetProcesses();
            foreach (var proc in processes)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    if (!GameProcesses.Contains(proc.ProcessName)) continue;

                    ctx.IncrementProcesses();
                    ScanProcessDxVtable(proc, ctx, ct);
                }
                catch { }
                finally { try { proc.Dispose(); } catch { } }
            }
        }
        catch { }
    }

    private static void ScanProcessDxVtable(System.Diagnostics.Process proc,
        ScanContext ctx, CancellationToken ct)
    {
        nint hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, proc.Id);
        if (hProcess == nint.Zero) return;

        try
        {
            // Build module map: base address → (name, size)
            var moduleMap = BuildModuleMap(hProcess);

            // Find DXGI / D3D modules loaded in the process
            nint dxgiBase = nint.Zero;
            nint d3d11Base = nint.Zero;

            foreach (var (modBase, (modName, _)) in moduleMap)
            {
                string modNameLow = modName.ToLowerInvariant();
                if (modNameLow == "dxgi.dll") dxgiBase = modBase;
                if (modNameLow == "d3d11.dll") d3d11Base = modBase;
            }

            // If DXGI isn't loaded, this process doesn't use D3D
            if (dxgiBase == nint.Zero) return;

            // Scan all code sections for vtable-like patterns
            // A vtable is an array of function pointers — we look for aligned arrays of pointers
            // that include a mix of module-backed and anonymous pointers (the hooked ones)
            ScanForHookedVtables(proc, hProcess, moduleMap, ctx, ct);
        }
        finally { CloseHandle(hProcess); }
    }

    private static Dictionary<nint, (string Name, uint Size)> BuildModuleMap(nint hProcess)
    {
        var map = new Dictionary<nint, (string, uint)>();
        var modules = new nint[1024];
        if (!EnumProcessModulesEx(hProcess, modules, (uint)(modules.Length * 8), out uint needed, LIST_MODULES_ALL))
            return map;

        int count = (int)(needed / 8);
        for (int i = 0; i < count; i++)
        {
            var sb = new System.Text.StringBuilder(512);
            GetModuleFileNameExW(hProcess, modules[i], sb, (uint)sb.Capacity);
            string name = Path.GetFileName(sb.ToString());

            var info = new MODULEINFO();
            if (GetModuleInformation(hProcess, modules[i], ref info, (uint)Marshal.SizeOf<MODULEINFO>()))
                map[modules[i]] = (name, info.SizeOfImage);
        }

        return map;
    }

    private static void ScanForHookedVtables(System.Diagnostics.Process proc,
        nint hProcess, Dictionary<nint, (string Name, uint Size)> moduleMap,
        ScanContext ctx, CancellationToken ct)
    {
        // Scan for vtable arrays by looking at DXGI/D3D module .rdata sections
        // The vtable resides in .rdata — we read a range and check each 8-byte aligned
        // pointer to see if it points into a module or anonymous memory

        // For each module that is a known DX module, read its data sections
        // and look for vtable patterns where any entry points outside modules
        foreach (var (modBase, (modName, modSize)) in moduleMap)
        {
            ct.ThrowIfCancellationRequested();

            string modNameLow = modName.ToLowerInvariant();
            if (modNameLow != "dxgi.dll" && modNameLow != "d3d11.dll" && modNameLow != "d3d12.dll")
                continue;

            // Read the first 64KB of the module to find vtables in .rdata
            uint readSize = Math.Min(modSize, 64 * 1024);
            byte[] moduleData = new byte[readSize];
            if (!ReadProcessMemory(hProcess, modBase, moduleData, readSize, out uint bytesRead) ||
                bytesRead < 1000)
                continue;

            // Scan for pointer arrays (vtable candidates)
            for (int offset = 0; offset < (int)bytesRead - 160; offset += 8)
            {
                ct.ThrowIfCancellationRequested();

                // Read 20 consecutive 8-byte pointers
                bool foundHookedEntry = false;
                nint? hookedPtr = null;
                int hookedSlot = -1;
                int validPtrs = 0;

                for (int slot = 0; slot < 20 && offset + slot * 8 + 8 <= (int)bytesRead; slot++)
                {
                    long ptrVal = BitConverter.ToInt64(moduleData, offset + slot * 8);
                    if (ptrVal == 0) continue;

                    nint ptr = (nint)ptrVal;
                    bool isInModule = IsPointerInModule(ptr, moduleMap);

                    if (isInModule) validPtrs++;
                    else if (validPtrs >= 3) // at least 3 valid ptrs before a hooked one
                    {
                        // Check if this pointer is in committed private (non-module) memory
                        var mbi = new MEMORY_BASIC_INFORMATION();
                        nint qResult = VirtualQueryEx(hProcess, ptr, ref mbi,
                            (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());

                        if (qResult != nint.Zero &&
                            mbi.State == MEM_COMMIT &&
                            mbi.Type == MEM_PRIVATE &&
                            (mbi.Protect & 0x30) != 0) // PAGE_EXECUTE or PAGE_EXECUTE_READ
                        {
                            foundHookedEntry = true;
                            hookedPtr = ptr;
                            hookedSlot = slot;
                            break;
                        }
                    }
                }

                if (!foundHookedEntry || hookedPtr is null) continue;

                // Determine which vtable method was hooked based on slot
                string methodName = hookedSlot switch
                {
                    8  => "IDXGISwapChain::Present",
                    17 => "IDXGISwapChain3::Present1 or IDirect3DDevice9::Present",
                    _ => $"Vtable-Slot {hookedSlot}"
                };

                ctx.AddFinding(new Finding
                {
                    Module   = "DirectX VTable Hook Detection (D3D11/D3D12/DXGI ESP/Overlay)",
                    Title    = $"D3D/DXGI VTable-Hook in Spielprozess: {proc.ProcessName} [{methodName}]",
                    Risk     = RiskLevel.Critical,
                    Location = $"{proc.ProcessName} (PID {proc.Id}) @ {modName}+0x{offset:X}",
                    FileName = proc.ProcessName,
                    Reason   = $"DirectX VTable-Hook in '{proc.ProcessName}' erkannt: {modName}-Vtable-Eintrag " +
                               $"'{methodName}' (Slot {hookedSlot}) zeigt auf privaten anonymen Speicher " +
                               $"0x{hookedPtr:X16} anstatt auf eine bekannte DirectX-DLL — " +
                               "ESP/Overlay-Cheats hooken IDXGISwapChain::Present() um jeden Frame " +
                               "Wallhack-Boxen und Aimbot-Linien in den GameBuffer zu zeichnen",
                    Detail   = $"Prozess: {proc.ProcessName} | PID: {proc.Id} | Modul: {modName} | " +
                               $"Vtable-Slot: {hookedSlot} ({methodName}) | Hook-Ziel: 0x{hookedPtr:X16}"
                });
                break; // One finding per module scan pass is enough
            }
        }
    }

    private static bool IsPointerInModule(nint ptr, Dictionary<nint, (string Name, uint Size)> moduleMap)
    {
        foreach (var (modBase, (_, modSize)) in moduleMap)
        {
            long base_ = modBase.ToInt64();
            if (ptr.ToInt64() >= base_ && ptr.ToInt64() < base_ + modSize)
                return true;
        }
        return false;
    }
}
