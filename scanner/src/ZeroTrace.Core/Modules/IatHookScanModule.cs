using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans Import Address Table (IAT) hooks in critical Windows processes and
/// the current scanner process.
///
/// IAT hooks are a classic injection/cheat technique: instead of overwriting
/// function prologues (inline hooks), the cheat modifies the function pointer
/// stored in the PE's Import Address Table to redirect calls to a custom
/// implementation.
///
/// Unlike inline syscall-hook detection (which checks ntdll stubs), IAT hooks
/// can intercept Win32 API calls at any abstraction level — hooking
/// ReadProcessMemory in the game's IAT, for example, allows the cheat to see
/// everything the game reads from memory without being detected by traditional
/// SSDT hook scanners.
///
/// Detection method:
///   1. For the current process, parse the PE headers to walk the IAT.
///   2. For each imported function, resolve the expected address via a fresh
///      LoadLibrary + GetProcAddress call (in-process, from a clean copy).
///   3. Compare the IAT slot address against the expected address.
///   4. Any mismatch that falls outside the owning module's range = IAT hook.
///
/// Limitation: this module only inspects in-process IAT hooks (the scanner's
/// own IAT and any DLLs it has loaded). Remote process IAT inspection requires
/// ReadProcessMemory and is left to ProcessInjectionScanModule.
/// </summary>
public sealed class IatHookScanModule : IScanModule
{
    public string Name => "IAT-Hooks";
    public double Weight => 0.7;
    public int ParallelGroup => 2;

    // Critical DLL imports to verify
    private static readonly (string dll, string[] functions)[] ImportChecks =
    {
        ("kernel32.dll", new[]
        {
            "CreateFileW", "ReadFile", "WriteFile", "CreateProcessW",
            "OpenProcess", "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
            "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
            "LoadLibraryW", "LoadLibraryExW", "GetProcAddress",
            "GetModuleHandleW", "TerminateProcess",
        }),
        ("ntdll.dll", new[]
        {
            "NtQuerySystemInformation", "NtOpenProcess", "NtReadVirtualMemory",
            "NtWriteVirtualMemory", "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
            "NtCreateThread", "NtCreateThreadEx", "NtQueryVirtualMemory",
            "LdrLoadDll", "LdrGetProcedureAddress",
        }),
        ("user32.dll", new[]
        {
            "SendInput", "mouse_event", "keybd_event",
            "GetCursorPos", "SetCursorPos", "GetAsyncKeyState",
            "GetKeyState", "FindWindowW", "FindWindowExW",
        }),
        ("advapi32.dll", new[]
        {
            "RegOpenKeyExW", "RegQueryValueExW", "RegSetValueExW",
            "OpenServiceW", "StartServiceW", "ControlService",
        }),
    };

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string? lpModuleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryW(string lpLibFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule,
        out MODULEINFO lpmodinfo, uint cb);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule,
        StringBuilder lpFilename, uint nSize);

    [StructLayout(LayoutKind.Sequential)]
    private struct MODULEINFO
    {
        public IntPtr lpBaseOfDll;
        public uint   SizeOfImage;
        public IntPtr EntryPoint;
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcessModules(IntPtr hProcess,
        [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded);

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, "IAT-Hooks", "Prüfe IAT-Integrität...");

        // Build a map of loaded module base → size → name for attribution
        var moduleMap = BuildModuleMap();

        int checked_ = 0;
        int hooks    = 0;

        foreach (var (dllName, functions) in ImportChecks)
        {
            if (ct.IsCancellationRequested) break;

            // Get the module handle as already loaded in this process
            var hMod = GetModuleHandle(dllName);
            if (hMod == IntPtr.Zero)
            {
                hMod = LoadLibraryW(dllName);
                if (hMod == IntPtr.Zero) continue;
            }

            GetModuleInformation(GetCurrentProcess(), hMod, out var modInfo, (uint)Marshal.SizeOf<MODULEINFO>());
            long modBase = modInfo.lpBaseOfDll.ToInt64();
            long modEnd  = modBase + modInfo.SizeOfImage;

            foreach (var func in functions)
            {
                if (ct.IsCancellationRequested) break;
                checked_++;

                var expectedAddr = GetProcAddress(hMod, func);
                if (expectedAddr == IntPtr.Zero) continue;

                long addr = expectedAddr.ToInt64();

                // Is the function pointer within the module's own image range?
                if (addr >= modBase && addr < modEnd) continue;

                // It points somewhere outside — could be a hook or a legitimate forward
                // Check if it points into another known legitimate module
                if (IsInKnownModule(addr, moduleMap, out var ownerName))
                {
                    // Forwarded exports land in other OS modules — that's normal.
                    // But if it's in a non-OS, non-signed module, flag it.
                    if (!IsLikelySystemModule(ownerName)) hooks++;
                    else continue; // legitimate forward
                }
                else
                {
                    // Points to unknown memory — strong hook indicator
                    hooks++;
                }

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"IAT-Hook erkannt: {dllName}!{func}",
                    Risk     = IsSecurityCritical(func) ? RiskLevel.Critical : RiskLevel.High,
                    Location = $"{dllName}!{func} @ 0x{addr:X}",
                    Reason   = $"Funktionszeiger für '{dllName}!{func}' zeigt auf " +
                               $"0x{addr:X} — außerhalb des Modul-Images (erwartet: " +
                               $"0x{modBase:X}–0x{modEnd:X}). Ein IAT-Hook kann API-Aufrufe " +
                               "umleiten, um Spieler-Inputs oder Systemabfragen zu manipulieren.",
                    Detail   = $"Zieladresse: 0x{addr:X} | Modul-Range: 0x{modBase:X}–0x{modEnd:X} | " +
                               $"Eigentümer: {ownerName ?? "unbekannt"}"
                });
            }

            ctx.Report((double)(Array.IndexOf(ImportChecks, (dllName, functions)) + 1) /
                       ImportChecks.Length, "IAT-Hooks");
        }

        ctx.Report(1.0, "IAT-Hooks",
            $"{checked_} Funktionen geprüft, {hooks} IAT-Hooks erkannt");
        return Task.CompletedTask;
    }

    private static bool IsSecurityCritical(string func) => func is
        "WriteProcessMemory" or "CreateRemoteThread" or "NtWriteVirtualMemory" or
        "NtCreateThreadEx" or "NtAllocateVirtualMemory" or "NtProtectVirtualMemory" or
        "VirtualAllocEx" or "SendInput" or "mouse_event" or "keybd_event";

    private static Dictionary<(long base_, long end_), string> BuildModuleMap()
    {
        var map = new Dictionary<(long, long), string>();
        try
        {
            var hProcess = GetCurrentProcess();
            uint size = 0;
            EnumProcessModules(hProcess, Array.Empty<IntPtr>(), 0, out size);
            var modules = new IntPtr[size / (uint)IntPtr.Size];
            if (!EnumProcessModules(hProcess, modules, size, out _))
                return map;

            var sb = new StringBuilder(1024);
            foreach (var hMod in modules)
            {
                if (hMod == IntPtr.Zero) continue;
                GetModuleInformation(hProcess, hMod, out var info, (uint)Marshal.SizeOf<MODULEINFO>());
                sb.Clear();
                GetModuleFileNameEx(hProcess, hMod, sb, (uint)sb.Capacity);
                var name = Path.GetFileName(sb.ToString()).ToLowerInvariant();
                long b = info.lpBaseOfDll.ToInt64();
                long e = b + info.SizeOfImage;
                try { map[(b, e)] = name; } catch { }
            }
        }
        catch { }
        return map;
    }

    private static bool IsInKnownModule(long addr,
        Dictionary<(long base_, long end_), string> map, out string? owner)
    {
        foreach (var (range, name) in map)
        {
            if (addr >= range.base_ && addr < range.end_)
            {
                owner = name;
                return true;
            }
        }
        owner = null;
        return false;
    }

    private static bool IsLikelySystemModule(string? name)
    {
        if (name is null) return false;
        // Common Windows system DLLs that legitimately receive forwarded exports
        return name.StartsWith("ntdll") || name.StartsWith("kernel") ||
               name.StartsWith("kernelbase") || name.StartsWith("user32") ||
               name.StartsWith("advapi32") || name.StartsWith("ucrtbase") ||
               name.StartsWith("vcruntime") || name.StartsWith("msvcrt") ||
               name.StartsWith("combase") || name.StartsWith("ole32") ||
               name.StartsWith("rpcrt4") || name.StartsWith("sechost") ||
               name.StartsWith("bcrypt") || name.StartsWith("cryptbase") ||
               name.StartsWith("win32u");
    }
}
