using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Communicates with the ZeroTrace kernel driver (ZeroTraceDriver.sys) via
/// DeviceIoControl IOCTLs to perform ring-0-level detections that cannot be
/// faked or hidden from userland:
///
///   • DKOM-hidden processes (visible in kernel EPROCESS list, absent from
///     Toolhelp32 / Task Manager).
///   • Hooked SSDT entries (patched kernel syscall table pointers).
///   • Ghost kernel modules (loaded but not in PsLoadedModuleList).
///   • Suspicious kernel callbacks (CreateProcess/Thread/LoadImage registered
///     by non-whitelisted modules).
///   • Hypervisor presence (CPUID + RDTSC timing) — detects cheat VMs.
///
/// If the driver is not installed the module records a single informational
/// finding and exits cleanly; nothing is required for the rest of the scan.
/// </summary>
public sealed class KernelBridgeModule : IScanModule
{
    public string Name => "Kernel-Bridge (Ring-0)";
    public double Weight => 2.0;
    public int ParallelGroup => 3;

    // ── P/Invoke ──────────────────────────────────────────────────────────────

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeHandle hDevice, uint dwIoControlCode,
        IntPtr lpInBuffer, uint nInBufferSize,
        IntPtr lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

    // ── IOCTL codes (must match ioctl.h) ──────────────────────────────────────

    private const uint FILE_DEVICE_UNKNOWN   = 0x00000022;
    private const uint METHOD_BUFFERED       = 0;
    private const uint FILE_READ_ACCESS      = 0x0001;
    private const uint GENERIC_READ          = 0x80000000;
    private const uint FILE_SHARE_READ       = 0x00000001;
    private const uint OPEN_EXISTING         = 3;

    private static uint CTL_CODE(uint device, uint func, uint method, uint access)
        => (device << 16) | (access << 14) | (func << 2) | method;

    private static readonly uint IOCTL_GET_PROCESSES =
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800 + 0, METHOD_BUFFERED, FILE_READ_ACCESS);
    private static readonly uint IOCTL_GET_HOOKS =
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800 + 1, METHOD_BUFFERED, FILE_READ_ACCESS);
    private static readonly uint IOCTL_GET_HIDDEN_DRIVERS =
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800 + 2, METHOD_BUFFERED, FILE_READ_ACCESS);
    private static readonly uint IOCTL_GET_CALLBACKS =
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800 + 3, METHOD_BUFFERED, FILE_READ_ACCESS);
    private static readonly uint IOCTL_DETECT_HYPERVISOR =
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800 + 7, METHOD_BUFFERED, FILE_READ_ACCESS);

    // ── Struct sizes (must match ioctl.h with Pack=8, CharSet=Unicode) ────────

    // ZTRACE_PROCESS_ENTRY: 4+4+4+4+8 + 64*2 + 260*2 = 672 bytes
    private const int ProcessEntrySize  = 672;
    private const int ProcessListHeader = 8;   // Count(4) + HiddenCount(4)
    private const int MaxProcesses      = 2048;

    // ZTRACE_HOOK_ENTRY: 8+8 + 64*2 + 64*2 + 8 + 8 = 288 bytes
    private const int HookEntrySize  = 288;
    private const int HookListHeader = 4;
    private const int MaxHooks       = 512;

    // ZTRACE_MODULE_ENTRY: 8+4+4 + 64*2 + 260*2 = 664 bytes
    private const int ModuleEntrySize  = 664;
    private const int ModuleListHeader = 4;
    private const int MaxModules       = 512;

    // ZTRACE_CALLBACK_ENTRY: 8+4+4 + 64*2 = 144 bytes
    private const int CallbackEntrySize  = 144;
    private const int CallbackListHeader = 4;
    private const int MaxCallbacks       = 128;

    // ZTRACE_HYPERVISOR_INFO: 1+1+2+4+4+16+8 = 36 bytes (padded to 40)
    private const int HypervisorInfoSize = 40;

    // Modules that legitimately register kernel callbacks
    private static readonly HashSet<string> CallbackWhitelist = new(StringComparer.OrdinalIgnoreCase)
    {
        "ntoskrnl.exe", "hal.dll", "ci.dll", "ksecdd.sys", "tcpip.sys",
        "netio.sys", "ndis.sys", "wdfilter.sys", "fltmgr.sys", "cng.sys",
        "MpKslDrv.sys", "WdFilter.sys", "MsMpEng.exe",   // Windows Defender
        "BEDaisy.sys", "BEService.exe",                    // BattlEye
        "EasyAntiCheat.sys", "EasyAntiCheat_EOS.sys",     // EAC
        "vgc.sys", "vgk.sys",                              // Vanguard
        "ZeroTraceDriver.sys"                              // ourselves
    };

    // ── Entry point ───────────────────────────────────────────────────────────

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.05, Name, "Oeffne Treiber-Verbindung...");

        using var hDev = CreateFile(
            @"\\.\ZeroTrace",
            GENERIC_READ,
            FILE_SHARE_READ,
            IntPtr.Zero,
            OPEN_EXISTING, 0, IntPtr.Zero);

        if (hDev.IsInvalid)
        {
            // Driver not installed — informational only
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "Kernel-Treiber nicht geladen",
                Risk     = RiskLevel.Low,
                Location = @"\\.\ZeroTrace",
                Reason   = "Der ZeroTrace-Kerneltreiber (ZeroTraceDriver.sys) ist nicht " +
                           "installiert oder nicht gestartet. Ring-0-Pruefungen (DKOM, " +
                           "SSDT-Hooks, Ghost-Treiber, Kernel-Callbacks) sind daher nicht " +
                           "verfuegbar. Fuer vollstaendige Erkennung bitte Treiber laden.",
                Detail   = $"Win32-Fehler: {Marshal.GetLastWin32Error()}"
            });
            ctx.Report(1.0, Name);
            return Task.CompletedTask;
        }

        ctx.Report(0.1, Name, "Treiber verbunden — starte Ring-0-Scans");

        QueryProcesses(hDev, ctx);
        ct.ThrowIfCancellationRequested();
        ctx.Report(0.3, Name);

        QueryHooks(hDev, ctx);
        ct.ThrowIfCancellationRequested();
        ctx.Report(0.5, Name);

        QueryHiddenDrivers(hDev, ctx);
        ct.ThrowIfCancellationRequested();
        ctx.Report(0.65, Name);

        QueryCallbacks(hDev, ctx);
        ct.ThrowIfCancellationRequested();
        ctx.Report(0.8, Name);

        QueryHypervisor(hDev, ctx);
        ctx.Report(1.0, Name, "Kernel-Bridge-Scan abgeschlossen");
        return Task.CompletedTask;
    }

    // ── IOCTL helpers ─────────────────────────────────────────────────────────

    private static bool SendIoctl(SafeFileHandle hDev, uint code, IntPtr buf, uint size)
    {
        return DeviceIoControl(hDev, code, IntPtr.Zero, 0, buf, size, out _, IntPtr.Zero);
    }

    // ── Process scan (DKOM detection) ─────────────────────────────────────────

    private static void QueryProcesses(SafeFileHandle hDev, ScanContext ctx)
    {
        int totalSize = ProcessListHeader + MaxProcesses * ProcessEntrySize;
        IntPtr buf = Marshal.AllocHGlobal(totalSize);
        try
        {
            Marshal.WriteInt64(buf, 0);
            if (!SendIoctl(hDev, IOCTL_GET_PROCESSES, buf, (uint)totalSize)) return;

            int count       = Marshal.ReadInt32(buf, 0);
            int hiddenCount = Marshal.ReadInt32(buf, 4);
            if (hiddenCount == 0) return;

            for (int i = 0; i < count && i < MaxProcesses; i++)
            {
                IntPtr entry = buf + ProcessListHeader + i * ProcessEntrySize;
                uint   flags = (uint)Marshal.ReadInt32(entry, 12);
                if ((flags & 0x1) == 0) continue; // not hidden

                uint   pid        = (uint)Marshal.ReadInt32(entry, 0);
                uint   parentPid  = (uint)Marshal.ReadInt32(entry, 4);
                string imageName  = ReadWStr(entry, 24, 64);
                string fullPath   = ReadWStr(entry, 24 + 128, 260);

                var ind = ctx.Matcher.MatchFileName(imageName)
                        ?? ctx.Matcher.MatchFileNameKeyword(imageName);

                ctx.AddFinding(new Finding
                {
                    Module   = "Kernel-Bridge (Ring-0)",
                    Title    = $"DKOM-versteckter Prozess: {imageName}",
                    Risk     = RiskLevel.Critical,
                    Location = string.IsNullOrEmpty(fullPath) ? imageName : fullPath,
                    FileName = imageName,
                    Reason   = $"Prozess PID={pid} PPID={parentPid} ('{imageName}') ist im " +
                               "NT-Kernel (EPROCESS-Kette via PsGetNextProcess) sichtbar, " +
                               "fehlt aber in der Toolhelp32-Prozessliste. Das ist das " +
                               "Signalmuster eines DKOM-Rootkit-Treibers." +
                               (ind is null ? "" : $" Indikator '{ind.Pattern}': {ind.Description}")
                });
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    // ── SSDT hook scan ────────────────────────────────────────────────────────

    private static void QueryHooks(SafeFileHandle hDev, ScanContext ctx)
    {
        int totalSize = HookListHeader + MaxHooks * HookEntrySize;
        IntPtr buf = Marshal.AllocHGlobal(totalSize);
        try
        {
            Marshal.WriteInt32(buf, 0);
            if (!SendIoctl(hDev, IOCTL_GET_HOOKS, buf, (uint)totalSize)) return;

            int count = Marshal.ReadInt32(buf, 0);
            for (int i = 0; i < count && i < MaxHooks; i++)
            {
                IntPtr entry   = buf + HookListHeader + i * HookEntrySize;
                ulong  fnAddr  = (ulong)Marshal.ReadInt64(entry, 0);
                ulong  hookTgt = (ulong)Marshal.ReadInt64(entry, 8);
                string fnName  = ReadWStr(entry, 16, 64);
                string tgtMod  = ReadWStr(entry, 16 + 128, 64);

                ctx.AddFinding(new Finding
                {
                    Module   = "Kernel-Bridge (Ring-0)",
                    Title    = $"SSDT-Hook erkannt: {fnName}",
                    Risk     = RiskLevel.Critical,
                    Location = $"SSDT[{fnName}]",
                    FileName = tgtMod,
                    Reason   = $"Die SSDT-Funktion '{fnName}' bei 0x{fnAddr:X16} zeigt auf " +
                               $"0x{hookTgt:X16} ({tgtMod}). Ein nicht-Windows-Modul hat den " +
                               "Systemaufruf umgeleitet — typisch fuer Rootkit-/Cheat-Treiber, " +
                               "die NtQuerySystemInformation patchen, um Prozesse oder Treiber " +
                               "zu verstecken."
                });
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    // ── Ghost driver scan ─────────────────────────────────────────────────────

    private static void QueryHiddenDrivers(SafeFileHandle hDev, ScanContext ctx)
    {
        int totalSize = ModuleListHeader + MaxModules * ModuleEntrySize;
        IntPtr buf = Marshal.AllocHGlobal(totalSize);
        try
        {
            Marshal.WriteInt32(buf, 0);
            if (!SendIoctl(hDev, IOCTL_GET_HIDDEN_DRIVERS, buf, (uint)totalSize)) return;

            int count = Marshal.ReadInt32(buf, 0);
            for (int i = 0; i < count && i < MaxModules; i++)
            {
                IntPtr entry    = buf + ModuleListHeader + i * ModuleEntrySize;
                ulong  baseAddr = (ulong)Marshal.ReadInt64(entry, 0);
                uint   size     = (uint)Marshal.ReadInt32(entry, 8);
                uint   flags    = (uint)Marshal.ReadInt32(entry, 12);
                string name     = ReadWStr(entry, 16, 64);
                string path     = ReadWStr(entry, 16 + 128, 260);

                if ((flags & 0x1) == 0) continue; // not a ghost driver

                var ind = ctx.Matcher.MatchFileName(name)
                        ?? ctx.Matcher.MatchFileNameKeyword(name);

                ctx.AddFinding(new Finding
                {
                    Module   = "Kernel-Bridge (Ring-0)",
                    Title    = $"Ghost-Treiber (nicht in PsLoadedModuleList): {name}",
                    Risk     = ind is null ? RiskLevel.High : RiskLevel.Critical,
                    Location = string.IsNullOrEmpty(path) ? name : path,
                    FileName = name,
                    Reason   = $"Kernel-Modul '{name}' (Base=0x{baseAddr:X16}, Size={size:N0} B) " +
                               "ist im Kernel geladen (per AuxKlib sichtbar), taucht aber " +
                               "NICHT in PsLoadedModuleList auf. Das ist das typische Muster " +
                               "eines per DKOM versteckten oder manuell gemappten Cheat-Treibers." +
                               (ind is null ? "" : $" Indikator '{ind.Pattern}': {ind.Description}")
                });
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    // ── Kernel callback scan ──────────────────────────────────────────────────

    private static void QueryCallbacks(SafeFileHandle hDev, ScanContext ctx)
    {
        int totalSize = CallbackListHeader + MaxCallbacks * CallbackEntrySize;
        IntPtr buf = Marshal.AllocHGlobal(totalSize);
        try
        {
            Marshal.WriteInt32(buf, 0);
            if (!SendIoctl(hDev, IOCTL_GET_CALLBACKS, buf, (uint)totalSize)) return;

            int count = Marshal.ReadInt32(buf, 0);
            var typeNames = new[] { "CreateProcess", "CreateThread", "LoadImage" };

            for (int i = 0; i < count && i < MaxCallbacks; i++)
            {
                IntPtr entry    = buf + CallbackListHeader + i * CallbackEntrySize;
                ulong  cbAddr   = (ulong)Marshal.ReadInt64(entry, 0);
                int    typeIdx  = Marshal.ReadInt32(entry, 8);
                string ownerMod = ReadWStr(entry, 16, 64);

                if (CallbackWhitelist.Contains(ownerMod)) continue;

                string typeName = typeIdx >= 0 && typeIdx < typeNames.Length
                    ? typeNames[typeIdx] : $"Type{typeIdx}";

                var ind = ctx.Matcher.MatchFileName(ownerMod)
                        ?? ctx.Matcher.MatchFileNameKeyword(ownerMod);

                ctx.AddFinding(new Finding
                {
                    Module   = "Kernel-Bridge (Ring-0)",
                    Title    = $"Ungueltige Kernel-Callback: {typeName} von '{ownerMod}'",
                    Risk     = ind is null ? RiskLevel.High : RiskLevel.Critical,
                    Location = $"PsSet{typeName}NotifyRoutine @ 0x{cbAddr:X16}",
                    FileName = ownerMod,
                    Reason   = $"Das Kernel-Modul '{ownerMod}' hat eine {typeName}-Callback " +
                               $"bei 0x{cbAddr:X16} registriert, ist aber nicht auf der " +
                               "Whitelist bekannter Sicherheitssoftware. Cheat-Treiber " +
                               "registrieren CreateProcess-Callbacks, um Anti-Cheat-Prozesse " +
                               "beim Start zu beenden, und LoadImage-Callbacks, um Anti-Cheat-" +
                               "DLLs am Laden zu hindern." +
                               (ind is null ? "" : $" Indikator: {ind.Description}")
                });
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    // ── Hypervisor detection ──────────────────────────────────────────────────

    private static void QueryHypervisor(SafeFileHandle hDev, ScanContext ctx)
    {
        IntPtr buf = Marshal.AllocHGlobal(HypervisorInfoSize);
        try
        {
            Marshal.WriteInt64(buf, 0);
            if (!SendIoctl(hDev, IOCTL_DETECT_HYPERVISOR, buf, (uint)HypervisorInfoSize)) return;

            bool present  = Marshal.ReadByte(buf, 0) != 0;
            bool timing   = Marshal.ReadByte(buf, 1) != 0;
            int  hvType   = Marshal.ReadInt32(buf, 4);
            uint maxLeaf  = (uint)Marshal.ReadInt32(buf, 8);
            var  vendorBytes = new byte[16];
            Marshal.Copy(buf + 12, vendorBytes, 0, 16);
            string vendor = Encoding.ASCII.GetString(vendorBytes).TrimEnd('\0');
            ulong  cycles = (ulong)Marshal.ReadInt64(buf, 28);

            if (!present) return;

            // Hyper-V is expected on Windows 11 HVCI machines — whitelist it
            // unless a second hypervisor layer is detected (nested VM)
            bool isMicrosoftHv = hvType == 2; // ZTRACE_HV_HYPER_V
            if (isMicrosoftHv && !timing) return;

            string hvName = hvType switch
            {
                1 => "Unbekannter Hypervisor",
                2 => "Microsoft Hyper-V",
                3 => "VMware",
                4 => "KVM",
                5 => "Xen",
                6 => "VirtualBox",
                7 => "Parallels",
                _ => "Kein Hypervisor"
            };

            ctx.AddFinding(new Finding
            {
                Module   = "Kernel-Bridge (Ring-0)",
                Title    = $"Hypervisor erkannt: {hvName}",
                Risk     = timing ? RiskLevel.Critical : RiskLevel.High,
                Location = $"CPUID 0x40000000 — {vendor}",
                Reason   = $"Das System laeuft in einer virtuellen Maschine ({hvName}, " +
                           $"Vendor='{vendor}', MaxLeaf=0x{maxLeaf:X8}). " +
                           $"CPUID-Timing: {cycles} Zyklen (>1000 = VM-Exit-Overhead). " +
                           "Ein normaler Gaming-PC sollte nicht in einer VM laufen. " +
                           "Einige Cheat-Setups verwenden einen Typ-1-Hypervisor, um " +
                           "den Cheat-Treiber vor dem Gast-OS-Level-Scanner zu verbergen.",
                Detail   = $"HV-Typ: {hvName} | Vendor: {vendor} | " +
                           $"Timing-Anomalie: {timing} | Zyklen: {cycles}"
            });
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    // ── String helpers ────────────────────────────────────────────────────────

    private static string ReadWStr(IntPtr basePtr, int byteOffset, int charCount)
    {
        var bytes = new byte[charCount * 2];
        Marshal.Copy(basePtr + byteOffset, bytes, 0, bytes.Length);
        return Encoding.Unicode.GetString(bytes).TrimEnd('\0');
    }
}
