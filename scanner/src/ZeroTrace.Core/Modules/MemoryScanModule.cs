using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Read-only memory scan of the detected game process(es): walks committed,
/// readable regions with VirtualQueryEx and reads them with ReadProcessMemory,
/// matching the content (cheat-string) indicators. This catches internal/injected
/// cheats that have no file on disk. It is bounded in volume and time. The game
/// memory is only read, never written. Heavier and more false-positive-prone than
/// the file checks, so it is a separate, toggleable module.
/// </summary>
public sealed class MemoryScanModule : IScanModule
{
    public string Name => "Speicher-Scan";
    public double Weight => 0.8;

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_PRIVATE = 0x20000;
    private const uint PAGE_NOACCESS = 0x01;
    private const uint PAGE_GUARD = 0x100;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;

    private const long MaxBytesPerProcess = 512L * 1024 * 1024;
    private const int ChunkSize = 1 * 1024 * 1024;
    private const int Overlap = 64;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out IntPtr read);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int VirtualQueryEx(IntPtr h, IntPtr addr, out MEMORY_BASIC_INFORMATION64 mbi, int len);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION64
    {
        public ulong BaseAddress;
        public ulong AllocationBase;
        public uint AllocationProtect;
        public uint __alignment1;
        public ulong RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
        public uint __alignment2;
    }

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        if (!ctx.Matcher.HasContentSignatures)
        {
            ctx.Report(1.0, "Speicher", "Keine Inhalts-Signaturen aktiv");
            return Task.CompletedTask;
        }

        Process[] all;
        try { all = Process.GetProcesses(); } catch { return Task.CompletedTask; }

        foreach (var p in all)
        {
            if (ct.IsCancellationRequested) break;
            string name, path = "";
            try { name = p.ProcessName + ".exe"; } catch { p.Dispose(); continue; }
            try { path = p.MainModule?.FileName ?? ""; } catch { }

            if (KnownPaths.MpFrameworkForProcess(name, path) is null) { p.Dispose(); continue; }

            try { ScanProcess(ctx, p, name, ct); } catch { }
            p.Dispose();
        }

        ctx.Report(1.0, "Speicher", "Spiel-Speicher geprueft");
        return Task.CompletedTask;
    }

    private void ScanProcess(ScanContext ctx, Process p, string name, CancellationToken ct)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, p.Id);
        if (h == IntPtr.Zero) return;

        try
        {
            CheckManualMaps(ctx, h, name, ct);

            long scanned = 0;
            ulong addr = 0x10000; // skip the null region
            int mbiSize = Marshal.SizeOf<MEMORY_BASIC_INFORMATION64>();
            var buffer = new byte[ChunkSize];

            while (scanned < MaxBytesPerProcess && !ct.IsCancellationRequested)
            {
                if (VirtualQueryEx(h, (IntPtr)addr, out var mbi, mbiSize) == 0) break;
                ulong regionSize = mbi.RegionSize;
                if (regionSize == 0) break;

                bool readable = mbi.State == MEM_COMMIT &&
                                (mbi.Protect & PAGE_NOACCESS) == 0 &&
                                (mbi.Protect & PAGE_GUARD) == 0;

                if (readable)
                {
                    if (ScanRegion(ctx, h, mbi.BaseAddress, regionSize, buffer, name, ref scanned, ct))
                        return; // one solid hit per process is enough
                }

                ulong next = mbi.BaseAddress + regionSize;
                if (next <= addr) break; // guard against wrap/no-progress
                addr = next;
            }
        }
        finally { CloseHandle(h); }
    }

    /// <summary>
    /// Looks for committed, private, executable+writable memory regions that have
    /// no module backing (PAGE_EXECUTE_READWRITE / PAGE_EXECUTE_WRITECOPY in a
    /// MEM_PRIVATE region ≥ 64 KB). This is the hallmark of a manually mapped DLL:
    /// the payload is injected directly without going through LoadLibrary, so no
    /// module entry appears in the module list — but the writable+executable
    /// footprint is still visible via VirtualQueryEx.
    /// </summary>
    private void CheckManualMaps(ScanContext ctx, IntPtr h, string procName, CancellationToken ct)
    {
        const ulong MinSize = 64 * 1024; // 64 KB minimum to filter tiny JIT stubs
        const int MaxHitsPerProcess = 3;
        int hits = 0;

        ulong addr = 0x10000;
        int mbiSize = Marshal.SizeOf<MEMORY_BASIC_INFORMATION64>();

        while (hits < MaxHitsPerProcess && !ct.IsCancellationRequested)
        {
            if (VirtualQueryEx(h, (IntPtr)addr, out var mbi, mbiSize) == 0) break;
            if (mbi.RegionSize == 0) break;

            if (mbi.State == MEM_COMMIT &&
                mbi.Type == MEM_PRIVATE &&
                mbi.RegionSize >= MinSize &&
                (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Verdaechtige RWX-Speicherregion (moegliche manuelle Injektion): {procName}",
                    Risk = RiskLevel.High,
                    Location = $"{procName} · 0x{mbi.BaseAddress:X16}",
                    FileName = procName,
                    Reason = $"Im Prozess '{procName}' wurde eine {mbi.RegionSize / 1024} KB grosse " +
                             "private, ausfuehrbare und beschreibbare (RWX) Speicherregion ohne " +
                             "Modul-Deckung gefunden. Das ist das charakteristische Merkmal einer " +
                             "manuell gemappten DLL (Injektion ohne LoadLibrary/LdrLoadDll), " +
                             "die keinen Modul-Eintrag hinterlaesst.",
                    Detail = $"Basisadresse: 0x{mbi.BaseAddress:X16} · Groesse: {mbi.RegionSize / 1024} KB · Schutz: 0x{mbi.Protect:X}"
                });
                hits++;
            }

            ulong next = mbi.BaseAddress + mbi.RegionSize;
            if (next <= addr) break;
            addr = next;
        }
    }

    private bool ScanRegion(ScanContext ctx, IntPtr h, ulong baseAddr, ulong size,
        byte[] buffer, string proc, ref long scanned, CancellationToken ct)
    {
        ulong offset = 0;
        while (offset < size && scanned < MaxBytesPerProcess && !ct.IsCancellationRequested)
        {
            int want = (int)Math.Min((ulong)ChunkSize, size - offset);
            if (!ReadProcessMemory(h, (IntPtr)(baseAddr + offset), buffer, want, out var readPtr))
                break;
            int read = readPtr.ToInt32();
            if (read <= 0) break;
            scanned += read;

            var ind = ctx.Matcher.MatchContent(buffer, read);
            if (ind is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Cheat-Signatur im Spiel-Speicher: {ind.Category}",
                    Risk = ind.Risk,
                    Location = $"{proc} · Speicheradresse 0x{baseAddr + offset:X}",
                    FileName = proc,
                    Reason = $"Im Arbeitsspeicher des Spielprozesses wurde das Muster '{ind.Pattern}' " +
                             $"gefunden. {ind.Description} Deutet auf einen internen/injizierten Cheat ohne " +
                             "Datei auf der Festplatte hin."
                });
                return true;
            }

            if ((ulong)read < (ulong)want) break;
            offset += (ulong)Math.Max(1, read - Overlap);
        }
        return false;
    }
}
