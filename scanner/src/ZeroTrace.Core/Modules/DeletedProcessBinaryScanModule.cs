using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects running processes whose executable file on disk has been deleted after launch —
/// a classic self-deleting cheat technique used to evade forensic analysis. After a cheat
/// injector or loader runs, it deletes its own binary to prevent investigators from finding
/// the file on disk; the process continues running from the already-mapped image in memory.
/// The module queries the full image path of each running process and verifies that the
/// corresponding file still exists on disk. Missing-but-running binaries are flagged with
/// Critical risk. Excludes known-legitimate patterns: system processes, Store apps (packages),
/// and processes with UNC paths. Also detects processes whose image path is a temp/random name.
/// </summary>
public sealed class DeletedProcessBinaryScanModule : IScanModule
{
    public string Name => "Deleted Process Binary Detection";
    public double Weight => 0.7;
    public int ParallelGroup => 2;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(
        nint hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

    private const uint PROCESS_QUERY_LIMITED = 0x1000;

    // These processes legitimately run without a persistent disk image
    private static readonly string[] LegitNoDiskProcesses =
    {
        "system", "registry", "secure system", "memory compression",
        "smss", "csrss", "wininit", "services", "lsass", "lsaiso",
        "dwm", "fontdrvhost", "sihost", "svchost",
    };

    // Path patterns that indicate temp/suspicious locations
    private static readonly string[] SuspiciousPathKeywords =
    {
        @"\temp\", @"\tmp\", @"\appdata\local\temp\",
        @"\downloads\", @"\desktop\",
        @"\programdata\", // not inherently suspicious but worth checking
    };

    // Extensions that are suspicious for running processes to have
    private static readonly string[] SuspiciousExts =
    { ".tmp", ".dat", ".log", ".bak" };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => ScanProcesses(ctx, ct), ct);
    }

    private void ScanProcesses(ScanContext ctx, CancellationToken ct)
    {
        foreach (var proc in Process.GetProcesses())
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                string nameLower = proc.ProcessName.ToLowerInvariant();

                // Skip known system processes with no disk image
                if (Array.Exists(LegitNoDiskProcesses, n => nameLower.Contains(n))) continue;

                string? imagePath = GetProcessImagePath(proc.Id);
                if (string.IsNullOrEmpty(imagePath)) continue;

                // Skip UNC paths and package-style paths
                if (imagePath.StartsWith(@"\\") || imagePath.Contains("WindowsApps")) continue;
                if (imagePath.StartsWith(@"\Device\")) continue; // NT device path format

                ctx.IncrementProcesses();

                // Check if the file still exists on disk
                bool exists = File.Exists(imagePath);
                if (exists)
                {
                    // Check for suspicious extension (process running as .tmp, .dat, etc.)
                    string ext = Path.GetExtension(imagePath).ToLowerInvariant();
                    if (Array.Exists(SuspiciousExts, e => e == ext))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Prozess mit verdächtiger Dateierweiterung: '{proc.ProcessName}' ({ext})",
                            Risk     = RiskLevel.High,
                            Location = imagePath,
                            FileName = Path.GetFileName(imagePath),
                            Reason   = $"Prozess '{proc.ProcessName}' (PID {proc.Id}) läuft als '{ext}'-Datei — " +
                                       "Cheat-Tools verwenden oft temp-artige Erweiterungen um AV/AC-Scans zu umgehen",
                            Detail   = $"Pfad: {imagePath} | Erweiterung: {ext} | PID: {proc.Id}"
                        });
                    }
                    continue; // file exists — no deleted binary concern
                }

                // File does not exist — flag as deleted process binary
                bool isInSuspiciousPath = Array.Exists(SuspiciousPathKeywords,
                    kw => imagePath.ToLowerInvariant().Contains(kw));

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Prozess läuft nach Selbst-Löschung: '{proc.ProcessName}' (PID {proc.Id})",
                    Risk     = RiskLevel.Critical,
                    Location = imagePath,
                    FileName = Path.GetFileName(imagePath),
                    Reason   = $"Prozess '{proc.ProcessName}' (PID {proc.Id}) ist aktiv, aber die zugehörige " +
                               $"Binärdatei '{imagePath}' existiert nicht mehr auf der Festplatte — " +
                               "klassisches Muster eines selbst-löschenden Cheat-Loaders der nach dem Start " +
                               "seine Spuren beseitigt",
                    Detail   = $"Prozess: {proc.ProcessName} | PID: {proc.Id} | " +
                               $"Gelöschter Pfad: {imagePath} | " +
                               $"Verdächtiger Pfad: {isInSuspiciousPath}"
                });
            }
            catch { }
            finally { proc.Dispose(); }
        }
    }

    private string? GetProcessImagePath(int pid)
    {
        nint hProc = OpenProcess(PROCESS_QUERY_LIMITED, false, pid);
        if (hProc == nint.Zero) return null;
        try
        {
            var sb = new StringBuilder(512);
            uint sz = (uint)sb.Capacity;
            return QueryFullProcessImageNameW(hProc, 0, sb, ref sz) ? sb.ToString() : null;
        }
        finally { CloseHandle(hProc); }
    }
}
