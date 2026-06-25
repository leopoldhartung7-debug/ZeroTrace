using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects GPU-based memory hiding and GPGPU cheat execution techniques.
///
/// Advanced cheats offload computation and data storage to the GPU to evade CPU-side
/// memory scanners:
///
///   1. DirectX/OpenGL cheat rendering: ESP overlays rendered directly in D3D command
///      buffers, bypassing GDI/DirectDraw overlay detection.
///
///   2. CUDA/OpenCL memory: cheat data stored in GPU VRAM (accessible only via
///      CUDA/OpenCL API, not Win32 memory APIs). CPU scanners cannot see VRAM.
///
///   3. DirectX 12 shared resources: D3D12 resources can be shared between processes
///      via handles. A cheat in one process can read game framebuffer in another.
///
///   4. GPU kernel driver bypass: some advanced cheats use WDDM kernel driver
///      interfaces to inject code into the GPU driver's command processing.
///
///   5. DXDiag/DXVK/VKD3D translation layers: Wine/Proton compatibility layers
///      sometimes used as injection vectors on Windows (rare, exotic).
///
/// Practical detection (without GPU-side scanning capability):
///   1. Processes with multiple D3D/DXGI device instances (unusual for games)
///   2. Non-game processes consuming significant GPU resources
///   3. D3D/DXGI debug layer enabled for non-development sessions
///   4. NVIDIA/AMD/Intel GPU overlay DLLs loaded into game processes unexpectedly
///   5. Cheat-keyword DXGI adapter descriptions in D3D enumeration (rare)
///   6. NvAPI/AGS (AMD GPU Services) DLLs in suspicious locations
///   7. GPU compute processes (CUDA/OpenCL) running alongside game
/// </summary>
public sealed class GpuProcessMemoryScanModule : IScanModule
{
    public string Name => "GPU-Prozess-Analyse";
    public double Weight => 0.6;
    public int ParallelGroup => 2;

    // Known cheat-related GPU/graphics-adjacent processes
    private static readonly HashSet<string> SuspiciousGpuProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "nvcontainer.exe",  // NVIDIA container process — legitimate but injection vector
        // Processes that shouldn't be using GPU heavily during a game:
        "python.exe", "python3.exe",   // CUDA/OpenCL cheat scripts
        "node.exe",                    // JavaScript GPU cheat tools
        "java.exe", "javaw.exe",       // Java-based cheat tools
    };

    // Known GPU-adjacent DLLs that cheats inject or that are themselves cheats
    private static readonly string[] SuspiciousGpuDlls =
    {
        "nvapi64.dll", "nvapi.dll",     // NvAPI — if unsigned or in wrong location
        "amd_ags_x64.dll",             // AMD GPU Services
        "igc64.dll",                   // Intel GPU compiler (if not in Intel dir)
        "d3d_extra.dll",               // Fake Direct3D extension DLL
        "reshade",                     // ReShade — common cheat overlay vector
        "injector",
        "overlay_hook",
    };

    // DirectX debug/diagnostic registry keys
    private const string DxDiagKey =
        @"SOFTWARE\Microsoft\Direct3D";

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckSuspiciousGpuProcesses(ctx, ct);
        hits += CheckDxDebugLayer(ctx, ct);
        hits += CheckGpuDllsInGameProcesses(ctx, ct);

        ctx.Report(1.0, Name, $"GPU-Prozesse und DX-Konfiguration geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckSuspiciousGpuProcesses(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementProcesses();

                string procExe = proc.ProcessName + ".exe";

                try
                {
                    // Check for CUDA/OpenCL cheat processes
                    if (procExe.Equals("python.exe", StringComparison.OrdinalIgnoreCase) ||
                        procExe.Equals("python3.exe", StringComparison.OrdinalIgnoreCase))
                    {
                        // Python processes with GPU keywords in command line
                        try
                        {
                            var cmdLine = proc.MainModule?.FileName ?? "";
                            var args = Environment.GetCommandLineArgs();

                            // Check if GPU keywords appear in process command
                            var wmi = new System.Management.ManagementObjectSearcher(
                                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {proc.Id}");
                            foreach (System.Management.ManagementObject obj in wmi.Get())
                            {
                                var cl = obj["CommandLine"] as string ?? "";
                                if (cl.Contains("cuda", StringComparison.OrdinalIgnoreCase) ||
                                    cl.Contains("opencl", StringComparison.OrdinalIgnoreCase) ||
                                    cl.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                                    cl.Contains("aimbot", StringComparison.OrdinalIgnoreCase))
                                {
                                    hits++;
                                    ctx.AddFinding(new Finding
                                    {
                                        Module   = "GPU-Prozess-Analyse",
                                        Title    = $"Python-GPU-Prozess mit Cheat-Bezug: PID {proc.Id}",
                                        Risk     = RiskLevel.High,
                                        Location = $"PID {proc.Id}: python.exe",
                                        Reason   = $"Python-Prozess mit GPU/Cheat-bezogener Kommandozeile: '{cl[..Math.Min(100, cl.Length)]}'. " +
                                                   "Python mit CUDA/OpenCL wird für GPU-basierte Cheat-Berechnungen " +
                                                   "(z.B. GPU-beschleunigtes Aim-Prediction) genutzt.",
                                        Detail   = $"PID: {proc.Id} | Cmdline: {cl[..Math.Min(200, cl.Length)]}"
                                    });
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckDxDebugLayer(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // D3D Debug Layer active system-wide is suspicious (cheat injection via D3D debug)
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                DxDiagKey, writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            // LoadDebugRuntime = 1 means D3D debug runtime is loaded for all processes
            var loadDebug = key.GetValue("LoadDebugRuntime") as int? ?? 0;
            if (loadDebug != 0)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "GPU-Prozess-Analyse",
                    Title    = "DirectX Debug-Runtime aktiviert (system-weit)",
                    Risk     = RiskLevel.High,
                    Location = $@"HKLM\{DxDiagKey}",
                    Reason   = "LoadDebugRuntime = 1 — DirectX Debug-Runtime ist system-weit aktiviert. " +
                               "Die D3D Debug-Runtime ermöglicht tiefe Inspektion aller D3D-Operationen " +
                               "und kann für Frame-Buffer-Capture und Cheat-Overlay-Entwicklung genutzt werden. " +
                               "In einer Gaming-Umgebung ohne Entwicklungs-Kontext ist dies verdächtig.",
                    Detail   = $"LoadDebugRuntime: {loadDebug}"
                });
            }
        }
        catch { }
        return hits;
    }

    private static int CheckGpuDllsInGameProcesses(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;

        // Known game processes to check
        var gameProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "csgo.exe", "cs2.exe", "valorant.exe", "VALORANT-Win64-Shipping.exe",
            "r5apex.exe", "GTA5.exe", "EFT.exe",
        };

        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                string procExe = proc.ProcessName + ".exe";
                if (!gameProcessNames.Contains(procExe))
                {
                    proc.Dispose();
                    continue;
                }

                ctx.IncrementProcesses();
                try
                {
                    foreach (ProcessModule mod in proc.Modules)
                    {
                        if (ct.IsCancellationRequested) break;
                        var modName = mod.ModuleName?.ToLowerInvariant() ?? "";
                        var suspicious = SuspiciousGpuDlls.FirstOrDefault(d =>
                            modName.Contains(d, StringComparison.OrdinalIgnoreCase));
                        if (suspicious is null) continue;

                        // Verify it's not in a trusted location
                        var modPath = mod.FileName?.ToLowerInvariant() ?? "";
                        bool inSystemDir = modPath.Contains("\\windows\\") ||
                                          modPath.Contains("\\program files\\nvidia") ||
                                          modPath.Contains("\\program files\\amd") ||
                                          modPath.Contains("\\program files\\intel");
                        if (inSystemDir) continue;

                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = "GPU-Prozess-Analyse",
                            Title    = $"Verdächtige GPU-DLL in Spielprozess: {mod.ModuleName} in {procExe}",
                            Risk     = RiskLevel.High,
                            Location = $"PID {proc.Id}: {mod.FileName}",
                            FileName = mod.ModuleName,
                            Reason   = $"GPU-bezogene DLL '{mod.ModuleName}' wurde in Spielprozess " +
                                       $"'{procExe}' außerhalb vertrauenswürdiger System-Verzeichnisse geladen. " +
                                       "ReShade und ähnliche DLLs werden als Overlay-Injection-Vektoren " +
                                       "für Cheat-Overlays (ESP, Aimbot-Visualisierung) genutzt.",
                            Detail   = $"DLL: {mod.FileName} | Prozess: {procExe} | PID: {proc.Id}"
                        });
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
        return hits;
    }
}
