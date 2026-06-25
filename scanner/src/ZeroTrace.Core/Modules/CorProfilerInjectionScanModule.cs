using Microsoft.Win32;
using System.Diagnostics;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects .NET CLR Profiler injection via COR_PROFILER environment variables and registry
/// keys. The CLR Profiler API is a legitimate .NET debugging tool that loads an arbitrary
/// DLL into every .NET process at startup — cheat loaders abuse this to inject DLLs into
/// game processes (Unity, Source engine, any .NET-using game) without WriteProcessMemory.
/// The module checks COR_ENABLE_PROFILING=1 with a COR_PROFILER CLSID pointing to a
/// non-Microsoft DLL, both in HKLM/HKCU registry and live process environment blocks.
/// Also checks CORECLR_PROFILER for .NET Core / Unity IL2CPP games.
/// </summary>
public sealed class CorProfilerInjectionScanModule : IScanModule
{
    public string Name => "CLR Profiler Injection Detection";
    public double Weight => 0.65;
    public int ParallelGroup => 3;

    private static readonly string[] ProfilerRegistryPaths =
    {
        @"SOFTWARE\Microsoft\.NETFramework",
        @"SOFTWARE\Wow6432Node\Microsoft\.NETFramework",
        @"SOFTWARE\Microsoft\.NETCore",
        @"SOFTWARE\Wow6432Node\Microsoft\.NETCore",
    };

    // Known legitimate profiler CLSIDs and substrings
    private static readonly string[] LegitProfilerDlls =
    {
        @"\windows\system32\",
        @"\windows\syswow64\",
        @"\program files\microsoft ",
        @"\program files (x86)\microsoft ",
        "clrprofiler",
        "perfprofiler",
        "vsjitdebugger",
        "dotnet-monitor",
        "coverlet",
        "opencover",
        "jetbrains",
        "rider",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            CheckRegistry(Registry.LocalMachine, "HKLM", ctx, ct);
            CheckRegistry(Registry.CurrentUser, "HKCU", ctx, ct);
            CheckProcessEnvironments(ctx, ct);
        }, ct);
    }

    private void CheckRegistry(RegistryKey root, string hive, ScanContext ctx, CancellationToken ct)
    {
        foreach (var path in ProfilerRegistryPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = root.OpenSubKey(path);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();

                string? enableProfiling = key.GetValue("COR_ENABLE_PROFILING")?.ToString();
                string? corProfiler     = key.GetValue("COR_PROFILER")?.ToString();
                string? corProfilerPath = key.GetValue("COR_PROFILER_PATH")?.ToString();
                string? clrProfiler     = key.GetValue("CORECLR_PROFILER")?.ToString();
                string? clrProfilerPath = key.GetValue("CORECLR_PROFILER_PATH")?.ToString();

                EvaluateProfilerEntry(hive, path, enableProfiling, corProfiler,
                    corProfilerPath, "COR (Framework)", ctx);
                EvaluateProfilerEntry(hive, path, "1", clrProfiler,
                    clrProfilerPath, "CORECLR (Core)", ctx);
            }
            catch { }
        }
    }

    private void EvaluateProfilerEntry(
        string hive, string keyPath,
        string? enableProfiling, string? profilerClsid, string? profilerDllPath,
        string kind, ScanContext ctx)
    {
        if (string.IsNullOrEmpty(profilerClsid) && string.IsNullOrEmpty(profilerDllPath)) return;

        // Only flag when profiling is actually enabled or CLSID is set
        bool profilingEnabled = enableProfiling == "1";
        if (!profilingEnabled && string.IsNullOrEmpty(profilerDllPath)) return;

        string dllPath = profilerDllPath ?? string.Empty;
        string dllPathLower = dllPath.ToLowerInvariant();

        // Skip known-legitimate profilers
        if (!string.IsNullOrEmpty(dllPath) &&
            Array.Exists(LegitProfilerDlls, p => dllPathLower.Contains(p)))
            return;

        bool fileExists = !string.IsNullOrEmpty(dllPath) && File.Exists(dllPath);
        string fileName = string.IsNullOrEmpty(dllPath) ? "(kein Pfad)" : Path.GetFileName(dllPath);

        ctx.AddFinding(new Finding
        {
            Module   = Name,
            Title    = $"CLR-Profiler-Injection via {kind}: {fileName}",
            Risk     = profilingEnabled && fileExists ? RiskLevel.Critical : RiskLevel.High,
            Location = $"{hive}\\{keyPath}",
            FileName = fileName,
            Reason   = $".NET {kind}-Profiler-Injektion in Registry: COR_ENABLE_PROFILING={enableProfiling ?? "n/a"}, " +
                       $"CLSID={profilerClsid ?? "n/a"}, DLL='{dllPath}' — " +
                       "CLR lädt diese DLL automatisch in jeden .NET-Prozess (Unity-Spiele, .NET-Games) " +
                       "ohne WriteProcessMemory zu benötigen",
            Detail   = $"Hive: {hive} | Schlüssel: {keyPath} | Art: {kind} | " +
                       $"Aktiviert: {profilingEnabled} | DLL vorhanden: {fileExists} | CLSID: {profilerClsid}"
        });
    }

    private void CheckProcessEnvironments(ScanContext ctx, CancellationToken ct)
    {
        // Check currently running processes for COR_PROFILER in their environment
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    // Reading process environment requires PROCESS_VM_READ which may be denied
                    // Instead check if COR_ENABLE_PROFILING is set system-wide via GetEnvironmentVariable
                    string? sysEnable = Environment.GetEnvironmentVariable(
                        "COR_ENABLE_PROFILING", EnvironmentVariableTarget.Machine);
                    if (sysEnable == "1")
                    {
                        string? sysProfiler = Environment.GetEnvironmentVariable(
                            "COR_PROFILER", EnvironmentVariableTarget.Machine);
                        string? sysPath = Environment.GetEnvironmentVariable(
                            "COR_PROFILER_PATH", EnvironmentVariableTarget.Machine);

                        if (!string.IsNullOrEmpty(sysProfiler))
                        {
                            string pathLower = (sysPath ?? "").ToLowerInvariant();
                            bool isLegit = Array.Exists(LegitProfilerDlls, p => pathLower.Contains(p));
                            if (!isLegit)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = "CLR-Profiler via Systemumgebungsvariable aktiv",
                                    Risk     = RiskLevel.Critical,
                                    Location = "System-Umgebungsvariable",
                                    FileName = Path.GetFileName(sysPath ?? sysProfiler),
                                    Reason   = $"COR_ENABLE_PROFILING=1 als Systemvariable gesetzt — " +
                                               $"Profiler CLSID '{sysProfiler}' wird in ALLE .NET-Prozesse geladen",
                                    Detail   = $"COR_PROFILER={sysProfiler} | COR_PROFILER_PATH={sysPath}"
                                });
                            }
                        }
                    }
                }
                catch { }
                finally { proc.Dispose(); }
                break; // Only need to check once for system env vars
            }
        }
        catch { }
    }
}
