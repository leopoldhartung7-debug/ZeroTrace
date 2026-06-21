using System.Management;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;
using Microsoft.Win32;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Inspects the four classic persistence surfaces: registry Run keys, the
/// Startup folders, scheduled tasks, and Windows services. Each autostart target
/// is run through the same file-based indicator/heuristic checks.
/// </summary>
public sealed class AutostartScanModule : IScanModule
{
    public string Name => "Autostart";
    public double Weight => 1.0;
    public bool ParallelSafe => true;

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ScanRunKeys(ctx, ct);
        ctx.Report(0.25, "Run-Keys", "Registry-Autostarts geprueft");

        ScanStartupFolders(ctx, ct);
        ctx.Report(0.5, "Startup-Ordner", "Autostart-Ordner geprueft");

        ScanScheduledTasks(ctx, ct);
        ctx.Report(0.75, "Geplante Tasks", "Aufgabenplanung geprueft");

        ScanServices(ctx, ct);
        ctx.Report(1.0, "Dienste", "Windows-Dienste geprueft");

        return Task.CompletedTask;
    }

    private static readonly (RegistryHive hive, string path, string label)[] RunKeys =
    {
        (RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Run",                       "HKCU\\Run"),
        (RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\RunOnce",                   "HKCU\\RunOnce"),
        (RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Explorer\Run",              "HKCU\\Explorer\\Run"),
        (RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",     "HKCU\\Policies\\Run"),
        (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run",                       "HKLM\\Run"),
        (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce",                   "HKLM\\RunOnce"),
        (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunServices",              "HKLM\\RunServices"),
        (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Explorer\Run",              "HKLM\\Explorer\\Run"),
        (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",     "HKLM\\Policies\\Run")
    };

    // Both views so 32-bit autostarts under Wow6432Node are not missed.
    private static readonly RegistryView[] RegViews = { RegistryView.Registry64, RegistryView.Registry32 };

    private void ScanRunKeys(ScanContext ctx, CancellationToken ct)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (hive, path, label) in RunKeys)
        foreach (var view in RegViews)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var key = baseKey.OpenSubKey(path);
                if (key is null) continue;
                ctx.IncrementRegistryKeys();

                foreach (var valueName in key.GetValueNames())
                {
                    var command = key.GetValue(valueName)?.ToString();
                    if (string.IsNullOrWhiteSpace(command)) continue;

                    var exe = ExtractExecutablePath(command);
                    // De-duplicate identical (key+value+target) across the two views.
                    if (!seen.Add($"{label}|{valueName}|{exe}")) continue;

                    InspectAutostartTarget(ctx, exe, command,
                        $"{label} -> {valueName}", "Registry-Autostart");
                }
            }
            catch { /* key missing or access denied */ }
        }
    }

    private void ScanStartupFolders(ScanContext ctx, CancellationToken ct)
    {
        foreach (var folder in new[] { KnownPaths.StartupUser, KnownPaths.StartupCommon })
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(folder)) continue;

            foreach (var entry in SafeGetFiles(folder))
            {
                var target = entry.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)
                    ? ResolveShortcut(entry) ?? entry
                    : entry;

                InspectAutostartTarget(ctx, target, target,
                    $"Startup-Ordner: {Path.GetFileName(entry)}", "Autostart-Ordner");
            }
        }
    }

    private void ScanScheduledTasks(ScanContext ctx, CancellationToken ct)
    {
        // Late-bound COM to the Task Scheduler service. Built into Windows; no NuGet.
        object? service = null;
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service");
            if (type is null) return;
            service = Activator.CreateInstance(type);
            if (service is null) return;
            dynamic svc = service;
            svc.Connect();
            dynamic root = svc.GetFolder("\\");
            WalkTaskFolder(root, ctx, ct);
        }
        catch { /* scheduler unavailable */ }
        finally
        {
            if (service is not null && Marshal.IsComObject(service))
                Marshal.ReleaseComObject(service);
        }
    }

    private void WalkTaskFolder(dynamic folder, ScanContext ctx, CancellationToken ct)
    {
        try
        {
            dynamic tasks = folder.GetTasks(1); // include hidden
            foreach (dynamic task in tasks)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    string name = task.Name;
                    dynamic def = task.Definition;
                    dynamic actions = def.Actions;
                    for (int idx = 1; idx <= actions.Count; idx++)
                    {
                        dynamic action = actions[idx];
                        // ActionType 0 == Exec
                        string? exePath = null;
                        try { exePath = action.Path as string; } catch { }
                        if (string.IsNullOrWhiteSpace(exePath)) continue;

                        var resolved = Environment.ExpandEnvironmentVariables(exePath);
                        InspectAutostartTarget(ctx, resolved, resolved,
                            $"Geplante Aufgabe: {name}", "Geplante Aufgabe");
                    }
                }
                catch { }
            }

            dynamic subFolders = folder.GetFolders(0);
            foreach (dynamic sub in subFolders)
                WalkTaskFolder(sub, ctx, ct);
        }
        catch { }
    }

    private void ScanServices(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, DisplayName, PathName, StartMode, State FROM Win32_Service");
            using var results = searcher.Get();
            foreach (ManagementObject mo in results)
            {
                using (mo)
                {
                    ct.ThrowIfCancellationRequested();
                    var startMode = mo["StartMode"] as string ?? "";
                    var pathName = mo["PathName"] as string;
                    var name = mo["Name"] as string ?? "?";
                    if (string.IsNullOrWhiteSpace(pathName)) continue;

                    var exe = ExtractExecutablePath(pathName);
                    // Auto-start services are the interesting persistence case.
                    bool auto = startMode.Equals("Auto", StringComparison.OrdinalIgnoreCase);
                    InspectAutostartTarget(ctx, exe, pathName,
                        $"Dienst: {name} ({startMode})",
                        "Windows-Dienst", elevate: auto);
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// Runs an autostart target through file inspection and adds a finding. If
    /// the target file is missing it still reports a low-severity note for review.
    /// </summary>
    private void InspectAutostartTarget(
        ScanContext ctx, string? exePath, string rawCommand,
        string location, string sourceLabel, bool elevate = false)
    {
        if (string.IsNullOrWhiteSpace(exePath)) return;

        if (File.Exists(exePath))
        {
            var finding = FileInspector.Inspect(exePath, ctx, Name);
            if (finding is not null)
            {
                finding.Location = $"{location} => {exePath}";
                if (elevate && finding.Risk < RiskLevel.High) finding.Risk++;
                finding.Reason = $"[{sourceLabel}] " + finding.Reason;
                ctx.AddFinding(finding);
            }
        }
        else
        {
            // A persistence entry pointing at a non-existent or unparsable file.
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Autostart-Eintrag ohne aufloesbare Datei",
                Risk = RiskLevel.Low,
                Location = location,
                Reason = $"[{sourceLabel}] Befehl verweist auf eine Datei, die nicht gefunden/aufgeloest " +
                         $"werden konnte: {rawCommand}",
                Detail = rawCommand
            });
        }
    }

    private static string? ExtractExecutablePath(string command)
    {
        command = command.Trim();
        if (command.Length == 0) return null;

        // Quoted path: "C:\...\app.exe" /args
        if (command.StartsWith('"'))
        {
            int end = command.IndexOf('"', 1);
            if (end > 1) return Environment.ExpandEnvironmentVariables(command[1..end]);
        }

        // Unquoted: take up to the first .exe occurrence if present.
        int exeIdx = command.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIdx >= 0)
            return Environment.ExpandEnvironmentVariables(command[..(exeIdx + 4)]);

        // Otherwise take the first whitespace-delimited token.
        int space = command.IndexOf(' ');
        var token = space > 0 ? command[..space] : command;
        return Environment.ExpandEnvironmentVariables(token);
    }

    private static string? ResolveShortcut(string lnkPath)
    {
        object? shell = null;
        try
        {
            var type = Type.GetTypeFromProgID("WScript.Shell");
            if (type is null) return null;
            shell = Activator.CreateInstance(type);
            if (shell is null) return null;
            dynamic ws = shell;
            dynamic sc = ws.CreateShortcut(lnkPath);
            string target = sc.TargetPath;
            return string.IsNullOrWhiteSpace(target) ? null : target;
        }
        catch { return null; }
        finally
        {
            if (shell is not null && Marshal.IsComObject(shell))
                Marshal.ReleaseComObject(shell);
        }
    }

    private static IEnumerable<string> SafeGetFiles(string dir)
    {
        try { return Directory.GetFiles(dir); }
        catch { return Array.Empty<string>(); }
    }
}
