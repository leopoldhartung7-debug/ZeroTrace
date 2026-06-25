using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects Windows Application Compatibility Layer abuse for privilege escalation and
/// cheat persistence. Two distinct techniques are checked:
///
/// (1) __COMPAT_LAYER / RunAsInvoker environment override: Setting the environment variable
///     __COMPAT_LAYER=RunAsInvoker forces auto-elevating processes (fodhelper.exe, sdclt.exe,
///     DiskCleanup) to run at the caller's integrity level instead of elevated — used by
///     cheat loaders to prevent UAC prompts when spawning elevated helper processes.
///     Also HKCU\AppCompatFlags\Compatibility Assistant\Store overrides.
///
/// (2) AppCompat flags on game/AC executables in HKCU registry:
///     HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers can force
///     any program to run with specific shims (RUNASADMIN, 256COLOR, WIN95, etc.).
///     Cheats set RUNASADMIN on their loader to auto-elevate without UAC, or force
///     anti-cheat binaries to run with compatibility shims that break their integrity checks.
/// </summary>
public sealed class CompatibilityLayerBypassScanModule : IScanModule
{
    public string Name => "Application Compatibility Layer Bypass Detection";
    public double Weight => 0.65;
    public int ParallelGroup => 3;

    private static readonly string[] SuspiciousCompatLayers =
    {
        "RUNASADMIN", "RUNASINVOKER",
        "DisableNXShowUI", "DisablePCA",
        "WIN95", "WIN98", "WIN2000",  // Rarely needed; can break DEP/ASLR
    };

    private static readonly string[] GameAndAcExecutables =
    {
        // Anti-cheat executables
        "EasyAntiCheat.exe", "EasyAntiCheat_EOS.exe",
        "BEService.exe", "BEService_x64.exe",
        "vgc.exe", "vgtray.exe",
        "FACEITClient.exe", "FACEITService.exe",
        "ESEAClient.exe", "ESEADriver3.exe",
        // Common game executables
        "cs2.exe", "csgo.exe",
        "VALORANT.exe", "VALORANT-Win64-Shipping.exe",
        "r5apex.exe", "r5apex_dx12.exe",
        "FortniteClient-Win64-Shipping.exe",
        "TslGame.exe", "EscapeFromTarkov.exe",
    };

    // High-risk auto-elevating Windows binaries targeted by RunAsInvoker bypass
    private static readonly string[] AutoElevatingBinaries =
    {
        "fodhelper.exe", "sdclt.exe", "cleanmgr.exe",
        "cmstp.exe", "mmc.exe", "msiexec.exe",
        "ComputerDefaults.exe", "CompMgmtLauncher.exe",
        "wsreset.exe", "winsat.exe",
    };

    private static readonly string[] CheatCompatKeywords =
    {
        "cheat", "hack", "inject", "loader", "bypass",
        "esp", "radar", "aimbot", "spoofer", "trainer",
        "temp", "downloads",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            CheckAppCompatLayers(ctx, ct);
            CheckCompatibilityAssistant(ctx, ct);
            CheckCompatLayerEnvironment(ctx, ct);
        }, ct);
    }

    private void CheckAppCompatLayers(ScanContext ctx, CancellationToken ct)
    {
        // Check HKCU and HKLM AppCompatFlags\Layers
        string[] keyPaths =
        {
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
        };

        foreach (string keyPath in keyPaths)
        {
            foreach (bool isHkcu in new[] { true, false })
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    RegistryKey root = isHkcu ? Registry.CurrentUser : Registry.LocalMachine;
                    string hive = isHkcu ? "HKCU" : "HKLM";

                    using var key = root.OpenSubKey(keyPath);
                    if (key is null) continue;

                    foreach (string valueName in key.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();

                        string? layers = key.GetValue(valueName) as string;
                        if (string.IsNullOrEmpty(layers)) continue;

                        string nameLower   = valueName.ToLowerInvariant();
                        string layersUpper = layers.ToUpperInvariant();
                        string fileName    = Path.GetFileName(valueName);

                        bool isRunAsAdmin = layersUpper.Contains("RUNASADMIN");
                        bool isAcExe      = Array.Exists(GameAndAcExecutables,
                            n => fileName.Equals(n, StringComparison.OrdinalIgnoreCase));

                        bool hasCheatKeyword = Array.Exists(CheatCompatKeywords,
                            kw => nameLower.Contains(kw));

                        bool hasSuspiciousLayer = Array.Exists(SuspiciousCompatLayers,
                            l => layersUpper.Contains(l));

                        if (!hasCheatKeyword && !isAcExe && !hasSuspiciousLayer) continue;

                        // RUNASADMIN on a cheat tool = auto-elevate without UAC
                        // Any compat layer on an AC executable = tamper
                        RiskLevel risk = (isAcExe || hasCheatKeyword)
                            ? RiskLevel.Critical
                            : RiskLevel.High;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"AppCompat-Layer auf {(isAcExe ? "Anti-Cheat" : "Verdächtiger")} Executable: {fileName}",
                            Risk     = risk,
                            Location = $@"{hive}\{keyPath}",
                            FileName = fileName,
                            Reason   = isAcExe
                                ? $"Compat-Layer '{layers}' auf Anti-Cheat-Binary '{valueName}' — " +
                                  "Kompatibilitäts-Layer können AC-Integrity-Checks brechen und " +
                                  "verhindern dass der Anti-Cheat korrekt startet"
                                : isRunAsAdmin
                                    ? $"RUNASADMIN-Compat-Layer auf '{valueName}' — Cheat-Loader " +
                                      "nutzen RUNASADMIN-AppCompat um automatisch ohne UAC-Prompt " +
                                      "erhöhte Rechte zu bekommen"
                                    : $"Verdächtiger Compat-Layer '{layers}' auf '{valueName}' " +
                                      "mit Cheat-Keyword im Pfad",
                            Detail   = $"Hive: {hive} | Exe: {valueName} | Layer: {layers} | " +
                                       $"RunAsAdmin: {isRunAsAdmin} | AC-Executable: {isAcExe} | " +
                                       $"Cheat-Keyword: {hasCheatKeyword}"
                        });
                    }
                }
                catch { }
            }
        }
    }

    private void CheckCompatibilityAssistant(ScanContext ctx, CancellationToken ct)
    {
        // Compatibility Assistant\Store records programs that triggered UAC or compat messages
        // Entries for programs in suspicious paths are a forensic artifact
        try
        {
            ct.ThrowIfCancellationRequested();
            using var key = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store");
            if (key is null) return;

            foreach (string valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                string vLower = valueName.ToLowerInvariant();
                bool hasCheatKeyword = Array.Exists(CheatCompatKeywords,
                    kw => vLower.Contains(kw));
                if (!hasCheatKeyword) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Compat-Assistant-Eintrag (Cheat-Keyword): {Path.GetFileName(valueName)}",
                    Risk     = RiskLevel.Medium,
                    Location = @"HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
                    FileName = Path.GetFileName(valueName),
                    Reason   = $"Compatibility Assistant hat Ausführung von '{valueName}' aufgezeichnet — " +
                               "dieser Eintrag zeigt dass ein Programm mit Cheat-Keyword in der Vergangenheit " +
                               "ausgeführt wurde und eine UAC/Kompatibilitätsmeldung ausgelöst hat (forensisches Artefakt)",
                    Detail   = $"Pfad: {valueName}"
                });
            }
        }
        catch { }
    }

    private void CheckCompatLayerEnvironment(ScanContext ctx, CancellationToken ct)
    {
        // Check if __COMPAT_LAYER is set in system or user environment
        string[] envVars = { "__COMPAT_LAYER", "__PROCESS_HISTORY" };
        string[] targets = { "Machine", "User" };

        foreach (string envVar in envVars)
        {
            ct.ThrowIfCancellationRequested();
            foreach (string target in targets)
            {
                try
                {
                    var targetEnum = target == "Machine"
                        ? EnvironmentVariableTarget.Machine
                        : EnvironmentVariableTarget.User;

                    string? value = Environment.GetEnvironmentVariable(envVar, targetEnum);
                    if (string.IsNullOrEmpty(value)) continue;

                    ctx.IncrementRegistryKeys();

                    bool isRunAsInvoker = value.Contains("RunAsInvoker",
                        StringComparison.OrdinalIgnoreCase);

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"{envVar} gesetzt ({target}): {value}",
                        Risk     = isRunAsInvoker ? RiskLevel.High : RiskLevel.Medium,
                        Location = $"{target} Environment: {envVar}",
                        FileName = envVar,
                        Reason   = isRunAsInvoker
                            ? $"__COMPAT_LAYER=RunAsInvoker in {target}-Umgebung gesetzt — " +
                              "erzwingt dass auto-elevierende Prozesse (fodhelper, sdclt) OHNE UAC " +
                              "mit normalen Benutzerrechten starten, was UAC-Bypass-Techniken ermöglicht"
                            : $"Umgebungsvariable '{envVar}={value}' in {target}-Scope gesetzt — " +
                              "ungewöhnlich und möglicherweise für Kompatibilitäts-Shim-Manipulation genutzt",
                        Detail   = $"Variable: {envVar} | Wert: {value} | Scope: {target} | " +
                                   $"RunAsInvoker: {isRunAsInvoker}"
                    });
                }
                catch { }
            }
        }
    }
}
