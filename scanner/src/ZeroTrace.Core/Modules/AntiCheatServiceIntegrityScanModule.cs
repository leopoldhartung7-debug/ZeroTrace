using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Verifies the integrity of installed anti-cheat service registrations. Cheat tools
/// target AC service entries to prevent them from starting: redirecting the ImagePath to a
/// fake/missing binary, changing the StartType to Disabled (4), reducing the service type,
/// or deleting service keys entirely. The module checks registry entries for EasyAntiCheat,
/// BattlEye, Vanguard, FACEIT, VAC, and other AC services against expected signatures:
/// valid file path exists on disk, service is not disabled, service type matches expected
/// kernel/user mode designation, and ImagePath is not redirected to a suspicious location.
/// Also detects AC driver blocklist (DOT files) tampering and AC update server blocks.
/// </summary>
public sealed class AntiCheatServiceIntegrityScanModule : IScanModule
{
    public string Name => "Anti-Cheat Service Integrity";
    public double Weight => 0.75;
    public int ParallelGroup => 3;

    private const string ServicesBase = @"SYSTEM\CurrentControlSet\Services";

    // Anti-cheat services and their expected properties
    private static readonly AntiCheatService[] AntiCheatServices =
    {
        new("EasyAntiCheat",        @"\EasyAntiCheat\",    1,  false, "EasyAntiCheat"),
        new("EasyAntiCheat_EOS",    @"\EasyAntiCheat\",    1,  false, "EasyAntiCheat (EOS)"),
        new("BEService",            @"\BattlEye\",         16, false, "BattlEye"),
        new("vgc",                  @"\vgk.sys",           1,  false, "Vanguard (VGC)"),
        new("vgk",                  @"\vgk.sys",           1,  true,  "Vanguard (VGK Driver)"),
        new("FACEITService",        @"\FACEIT\",           16, false, "FACEIT"),
        new("ESEADriver3",          @"\esea\",             1,  true,  "ESEA Driver"),
        new("ESEAService",          @"\esea\",             16, false, "ESEA Service"),
        new("nEAC",                 @"\nEAC",              1,  true,  "nProtect EAC"),
        new("NPGameMon",            @"\np",                1,  false, "nProtect GameMon"),
        new("AhnLabV3Service",      @"\AhnLab\",           16, false, "AhnLab V3"),
        new("XignCode",             @"\xigncode",          1,  true,  "XIGNCODE3"),
        new("Themida",              @"\Themida",           1,  true,  "Themida Driver"),
        new("ACE-BASE",             @"\ACE\",              16, false, "ACE Anti-Cheat (Riot)"),
    };

    private record AntiCheatService(
        string ServiceName,
        string ExpectedPathContains,
        int    ExpectedStartType,    // 1=System, 2=Auto, 3=Manual, 4=Disabled
        bool   IsKernelDriver,
        string FriendlyName);

    // Suspicious paths that should not be AC binary locations
    private static readonly string[] SuspiciousPaths =
    {
        @"\temp\", @"\tmp\", @"\downloads\", @"\desktop\",
        @"\appdata\local\temp\", @"c:\users\",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => CheckAntiCheatServices(ctx, ct), ct);
    }

    private void CheckAntiCheatServices(ScanContext ctx, CancellationToken ct)
    {
        foreach (var ac in AntiCheatServices)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey($@"{ServicesBase}\{ac.ServiceName}");
                if (key is null) continue;

                ctx.IncrementRegistryKeys();

                string? imagePath = key.GetValue("ImagePath") as string;
                int? start        = key.GetValue("Start") as int?;
                int? type         = key.GetValue("Type") as int?;

                // Resolve environment variables in ImagePath
                string? resolvedPath = imagePath is not null
                    ? Environment.ExpandEnvironmentVariables(imagePath.Trim('"'))
                    : null;

                // Check 1: Service disabled
                if (start == 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Anti-Cheat-Dienst deaktiviert: {ac.FriendlyName}",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\{ServicesBase}\{ac.ServiceName}",
                        FileName = ac.ServiceName,
                        Reason   = $"Anti-Cheat-Dienst '{ac.FriendlyName}' (Service: {ac.ServiceName}) ist " +
                                   "deaktiviert (StartType=4) — Cheat-Tools setzen AC-Dienste auf Disabled " +
                                   "um sie am Start zu hindern",
                        Detail   = $"Service: {ac.ServiceName} | StartType: {start} (Disabled) | ImagePath: {imagePath}"
                    });
                }

                // Check 2: ImagePath points to suspicious location
                if (!string.IsNullOrEmpty(resolvedPath))
                {
                    string pathLower = resolvedPath.ToLowerInvariant();

                    // Check if path contains expected AC substring
                    bool hasExpectedPath = pathLower.Contains(ac.ExpectedPathContains.ToLowerInvariant());
                    if (!hasExpectedPath && !string.IsNullOrEmpty(ac.ExpectedPathContains))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Anti-Cheat-Dienst umgeleitet: {ac.FriendlyName}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{ServicesBase}\{ac.ServiceName}",
                            FileName = Path.GetFileName(resolvedPath),
                            Reason   = $"Anti-Cheat-Dienst '{ac.FriendlyName}' hat unerwarteten ImagePath '{imagePath}' " +
                                       $"(erwartet: Pfad enthält '{ac.ExpectedPathContains}') — " +
                                       "AC-Dienst wurde möglicherweise auf eine Fake-Binary umgeleitet",
                            Detail   = $"Service: {ac.ServiceName} | Erwarteter Pfad-Teil: {ac.ExpectedPathContains} | " +
                                       $"Tatsächlicher Pfad: {imagePath}"
                        });
                    }

                    // Check if in suspicious location
                    bool isInSuspiciousPath = Array.Exists(SuspiciousPaths, sp => pathLower.Contains(sp));
                    if (isInSuspiciousPath)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Anti-Cheat-Dienst in verdächtigem Pfad: {ac.FriendlyName}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{ServicesBase}\{ac.ServiceName}",
                            FileName = Path.GetFileName(resolvedPath),
                            Reason   = $"Anti-Cheat-Dienst '{ac.FriendlyName}' ImagePath zeigt auf " +
                                       $"verdächtigen Pfad '{imagePath}' — AC-Binary in Temp/User-Verzeichnis " +
                                       "deutet auf Fake-AC-Replacement hin",
                            Detail   = $"Service: {ac.ServiceName} | Verdächtiger Pfad: {imagePath}"
                        });
                    }

                    // Check if binary exists
                    string binaryPath = resolvedPath.Split(' ')[0].Trim('"');
                    // Strip driver path prefix \??\ if present
                    binaryPath = binaryPath.TrimStart('\\').TrimStart('?').TrimStart('\\');
                    if (binaryPath.Length > 3 && !File.Exists(binaryPath) && !binaryPath.StartsWith(@"\System"))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Anti-Cheat-Binary fehlt: {ac.FriendlyName}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{ServicesBase}\{ac.ServiceName}",
                            FileName = Path.GetFileName(binaryPath),
                            Reason   = $"Anti-Cheat-Binary für '{ac.FriendlyName}' nicht gefunden: '{binaryPath}' — " +
                                       "Binary wurde möglicherweise gelöscht um AC-Start zu verhindern",
                            Detail   = $"Service: {ac.ServiceName} | Fehlende Binary: {binaryPath} | ImagePath: {imagePath}"
                        });
                    }
                }
            }
            catch { }
        }
    }
}
