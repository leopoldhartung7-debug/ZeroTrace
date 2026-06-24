using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans Windows named kernel objects that cheats use for inter-process
/// communication and single-instance checks:
///  - Named pipes  (\\.\pipe\*)
///  - Known cheat mutexes (via Mutex.OpenExisting)
///
/// Pipe names and mutex names are checked against the indicator matcher.
/// Only readable/accessible objects are enumerated; access-denied entries
/// are silently skipped so no elevation is required.
/// </summary>
public sealed class NamedResourceScanModule : IScanModule
{
    public string Name => "Kernel-Objekte";
    public double Weight => 0.5;
    public int ParallelGroup => 2;

    private static readonly string[] KnownCheatMutexes =
    {
        // FiveM cheats
        "TsunamiMenu", "LynxMenu", "OzarkMenu", "NexusMenu", "RxCEMenu",
        "2Take1Menu", "CheraxMenu", "MidnightMenu", "SpaceDustMenu",
        "RedENGINEMutex", "EulenMutex", "HammafiaCheat", "DesudoMutex",
        "ImpaughtMutex", "PhantomXMutex", "KiddionMutex",
        // CS2 / CSGO cheats
        "AimwareMutex", "FecurityMutex", "OnetapMutex", "NeverloseMutex",
        "GamesenseMutex", "FatalityMutex", "NixWareMutex", "LuminaMutex",
        // Minecraft cheats
        "LiquidBounceMutex", "WurstMutex", "VapeMutex",
        // Generic cheat infrastructure
        "HWIDSpooferMutex", "CheatLoaderMutex", "InjectMutex",
        "UnknownCheatsClient", "CheatEngineMutex",
        // 2025/2026 additions — modern FiveM / GTA menus and Vanguard-bypass tools
        "YimMenuMutex", "StandMenuMutex", "LambdaMenuMutex", "AbsoluteMenuMutex",
        "SpectreMenuMutex", "CelestialMutex", "SusanoMutex", "HyperionMutex",
        "NSAwareMutex", "ReaperMenuMutex", "PrimordialMutex",
        "PhoenixCheatMutex", "SunsetCheatMutex", "VoidCheatsMutex",
        // Modern Valorant / Apex / Warzone cheats
        "ValorHackMutex", "VanguardBypassMutex", "RingoneMutex",
        "BlackCellMutex", "EngineOwningMutex", "RicochetBypassMutex",
        // DMA tooling
        "MemProcFSMutex", "LeechCoreMutex", "PCILeechMutex",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int pipeCount = 0, mutexHits = 0, pipeHits = 0;

        // --- Named pipes -------------------------------------------------
        try
        {
            var pipes = Directory.GetFiles(@"\\.\pipe\", "*", SearchOption.TopDirectoryOnly);
            foreach (var pipe in pipes)
            {
                if (ct.IsCancellationRequested) break;
                pipeCount++;
                var name = Path.GetFileName(pipe);

                var hit = ctx.Matcher.MatchFileNameKeyword(name)
                          ?? ctx.Matcher.MatchPathKeyword(name);
                if (hit is null) continue;

                pipeHits++;
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Verdaechtiger Named Pipe: {name}",
                    Risk     = hit.Risk,
                    Location = pipe,
                    FileName = name,
                    Reason   = $"Named Pipe '{name}' entspricht Indikator '{hit.Pattern}' ({hit.Category}). " +
                               hit.Description,
                });
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (DirectoryNotFoundException) { }
        catch { }

        // --- Known cheat mutexes -----------------------------------------
        foreach (var mutexName in KnownCheatMutexes)
        {
            if (ct.IsCancellationRequested) break;
            try
            {
                using var m = Mutex.OpenExisting(mutexName);
                // If we get here the mutex exists.
                mutexHits++;
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat-Mutex aktiv: {mutexName}",
                    Risk     = RiskLevel.High,
                    Location = $@"\\.\Global\{mutexName}",
                    FileName = mutexName,
                    Reason   = $"Bekanntes Cheat-Mutex '{mutexName}' ist gerade aktiv — " +
                               "das zugehoerige Tool laeut moeglicherweise im Hintergrund.",
                });
            }
            catch (WaitHandleCannotBeOpenedException) { /* doesn't exist */ }
            catch (UnauthorizedAccessException)
            {
                // Mutex exists but we can't open it — still suspicious.
                mutexHits++;
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat-Mutex (kein Zugriff): {mutexName}",
                    Risk     = RiskLevel.Medium,
                    Location = $@"\\.\Global\{mutexName}",
                    FileName = mutexName,
                    Reason   = $"Bekanntes Cheat-Mutex '{mutexName}' existiert (Zugriff verweigert) — " +
                               "moeglicherweise durch Cheat geschuetzt.",
                });
            }
            catch { }
        }

        ctx.Report(1.0, "Kernel-Objekte",
            $"{pipeCount} Pipes geprueft, {pipeHits} Pipe-Treffer, {mutexHits} Mutex-Treffer");
        return Task.CompletedTask;
    }
}
