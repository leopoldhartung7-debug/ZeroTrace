using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects AppInit_DLLs abuse in the HKCU (per-user) registry hive — a technique distinct
/// from and complementary to the HKLM AppInit_DLLs check. HKCU AppInit_DLLs (under
/// HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows) are loaded WITHOUT administrator
/// privileges into every GUI process (any process importing USER32.DLL) for the current user.
/// This makes it ideal for cheat injection that doesn't require elevation: a user-mode cheat
/// loader sets HKCU\...\AppInit_DLLs to its DLL path, and every subsequent GUI process
/// (including the game) automatically loads the cheat DLL on startup. Also checks
/// LoadAppInit_DLLs enable flag and RequireSignedAppInit_DLLs status per hive. The HKCU
/// variant is particularly suspicious because no legitimate software uses per-user AppInit.
/// </summary>
public sealed class HkcuAppInitDllsScanModule : IScanModule
{
    public string Name => "HKCU AppInit_DLLs Injection Detection";
    public double Weight => 0.75;
    public int ParallelGroup => 3;

    private const string AppInitKeyPath =
        @"Software\Microsoft\Windows NT\CurrentVersion\Windows";

    // Legitimate HKLM AppInit_DLLs (common — not flagged in this module)
    private static readonly HashSet<string> LegitHklmAppInitDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "igfxpph.dll", "iertutil.dll", "nvvsvc.exe",
    };

    private static readonly string[] SuspiciousAppInitKeywords =
    {
        "cheat", "hack", "esp", "inject", "bypass",
        "loader", "hook", "trainer", "radar", "aimbot",
        "temp", "appdata", "downloads",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => CheckAppInitDlls(ctx, ct), ct);
    }

    private void CheckAppInitDlls(ScanContext ctx, CancellationToken ct)
    {
        // HKCU check (primary — always suspicious)
        CheckHive(Registry.CurrentUser, "HKCU", AppInitKeyPath, ctx, ct, isHkcu: true);

        // HKLM check (supplement — only flag non-system paths)
        CheckHive(Registry.LocalMachine, "HKLM",
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", ctx, ct, isHkcu: false);
        CheckHive(Registry.LocalMachine, "HKLM",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows", ctx, ct, isHkcu: false);
    }

    private void CheckHive(RegistryKey root, string hiveName, string keyPath,
        ScanContext ctx, CancellationToken ct, bool isHkcu)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            using var key = root.OpenSubKey(keyPath);
            if (key is null) return;

            ctx.IncrementRegistryKeys();

            string? appInitValue = key.GetValue("AppInit_DLLs") as string;
            object? loadFlag     = key.GetValue("LoadAppInit_DLLs");
            object? requireSigned = key.GetValue("RequireSignedAppInit_DLLs");

            int loadFlagInt    = loadFlag is int lf ? lf : 0;
            int requireSignedInt = requireSigned is int rs ? rs : 0;

            // RequireSignedAppInit_DLLs = 0 means unsigned DLLs are allowed (weaker security)
            bool signingDisabled = requireSignedInt == 0;

            if (!string.IsNullOrWhiteSpace(appInitValue) && loadFlagInt != 0)
            {
                // Split by space or comma — multiple DLLs can be listed
                string[] dlls = appInitValue.Split(new char[] { ' ', ',', ';' },
                    StringSplitOptions.RemoveEmptyEntries);

                foreach (string dll in dlls)
                {
                    ct.ThrowIfCancellationRequested();
                    string dllPath  = dll.Trim().Trim('"');
                    string dllLower = dllPath.ToLowerInvariant();
                    string fileName = Path.GetFileName(dllPath);

                    // For HKLM: skip known-legitimate DLLs in system32
                    if (!isHkcu)
                    {
                        if (LegitHklmAppInitDlls.Contains(fileName)) continue;
                        if (dllLower.StartsWith(@"c:\windows\system32\") ||
                            dllLower.StartsWith(@"c:\windows\syswow64\")) continue;
                    }

                    bool hasSuspiciousKeyword = Array.Exists(SuspiciousAppInitKeywords,
                        kw => dllLower.Contains(kw));

                    bool fileExists = File.Exists(dllPath);

                    // HKCU AppInit_DLLs is ALWAYS suspicious regardless of content
                    // HKLM is only flagged for non-system DLLs
                    RiskLevel risk = (isHkcu || hasSuspiciousKeyword)
                        ? RiskLevel.Critical
                        : fileExists ? RiskLevel.High : RiskLevel.Medium;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"AppInit_DLL-Injection ({hiveName}): {fileName}",
                        Risk     = risk,
                        Location = $@"{hiveName}\{keyPath}",
                        FileName = fileName,
                        Reason   = isHkcu
                            ? $"HKCU AppInit_DLLs enthält '{dllPath}' — diese Technik injiziert " +
                              "die DLL OHNE Administratorrechte in jeden GUI-Prozess (inkl. Spielprozess) " +
                              "beim Start. Kein legitimes Programm verwendet HKCU AppInit_DLLs. " +
                              $"Signaturprüfung: {(signingDisabled ? "DEAKTIVIERT (jede DLL erlaubt)" : "aktiv")}"
                            : hasSuspiciousKeyword
                                ? $"HKLM AppInit_DLLs enthält verdächtige DLL '{dllPath}' " +
                                  $"mit Cheat/Inject-Keyword — wird in alle GUI-Prozesse geladen"
                                : $"HKLM AppInit_DLLs enthält unbekannte DLL '{dllPath}' " +
                                  "außerhalb System32 — alle GUI-Prozesse laden diese DLL automatisch",
                        Detail   = $"Hive: {hiveName} | DLL: {dllPath} | LoadAppInit: {loadFlagInt} | " +
                                   $"RequireSigned: {requireSignedInt} | Vorhanden: {fileExists} | " +
                                   $"Cheat-Keyword: {hasSuspiciousKeyword} | HKCU: {isHkcu}"
                    });
                }
            }

            // Even if AppInit_DLLs is empty, flag if LoadAppInit=1 and RequireSigned=0
            // because that's a weakened configuration ready for injection
            if (isHkcu && loadFlagInt != 0 && string.IsNullOrWhiteSpace(appInitValue))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"HKCU AppInit_DLLs aktiviert (leer): potenzielle Vorbereitung",
                    Risk     = RiskLevel.Medium,
                    Location = $@"HKCU\{keyPath}",
                    FileName = "AppInit_DLLs",
                    Reason   = "HKCU LoadAppInit_DLLs ist aktiviert aber AppInit_DLLs-Wert ist leer — " +
                               "LoadAppInit ohne DLL-Wert kann eine Vorbereitung für spätere Cheat-DLL-Injektion sein, " +
                               $"oder die DLL wurde bereits entfernt. Signaturprüfung: {(signingDisabled ? "DEAKTIVIERT" : "aktiv")}",
                    Detail   = $"LoadAppInit_DLLs: {loadFlagInt} | RequireSignedAppInit: {requireSignedInt}"
                });
            }
        }
        catch { }
    }
}
