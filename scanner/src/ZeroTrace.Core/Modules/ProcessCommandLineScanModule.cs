using System.Management;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Enumerates all running process command lines via WMI Win32_Process and flags processes
/// started with cheat-specific arguments. Unlike image-name scanning, command-line analysis
/// reveals cheat tools that rename their executable but pass recognizable flags (--inject,
/// --pid=, --dll=, --bypass) or invoke known cheat tools by name as arguments. Also detects
/// obfuscated PowerShell one-liners (-EncodedCommand, -enc, iex download cradles) launched
/// by shell processes, and LOLBIN chains (certutil -decode, mshta http://) used by cheat
/// loaders to fetch and execute payloads while appearing as legitimate Windows tools.
/// Command lines are never stored or transmitted — only the finding metadata is kept.
/// </summary>
public sealed class ProcessCommandLineScanModule : IScanModule
{
    public string Name => "Process Command Line Argument Scan";
    public double Weight => 0.65;
    public int ParallelGroup => 3;

    private static readonly string[] CheatArgKeywords =
    {
        // Direct injection flags
        "--inject", "/inject", "-inject",
        "--dll=", "/dll=", "-dll=",
        "--pid=", "/pid=",
        "--hook", "/hook",
        "--attach",
        // Cheat feature flags
        "--esp", "/esp",
        "--aimbot", "/aimbot",
        "--radar", "/radar",
        "--bypass", "/bypass",
        "--spoof", "/spoof",
        "--hwid",
        "--loader",
        "--menu",
        "--norecoil", "--no-recoil",
        "--triggerbot", "--trigger",
        "--softaim", "--aimassist",
        "--wallhack", "--wh",
        "--speedhack",
        "--silent",
        // Known cheat tool names as arguments
        "kiddion", "memprocfs", "cherax", "2take1", "midnight",
        "bigbaseV", "enhanced-native", "sxac", "eulenscript",
        "ozark", "phantom-x", "re-enable",
        "NoPing", "ExitLag", "WTFast",
        // Cheat DLL file names
        "cheat.dll", "hack.dll", "esp.dll", "aimbot.dll",
        "inject.dll", "bypass.dll", "radar.dll",
        "minhook.dll", "detours.dll",
    };

    private static readonly string[] EncodedLaunchIndicators =
    {
        "-EncodedCommand", "-encodedcommand",
        "-enc ", "-e ", "-ec ",
        // Classic obfuscation
        "^p^o^w^e^r", "^c^m^d",
        // Download cradles
        "FromBase64String", "IEX(", "IEX (", "iex(",
        "Net.WebClient", "DownloadString", "DownloadFile",
        "WebRequest", "Invoke-Expression",
        "(New-Object", "bitsadmin /transfer",
        "certutil -decode", "certutil -urlcache",
        "mshta http", "mshta vbscript",
        "regsvr32 /u /s /i:http",
        "wscript //B //E:jscript",
        "cscript //B //E:jscript",
        "rundll32 javascript:",
    };

    // Processes that legitimately have encoded commands (IT automation, CI)
    private static readonly HashSet<string> WhitelistedEncoderProcs = new(StringComparer.OrdinalIgnoreCase)
    {
        "vstest.console", "devenv", "msbuild", "nuget",
        "pwsh", "ansible", "chocolatey", "choco",
        "WinDefend", "MsMpEng",
    };

    // System paths — encoded commands from these are usually okay
    private static readonly string[] TrustedExecPaths =
    {
        @"c:\windows\system32\",
        @"c:\windows\syswow64\",
        @"c:\program files\windowsapps\",
        @"c:\program files\windows powershell\",
        @"c:\program files\powershell\",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => ScanCommandLines(ctx, ct), ct);
    }

    private void ScanCommandLines(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                new SelectQuery("Win32_Process",
                    "",
                    new[] { "ProcessId", "Name", "CommandLine", "ExecutablePath" }));
            using var results = searcher.Get();

            foreach (ManagementObject proc in results)
            {
                ct.ThrowIfCancellationRequested();

                string name      = proc["Name"]?.ToString() ?? "";
                string cmdLine   = proc["CommandLine"]?.ToString() ?? "";
                string execPath  = proc["ExecutablePath"]?.ToString() ?? "";
                int    pid       = Convert.ToInt32(proc["ProcessId"]);

                if (string.IsNullOrWhiteSpace(cmdLine)) continue;
                ctx.IncrementRegistryKeys();

                bool hasCheatArg = Array.Exists(CheatArgKeywords,
                    kw => cmdLine.Contains(kw, StringComparison.OrdinalIgnoreCase));

                bool hasEncodedLaunch = Array.Exists(EncodedLaunchIndicators,
                    kw => cmdLine.Contains(kw, StringComparison.OrdinalIgnoreCase));

                if (!hasCheatArg && !hasEncodedLaunch) continue;

                // Filter encoded commands from whitelisted/trusted processes
                if (hasEncodedLaunch && !hasCheatArg)
                {
                    if (WhitelistedEncoderProcs.Contains(name)) continue;
                    string execLower = execPath.ToLowerInvariant();
                    if (Array.Exists(TrustedExecPaths, p => execLower.StartsWith(p))) continue;
                }

                string displayCmd = cmdLine.Length > 300
                    ? cmdLine[..300] + "…"
                    : cmdLine;

                RiskLevel risk = hasCheatArg ? RiskLevel.High : RiskLevel.Medium;

                string reason = hasCheatArg
                    ? $"Prozess '{name}' wurde mit Cheat-spezifischen Argumenten gestartet — " +
                      "Injektions-Flags (--inject, --dll, --pid), Cheat-Feature-Switches " +
                      "(--esp, --radar, --bypass) oder bekannte Cheat-Tool-Namen in der Kommandozeile"
                    : $"Prozess '{name}' enthält Download-Cradle oder Obfuskations-Muster " +
                      "in der Kommandozeile — typisches Muster von Cheat-Loaders die " +
                      "LOLBIN-Techniken (certutil, mshta, wscript) oder encodiertes PowerShell nutzen";

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Verdächtige Kommandozeile: {name} (PID {pid})",
                    Risk     = risk,
                    Location = $"PID {pid}: {(execPath.Length > 0 ? execPath : name)}",
                    FileName = name,
                    Reason   = reason + $"\nKommandozeile: '{displayCmd}'",
                    Detail   = $"PID: {pid} | Name: {name} | Pfad: {execPath} | " +
                               $"Cheat-Arg: {hasCheatArg} | Encode/Cradle: {hasEncodedLaunch} | " +
                               $"Cmd: {displayCmd}"
                });
            }
        }
        catch { }
    }
}
