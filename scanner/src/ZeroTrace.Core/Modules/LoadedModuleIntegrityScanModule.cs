using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Verifies integrity of loaded modules in game processes by comparing
/// on-disk file hashes against the actual in-memory content.
///
/// Code Tampering / In-Memory Patching:
///   Cheats don't always inject new DLLs — sometimes they patch existing loaded modules:
///
///   1. ntdll.dll patching: hook NtQuerySystemInformation, NtQueryVirtualMemory, etc.
///      to blind the scanner to what's in memory (inline hook in ntdll code section)
///
///   2. Game DLL patching: modify game client DLLs in memory to disable anti-cheat
///      integrity checks, enable debug modes, or alter game logic (ESP).
///
///   3. Anti-cheat DLL patching: modify loaded AC module code to NOP out detection
///      routines or always return "clean" from scan functions.
///
///   4. Direct memory write on PE code sections:
///      VirtualProtect → RW, write patch bytes, VirtualProtect → RX back.
///
/// Detection:
///   1. For each loaded module in game/target processes, read the on-disk PE
///   2. Compare the .text (code) section hash from disk vs in-memory
///   3. Discrepancies that don't match known relocations indicate patching
///   4. Also check for modules with zeroed PE headers (module stomping)
///   5. Check for duplicate module names in different paths (shadow loading)
/// </summary>
public sealed class LoadedModuleIntegrityScanModule : IScanModule
{
    public string Name => "Modul-Integritäts-Verifikation";
    public double Weight => 1.1;
    public int ParallelGroup => 0;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;

    // Critical modules to always verify in game processes
    private static readonly HashSet<string> CriticalModules = new(StringComparer.OrdinalIgnoreCase)
    {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll",
        "user32.dll", "advapi32.dll", "ws2_32.dll",
        "dbghelp.dll",
    };

    // Game processes to check module integrity in
    private static readonly HashSet<string> TargetProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "csgo.exe", "cs2.exe", "valorant.exe", "VALORANT-Win64-Shipping.exe",
        "r5apex.exe", "FortniteClient-Win64-Shipping.exe",
        "GTA5.exe", "EFT.exe", "pubg.exe",
        "overwatch.exe", "Overwatch.exe",
        "RainbowSix.exe",
    };

    // Anti-cheat modules to verify
    private static readonly HashSet<string> AntiCheatModules = new(StringComparer.OrdinalIgnoreCase)
    {
        "EasyAntiCheat.dll", "eac_main.dll",
        "BEClient.dll", "BEClient_x64.dll",
        "vanguard.dll",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                string procExe = proc.ProcessName + ".exe";
                if (!TargetProcesses.Contains(procExe))
                {
                    proc.Dispose();
                    continue;
                }

                ctx.IncrementProcesses();
                try
                {
                    hits += VerifyProcessModules(proc, ctx, ct);
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }

        ctx.Report(1.0, Name, $"Modul-Integrität in Spielprozessen geprüft, {hits} Anomalien");
        return Task.CompletedTask;
    }

    private static int VerifyProcessModules(Process proc, ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        string procExe = proc.ProcessName + ".exe";
        IntPtr hProcess = IntPtr.Zero;

        try
        {
            hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                false, proc.Id);
            if (hProcess == IntPtr.Zero) return 0;

            // Track module names to detect duplicates (shadow loading)
            var seenModuleNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (ProcessModule mod in proc.Modules)
            {
                if (ct.IsCancellationRequested) break;

                string modName = mod.ModuleName ?? "";
                string modPath = mod.FileName ?? "";

                bool isCritical = CriticalModules.Contains(modName);
                bool isAc = AntiCheatModules.Contains(modName);

                // Check for duplicate module names from different paths (shadow loading)
                if (seenModuleNames.TryGetValue(modName, out var existingPath))
                {
                    if (!string.Equals(existingPath, modPath, StringComparison.OrdinalIgnoreCase))
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Modul-Integritäts-Verifikation",
                            Title    = $"Doppeltes Modul in verschiedenen Pfaden: {modName}",
                            Risk     = RiskLevel.Critical,
                            Location = $"PID {proc.Id}: {modPath}",
                            FileName = modName,
                            Reason   = $"DLL '{modName}' ist zweimal in Prozess '{procExe}' geladen: " +
                                       $"'{existingPath}' und '{modPath}'. " +
                                       "Shadow Loading: Cheat-Software lädt eine modifizierte Kopie " +
                                       "einer System-DLL aus einem anderen Pfad, um Syscall-Hooks " +
                                       "zu umgehen (ntdll.dll Shadow Copy-Technik).",
                            Detail   = $"Modul: {modName} | Pfad 1: {existingPath} | Pfad 2: {modPath}"
                        });
                    }
                    continue;
                }
                seenModuleNames[modName] = modPath;

                if (!isCritical && !isAc) continue;
                if (!File.Exists(modPath)) continue;

                ctx.IncrementFiles();

                // Compare PE code section hash: disk vs memory
                hits += CompareModuleCodeSection(proc, hProcess, mod, modName, procExe, ctx);
            }
        }
        catch { }
        finally
        {
            if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
        }
        return hits;
    }

    private static int CompareModuleCodeSection(Process proc, IntPtr hProcess,
        ProcessModule mod, string modName, string procExe, ScanContext ctx)
    {
        try
        {
            // Read PE header from memory to find .text section
            var header = new byte[0x400];
            if (!ReadProcessMemory(hProcess, mod.BaseAddress, header, header.Length,
                out int read) || read < 0x100)
                return 0;

            // Verify MZ header
            if (header[0] != 0x4D || header[1] != 0x5A)
            {
                // Zeroed header = module stomping
                ctx.AddFinding(new Finding
                {
                    Module   = "Modul-Integritäts-Verifikation",
                    Title    = $"PE-Header fehlt in geladenem Modul: {modName}",
                    Risk     = RiskLevel.Critical,
                    Location = $"PID {proc.Id}: {modName} @ 0x{mod.BaseAddress.ToInt64():X}",
                    FileName = modName,
                    Reason   = $"Geladenes Modul '{modName}' in '{procExe}' hat keinen MZ-Header " +
                               "(erstes Byte: 0x{header[0]:X2}). " +
                               "Module Stomping: Cheat-Software löscht PE-Header nach dem Laden, " +
                               "um die DLL vor Memory-Scannern zu verstecken (sie erscheint als " +
                               "normaler Speicher, nicht als Modul).",
                    Detail   = $"Modul: {modName} | Adresse: 0x{mod.BaseAddress.ToInt64():X} | " +
                               $"Header[0..3]: {header[0]:X2} {header[1]:X2} {header[2]:X2} {header[3]:X2}"
                });
                return 1;
            }

            // Get PE offset
            int e_lfanew = BitConverter.ToInt32(header, 0x3C);
            if (e_lfanew < 0 || e_lfanew + 0x100 > header.Length) return 0;

            // Read number of sections and section headers
            ushort numSections = BitConverter.ToUInt16(header, e_lfanew + 6);
            ushort optHeaderSize = BitConverter.ToUInt16(header, e_lfanew + 20);
            int sectionOffset = e_lfanew + 24 + optHeaderSize;

            if (numSections == 0 || sectionOffset + numSections * 40 > header.Length) return 0;

            // Find .text section
            for (int i = 0; i < numSections; i++)
            {
                int sOff = sectionOffset + i * 40;
                if (sOff + 40 > header.Length) break;

                // Section name (8 bytes)
                var sectionName = System.Text.Encoding.ASCII.GetString(header, sOff, 8)
                    .TrimEnd('\0');
                if (!sectionName.Equals(".text", StringComparison.OrdinalIgnoreCase)) continue;

                uint virtualSize = BitConverter.ToUInt32(header, sOff + 16);
                uint virtualAddress = BitConverter.ToUInt32(header, sOff + 20);
                uint rawDataOffset = BitConverter.ToUInt32(header, sOff + 20 + 4);

                if (virtualSize == 0 || virtualSize > 50 * 1024 * 1024) break; // >50MB unreasonable

                // Read a sample of the code section from memory (first 4KB)
                int sampleSize = (int)Math.Min(4096, virtualSize);
                var memorySample = new byte[sampleSize];
                var codeAddr = new IntPtr(mod.BaseAddress.ToInt64() + virtualAddress);
                if (!ReadProcessMemory(hProcess, codeAddr, memorySample, sampleSize, out int memRead)
                    || memRead < 16)
                    break;

                // Read same region from disk
                try
                {
                    using var fs = new FileStream(mod.FileName!, FileMode.Open,
                        FileAccess.Read, FileShare.ReadWrite);
                    var diskSample = new byte[sampleSize];
                    fs.Seek(rawDataOffset, SeekOrigin.Begin);
                    int diskRead = fs.Read(diskSample, 0, sampleSize);
                    if (diskRead < 16) break;

                    // Count differing bytes (allow for relocations: up to 5% diff is OK)
                    int diffs = 0;
                    for (int j = 0; j < Math.Min(memRead, diskRead); j++)
                    {
                        if (memorySample[j] != diskSample[j]) diffs++;
                    }

                    double diffRatio = (double)diffs / Math.Min(memRead, diskRead);
                    if (diffRatio > 0.05) // >5% differences in code section = patched
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Modul-Integritäts-Verifikation",
                            Title    = $"Code-Sektion gepacht: {modName} in {procExe}",
                            Risk     = AntiCheatModules.Contains(modName) ||
                                       modName.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase)
                                       ? RiskLevel.Critical : RiskLevel.High,
                            Location = $"PID {proc.Id}: {modName}.text @ 0x{codeAddr.ToInt64():X}",
                            FileName = modName,
                            Reason   = $"Die .text-Sektion von '{modName}' in '{procExe}' " +
                                       $"weicht zu {diffRatio:P0} von der Disk-Version ab " +
                                       $"({diffs} von {Math.Min(memRead, diskRead)} Bytes unterschiedlich). " +
                                       "In-Memory-Patching: Cheat-Software überschreibt Code-Bytes " +
                                       "mit JMP-Instruktionen (Inline Hooks), um Funktionen umzuleiten.",
                            Detail   = $"Modul: {modName} | Diff: {diffRatio:P1} ({diffs}/{Math.Min(memRead, diskRead)} Bytes) | " +
                                       $"Sample: {sampleSize} Bytes der .text-Sektion"
                        });
                        return 1;
                    }
                }
                catch { }
                break;
            }
        }
        catch { }
        return 0;
    }
}
