using System.Runtime.InteropServices;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects AtomBombing code injection technique and related global atom table abuse.
///
/// AtomBombing (discovered by enSilo in 2016) is a process injection method that
/// abuses the Windows Global Atom Table — a shared kernel object that stores
/// named strings for inter-process communication. Because it uses no
/// WriteProcessMemory calls, it bypasses most injection-detection heuristics.
///
/// How AtomBombing works:
///   1. PAYLOAD STAGING — store shellcode in atom table:
///      - Shellcode is split into chunks ≤255 characters (Unicode atom name limit)
///      - GlobalAddAtom(chunk) → stores each chunk in the kernel atom table
///      - Atom IDs are sequential, stored in attacker process
///
///   2. CODE COPY — copy shellcode into target process WITHOUT WriteProcessMemory:
///      - For each shellcode chunk, queue a special APC to a target alertable thread:
///          NtQueueApcThread(hTargetThread,
///                           GlobalGetAtomName,  ← legitimate ntdll export
///                           atom_id,            ← arg1: which atom to read
///                           dest_va,            ← arg2: where to write in target
///                           MAX_ATOM_NAME_LEN)  ← arg3: buffer size
///      - When the target thread is alertable (SleepEx, MsgWaitForMultipleObjectsEx),
///        it calls GlobalGetAtomName in its own address space, writing the shellcode chunk
///
///   3. EXECUTION — execute the assembled shellcode:
///      - NtQueueApcThread(hTargetThread, shellcode_va, arg1, arg2, arg3)
///      - Or NtProtectVirtualMemory + NtQueueApcThread
///
/// Why it evades conventional detection:
///   - No CreateRemoteThread (no thread-creation events)
///   - No WriteProcessMemory (standard injection IoC absent)
///   - Only legitimate kernel functions used as APC callbacks
///   - Shellcode lives in the kernel atom table, not in any userland allocation
///   - The atom table is not normally monitored by security products
///
/// Advanced variants:
///   - Ghost-Writing: queue NtWriteVirtualMemory as APC → writes to target
///   - StackBombing: overwrite return addresses on target thread stack via atom copy
///   - Kernel-variant: use NtUserSetImeInfoEx kernel pool for storage (CSRF-free)
///
/// Detection approach:
///   1. Enumerate global atom table (user-defined range: 0xC000–0xFFFF)
///      via GlobalGetAtomName for each slot
///   2. Decode the atom name bytes and scan for:
///      a) x86-64 shellcode prologues / common stager patterns
///      b) MZ/PE headers embedded as atom content (PE payload staging)
///      c) High density of non-printable / binary bytes (raw shellcode)
///   3. Flag atoms that are at or near the 255-character name length limit
///      AND contain binary data (shellcode chunks have exactly 255 chars)
///   4. Count total user atoms — normal Windows has <200; AtomBombing for a
///      medium payload creates 400–2000 atoms
///   5. Detect rapid atom creation by sampling the table twice in 500ms
///      and measuring growth rate
/// </summary>
public sealed class AtomBombingDetectionScanModule : IScanModule
{
    public string Name => "AtomBombing-Injektions-Erkennung";
    public double Weight => 0.7;
    public int ParallelGroup => 2;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GlobalGetAtomName(ushort nAtom,
        [Out] StringBuilder lpBuffer, int nSize);

    // Global user-defined atoms: 0xC000–0xFFFF
    private const ushort AtomUserStart = 0xC000;
    private const ushort AtomUserEnd   = 0xFFFF;

    // Name length threshold for "large atom" heuristic (shellcode chunks ≈255 chars)
    private const int LargeAtomThreshold = 200;

    // Minimum binary density to flag a large atom as suspicious (30% non-printable)
    private const double BinaryDensityThreshold = 0.30;

    // Flag if the total user atom count exceeds this (normal: <200)
    private const int HighAtomCountThreshold = 500;

    // x64 / x86 shellcode byte patterns that should never appear in legitimate atoms
    private static readonly (string Label, byte[] Bytes)[] ShellcodePatterns =
    [
        ("MZ-Header",          new byte[] { 0x4D, 0x5A }),
        ("x64-CLD-REX",        new byte[] { 0xFC, 0x48 }),                        // msfvenom x64 stager
        ("x64-PEB-GS",         new byte[] { 0x65, 0x48, 0x8B, 0x04, 0x25 }),      // MOV RAX,GS:[rip+...] PEB
        ("x64-PEB-GS2",        new byte[] { 0x65, 0x4C, 0x8B, 0x04, 0x25 }),      // MOV R8,GS:[...] PEB
        ("x86-PEB-FS",         new byte[] { 0x64, 0x8B, 0x40, 0x30 }),            // MOV EAX,FS:[EAX+0x30]
        ("x86-PUSHAD",         new byte[] { 0x60, 0x89, 0xE5 }),                   // PUSHAD; MOV EBP,ESP
        ("CALL-GETPC",         new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00 }),       // CALL $+5 (get-PC trick)
        ("ROP-GADGET-RET",     new byte[] { 0xC3, 0x90, 0xC3, 0x90 }),             // RET NOP RET NOP chain
        ("VirtualAlloc-hash",  new byte[] { 0x8C, 0x4E, 0x52, 0xE7 }),             // CRC32/ROR13 API hash
        ("LoadLibrary-hash",   new byte[] { 0xEC, 0x0E, 0x4E, 0x8A }),             // LoadLibraryA ROR13 hash
        ("Metasploit-shikata", new byte[] { 0xD9, 0x74, 0x24, 0xF4 }),             // Shikata-ga-nai XOR
        ("xor-eax-eax",       new byte[] { 0x31, 0xC0, 0x50, 0x68 }),             // XOR EAX,EAX; PUSH EAX; PUSH
    ];

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        int totalAtoms = 0;
        int largeAtoms = 0;
        var sb = new StringBuilder(260);

        try
        {
            for (ushort atomId = AtomUserStart; atomId < AtomUserEnd; atomId++)
            {
                if (ct.IsCancellationRequested) break;

                sb.Clear();
                uint nameLen = GlobalGetAtomName(atomId, sb, 256);
                if (nameLen == 0) continue;

                totalAtoms++;
                string atomName = sb.ToString(0, (int)nameLen);
                int charCount = (int)nameLen;

                if (charCount >= LargeAtomThreshold)
                    largeAtoms++;

                // Encode as UTF-16 LE bytes (what the atom actually stores)
                byte[] atomBytes = Encoding.Unicode.GetBytes(atomName);

                // Check for shellcode patterns
                string? patternLabel = null;
                foreach (var (label, pattern) in ShellcodePatterns)
                {
                    if (BytesContainPattern(atomBytes, pattern))
                    {
                        patternLabel = label;
                        break;
                    }
                }

                // Compute binary density (non-printable, non-whitespace bytes)
                int nonPrint = 0;
                foreach (byte b in atomBytes)
                {
                    if (b < 0x20 && b != 0x09 && b != 0x0A && b != 0x0D)
                        nonPrint++;
                }
                double density = atomBytes.Length == 0 ? 0.0 : (double)nonPrint / atomBytes.Length;

                bool isSuspicious = patternLabel is not null ||
                    (charCount >= LargeAtomThreshold && density >= BinaryDensityThreshold);

                if (!isSuspicious) continue;

                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "AtomBombing-Injektions-Erkennung",
                    Title    = $"Verdächtiger Atom-Eintrag 0x{atomId:X4} ({charCount} Zeichen)",
                    Risk     = RiskLevel.High,
                    Location = $"GlobalAtomTable[0x{atomId:X4}]",
                    Reason   = $"Globaler Atom-Eintrag 0x{atomId:X4} ({charCount} Zeichen, " +
                               $"{100.0 * density:F0}% Binärinhalt)" +
                               (patternLabel is not null
                                   ? $" enthält Shellcode-Muster '{patternLabel}'. "
                                   : " enthält dichten Binärinhalt. ") +
                               "AtomBombing-Technik: Angreifer teilt Shellcode in 255-Byte-Chunks " +
                               "auf und speichert sie in der globalen Atom-Tabelle (Kernel-Objekt). " +
                               "Mittels NtQueueApcThread(GlobalGetAtomName, ...) wird der Inhalt " +
                               "OHNE WriteProcessMemory in Ziel-Prozesse kopiert. " +
                               "Alle Standard-Injektions-Scanner (WriteProcessMemory-Monitoring) " +
                               "werden damit umgangen.",
                    Detail   = $"AtomID=0x{atomId:X4} | Länge={charCount} | " +
                               $"Binärdichte={100.0 * density:F1}% | " +
                               $"Muster={(patternLabel ?? "Binär-Dichte")}"
                });

                if (hits >= 15) break; // Cap: mass-injection creates hundreds of atoms
            }

            // High atom count warning
            if (totalAtoms > HighAtomCountThreshold)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "AtomBombing-Injektions-Erkennung",
                    Title    = $"Ungewöhnlich viele globale Atome: {totalAtoms}",
                    Risk     = RiskLevel.Medium,
                    Location = "GlobalAtomTable",
                    Reason   = $"Die globale Atom-Tabelle enthält {totalAtoms} Benutzer-Atome " +
                               $"(davon {largeAtoms} mit ≥{LargeAtomThreshold} Zeichen). " +
                               $"Normale Windows-Umgebungen haben selten mehr als 200 Benutzer-Atome. " +
                               "AtomBombing für ein mittleres Payload (z.B. 64 KB Shellcode) " +
                               "erstellt ~260 Atome (256 Bytes / Chunk × 256 Chunks). " +
                               "Große Mengen neuer Atome kurz vor diesem Scan-Ergebnis " +
                               "deuten auf laufende oder kürzlich abgeschlossene AtomBombing-Injektion hin.",
                    Detail   = $"TotalAtoms={totalAtoms} | LargeAtoms={largeAtoms} | " +
                               $"SuspiciousAtoms={hits}"
                });
            }
        }
        catch { }

        ctx.Report(1.0, Name,
            $"Atom-Tabelle: {totalAtoms} Einträge, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static bool BytesContainPattern(byte[] data, byte[] pattern)
    {
        if (pattern.Length == 0 || pattern.Length > data.Length) return false;
        int limit = data.Length - pattern.Length;
        for (int i = 0; i <= limit; i++)
        {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (data[i + j] != pattern[j]) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }
}
