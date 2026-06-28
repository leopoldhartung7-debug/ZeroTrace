using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects Layered Service Provider (LSP) DLLs in the Winsock2 catalog that could
/// intercept all network traffic from game processes. LSPs are legacy DLLs inserted
/// into every process making network calls; cheats install them to sniff encrypted game
/// packets, inject traffic, or implement network-level radar. The module reads both
/// Protocol_Catalog9 and NameSpace_Catalog5 from the Winsock2 registry key, validates
/// each provider DLL path against known-legitimate system directories, flags missing
/// DLLs (remnants of removed cheats) and non-system provider DLLs.
/// </summary>
public sealed class LspProviderScanModule : IScanModule
{
    public string Name => "LSP Provider Integrity";
    public double Weight => 0.6;
    public int ParallelGroup => 3;

    private const string WinsockBase =
        @"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters";

    private static readonly string[] SystemPaths =
    {
        @"\windows\system32\",
        @"\windows\syswow64\",
        @"\windows\winsxs\",
    };

    private static readonly string[] CheatLspKeywords =
    {
        "winpcap", "npcap", "windivert", "proxifier", "fiddler",
        "charles", "wireshark", "rawsock", "wsock32hook", "ws2hook",
        "netspy", "sockspy", "hookwinsock", "mitmproxy", "burp",
        "trafficfilter", "netfilter", "netredirect",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            ScanProtocolCatalog(ctx, ct);
            ScanNamespaceCatalog(ctx, ct);
        }, ct);
    }

    private void ScanProtocolCatalog(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                WinsockBase + @"\Protocol_Catalog9\Catalog_Entries");
            if (key is null) return;

            foreach (var entryName in key.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var entry = key.OpenSubKey(entryName);
                    if (entry is null) continue;

                    var packed = entry.GetValue("PackedCatalogItem") as byte[];
                    if (packed is null || packed.Length < 40) continue;

                    string? dllPath = ExtractDllPathFromBlob(packed);
                    if (string.IsNullOrEmpty(dllPath)) continue;

                    ctx.IncrementRegistryKeys();
                    ValidateProvider(dllPath, "Protocol_Catalog9", ctx);
                }
                catch { }
            }
        }
        catch { }
    }

    private void ScanNamespaceCatalog(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                WinsockBase + @"\NameSpace_Catalog5\Catalog_Entries");
            if (key is null) return;

            foreach (var entryName in key.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var entry = key.OpenSubKey(entryName);
                    if (entry is null) continue;

                    var libPath = entry.GetValue("LibraryPath") as string;
                    if (string.IsNullOrEmpty(libPath)) continue;

                    ctx.IncrementRegistryKeys();
                    ValidateProvider(libPath, "NameSpace_Catalog5", ctx);
                }
                catch { }
            }
        }
        catch { }
    }

    private void ValidateProvider(string dllPath, string catalogName, ScanContext ctx)
    {
        string pathLower = dllPath.ToLowerInvariant();
        string fileName  = Path.GetFileName(dllPath);

        // Match known cheat/proxy LSP names
        foreach (var kw in CheatLspKeywords)
        {
            if (pathLower.Contains(kw))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title  = $"Cheat-LSP-Provider erkannt: {fileName}",
                    Risk   = RiskLevel.Critical,
                    Location = dllPath,
                    FileName = fileName,
                    Reason = $"Winsock2 {catalogName} enthält bekannte Netzwerk-Intercept-DLL '{fileName}' — " +
                             "wird in jeden Netzwerkprozess geladen und kann Spielpakete abfangen oder injizieren",
                    Detail = $"Katalog: {catalogName} | Pfad: {dllPath} | Stichwort: {kw}"
                });
                return;
            }
        }

        // Legitimate system path → skip
        if (Array.Exists(SystemPaths, sp => pathLower.Contains(sp))) return;

        // Non-system DLL: check file existence
        bool exists = File.Exists(dllPath);
        if (!exists)
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Fehlende LSP-DLL im Winsock-Katalog: {fileName}",
                Risk     = RiskLevel.High,
                Location = dllPath,
                FileName = fileName,
                Reason   = $"Winsock2 {catalogName} referenziert nicht vorhandene DLL '{dllPath}' — " +
                           "Rückstand einer entfernten Cheat-Software, die den Katalog nicht bereinigt hat",
                Detail   = $"Katalog: {catalogName} | DLL nicht gefunden"
            });
            return;
        }

        ctx.AddFinding(new Finding
        {
            Module   = Name,
            Title    = $"Nicht-System-LSP-Provider: {fileName}",
            Risk     = RiskLevel.High,
            Location = dllPath,
            FileName = fileName,
            Reason   = $"Winsock2 {catalogName} enthält Drittanbieter-DLL '{fileName}' außerhalb von System32 — " +
                       "LSPs werden in jeden Netzwerkprozess injiziert und können Spielverkehr abfangen",
            Detail   = $"Katalog: {catalogName} | Pfad: {dllPath}"
        });
    }

    /// <summary>
    /// The PackedCatalogItem blob encodes a WSAPROTOCOL_INFOW struct (up to 512 bytes)
    /// followed by a null-terminated UTF-16 DLL path. Search for the ".dll" UTF-16 pattern
    /// and reconstruct the path by walking backwards to the start of the string.
    /// </summary>
    private static string? ExtractDllPathFromBlob(byte[] blob)
    {
        try
        {
            byte[] dllSig = System.Text.Encoding.Unicode.GetBytes(".dll");
            for (int i = 0; i <= blob.Length - dllSig.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < dllSig.Length; j++)
                    if (blob[i + j] != dllSig[j]) { match = false; break; }
                if (!match) continue;

                int end   = i + dllSig.Length;
                int start = i;
                // Walk backwards; UTF-16 chars are 2 bytes, null char = 00 00
                while (start >= 2)
                {
                    ushort ch = (ushort)(blob[start - 2] | (blob[start - 1] << 8));
                    if (ch == 0) break;
                    start -= 2;
                }
                if ((start & 1) != 0) start++;
                if (end - start < 8) continue;

                string path = System.Text.Encoding.Unicode.GetString(blob, start, end - start);
                if (path.Contains('\\') && path.Length > 4) return path;
            }
        }
        catch { }
        return null;
    }
}
