using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans browser history and application caches for cryptocurrency payment artifacts
/// related to cheat purchases.
///
/// Cheat vendors exclusively accept cryptocurrency payments to maintain anonymity:
///   - Bitcoin (BTC), Ethereum (ETH), Monero (XMR), Litecoin (LTC)
///   - Crypto payment processors: CoinGate, NOWPayments, CoinPayments, Cryptomus
///   - Peer-to-peer exchanges: LocalBitcoins, Paxful
///
/// Ocean and detect.ac check crypto payment trails because:
///   - Browser history with crypto payment processor + cheat site in sequence = direct purchase
///   - Crypto wallet addresses in clipboard/downloads match known cheat vendor payment addresses
///   - MetaMask, Exodus, Electrum browser extensions and wallet files being present
///     alongside cheat indicators compounds the signal
///
/// Files scanned:
///   Chrome/Edge/Brave History SQLite (byte-grep for crypto/cheat combos)
///   Firefox places.sqlite
///   Crypto wallet directories in AppData
///   MetaMask extension data
/// </summary>
public sealed class CryptoPaymentCheatScanModule : IScanModule
{
    public string Name => "Krypto-Zahlung Cheat-Kauf Forensik Scan";
    public double Weight => 0.45;
    public int ParallelGroup => 4;

    private static readonly string[] CryptoCheatCombinedKeywords =
    {
        // Cheat sites that accept crypto (the combo of crypto + cheat domain in history)
        "gamesense", "onetap", "fatality", "aimware",
        "neverlose", "skeet.cc", "limeware", "ev0lve",
        "2take1", "kiddion", "cherax", "ozark", "stand.sh",
        "engineowning", "iniuria", "vapeflux",
        "elitepvpers", "unknowncheats",
        "pcileech", "memprocfs",
        // Crypto payment processor keywords (combined with cheat = purchase)
        "coingate", "coinpayments", "nowpayments", "cryptomus",
        "btcpay", "coinbase commerce",
        // Crypto addresses near cheat keywords (hard to detect without parsing,
        // so we look for known payment processor domain fragments)
        "checkout.coingate", "pay.coingate",
        "checkout.nowpayments",
        "localbitcoins", "paxful",
        // Monero (XMR) is the preferred currency for cheat purchases (privacy coin)
        "getmonero", "monerujo", "xmrig",   // XMR miner = suspicious on gaming PC
    };

    private static readonly string[] CryptoWalletDirs =
    {
        // MetaMask (Chrome extension data)
        @"Google\Chrome\User Data\Default\Extensions\nkbihfbeogaeaoehlefnkodbefgpgknn",
        @"Microsoft\Edge\User Data\Default\Extensions\ejbalbakoplchlghecdalmeeeajnimhm",
        @"BraveSoftware\Brave-Browser\User Data\Default\Extensions\nkbihfbeogaeaoehlefnkodbefgpgknn",
        // Exodus wallet
        "Exodus",
        // Electrum
        "Electrum",
        // Monero CLI wallet
        "Monero",
        // Ledger Live
        "Ledger Live",
    };

    private static readonly string[] BrowserHistoryFiles =
    {
        // Chromium family History SQLite files
        @"Google\Chrome\User Data\Default\History",
        @"BraveSoftware\Brave-Browser\User Data\Default\History",
        @"Microsoft\Edge\User Data\Default\History",
        @"Vivaldi\User Data\Default\History",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        string local   = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        // Scan browser History files (SQLite — byte-grep)
        foreach (string histPath in BrowserHistoryFiles)
        {
            ct.ThrowIfCancellationRequested();
            string fullPath = System.IO.Path.Combine(local, histPath);
            if (System.IO.File.Exists(fullPath))
                ScanBrowserHistory(ctx, fullPath, ct);
        }

        // Firefox places.sqlite
        string ffProfiles = System.IO.Path.Combine(roaming, "Mozilla", "Firefox", "Profiles");
        if (System.IO.Directory.Exists(ffProfiles))
        {
            try
            {
                foreach (string profile in System.IO.Directory.GetDirectories(ffProfiles))
                {
                    ct.ThrowIfCancellationRequested();
                    string places = System.IO.Path.Combine(profile, "places.sqlite");
                    if (System.IO.File.Exists(places))
                        ScanBrowserHistory(ctx, places, ct);
                }
            }
            catch { }
        }

        // Scan crypto wallet directories
        ScanCryptoWallets(ctx, local, roaming, ct);
    }

    private void ScanBrowserHistory(ScanContext ctx, string path, CancellationToken ct)
    {
        try
        {
            var info = new System.IO.FileInfo(path);
            if (info.Length == 0 || info.Length > 100 * 1024 * 1024) return;
            ctx.IncrementFiles();

            byte[] raw = System.IO.File.ReadAllBytes(path);
            string text = System.Text.Encoding.UTF8.GetString(raw).ToLowerInvariant();
            string fileName = System.IO.Path.GetFileName(path);

            foreach (string kw in CryptoCheatCombinedKeywords)
            {
                ct.ThrowIfCancellationRequested();
                if (!text.Contains(kw.ToLowerInvariant())) continue;

                int idx = text.IndexOf(kw.ToLowerInvariant(), StringComparison.Ordinal);
                int start = Math.Max(0, idx - 40);
                int end = Math.Min(text.Length, idx + kw.Length + 80);
                string snippet = text.Substring(start, end - start)
                                     .Replace('\0', ' ')
                                     .Replace('\n', ' ')
                                     .Trim();

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat/Krypto-Kaufindiz in Browser-History: '{kw}'",
                    Risk     = RiskLevel.High,
                    Location = path,
                    FileName = fileName,
                    Reason   = $"Browser-History '{fileName}' enthält '{kw}' — ein Indiz für " +
                               "Cheat-Kauf oder Krypto-Payment-Aktivität im Zusammenhang mit Cheat-" +
                               "Marktplätzen. Cheat-Anbieter akzeptieren ausschließlich Krypto für " +
                               "Anonymität. Ocean und detect.ac scannen Browser-History auf Kauf-Kombis.",
                    Detail   = $"Datei: {fileName} | Schlüsselwort: '{kw}' | Kontext: \"{snippet}\""
                });
                return; // one finding per file
            }
        }
        catch { }
    }

    private void ScanCryptoWallets(ScanContext ctx, string local, string roaming, CancellationToken ct)
    {
        foreach (string walletPath in CryptoWalletDirs)
        {
            ct.ThrowIfCancellationRequested();
            string fullPath = System.IO.Path.Combine(local, walletPath);
            if (!System.IO.Directory.Exists(fullPath))
            {
                fullPath = System.IO.Path.Combine(roaming, walletPath);
            }

            if (!System.IO.Directory.Exists(fullPath)) continue;

            string walletName = System.IO.Path.GetFileName(walletPath);
            // MetaMask extension dirs have the extension ID as name — label them properly
            if (walletPath.Contains("nkbihfbeogaeaoehlefnkodbefgpgknn") ||
                walletPath.Contains("ejbalbakoplchlghecdalmeeeajnimhm"))
                walletName = "MetaMask";

            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Krypto-Wallet auf Gaming-PC gefunden: {walletName}",
                Risk     = RiskLevel.Medium,
                Location = fullPath,
                FileName = walletName,
                Reason   = $"Krypto-Wallet '{walletName}' auf diesem Gaming-PC gefunden. " +
                           "Cryptocurrency-Wallets auf Gaming-PCs können auf Cheat-Käufe hinweisen, " +
                           "da Cheat-Anbieter ausschließlich Krypto akzeptieren. In Kombination mit " +
                           "anderen Cheat-Indikatoren ist dies ein starkes Signal.",
                Detail   = $"Wallet-Pfad: {fullPath} | Wallet-Name: {walletName}"
            });
        }
    }
}
