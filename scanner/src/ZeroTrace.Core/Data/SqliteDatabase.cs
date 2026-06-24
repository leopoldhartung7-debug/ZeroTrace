using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;
using Microsoft.Data.Sqlite;

namespace ZeroTrace.Core.Data;

/// <summary>
/// Owns the SQLite connection string, creates the schema on first run,
/// verifies integrity, and seeds the built-in heuristic indicators.
/// No network access is performed at any point.
/// </summary>
public sealed class SqliteDatabase
{
    public string ConnectionString { get; }
    public string Path { get; }

    public SqliteDatabase(string? path = null)
    {
        Path = path ?? KnownPaths.DatabasePath;
        ConnectionString = new SqliteConnectionStringBuilder
        {
            DataSource = Path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared
        }.ToString();
    }

    public SqliteConnection OpenConnection()
    {
        var conn = new SqliteConnection(ConnectionString);
        conn.Open();
        using (var pragma = conn.CreateCommand())
        {
            pragma.CommandText = "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;";
            pragma.ExecuteNonQuery();
        }
        return conn;
    }

    /// <summary>Creates tables if missing. Idempotent.</summary>
    public void EnsureCreated()
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = SchemaSql;
        cmd.ExecuteNonQuery();
    }

    /// <summary>Runs PRAGMA integrity_check; returns true if the database is sound.</summary>
    public bool VerifyIntegrity()
    {
        try
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "PRAGMA integrity_check;";
            var result = cmd.ExecuteScalar() as string;
            return string.Equals(result, "ok", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Seeds / upgrades the built-in heuristic indicators. A version number stored
    /// in the settings table is used so new indicators are pushed to existing
    /// installations on the next launch. Manual (user-added) indicators are never
    /// touched — only rows with source='builtin-heuristic' are replaced.
    /// </summary>
    public void SeedDefaultsIfEmpty()
    {
        const int CurrentVersion = 6;
        using var conn = OpenConnection();

        // Check stored seed version.
        int storedVersion = 0;
        using (var qv = conn.CreateCommand())
        {
            qv.CommandText = "SELECT value FROM settings WHERE key='builtin_indicator_version';";
            var res = qv.ExecuteScalar();
            if (res != null) int.TryParse(res.ToString(), out storedVersion);
        }
        if (storedVersion >= CurrentVersion) return;

        var seeds = new (IndicatorType type, string pattern, RiskLevel risk, string category, string desc)[]
        {
            // ── File-name keywords ────────────────────────────────────────────────
            (IndicatorType.FileNameKeyword, "injector",       RiskLevel.Medium,   "Injector",        "Dateiname enthaelt 'injector'."),
            (IndicatorType.FileNameKeyword, "loader",         RiskLevel.Low,      "Loader",          "Dateiname enthaelt 'loader'."),
            (IndicatorType.FileNameKeyword, "aimbot",         RiskLevel.High,     "Aimbot",          "Dateiname enthaelt 'aimbot'."),
            (IndicatorType.FileNameKeyword, "cheat",          RiskLevel.Medium,   "Generic",         "Dateiname enthaelt 'cheat'."),
            (IndicatorType.FileNameKeyword, "trainer",        RiskLevel.Low,      "Trainer",         "Dateiname enthaelt 'trainer'."),
            (IndicatorType.FileNameKeyword, "menyoo",         RiskLevel.Low,      "Mod Menu",        "Pfad enthaelt 'menyoo'."),
            (IndicatorType.FileNameKeyword, "executor",       RiskLevel.Medium,   "Executor",        "Dateiname enthaelt 'executor'."),
            (IndicatorType.FileNameKeyword, "spoofer",        RiskLevel.High,     "Spoofer",         "Dateiname enthaelt 'spoofer'."),
            (IndicatorType.FileNameKeyword, "dumper",         RiskLevel.Medium,   "Dumper",          "Dateiname enthaelt 'dumper'."),
            (IndicatorType.FileNameKeyword, "bypass",         RiskLevel.Low,      "Bypass",          "Dateiname enthaelt 'bypass'."),
            (IndicatorType.FileNameKeyword, "kdmapper",       RiskLevel.High,     "Manual-Mapper",   "Bekannter Treiber-Mapper."),
            (IndicatorType.FileNameKeyword, "manualmap",      RiskLevel.High,     "Manual-Mapper",   "Manuelles DLL/Treiber-Mapping."),
            (IndicatorType.FileNameKeyword, "dsefix",         RiskLevel.High,     "DSE-Bypass",      "Treiber-Signaturpruefung deaktivieren."),
            (IndicatorType.FileNameKeyword, "physmem",        RiskLevel.High,     "Kernel-Exploit",  "Physischer-Speicher-Treiber."),
            (IndicatorType.FileNameKeyword, "mhyprot",        RiskLevel.High,     "Vulnerable-Driver","Anfaelliger miHoYo-Treiber."),
            (IndicatorType.FileNameKeyword, "dbk64",          RiskLevel.High,     "Kernel-Treiber",  "Cheat-Engine-Kernel-Treiber."),
            // FiveM / GTA
            (IndicatorType.FileNameKeyword, "eulen",          RiskLevel.High,     "FiveM-Cheat",     "FiveM-Cheat 'Eulen'."),
            (IndicatorType.FileNameKeyword, "hammafia",       RiskLevel.High,     "FiveM-Cheat",     "FiveM-Cheat 'Hammafia'."),
            (IndicatorType.FileNameKeyword, "desudo",         RiskLevel.High,     "FiveM-Cheat",     "FiveM-Cheat 'Desudo'."),
            (IndicatorType.FileNameKeyword, "impaught",       RiskLevel.High,     "FiveM-Cheat",     "FiveM-Cheat 'Impaught'."),
            (IndicatorType.FileNameKeyword, "scarlet",        RiskLevel.Medium,   "FiveM-Cheat",     "FiveM-Cheat 'Scarlet'."),
            (IndicatorType.FileNameKeyword, "kiddion",        RiskLevel.High,     "GTA-Cheat",       "GTA-Cheat 'Kiddion'."),
            (IndicatorType.FileNameKeyword, "phantom-x",      RiskLevel.High,     "FiveM-Cheat",     "FiveM-Cheat 'Phantom-X'."),
            (IndicatorType.FileNameKeyword, "tsunami",        RiskLevel.High,     "FiveM-Cheat",     "FiveM-Cheat 'Tsunami'."),
            (IndicatorType.FileNameKeyword, "lynxcheat",      RiskLevel.High,     "FiveM-Cheat",     "FiveM-Cheat 'Lynx'."),
            (IndicatorType.FileNameKeyword, "ozark",          RiskLevel.High,     "FiveM-Cheat",     "FiveM-Cheat 'Ozark'."),
            (IndicatorType.FileNameKeyword, "rxce",           RiskLevel.High,     "FiveM-Cheat",     "FiveM-Cheat 'RxCE'."),
            (IndicatorType.FileNameKeyword, "nexusmenu",      RiskLevel.High,     "FiveM-Cheat",     "FiveM-Cheat 'Nexus Menu'."),
            (IndicatorType.FileNameKeyword, "2take1",         RiskLevel.High,     "GTA-Cheat",       "GTA-Cheat '2Take1'."),
            (IndicatorType.FileNameKeyword, "cherax",         RiskLevel.High,     "GTA-Cheat",       "GTA-Mod-Menu 'Cherax'."),
            (IndicatorType.FileNameKeyword, "midnight",       RiskLevel.Medium,   "GTA-Cheat",       "'Midnight' GTA-Mod-Menu."),
            (IndicatorType.FileNameKeyword, "spacedust",      RiskLevel.High,     "GTA-Cheat",       "GTA-Cheat 'SpaceDust'."),
            (IndicatorType.FileNameKeyword, "modest",         RiskLevel.High,     "GTA-Cheat",       "GTA-'Modest Menu'."),
            (IndicatorType.FileNameKeyword, "skulking",       RiskLevel.High,     "GTA-Cheat",       "GTA-Cheat 'Skulking'."),
            // CS2 / CSGO
            (IndicatorType.FileNameKeyword, "aimware",        RiskLevel.Critical, "CS2-Cheat",       "CS2-Cheat 'Aimware'."),
            (IndicatorType.FileNameKeyword, "fecurity",       RiskLevel.Critical, "CS2-Cheat",       "CS2-Cheat 'Fecurity'."),
            (IndicatorType.FileNameKeyword, "onetap",         RiskLevel.Critical, "CS2-Cheat",       "CS2-Cheat 'Onetap'."),
            (IndicatorType.FileNameKeyword, "neverlose",      RiskLevel.Critical, "CS2-Cheat",       "CS2-Cheat 'Neverlose'."),
            (IndicatorType.FileNameKeyword, "gamesense",      RiskLevel.Critical, "CS2-Cheat",       "CS2-Cheat 'Gamesense'."),
            (IndicatorType.FileNameKeyword, "fatality",       RiskLevel.High,     "CS2-Cheat",       "CS2-Cheat 'Fatality'."),
            (IndicatorType.FileNameKeyword, "nixware",        RiskLevel.High,     "CS2-Cheat",       "CS2-Cheat 'NixWare'."),
            (IndicatorType.FileNameKeyword, "lumina",         RiskLevel.High,     "CS2-Cheat",       "CS2-Cheat 'Lumina'."),
            (IndicatorType.FileNameKeyword, "skycheats",      RiskLevel.High,     "Cheat-Tool",      "'SkyCheats'-Token."),
            // Minecraft
            (IndicatorType.FileNameKeyword, "liquidbounce",   RiskLevel.High,     "MC-Cheat",        "MC-Cheat 'LiquidBounce'."),
            (IndicatorType.FileNameKeyword, "wurst",          RiskLevel.High,     "MC-Cheat",        "MC-Cheat 'Wurst'."),
            (IndicatorType.FileNameKeyword, "aristois",       RiskLevel.High,     "MC-Cheat",        "MC-Cheat 'Aristois'."),
            (IndicatorType.FileNameKeyword, "vape",           RiskLevel.High,     "MC-Cheat",        "MC-Ghost-Client 'Vape'."),
            (IndicatorType.FileNameKeyword, "sigmaclient",    RiskLevel.High,     "MC-Cheat",        "MC-Cheat 'Sigma'."),
            (IndicatorType.FileNameKeyword, "novoline",       RiskLevel.High,     "MC-Cheat",        "MC-Cheat 'Novoline'."),
            (IndicatorType.FileNameKeyword, "meteorclient",   RiskLevel.High,     "MC-Cheat",        "MC-Cheat 'Meteor'."),
            (IndicatorType.FileNameKeyword, "killaura",       RiskLevel.High,     "MC-Cheat",        "KillAura-Hack."),
            (IndicatorType.FileNameKeyword, "autoclicker",    RiskLevel.Medium,   "Autoclicker",     "Autoclicker."),
            // Injectors
            (IndicatorType.FileNameKeyword, "xenos",          RiskLevel.High,     "Injector",        "Xenos-Injector."),
            (IndicatorType.FileNameKeyword, "extremeinjector",RiskLevel.High,     "Injector",        "Extreme Injector."),
            (IndicatorType.FileNameKeyword, "winject",        RiskLevel.High,     "Injector",        "WinInject-Injector."),
            (IndicatorType.FileNameKeyword, "netinject",      RiskLevel.High,     "Injector",        "NetInject-Injector."),
            (IndicatorType.FileNameKeyword, "reclass",        RiskLevel.High,     "Debugger",        "ReClass.NET-Reverse-Tool."),
            (IndicatorType.FileNameKeyword, "scylla",         RiskLevel.High,     "Dumper",          "Scylla-Dumper."),
            (IndicatorType.FileNameKeyword, "x64dbg",         RiskLevel.High,     "Debugger",        "x64dbg-Debugger."),
            (IndicatorType.FileNameKeyword, "x32dbg",         RiskLevel.High,     "Debugger",        "x32dbg-Debugger."),
            (IndicatorType.FileNameKeyword, "cheatengine",    RiskLevel.High,     "Debugger",        "Cheat Engine."),
            // Spoofers
            (IndicatorType.FileNameKeyword, "hwid_reset",     RiskLevel.High,     "Spoofer",         "HWID-Reset-Werkzeug."),
            (IndicatorType.FileNameKeyword, "serial_spoof",   RiskLevel.High,     "Spoofer",         "Seriennummer-Spoofer."),
            (IndicatorType.FileNameKeyword, "disk_serial",    RiskLevel.High,     "Spoofer",         "Festplatten-SN-Spoofer."),
            (IndicatorType.FileNameKeyword, "bios_spoof",     RiskLevel.High,     "Spoofer",         "BIOS-Spoofer."),
            (IndicatorType.FileNameKeyword, "macchanger",     RiskLevel.Medium,   "Spoofer",         "MAC-Adress-Changer."),
            (IndicatorType.FileNameKeyword, "uuid_changer",   RiskLevel.High,     "Spoofer",         "UUID/SMBIOS-Changer."),
            (IndicatorType.FileNameKeyword, "volumeid",       RiskLevel.High,     "Spoofer",         "VolumeID-Werkzeug (aendert Laufwerk-SN)."),
            (IndicatorType.FileNameKeyword, "polargen",       RiskLevel.High,     "Spoofer",         "Polargen-HWID-Spoofer."),
            // BYOVD keywords
            (IndicatorType.FileNameKeyword, "gdrv",           RiskLevel.High,     "BYOVD-Treiber",   "Gigabyte-GDRV-Treiber (BYOVD)."),
            (IndicatorType.FileNameKeyword, "rtcore",         RiskLevel.High,     "BYOVD-Treiber",   "RTCore-MSI-Treiber (BYOVD)."),
            (IndicatorType.FileNameKeyword, "winring",        RiskLevel.High,     "BYOVD-Treiber",   "WinRing0-Treiber (BYOVD)."),
            (IndicatorType.FileNameKeyword, "kprocesshacker", RiskLevel.Critical, "Kernel-Treiber",  "Process-Hacker-Kernel-Treiber."),

            // ── Exact file names ──────────────────────────────────────────────────
            (IndicatorType.FileName, "capcom.sys",            RiskLevel.Critical, "Kernel-Exploit",  "Capcom-Treiber – BYOVD-Exploit."),
            (IndicatorType.FileName, "mhyprot2.sys",          RiskLevel.Critical, "Vulnerable-Driver","Anfaelliger miHoYo-Treiber."),
            (IndicatorType.FileName, "dbk64.sys",             RiskLevel.Critical, "Kernel-Treiber",  "Cheat-Engine-Kernel-Treiber."),
            (IndicatorType.FileName, "gdrv.sys",              RiskLevel.Critical, "BYOVD-Treiber",   "Gigabyte-Treiber (BYOVD)."),
            (IndicatorType.FileName, "rtcore64.sys",          RiskLevel.Critical, "BYOVD-Treiber",   "MSI-Afterburner-Treiber (BYOVD)."),
            (IndicatorType.FileName, "rtcore32.sys",          RiskLevel.Critical, "BYOVD-Treiber",   "MSI-Afterburner-Treiber x32 (BYOVD)."),
            (IndicatorType.FileName, "winring0x64.sys",       RiskLevel.Critical, "BYOVD-Treiber",   "WinRing0-Treiber x64 (BYOVD)."),
            (IndicatorType.FileName, "winring0.sys",          RiskLevel.Critical, "BYOVD-Treiber",   "WinRing0-Treiber (BYOVD)."),
            (IndicatorType.FileName, "nicm.sys",              RiskLevel.Critical, "BYOVD-Treiber",   "NICM-BYOVD-Exploit-Treiber."),
            (IndicatorType.FileName, "kprocesshacker.sys",    RiskLevel.Critical, "Kernel-Treiber",  "Process-Hacker-Kernel-Treiber."),
            (IndicatorType.FileName, "speedfan.sys",          RiskLevel.High,     "BYOVD-Treiber",   "Speedfan-Treiber (fuer BYOVD missbraucht)."),
            (IndicatorType.FileName, "aswsp.sys",             RiskLevel.High,     "BYOVD-Treiber",   "Alter Avast-Treiber (fuer BYOVD missbraucht)."),

            // ── Content strings ───────────────────────────────────────────────────
            // Cheat watermarks
            (IndicatorType.ContentString, "redengine",        RiskLevel.High,     "Cheat-Signatur",  "FiveM-Cheat 'RedENGINE' im Datei-Inhalt."),
            (IndicatorType.ContentString, "skript.gg",        RiskLevel.High,     "Cheat-Signatur",  "skript.gg im Datei-Inhalt."),
            (IndicatorType.ContentString, "hxcheats",         RiskLevel.High,     "Cheat-Signatur",  "hxcheats im Datei-Inhalt."),
            (IndicatorType.ContentString, "cherax",           RiskLevel.High,     "Cheat-Signatur",  "Cherax im Datei-Inhalt."),
            (IndicatorType.ContentString, "hwidspoofer",      RiskLevel.High,     "Spoofer",         "HWID-Spoofer-Token im Datei-Inhalt."),
            (IndicatorType.ContentString, "tsunami.gg",       RiskLevel.High,     "Cheat-Signatur",  "tsunami.gg im Datei-Inhalt."),
            (IndicatorType.ContentString, "eulen",            RiskLevel.High,     "FiveM-Cheat",     "Eulen im Datei-Inhalt."),
            (IndicatorType.ContentString, "hammafia",         RiskLevel.High,     "FiveM-Cheat",     "Hammafia im Datei-Inhalt."),
            (IndicatorType.ContentString, "desudo",           RiskLevel.High,     "FiveM-Cheat",     "Desudo im Datei-Inhalt."),
            (IndicatorType.ContentString, "impaught",         RiskLevel.High,     "FiveM-Cheat",     "Impaught im Datei-Inhalt."),
            (IndicatorType.ContentString, "kiddion",          RiskLevel.High,     "GTA-Cheat",       "Kiddion im Datei-Inhalt."),
            (IndicatorType.ContentString, "phantom-x",        RiskLevel.High,     "FiveM-Cheat",     "Phantom-X im Datei-Inhalt."),
            (IndicatorType.ContentString, "2take1",           RiskLevel.High,     "GTA-Cheat",       "2Take1 im Datei-Inhalt."),
            (IndicatorType.ContentString, "onetap.su",        RiskLevel.High,     "CS2-Cheat",       "onetap.su im Datei-Inhalt."),
            (IndicatorType.ContentString, "neverlose.cc",     RiskLevel.High,     "CS2-Cheat",       "neverlose.cc im Datei-Inhalt."),
            (IndicatorType.ContentString, "gamesense.pub",    RiskLevel.High,     "CS2-Cheat",       "gamesense.pub im Datei-Inhalt."),
            (IndicatorType.ContentString, "aimware.net",      RiskLevel.High,     "CS2-Cheat",       "aimware.net im Datei-Inhalt."),
            (IndicatorType.ContentString, "fecurity",         RiskLevel.High,     "CS2-Cheat",       "fecurity im Datei-Inhalt."),
            (IndicatorType.ContentString, "fatality.win",     RiskLevel.High,     "CS2-Cheat",       "fatality.win im Datei-Inhalt."),
            (IndicatorType.ContentString, "ozark",            RiskLevel.High,     "FiveM-Cheat",     "Ozark im Datei-Inhalt."),
            (IndicatorType.ContentString, "rxce",             RiskLevel.High,     "FiveM-Cheat",     "RxCE im Datei-Inhalt."),
            // Aimbot / ESP
            (IndicatorType.ContentString, "aimbot",           RiskLevel.High,     "Aimbot",          "'aimbot' im Datei-Inhalt."),
            (IndicatorType.ContentString, "triggerbot",       RiskLevel.High,     "Aimbot",          "'triggerbot' im Datei-Inhalt."),
            (IndicatorType.ContentString, "silentaim",        RiskLevel.High,     "Aimbot",          "'silentaim' im Datei-Inhalt."),
            (IndicatorType.ContentString, "trigger bot",      RiskLevel.High,     "Aimbot",          "'trigger bot' im Datei-Inhalt."),
            (IndicatorType.ContentString, "magic bullet",     RiskLevel.High,     "Aimbot",          "'magic bullet' im Datei-Inhalt."),
            (IndicatorType.ContentString, "bone aim",         RiskLevel.High,     "Aimbot",          "'bone aim' im Datei-Inhalt."),
            (IndicatorType.ContentString, "head aim",         RiskLevel.High,     "Aimbot",          "'head aim' im Datei-Inhalt."),
            (IndicatorType.ContentString, "fov circle",       RiskLevel.Medium,   "Aimbot",          "'fov circle' im Datei-Inhalt."),
            (IndicatorType.ContentString, "recoil control",   RiskLevel.Medium,   "Recoil",          "'recoil control' im Datei-Inhalt."),
            (IndicatorType.ContentString, "esp_render",       RiskLevel.Medium,   "ESP/Wallhack",    "ESP-Render-Token im Datei-Inhalt."),
            (IndicatorType.ContentString, "wallhack",         RiskLevel.Medium,   "ESP/Wallhack",    "'wallhack' im Datei-Inhalt."),
            (IndicatorType.ContentString, "player esp",       RiskLevel.High,     "ESP/Cheat",       "'player esp' im Datei-Inhalt."),
            (IndicatorType.ContentString, "entity esp",       RiskLevel.High,     "ESP/Cheat",       "'entity esp' im Datei-Inhalt."),
            (IndicatorType.ContentString, "esp draw",         RiskLevel.High,     "ESP/Cheat",       "'esp draw' im Datei-Inhalt."),
            // Cheat UI / generic
            (IndicatorType.ContentString, "norecoil",         RiskLevel.Medium,   "Recoil",          "'norecoil' im Datei-Inhalt."),
            (IndicatorType.ContentString, "godmode",          RiskLevel.Medium,   "Generic",         "'godmode' im Datei-Inhalt."),
            (IndicatorType.ContentString, "speedhack",        RiskLevel.Medium,   "Speed-Hack",      "'speedhack' im Datei-Inhalt."),
            (IndicatorType.ContentString, "bhop",             RiskLevel.Medium,   "Movement-Hack",   "'bhop' im Datei-Inhalt."),
            (IndicatorType.ContentString, "noclip",           RiskLevel.Medium,   "Movement-Hack",   "'noclip' im Datei-Inhalt."),
            (IndicatorType.ContentString, "esp menu",         RiskLevel.Medium,   "Cheat-Menue",     "'esp menu' im Datei-Inhalt."),
            (IndicatorType.ContentString, "fly hack",         RiskLevel.Medium,   "Movement-Hack",   "'fly hack' im Datei-Inhalt."),
            (IndicatorType.ContentString, "kill aura",        RiskLevel.High,     "MC-Cheat",        "'kill aura' im Datei-Inhalt."),
            (IndicatorType.ContentString, "unknowncheats",    RiskLevel.Medium,   "Generic",         "unknowncheats-Forum-Token im Datei-Inhalt."),
            (IndicatorType.ContentString, "bypass anticheat", RiskLevel.High,     "AC-Bypass",       "AC-Bypass-Token im Datei-Inhalt."),
            (IndicatorType.ContentString, "cheat engine",     RiskLevel.High,     "Debugger",        "'cheat engine' im Datei-Inhalt."),
            // Injection techniques
            (IndicatorType.ContentString, "dll inject",       RiskLevel.High,     "Injector",        "'dll inject' im Datei-Inhalt."),
            (IndicatorType.ContentString, "loadlibraryw",     RiskLevel.Medium,   "Injector",        "LoadLibraryW-Injektionstechnik im Datei-Inhalt."),
            (IndicatorType.ContentString, "writeprocessmemory",RiskLevel.Medium,  "Injector",        "WriteProcessMemory im Datei-Inhalt."),
            (IndicatorType.ContentString, "createremotethread",RiskLevel.High,    "Injector",        "CreateRemoteThread im Datei-Inhalt."),
            (IndicatorType.ContentString, "ntmapviewofsection",RiskLevel.High,    "Injector",        "NtMapViewOfSection (manuel Map) im Datei-Inhalt."),
            (IndicatorType.ContentString, "process_hollow",   RiskLevel.High,     "Injector",        "Process-Hollowing im Datei-Inhalt."),
            (IndicatorType.ContentString, "manual map",       RiskLevel.Medium,   "Manual-Mapper",   "'manual map' im Datei-Inhalt."),
            // HWID spoofer tokens
            (IndicatorType.ContentString, "hwid spoof",       RiskLevel.High,     "HWID-Spoofer",    "'hwid spoof' im Datei-Inhalt."),
            (IndicatorType.ContentString, "vac bypass",       RiskLevel.High,     "AC-Bypass",       "'vac bypass' im Datei-Inhalt."),
            (IndicatorType.ContentString, "hwid bypassed",    RiskLevel.High,     "Spoofer",         "'hwid bypassed' im Datei-Inhalt."),
            (IndicatorType.ContentString, "hwid changed",     RiskLevel.High,     "Spoofer",         "'hwid changed' im Datei-Inhalt."),
            (IndicatorType.ContentString, "spoofer_main",     RiskLevel.High,     "Spoofer",         "'spoofer_main'-Marker im Datei-Inhalt."),
            // BYOVD / kernel
            (IndicatorType.ContentString, "byovd",            RiskLevel.Critical, "BYOVD",           "BYOVD-Token im Datei-Inhalt."),
            (IndicatorType.ContentString, "dse bypass",       RiskLevel.Critical, "DSE-Bypass",      "DSE-Bypass im Datei-Inhalt."),
            (IndicatorType.ContentString, "kdmapper",         RiskLevel.Critical, "Manual-Mapper",   "KDMapper-Token im Datei-Inhalt."),
            (IndicatorType.ContentString, "capcom exploit",   RiskLevel.Critical, "Kernel-Exploit",  "Capcom-Exploit im Datei-Inhalt."),
            (IndicatorType.ContentString, "radmem",           RiskLevel.High,     "Kernel-Tool",     "RadMem-Tool im Datei-Inhalt."),

            // ── URL domain keywords ───────────────────────────────────────────────
            (IndicatorType.UrlDomainKeyword, "redengine",     RiskLevel.High,   "Cheat-Shop",       "RedENGINE-Domain (FiveM)."),
            (IndicatorType.UrlDomainKeyword, "skript.gg",     RiskLevel.High,   "Cheat-Shop",       "skript.gg (FiveM)."),
            (IndicatorType.UrlDomainKeyword, "eulen",         RiskLevel.High,   "Cheat-Shop",       "Eulen-Domain (FiveM)."),
            (IndicatorType.UrlDomainKeyword, "hxcheats",      RiskLevel.High,   "Cheat-Shop",       "Hx-Cheats-Domain."),
            (IndicatorType.UrlDomainKeyword, "cherax",        RiskLevel.High,   "Cheat-Shop",       "Cherax-Domain (GTA)."),
            (IndicatorType.UrlDomainKeyword, "hammafia",      RiskLevel.High,   "Cheat-Shop",       "Hammafia-Domain (FiveM)."),
            (IndicatorType.UrlDomainKeyword, "desudo",        RiskLevel.High,   "Cheat-Shop",       "Desudo-Domain (FiveM)."),
            (IndicatorType.UrlDomainKeyword, "eulen.ac",      RiskLevel.High,   "Cheat-Shop",       "eulen.ac (FiveM)."),
            (IndicatorType.UrlDomainKeyword, "impaught",      RiskLevel.High,   "Cheat-Shop",       "Impaught-Domain (FiveM)."),
            (IndicatorType.UrlDomainKeyword, "gamepay",       RiskLevel.Medium, "Cheat-Shop",       "GamePay-Cheat-Domain."),
            (IndicatorType.UrlDomainKeyword, "phantom-x",     RiskLevel.High,   "Cheat-Shop",       "Phantom-X-Domain."),
            (IndicatorType.UrlDomainKeyword, "lynxcheats",    RiskLevel.High,   "Cheat-Shop",       "LynxCheats-Domain."),
            (IndicatorType.UrlDomainKeyword, "tsunami.gg",    RiskLevel.High,   "Cheat-Shop",       "tsunami.gg (FiveM)."),
            (IndicatorType.UrlDomainKeyword, "ozarkmenu",     RiskLevel.High,   "Cheat-Shop",       "Ozark-Domain (FiveM)."),
            (IndicatorType.UrlDomainKeyword, "rxce.gg",       RiskLevel.High,   "Cheat-Shop",       "rxce.gg (FiveM)."),
            (IndicatorType.UrlDomainKeyword, "nexusmenu",     RiskLevel.High,   "Cheat-Shop",       "Nexus-Menu-Domain (FiveM)."),
            (IndicatorType.UrlDomainKeyword, "aimware.net",   RiskLevel.Critical,"CS2-Cheat-Shop",  "aimware.net (CS2)."),
            (IndicatorType.UrlDomainKeyword, "onetap.su",     RiskLevel.Critical,"CS2-Cheat-Shop",  "onetap.su (CS2)."),
            (IndicatorType.UrlDomainKeyword, "neverlose.cc",  RiskLevel.Critical,"CS2-Cheat-Shop",  "neverlose.cc (CS2)."),
            (IndicatorType.UrlDomainKeyword, "gamesense.pub", RiskLevel.Critical,"CS2-Cheat-Shop",  "gamesense.pub (CS2)."),
            (IndicatorType.UrlDomainKeyword, "fatality.win",  RiskLevel.High,   "CS2-Cheat-Shop",   "fatality.win (CS2)."),
            (IndicatorType.UrlDomainKeyword, "vape.gg",       RiskLevel.High,   "MC-Cheat-Shop",    "vape.gg (Minecraft)."),
            (IndicatorType.UrlDomainKeyword, "liquidbounce.net",RiskLevel.High, "MC-Cheat-Shop",    "liquidbounce.net (Minecraft)."),
            (IndicatorType.UrlDomainKeyword, "wurstclient.net",RiskLevel.High,  "MC-Cheat-Shop",    "wurstclient.net (Minecraft)."),
            (IndicatorType.UrlDomainKeyword, "unknowncheats", RiskLevel.Medium, "Cheat-Forum",      "unknowncheats-Forum."),
            (IndicatorType.UrlDomainKeyword, "elitepvpers",   RiskLevel.Low,    "Cheat-Forum",      "elitepvpers-Forum."),
            (IndicatorType.UrlDomainKeyword, "mpgh.net",      RiskLevel.Medium, "Cheat-Forum",      "mpgh.net (Multi-Hack-Forum)."),
            (IndicatorType.UrlDomainKeyword, "hackforums",    RiskLevel.Medium, "Cheat-Forum",      "hackforums.net."),
            (IndicatorType.UrlDomainKeyword, "fearless-cheat",RiskLevel.High,   "Cheat-Shop",       "fearless-cheat.net."),
            (IndicatorType.UrlDomainKeyword, "guidedhacking", RiskLevel.Medium, "Cheat-Forum",      "guidedhacking.com."),
            (IndicatorType.UrlDomainKeyword, "cheating-network",RiskLevel.High, "Cheat-Forum",      "cheating-network.de."),
            (IndicatorType.UrlDomainKeyword, "sellix.io",     RiskLevel.Medium, "Cheat-Marktplatz", "sellix.io (haeufig Cheat-Verkauf)."),
            (IndicatorType.UrlDomainKeyword, "plati.ru",      RiskLevel.Medium, "Cheat-Marktplatz", "plati.ru (russische Plattform)."),
            (IndicatorType.UrlDomainKeyword, "2take1.menu",   RiskLevel.High,   "GTA-Cheat-Shop",   "2take1.menu (GTA)."),

            // ── Process names ─────────────────────────────────────────────────────
            (IndicatorType.ProcessName, "processhacker",        RiskLevel.Medium,  "Tool",      "Process Hacker."),
            (IndicatorType.ProcessName, "x64dbg",               RiskLevel.High,    "Debugger",  "x64dbg-Debugger."),
            (IndicatorType.ProcessName, "x32dbg",               RiskLevel.High,    "Debugger",  "x32dbg-Debugger."),
            (IndicatorType.ProcessName, "windbg",               RiskLevel.High,    "Debugger",  "WinDbg-Debugger."),
            (IndicatorType.ProcessName, "cheatengine-x86_64",   RiskLevel.High,    "Debugger",  "Cheat Engine x64."),
            (IndicatorType.ProcessName, "cheatengine-i386",     RiskLevel.High,    "Debugger",  "Cheat Engine x86."),
            (IndicatorType.ProcessName, "reclass.net",          RiskLevel.High,    "Debugger",  "ReClass.NET."),
            (IndicatorType.ProcessName, "scylla_x64",           RiskLevel.High,    "Dumper",    "Scylla x64."),
            (IndicatorType.ProcessName, "extremeinjector",      RiskLevel.High,    "Injector",  "Extreme Injector."),
            (IndicatorType.ProcessName, "xenos64",              RiskLevel.High,    "Injector",  "Xenos Injector x64."),
            (IndicatorType.ProcessName, "xenos32",              RiskLevel.High,    "Injector",  "Xenos Injector x32."),
            (IndicatorType.ProcessName, "procexp64",            RiskLevel.Medium,  "Tool",      "Process Explorer x64."),
            (IndicatorType.ProcessName, "procexp",              RiskLevel.Medium,  "Tool",      "Process Explorer."),
            (IndicatorType.ProcessName, "procmon",              RiskLevel.Medium,  "Tool",      "Process Monitor."),
            (IndicatorType.ProcessName, "wireshark",            RiskLevel.Medium,  "Sniffer",   "Wireshark."),
            (IndicatorType.ProcessName, "fiddler",              RiskLevel.Medium,  "Proxy",     "Fiddler-Proxy."),
            (IndicatorType.ProcessName, "dumpcap",              RiskLevel.Medium,  "Sniffer",   "WireShark DumpCap."),
            (IndicatorType.ProcessName, "2take1",               RiskLevel.Critical,"GTA-Cheat", "2Take1-Prozess."),
            (IndicatorType.ProcessName, "kiddionsmm",           RiskLevel.Critical,"GTA-Cheat", "Kiddion Modest Menu."),

            // ── Version 3: Private / Unknown Cheat Detection ─────────────────────

            // File-name keywords for private / home-coded cheats
            (IndicatorType.FileNameKeyword, "aimlock",          RiskLevel.High,   "Aimbot",         "Dateiname enthaelt 'aimlock'."),
            (IndicatorType.FileNameKeyword, "autoaim",          RiskLevel.High,   "Aimbot",         "Dateiname enthaelt 'autoaim'."),
            (IndicatorType.FileNameKeyword, "ragebot",          RiskLevel.High,   "Aimbot",         "Dateiname enthaelt 'ragebot' (Rage-Aimbot)."),
            (IndicatorType.FileNameKeyword, "legitbot",         RiskLevel.High,   "Aimbot",         "Dateiname enthaelt 'legitbot'."),
            (IndicatorType.FileNameKeyword, "triggerbot",       RiskLevel.High,   "Aimbot",         "Dateiname enthaelt 'triggerbot'."),
            (IndicatorType.FileNameKeyword, "spinbot",          RiskLevel.High,   "Anti-Aim",       "Dateiname enthaelt 'spinbot'."),
            (IndicatorType.FileNameKeyword, "antiaim",          RiskLevel.High,   "Anti-Aim",       "Dateiname enthaelt 'antiaim'."),
            (IndicatorType.FileNameKeyword, "wallhack",         RiskLevel.High,   "ESP/Wallhack",   "Dateiname enthaelt 'wallhack'."),
            (IndicatorType.FileNameKeyword, "maphack",          RiskLevel.High,   "Map-Hack",       "Dateiname enthaelt 'maphack'."),
            (IndicatorType.FileNameKeyword, "hackdll",          RiskLevel.High,   "Cheat-DLL",      "Dateiname enthaelt 'hackdll'."),
            (IndicatorType.FileNameKeyword, "cheatdll",         RiskLevel.High,   "Cheat-DLL",      "Dateiname enthaelt 'cheatdll'."),
            (IndicatorType.FileNameKeyword, "privcheat",        RiskLevel.High,   "Privater-Cheat", "Dateiname enthaelt 'privcheat' (privater Cheat)."),
            (IndicatorType.FileNameKeyword, "internalcheat",    RiskLevel.High,   "Cheat",          "Dateiname enthaelt 'internalcheat'."),
            (IndicatorType.FileNameKeyword, "externalcheat",    RiskLevel.High,   "Cheat",          "Dateiname enthaelt 'externalcheat'."),
            (IndicatorType.FileNameKeyword, "vmprotect",        RiskLevel.Medium, "Packer",         "VMProtect-Packer (haeufig bei Cheat-Schutz verwendet)."),
            (IndicatorType.FileNameKeyword, "themida",          RiskLevel.Medium, "Packer",         "Themida-Packer (haeufig bei Cheat-Schutz verwendet)."),
            (IndicatorType.FileNameKeyword, "hacktools",        RiskLevel.High,   "Cheat-Tool",     "Dateiname enthaelt 'hacktools'."),
            (IndicatorType.FileNameKeyword, "skinchanger",      RiskLevel.Medium, "Skin-Hack",      "Dateiname enthaelt 'skinchanger'."),
            (IndicatorType.FileNameKeyword, "nosteam",          RiskLevel.Medium, "Raubkopie",      "NoSteam-Bypass (Steam-Authentisierung umgehen)."),
            (IndicatorType.FileNameKeyword, "steamcrack",       RiskLevel.High,   "Raubkopie",      "Steam-Cracker im Dateinamen."),
            (IndicatorType.FileNameKeyword, "eacbypass",        RiskLevel.Critical,"AC-Bypass",     "EAC-Bypass-Tool."),
            (IndicatorType.FileNameKeyword, "bebypass",         RiskLevel.Critical,"AC-Bypass",     "BattlEye-Bypass-Tool."),

            // Content strings: hooking / overlay frameworks used in nearly every cheat
            (IndicatorType.ContentString, "kiero",              RiskLevel.High,   "D3D-Hook",       "Kiero-D3D11-Hook-Bibliothek im Datei-Inhalt (fast nur in Cheats verwendet)."),
            (IndicatorType.ContentString, "minhook",            RiskLevel.Medium, "Hook-Framework", "MinHook-Bibliothek im Datei-Inhalt (Hooking-Framework)."),
            (IndicatorType.ContentString, "present hook",       RiskLevel.High,   "D3D-Hook",       "'present hook' – Direct3D Present()-Hook (Cheat-Overlay)."),
            (IndicatorType.ContentString, "vtable hook",        RiskLevel.High,   "Hook",           "'vtable hook' – virtuelle Tabelle gehooked (Cheat-Technik)."),
            (IndicatorType.ContentString, "d3d11 hook",         RiskLevel.High,   "D3D-Hook",       "Direct3D-11-Hook im Datei-Inhalt."),
            (IndicatorType.ContentString, "dx11hook",           RiskLevel.High,   "D3D-Hook",       "DX11-Hook-String im Datei-Inhalt."),

            // Anti-detection strings
            (IndicatorType.ContentString, "anti obs",           RiskLevel.High,   "Anti-Detection", "'anti obs' – OBS-Erkennung umgehen."),
            (IndicatorType.ContentString, "anti screenshot",    RiskLevel.High,   "Anti-Detection", "Screenshot-Erkennung umgehen."),
            (IndicatorType.ContentString, "anti debug",         RiskLevel.High,   "Anti-Detection", "Anti-Debugger-Technik im Datei-Inhalt."),
            (IndicatorType.ContentString, "isdebuggerpresent",  RiskLevel.Medium, "Anti-Debug",     "IsDebuggerPresent-Aufruf (Anti-Debug-Check)."),
            (IndicatorType.ContentString, "checkremotedebugger",RiskLevel.Medium, "Anti-Debug",     "CheckRemoteDebuggerPresent (Anti-Debug)."),

            // Anti-cheat bypass strings
            (IndicatorType.ContentString, "eac bypass",         RiskLevel.Critical,"AC-Bypass",     "Easy Anti-Cheat Bypass im Datei-Inhalt."),
            (IndicatorType.ContentString, "battleye bypass",    RiskLevel.Critical,"AC-Bypass",     "BattlEye-Bypass im Datei-Inhalt."),
            (IndicatorType.ContentString, "faceit bypass",      RiskLevel.Critical,"AC-Bypass",     "Faceit-Bypass im Datei-Inhalt."),
            (IndicatorType.ContentString, "anticheat bypass",   RiskLevel.Critical,"AC-Bypass",     "Generischer Anti-Cheat-Bypass im Datei-Inhalt."),
            (IndicatorType.ContentString, "vac proof",          RiskLevel.High,    "AC-Bypass",     "'vac proof' – VAC-Umgehungsbehauptung im Datei-Inhalt."),
            (IndicatorType.ContentString, "be bypass",          RiskLevel.Critical,"AC-Bypass",     "BattlEye-Bypass (be bypass) im Datei-Inhalt."),

            // Aimbot / ESP strings specific to private/self-coded cheats
            (IndicatorType.ContentString, "ragebot",            RiskLevel.High,   "Aimbot",         "'ragebot' – Rage-Aimbot-Modul im Datei-Inhalt."),
            (IndicatorType.ContentString, "legitbot",           RiskLevel.High,   "Aimbot",         "'legitbot' – Legit-Aimbot-Modul im Datei-Inhalt."),
            (IndicatorType.ContentString, "spinbot",            RiskLevel.High,   "Anti-Aim",       "'spinbot' – Spinbot/Anti-Aim im Datei-Inhalt."),
            (IndicatorType.ContentString, "anti aim",           RiskLevel.High,   "Anti-Aim",       "'anti aim' – Anti-Aim-Feature im Datei-Inhalt."),
            (IndicatorType.ContentString, "aim resolver",       RiskLevel.High,   "Anti-Aim",       "Aim-Resolver fuer Anti-Aim im Datei-Inhalt."),
            (IndicatorType.ContentString, "no spread",          RiskLevel.High,   "Aimbot",         "'no spread' – Streuung entfernt im Datei-Inhalt."),
            (IndicatorType.ContentString, "no recoil",          RiskLevel.High,   "Recoil",         "'no recoil' im Datei-Inhalt."),
            (IndicatorType.ContentString, "no flash",           RiskLevel.Medium, "Visual-Hack",    "'no flash' – Flash-Entfernung im Datei-Inhalt."),
            (IndicatorType.ContentString, "aim fov",            RiskLevel.High,   "Aimbot",         "'aim fov' – Aimbot-FOV im Datei-Inhalt."),
            (IndicatorType.ContentString, "aim step",           RiskLevel.High,   "Aimbot",         "'aim step' – Aimbot-Schrittweite im Datei-Inhalt."),
            (IndicatorType.ContentString, "aim assist",         RiskLevel.High,   "Aimbot",         "'aim assist' – Zielhilfe im Datei-Inhalt."),
            (IndicatorType.ContentString, "world to screen",    RiskLevel.High,   "ESP",            "Welt-zu-Screen-Projektion im Datei-Inhalt (ESP-Rendering)."),
            (IndicatorType.ContentString, "bone matrix",        RiskLevel.High,   "Aimbot",         "Knochen-Matrix fuer Aimbot-Targeting im Datei-Inhalt."),
            (IndicatorType.ContentString, "skinchanger",        RiskLevel.Medium, "Visual-Hack",    "Skin-Changer im Datei-Inhalt."),
            (IndicatorType.ContentString, "radar hack",         RiskLevel.High,   "Radar",          "Radar-Hack im Datei-Inhalt."),
            (IndicatorType.ContentString, "chams",              RiskLevel.High,   "ESP",            "'chams' – Material-ESP im Datei-Inhalt."),
            (IndicatorType.ContentString, "glow esp",           RiskLevel.High,   "ESP",            "Glow-ESP-Funktion im Datei-Inhalt."),

            // Private cheat loader/DRM strings
            (IndicatorType.ContentString, "panic key",          RiskLevel.High,   "Cheat-Loader",   "'panic key' – Notfall-Entlade-Taste in privatem Cheat."),
            (IndicatorType.ContentString, "unload cheat",       RiskLevel.High,   "Cheat-Loader",   "'unload cheat' – Cheat-Entlade-Routine."),
            (IndicatorType.ContentString, "injection complete", RiskLevel.High,   "Injector",       "'injection complete' – Injektionserfolg-Meldung."),
            (IndicatorType.ContentString, "inject success",     RiskLevel.High,   "Injector",       "'inject success' im Datei-Inhalt."),
            (IndicatorType.ContentString, "cheat loader",       RiskLevel.High,   "Cheat-Loader",   "'cheat loader' im Datei-Inhalt."),
            (IndicatorType.ContentString, "hwid check",         RiskLevel.Medium, "Cheat-DRM",      "HWID-Pruefung (cheat DRM) im Datei-Inhalt."),

            // Stealthy injection APIs (almost never legitimately used in user-space apps)
            (IndicatorType.ContentString, "NtCreateThreadEx",   RiskLevel.High,   "Injector",       "NtCreateThreadEx – unentdeckte Thread-Injektion."),
            (IndicatorType.ContentString, "RtlCreateUserThread",RiskLevel.High,   "Injector",       "RtlCreateUserThread – alternative Injektionsmethode."),
            (IndicatorType.ContentString, "LdrLoadDll",         RiskLevel.High,   "Injector",       "LdrLoadDll – indirektes DLL-Laden (Injektionstechnik)."),
            (IndicatorType.ContentString, "NtProtectVirtualMemory",RiskLevel.High,"Injector",       "NtProtectVirtualMemory – Speicherschutz-Aenderung (Shellcode-Injektion)."),
            (IndicatorType.ContentString, "NtWriteVirtualMemory",RiskLevel.High,  "Injector",       "NtWriteVirtualMemory – direktes Speicherschreiben."),
            (IndicatorType.ContentString, "SetWindowsHookEx",   RiskLevel.Medium, "Hook",           "SetWindowsHookEx – globaler Systemhook (Injektionstechnik)."),

            // Reverse-engineering / developer tools as content strings
            (IndicatorType.ContentString, "offset_manager",     RiskLevel.High,   "Cheat-Dev",      "Offset-Manager-String im Datei-Inhalt (Cheat-Entwicklung)."),
            (IndicatorType.ContentString, "entity list",        RiskLevel.High,   "Cheat-Dev",      "Entity-List-Zugriff im Datei-Inhalt (Spielspeicher-Hack)."),
            (IndicatorType.ContentString, "local player",       RiskLevel.Medium, "Cheat-Dev",      "LocalPlayer-Pointer im Datei-Inhalt (Spielspeicher-Hack)."),
            (IndicatorType.ContentString, "draw_box",           RiskLevel.High,   "ESP",            "draw_box-Funktion im Datei-Inhalt (ESP-Rendering)."),
            (IndicatorType.ContentString, "draw_line",          RiskLevel.Medium, "ESP",            "draw_line im Datei-Inhalt (ESP-Hilfslinien)."),

            // More URL domains
            (IndicatorType.UrlDomainKeyword, "aimware",         RiskLevel.Critical,"CS2-Cheat-Shop","aimware (CS2-Cheat)."),
            (IndicatorType.UrlDomainKeyword, "fecurity",        RiskLevel.Critical,"CS2-Cheat-Shop","fecurity (CS2-Cheat)."),
            (IndicatorType.UrlDomainKeyword, "nixware",         RiskLevel.High,    "CS2-Cheat-Shop","nixware (CS2-Cheat)."),
            (IndicatorType.UrlDomainKeyword, "lumina",          RiskLevel.High,    "CS2-Cheat-Shop","lumina (CS2-Cheat)."),
            (IndicatorType.UrlDomainKeyword, "aristois",        RiskLevel.High,    "MC-Cheat-Shop", "aristois.net (Minecraft)."),
            (IndicatorType.UrlDomainKeyword, "sigmaclient",     RiskLevel.High,    "MC-Cheat-Shop", "sigma (Minecraft)."),
            (IndicatorType.UrlDomainKeyword, "meteorclient",    RiskLevel.High,    "MC-Cheat-Shop", "meteorclient (Minecraft)."),
            (IndicatorType.UrlDomainKeyword, "lolz.guru",       RiskLevel.Medium,  "Cheat-Forum",   "lolz.guru (russisches Cheat-Forum)."),
            (IndicatorType.UrlDomainKeyword, "blackhatworld",   RiskLevel.Medium,  "Hack-Forum",    "blackhatworld (Hacking-Forum)."),
            (IndicatorType.UrlDomainKeyword, "sinisterly",      RiskLevel.Medium,  "Cheat-Forum",   "sinisterly.com (Cheat-Forum)."),
            (IndicatorType.UrlDomainKeyword, "gamehag",         RiskLevel.Low,     "Cheat-Markt",   "gamehag (teils Cheat-Werbung)."),
            (IndicatorType.UrlDomainKeyword, "skidrow",         RiskLevel.Medium,  "Raubkopie",     "skidrow (Crack-/Warez-Seite)."),
            (IndicatorType.UrlDomainKeyword, "crackwatch",      RiskLevel.Medium,  "Raubkopie",     "crackwatch (Crack-Tracker)."),
            (IndicatorType.UrlDomainKeyword, "cs.money",        RiskLevel.Low,     "CS-Trading",    "cs.money (CS2-Item-Marktplatz, teils RMT-Betrug)."),
            (IndicatorType.UrlDomainKeyword, "buff.163",        RiskLevel.Low,     "CS-Trading",    "buff.163.com (CS2-Trading)."),

            // Process names: reverse engineering / analysis tools
            (IndicatorType.ProcessName, "dnspy",                RiskLevel.High,   "RE-Tool",   "dnSpy – .NET-Dekompiler (Reverse Engineering)."),
            (IndicatorType.ProcessName, "ilspy",                RiskLevel.High,   "RE-Tool",   "ILSpy – .NET-Dekompiler."),
            (IndicatorType.ProcessName, "dotpeek",              RiskLevel.Medium, "RE-Tool",   "dotPeek – JetBrains .NET-Dekompiler."),
            (IndicatorType.ProcessName, "ghidra",               RiskLevel.High,   "RE-Tool",   "Ghidra – NSA Reverse-Engineering-Framework."),
            (IndicatorType.ProcessName, "ida64",                RiskLevel.High,   "Disassembler","IDA Pro x64."),
            (IndicatorType.ProcessName, "ida",                  RiskLevel.High,   "Disassembler","IDA Pro."),
            (IndicatorType.ProcessName, "ollydbg",              RiskLevel.High,   "Debugger",  "OllyDbg – Debugger."),
            (IndicatorType.ProcessName, "pestudio",             RiskLevel.High,   "RE-Tool",   "PE Studio – PE-Analyse-Tool."),
            (IndicatorType.ProcessName, "hxd",                  RiskLevel.Medium, "Hex-Editor","HxD – Hex-Editor."),
            (IndicatorType.ProcessName, "010editor",            RiskLevel.Medium, "Hex-Editor","010 Editor – Hex-Editor."),
            (IndicatorType.ProcessName, "immunity debugger",    RiskLevel.High,   "Debugger",  "Immunity Debugger."),
            (IndicatorType.ProcessName, "httpdebuggerui",       RiskLevel.Medium, "Proxy",     "HTTP Debugger Pro – HTTP-MITM-Proxy."),
            (IndicatorType.ProcessName, "charles",              RiskLevel.Medium, "Proxy",     "Charles – HTTP-Proxy-Tool."),
            (IndicatorType.ProcessName, "mitmproxy",            RiskLevel.Medium, "Proxy",     "mitmproxy – Man-in-the-Middle-Proxy."),
            (IndicatorType.ProcessName, "apimonitor",           RiskLevel.High,   "RE-Tool",   "API Monitor – API-Aufruf-Logger."),
            (IndicatorType.ProcessName, "dbgview",              RiskLevel.Medium, "RE-Tool",   "DebugView – OutputDebugString-Logger."),
            (IndicatorType.ProcessName, "cff explorer",         RiskLevel.Medium, "RE-Tool",   "CFF Explorer – PE-Editor."),
            (IndicatorType.ProcessName, "resource hacker",      RiskLevel.Medium, "RE-Tool",   "Resource Hacker – PE-Ressourcen-Editor."),

            // ── Version 4: 2025/2026 cheat library refresh ───────────────────────
            // Modern FiveM menu / kernel cheats
            (IndicatorType.FileNameKeyword, "yimmenu",          RiskLevel.Critical,"GTA-Cheat",       "GTA-Mod-Menu 'YimMenu'."),
            (IndicatorType.FileNameKeyword, "lambda menu",      RiskLevel.High,    "GTA-Cheat",       "GTA-Cheat 'Lambda Menu'."),
            (IndicatorType.FileNameKeyword, "absolute menu",    RiskLevel.High,    "GTA-Cheat",       "GTA-Mod-Menu 'Absolute'."),
            (IndicatorType.FileNameKeyword, "stand menu",       RiskLevel.High,    "GTA-Cheat",       "GTA-Mod-Menu 'Stand'."),
            (IndicatorType.FileNameKeyword, "spectre menu",     RiskLevel.High,    "FiveM-Cheat",     "FiveM-Cheat 'Spectre'."),
            (IndicatorType.FileNameKeyword, "celestial",        RiskLevel.High,    "FiveM-Cheat",     "FiveM-Cheat 'Celestial'."),
            (IndicatorType.FileNameKeyword, "susano",           RiskLevel.High,    "FiveM-Cheat",     "FiveM-Cheat 'Susano'."),
            (IndicatorType.FileNameKeyword, "hyperion",         RiskLevel.High,    "FiveM-Cheat",     "FiveM-Cheat 'Hyperion'."),
            (IndicatorType.FileNameKeyword, "nsaware",          RiskLevel.High,    "FiveM-Cheat",     "FiveM-Cheat 'NSAware'."),
            (IndicatorType.FileNameKeyword, "reaper menu",      RiskLevel.High,    "FiveM-Cheat",     "FiveM-Cheat 'Reaper'."),
            (IndicatorType.FileNameKeyword, "void cheats",      RiskLevel.High,    "Cheat-Shop",      "'Void Cheats'-Marker."),
            (IndicatorType.FileNameKeyword, "primordial",       RiskLevel.High,    "Cheat",           "Cheat 'Primordial'."),
            (IndicatorType.FileNameKeyword, "sunset cheat",     RiskLevel.High,    "FiveM-Cheat",     "FiveM-Cheat 'Sunset'."),
            (IndicatorType.FileNameKeyword, "phoenix cheat",    RiskLevel.High,    "Cheat",           "Cheat 'Phoenix'."),
            (IndicatorType.FileNameKeyword, "skript.gg",        RiskLevel.High,    "FiveM-Cheat",     "FiveM 'skript.gg' Marker."),
            // Modern Valorant / Apex / Warzone cheats
            (IndicatorType.FileNameKeyword, "valorhack",        RiskLevel.Critical,"Valorant-Cheat",  "Valorant-Cheat 'ValorHack'."),
            (IndicatorType.FileNameKeyword, "vanguardbypass",   RiskLevel.Critical,"Valorant-Cheat",  "Valorant Vanguard-Bypass."),
            (IndicatorType.FileNameKeyword, "ringone",          RiskLevel.High,    "Apex-Cheat",      "Apex-Cheat 'Ringone'."),
            (IndicatorType.FileNameKeyword, "warzone unlock",   RiskLevel.High,    "Warzone-Cheat",   "Warzone-Unlock-Tool."),
            (IndicatorType.FileNameKeyword, "blackcell",        RiskLevel.High,    "Warzone-Cheat",   "Warzone-Cheat 'BlackCell'."),
            (IndicatorType.FileNameKeyword, "engineowning",     RiskLevel.High,    "Cheat-Shop",      "EngineOwning-Cheat."),
            // DMA / external hardware cheats
            (IndicatorType.FileNameKeyword, "memprocfs",        RiskLevel.High,    "DMA-Tool",        "MemProcFS – DMA-Memory-Reader."),
            (IndicatorType.FileNameKeyword, "leechcore",        RiskLevel.High,    "DMA-Tool",        "LeechCore – DMA-FPGA-Treiber."),
            (IndicatorType.FileNameKeyword, "pcileech",         RiskLevel.High,    "DMA-Tool",        "PCILeech – DMA-Tool."),
            (IndicatorType.FileNameKeyword, "openrgb",          RiskLevel.Low,     "Tool",            "OpenRGB – haeufig neben DMA-Setups."),
            (IndicatorType.FileNameKeyword, "screamingbee",     RiskLevel.Medium,  "Tool",            "MorphVOX-Stimmenwandler (haeufig bei Smurfern)."),
            // Modern HWID spoofers
            (IndicatorType.FileNameKeyword, "permspoofer",      RiskLevel.High,    "Spoofer",         "PermSpoofer-HWID-Tool."),
            (IndicatorType.FileNameKeyword, "tempspoofer",      RiskLevel.High,    "Spoofer",         "TempSpoofer-HWID-Tool."),
            (IndicatorType.FileNameKeyword, "ultraspoofer",     RiskLevel.High,    "Spoofer",         "UltraSpoofer-Tool."),
            (IndicatorType.FileNameKeyword, "veiledspoofer",    RiskLevel.High,    "Spoofer",         "Veiled-Spoofer-Tool."),
            (IndicatorType.FileNameKeyword, "smbios spoof",     RiskLevel.High,    "Spoofer",         "SMBIOS-Spoofer-Werkzeug."),
            (IndicatorType.FileNameKeyword, "tpmbypass",        RiskLevel.High,    "Spoofer",         "TPM-Bypass-Werkzeug."),
            // Modern content strings
            (IndicatorType.ContentString, "yimmenu",            RiskLevel.High,    "GTA-Cheat",       "YimMenu im Datei-Inhalt."),
            (IndicatorType.ContentString, "engineowning",       RiskLevel.High,    "Cheat-Shop",      "EngineOwning im Datei-Inhalt."),
            (IndicatorType.ContentString, "vanguard bypass",    RiskLevel.Critical,"AC-Bypass",       "Vanguard-Bypass im Datei-Inhalt."),
            (IndicatorType.ContentString, "ricochet bypass",    RiskLevel.Critical,"AC-Bypass",       "Ricochet-Bypass (Warzone) im Datei-Inhalt."),
            (IndicatorType.ContentString, "permspoof",          RiskLevel.High,    "Spoofer",         "permanent spoof Token im Datei-Inhalt."),
            (IndicatorType.ContentString, "dma cheat",          RiskLevel.High,    "DMA-Tool",        "'dma cheat' im Datei-Inhalt."),
            (IndicatorType.ContentString, "screencapture bypass",RiskLevel.High,   "AC-Bypass",       "Screenshare-Bypass im Datei-Inhalt."),
            (IndicatorType.ContentString, "hwid permanent",     RiskLevel.High,    "Spoofer",         "'hwid permanent' im Datei-Inhalt."),
            (IndicatorType.ContentString, "secureboot disable", RiskLevel.High,    "AC-Bypass",       "Secure Boot Disable Token im Datei-Inhalt."),
            // Modern cheat-marketplace URLs
            (IndicatorType.UrlDomainKeyword, "yimmenu.com",     RiskLevel.High,    "Cheat-Shop",      "yimmenu.com."),
            (IndicatorType.UrlDomainKeyword, "engineowning",    RiskLevel.High,    "Cheat-Shop",      "EngineOwning-Domain."),
            (IndicatorType.UrlDomainKeyword, "interwebz",       RiskLevel.High,    "Cheat-Shop",      "InterwebZ-Cheat-Shop."),
            (IndicatorType.UrlDomainKeyword, "lavicheats",      RiskLevel.High,    "Cheat-Shop",      "LaviCheats-Domain."),
            (IndicatorType.UrlDomainKeyword, "darkcheats",      RiskLevel.High,    "Cheat-Shop",      "DarkCheats-Domain."),
            (IndicatorType.UrlDomainKeyword, "iwantcheats",     RiskLevel.High,    "Cheat-Shop",      "IWantCheats-Domain."),
            (IndicatorType.UrlDomainKeyword, "phantomoverlay",  RiskLevel.High,    "Cheat-Shop",      "PhantomOverlay-Cheat-Shop."),
            (IndicatorType.UrlDomainKeyword, "ringone",         RiskLevel.High,    "Cheat-Shop",      "Ringone-Domain."),
            (IndicatorType.UrlDomainKeyword, "celestialcheats", RiskLevel.High,    "Cheat-Shop",      "Celestial-Cheats-Domain."),
            // Process names (modern)
            (IndicatorType.ProcessName, "memprocfs",            RiskLevel.High,    "DMA-Tool",        "MemProcFS-Prozess."),
            (IndicatorType.ProcessName, "leechcore",            RiskLevel.High,    "DMA-Tool",        "LeechCore-Prozess."),
            (IndicatorType.ProcessName, "pcileech",             RiskLevel.High,    "DMA-Tool",        "PCILeech-Prozess."),
            (IndicatorType.ProcessName, "yimmenu",              RiskLevel.Critical,"GTA-Cheat",       "YimMenu-Prozess."),
            (IndicatorType.ProcessName, "stand",                RiskLevel.Critical,"GTA-Cheat",       "Stand-Menu-Prozess."),

            // ── Version 5: extended detection — anti-detection, new cheats ───────
            // More FiveM / GTA menus
            (IndicatorType.FileNameKeyword, "olympus menu",     RiskLevel.High,    "FiveM-Cheat",     "FiveM-Cheat 'Olympus'."),
            (IndicatorType.FileNameKeyword, "baddie menu",      RiskLevel.High,    "FiveM-Cheat",     "FiveM-Cheat 'Baddie'."),
            (IndicatorType.FileNameKeyword, "sentinel",         RiskLevel.High,    "Cheat",           "Cheat 'Sentinel'."),
            (IndicatorType.FileNameKeyword, "horizon menu",     RiskLevel.High,    "FiveM-Cheat",     "FiveM-Cheat 'Horizon'."),
            (IndicatorType.FileNameKeyword, "nova menu",        RiskLevel.High,    "FiveM-Cheat",     "FiveM-Cheat 'Nova'."),
            (IndicatorType.FileNameKeyword, "devious",          RiskLevel.High,    "FiveM-Cheat",     "FiveM-Cheat 'Devious'."),
            (IndicatorType.FileNameKeyword, "goofymenu",        RiskLevel.High,    "GTA-Cheat",       "GTA-Cheat 'GoofyMenu'."),
            (IndicatorType.FileNameKeyword, "paragon menu",     RiskLevel.High,    "GTA-Cheat",       "GTA-Mod-Menu 'Paragon'."),
            (IndicatorType.FileNameKeyword, "flax menu",        RiskLevel.High,    "FiveM-Cheat",     "FiveM-Cheat 'Flax'."),
            (IndicatorType.FileNameKeyword, "zync menu",        RiskLevel.High,    "FiveM-Cheat",     "FiveM-Cheat 'Zync'."),
            (IndicatorType.FileNameKeyword, "crxss",            RiskLevel.High,    "FiveM-Cheat",     "FiveM-Cheat 'Crxss'."),
            // Anti-detection / streamproof / screen-capture bypass
            (IndicatorType.FileNameKeyword, "streamproof",      RiskLevel.High,    "Anti-Detection",  "Streamproof-Tool (versteckt Fenster vor OBS/Streamlabs)."),
            (IndicatorType.FileNameKeyword, "antiscreen",       RiskLevel.High,    "Anti-Detection",  "Anti-Screen-Capture-Tool."),
            (IndicatorType.FileNameKeyword, "dxgi bypass",      RiskLevel.High,    "Anti-Detection",  "DXGI-Bypass (Screenshot-Schutz umgehen)."),
            (IndicatorType.FileNameKeyword, "obs bypass",       RiskLevel.High,    "Anti-Detection",  "OBS-Bypass-Tool."),
            (IndicatorType.FileNameKeyword, "screenshare bypass",RiskLevel.High,   "Anti-Detection",  "Screenshare-Bypass-Tool."),
            (IndicatorType.FileNameKeyword, "hidewindow",       RiskLevel.High,    "Anti-Detection",  "Fenster-Versteck-Tool."),
            // More HWID spoofer brands
            (IndicatorType.FileNameKeyword, "iospoofer",        RiskLevel.High,    "Spoofer",         "IOSpoofer-HWID-Tool."),
            (IndicatorType.FileNameKeyword, "ghostspoofer",     RiskLevel.High,    "Spoofer",         "GhostSpoofer-HWID-Tool."),
            (IndicatorType.FileNameKeyword, "spoofer elite",    RiskLevel.High,    "Spoofer",         "Elite-Spoofer-Tool."),
            (IndicatorType.FileNameKeyword, "kernel spoofer",   RiskLevel.High,    "Spoofer",         "Kernel-Level-Spoofer."),
            (IndicatorType.FileNameKeyword, "easyspoofhwid",    RiskLevel.High,    "Spoofer",         "EasySpoof-HWID-Tool."),
            // Warzone / CoD cheats
            (IndicatorType.FileNameKeyword, "unlock all",       RiskLevel.High,    "Warzone-Cheat",   "CoD/Warzone Unlock-All-Tool."),
            (IndicatorType.FileNameKeyword, "cod cheat",        RiskLevel.High,    "Warzone-Cheat",   "CoD-Cheat-Datei."),
            (IndicatorType.FileNameKeyword, "godmode",          RiskLevel.Medium,  "Cheat",           "Godmode-Cheat im Dateinamen."),
            // More injector names
            (IndicatorType.FileNameKeyword, "sxinject",         RiskLevel.High,    "Injector",        "SX Injector."),
            (IndicatorType.FileNameKeyword, "process inject",   RiskLevel.High,    "Injector",        "'process inject' im Dateinamen."),
            (IndicatorType.FileNameKeyword, "ghostinject",      RiskLevel.High,    "Injector",        "Ghost Injector."),
            // Exact file names
            (IndicatorType.FileName, "valorhack.exe",           RiskLevel.Critical,"Valorant-Cheat",  "ValorHack-Prozess."),
            (IndicatorType.FileName, "ringone.exe",             RiskLevel.Critical,"Apex-Cheat",      "Ringone-Apex-Cheat."),
            (IndicatorType.FileName, "memprocfs.exe",           RiskLevel.High,    "DMA-Tool",        "MemProcFS-Tool."),
            (IndicatorType.FileName, "pcileech.exe",            RiskLevel.High,    "DMA-Tool",        "PCILeech-Tool."),
            // Content strings
            (IndicatorType.ContentString, "streamproof",        RiskLevel.High,    "Anti-Detection",  "Streamproof-Modus im Datei-Inhalt."),
            (IndicatorType.ContentString, "obs bypass",         RiskLevel.High,    "Anti-Detection",  "OBS-Bypass im Datei-Inhalt."),
            (IndicatorType.ContentString, "hwid spoofer",       RiskLevel.High,    "Spoofer",         "HWID-Spoofer im Datei-Inhalt."),
            (IndicatorType.ContentString, "kernel spoof",       RiskLevel.High,    "Spoofer",         "Kernel-Spoofing im Datei-Inhalt."),
            (IndicatorType.ContentString, "shadow ban bypass",  RiskLevel.High,    "AC-Bypass",       "Shadow-Ban-Bypass im Datei-Inhalt."),
            (IndicatorType.ContentString, "ip ban bypass",      RiskLevel.High,    "AC-Bypass",       "IP-Ban-Bypass im Datei-Inhalt."),
            (IndicatorType.ContentString, "ring0",              RiskLevel.Critical,"Kernel-Exploit",  "Ring-0 / Kernel-Exploit im Datei-Inhalt."),
            (IndicatorType.ContentString, "kernel exploit",     RiskLevel.Critical,"Kernel-Exploit",  "Kernel-Exploit im Datei-Inhalt."),
            (IndicatorType.ContentString, "driver exploit",     RiskLevel.Critical,"BYOVD",           "Treiber-Exploit im Datei-Inhalt."),
            (IndicatorType.ContentString, "dll injection",      RiskLevel.High,    "Injector",        "DLL-Injection im Datei-Inhalt."),
            (IndicatorType.ContentString, "hide window",        RiskLevel.High,    "Anti-Detection",  "Fenster-Versteck-Technik im Datei-Inhalt."),
            (IndicatorType.ContentString, "dxgi capture",       RiskLevel.High,    "Anti-Detection",  "DXGI-Capture-Bypass im Datei-Inhalt."),
            (IndicatorType.ContentString, "exempt from capture",RiskLevel.High,    "Anti-Detection",  "SetWindowDisplayAffinity-Bypass im Datei-Inhalt."),
            (IndicatorType.ContentString, "battleye undetected",RiskLevel.Critical,"AC-Bypass",       "BattlEye-Undetected-Behauptung im Datei-Inhalt."),
            (IndicatorType.ContentString, "eac undetected",     RiskLevel.Critical,"AC-Bypass",       "EAC-Undetected im Datei-Inhalt."),
            (IndicatorType.ContentString, "fully undetected",   RiskLevel.High,    "AC-Bypass",       "Fully-Undetected-Behauptung im Datei-Inhalt."),
            (IndicatorType.ContentString, "fud cheat",          RiskLevel.High,    "AC-Bypass",       "FUD-Cheat-Behauptung im Datei-Inhalt."),
            // URL domains
            (IndicatorType.UrlDomainKeyword, "olympuscheats",   RiskLevel.High,    "Cheat-Shop",      "Olympus-Cheats-Domain."),
            (IndicatorType.UrlDomainKeyword, "horizoncheats",   RiskLevel.High,    "Cheat-Shop",      "Horizon-Cheats-Domain."),
            (IndicatorType.UrlDomainKeyword, "paragonmenu",     RiskLevel.High,    "Cheat-Shop",      "Paragon-Menu-Domain."),
            (IndicatorType.UrlDomainKeyword, "cheatsquad",      RiskLevel.High,    "Cheat-Shop",      "CheatSquad-Domain."),
            (IndicatorType.UrlDomainKeyword, "predatorcheats",  RiskLevel.High,    "Cheat-Shop",      "Predator-Cheats-Domain."),
            (IndicatorType.UrlDomainKeyword, "streamproof",     RiskLevel.High,    "Anti-Detection",  "Streamproof-Domain."),
            (IndicatorType.UrlDomainKeyword, "ozarkgta",        RiskLevel.High,    "Cheat-Shop",      "Ozark-GTA-Domain."),
            (IndicatorType.UrlDomainKeyword, "undetectedcheats",RiskLevel.High,    "Cheat-Shop",      "UndetectedCheats-Domain."),
            (IndicatorType.UrlDomainKeyword, "nocheats",        RiskLevel.High,    "Cheat-Shop",      "NoCheats/NoMercyCheats-Domain."),
            (IndicatorType.UrlDomainKeyword, "skycheats",       RiskLevel.High,    "Cheat-Shop",      "SkyCheats-Domain."),
            (IndicatorType.UrlDomainKeyword, "rewas",           RiskLevel.High,    "Cheat-Shop",      "Rewas-Cheat-Shop-Domain."),
            (IndicatorType.UrlDomainKeyword, "susano",          RiskLevel.High,    "Cheat-Shop",      "Susano-FiveM-Domain."),
            (IndicatorType.UrlDomainKeyword, "celestial",       RiskLevel.High,    "Cheat-Shop",      "Celestial-FiveM-Domain."),
            // Process names
            (IndicatorType.ProcessName, "valorhack",            RiskLevel.Critical,"Valorant-Cheat",  "ValorHack-Prozess."),
            (IndicatorType.ProcessName, "ringone",              RiskLevel.Critical,"Apex-Cheat",      "Ringone-Prozess."),
            (IndicatorType.ProcessName, "systeminformer",       RiskLevel.Medium,  "Tool",            "System Informer (Process Hacker Nachfolger)."),
            (IndicatorType.ProcessName, "processhacker3",       RiskLevel.Medium,  "Tool",            "Process Hacker 3."),
            (IndicatorType.ProcessName, "cheatengine",          RiskLevel.High,    "Debugger",        "Cheat Engine."),
            (IndicatorType.ProcessName, "streamproof",          RiskLevel.High,    "Anti-Detection",  "Streamproof-Prozess."),

            // ── Version 6: Cross-game expansion, kernel tools, EFT/Rust/R6/Apex ─
            // ── Escape from Tarkov cheats ────────────────────────────────────────
            (IndicatorType.FileNameKeyword, "tarkovcheat",      RiskLevel.Critical,"EFT-Cheat",       "Escape-from-Tarkov-Cheat."),
            (IndicatorType.FileNameKeyword, "eft cheat",        RiskLevel.Critical,"EFT-Cheat",       "EFT-Cheat im Dateinamen."),
            (IndicatorType.FileNameKeyword, "tarkov esp",       RiskLevel.Critical,"EFT-Cheat",       "EFT-ESP im Dateinamen."),
            (IndicatorType.FileNameKeyword, "tarkov aimbot",    RiskLevel.Critical,"EFT-Cheat",       "EFT-Aimbot im Dateinamen."),
            (IndicatorType.FileNameKeyword, "evilcheats",       RiskLevel.Critical,"EFT-Cheat",       "EvilCheats-EFT-Produkt."),
            (IndicatorType.FileNameKeyword, "ohwow",            RiskLevel.Critical,"EFT-Cheat",       "OhWow-EFT-Cheat."),
            (IndicatorType.FileNameKeyword, "gamerpride",       RiskLevel.High,    "EFT-Cheat",       "GamerPride-EFT-Cheat."),
            (IndicatorType.FileNameKeyword, "exvalid",          RiskLevel.High,    "EFT-Cheat",       "ExValid-EFT-Cheat."),
            (IndicatorType.FileNameKeyword, "escape hack",      RiskLevel.High,    "EFT-Cheat",       "Escape-Hack im Dateinamen."),

            // ── Rust cheats ──────────────────────────────────────────────────────
            (IndicatorType.FileNameKeyword, "rust hack",        RiskLevel.Critical,"Rust-Cheat",      "Rust-Cheat im Dateinamen."),
            (IndicatorType.FileNameKeyword, "rust esp",         RiskLevel.Critical,"Rust-Cheat",      "Rust-ESP-Cheat."),
            (IndicatorType.FileNameKeyword, "rust aimbot",      RiskLevel.Critical,"Rust-Cheat",      "Rust-Aimbot."),
            (IndicatorType.FileNameKeyword, "rustez",           RiskLevel.High,    "Rust-Cheat",      "RustEZ-Cheat."),
            (IndicatorType.FileNameKeyword, "rustcheats",       RiskLevel.High,    "Rust-Cheat",      "RustCheats-Dateiname."),
            (IndicatorType.FileNameKeyword, "rustclient",       RiskLevel.Medium,  "Rust-Cheat",      "'rustclient' im Dateinamen."),

            // ── Rainbow Six Siege cheats ─────────────────────────────────────────
            (IndicatorType.FileNameKeyword, "r6 cheat",         RiskLevel.Critical,"R6-Cheat",        "R6-Siege-Cheat im Dateinamen."),
            (IndicatorType.FileNameKeyword, "siege hack",       RiskLevel.Critical,"R6-Cheat",        "Siege-Hack im Dateinamen."),
            (IndicatorType.FileNameKeyword, "r6 esp",           RiskLevel.High,    "R6-Cheat",        "R6-ESP-Cheat."),
            (IndicatorType.FileNameKeyword, "r6hacks",          RiskLevel.High,    "R6-Cheat",        "R6Hacks-Dateiname."),
            (IndicatorType.FileNameKeyword, "strike.gg",        RiskLevel.High,    "R6-Cheat",        "Strike.gg R6-Cheat."),

            // ── Apex Legends cheats ───────────────────────────────────────────────
            (IndicatorType.FileNameKeyword, "apex esp",         RiskLevel.Critical,"Apex-Cheat",      "Apex-ESP im Dateinamen."),
            (IndicatorType.FileNameKeyword, "apex aimbot",      RiskLevel.Critical,"Apex-Cheat",      "Apex-Aimbot im Dateinamen."),
            (IndicatorType.FileNameKeyword, "apexhacks",        RiskLevel.High,    "Apex-Cheat",      "ApexHacks-Dateiname."),
            (IndicatorType.FileNameKeyword, "predatorlegends",  RiskLevel.High,    "Apex-Cheat",      "PredatorLegends-Apex-Cheat."),
            (IndicatorType.FileNameKeyword, "apex cheat",       RiskLevel.Critical,"Apex-Cheat",      "Apex-Cheat im Dateinamen."),

            // ── Fortnite cheats ───────────────────────────────────────────────────
            (IndicatorType.FileNameKeyword, "fn cheat",         RiskLevel.High,    "Fortnite-Cheat",  "Fortnite-Cheat im Dateinamen."),
            (IndicatorType.FileNameKeyword, "fortnite esp",     RiskLevel.High,    "Fortnite-Cheat",  "Fortnite-ESP im Dateinamen."),
            (IndicatorType.FileNameKeyword, "fn aimbot",        RiskLevel.High,    "Fortnite-Cheat",  "Fortnite-Aimbot im Dateinamen."),
            (IndicatorType.FileNameKeyword, "hydranx",          RiskLevel.High,    "Fortnite-Cheat",  "Hydranx-Fortnite-Cheat."),
            (IndicatorType.FileNameKeyword, "fn hack",          RiskLevel.High,    "Fortnite-Cheat",  "Fortnite-Hack im Dateinamen."),

            // ── DayZ cheats ───────────────────────────────────────────────────────
            (IndicatorType.FileNameKeyword, "dayz cheat",       RiskLevel.High,    "DayZ-Cheat",      "DayZ-Cheat im Dateinamen."),
            (IndicatorType.FileNameKeyword, "dayz esp",         RiskLevel.High,    "DayZ-Cheat",      "DayZ-ESP im Dateinamen."),
            (IndicatorType.FileNameKeyword, "dayz hack",        RiskLevel.High,    "DayZ-Cheat",      "DayZ-Hack im Dateinamen."),

            // ── Battlefield cheats ────────────────────────────────────────────────
            (IndicatorType.FileNameKeyword, "bf2042 cheat",     RiskLevel.High,    "BF-Cheat",        "Battlefield 2042 Cheat."),
            (IndicatorType.FileNameKeyword, "bf esp",           RiskLevel.High,    "BF-Cheat",        "Battlefield-ESP im Dateinamen."),

            // ── More BYOVD vulnerable drivers ─────────────────────────────────────
            (IndicatorType.FileName, "AsrDrv104.sys",           RiskLevel.Critical,"BYOVD-Treiber",   "ASRock-Treiber – BYOVD-Exploit."),
            (IndicatorType.FileName, "AsrDrv106.sys",           RiskLevel.Critical,"BYOVD-Treiber",   "ASRock-Treiber v106 – BYOVD."),
            (IndicatorType.FileName, "nvflash64.sys",           RiskLevel.Critical,"BYOVD-Treiber",   "NVIDIA-Flash-Treiber – BYOVD."),
            (IndicatorType.FileName, "ProcExp152.sys",          RiskLevel.High,    "Tool",            "Process-Explorer-Treiber."),
            (IndicatorType.FileName, "ene.sys",                 RiskLevel.High,    "BYOVD-Treiber",   "ENE-Treiber – BYOVD."),
            (IndicatorType.FileName, "inpoutx64.sys",           RiskLevel.High,    "BYOVD-Treiber",   "InpOut x64-Treiber – BYOVD."),
            (IndicatorType.FileName, "hwinfo64a.sys",           RiskLevel.High,    "BYOVD-Treiber",   "HWiNFO64-Treiber – potenziell BYOVD."),
            (IndicatorType.FileName, "amdppm.sys",              RiskLevel.High,    "BYOVD-Treiber",   "AMD-PPM-Treiber – BYOVD."),
            (IndicatorType.FileName, "WinIo64.sys",             RiskLevel.Critical,"BYOVD-Treiber",   "WinIO64-Treiber – BYOVD."),
            (IndicatorType.FileName, "IObitUnlocker.sys",       RiskLevel.High,    "BYOVD-Treiber",   "IOBit-Unlocker-Treiber – missbraucht."),
            (IndicatorType.FileName, "cpuz141.sys",             RiskLevel.Critical,"BYOVD-Treiber",   "CPU-Z-Treiber – BYOVD (sehr haeufig)."),
            (IndicatorType.FileName, "cpuz_x64.sys",            RiskLevel.Critical,"BYOVD-Treiber",   "CPU-Z x64-Treiber – BYOVD."),
            (IndicatorType.FileName, "ZemanaAM.sys",            RiskLevel.High,    "BYOVD-Treiber",   "Zemana-AM-Treiber – BYOVD-missbraucht."),
            (IndicatorType.FileName, "MTi4Win64.sys",           RiskLevel.High,    "BYOVD-Treiber",   "MSI-Treiber – BYOVD."),

            // ── Kernel tool keywords ───────────────────────────────────────────────
            (IndicatorType.FileNameKeyword, "cpuz",             RiskLevel.High,    "BYOVD-Treiber",   "CPU-Z-Treiber-Datei (haeufig fuer BYOVD verwendet)."),
            (IndicatorType.FileNameKeyword, "asrdrv",           RiskLevel.High,    "BYOVD-Treiber",   "ASRock-Treiber-Datei – BYOVD."),
            (IndicatorType.FileNameKeyword, "drvsys",           RiskLevel.Medium,  "Kernel-Tool",     "'drvsys' im Dateinamen – verdaechtige Treiberdatei."),
            (IndicatorType.FileNameKeyword, "cheatdrv",         RiskLevel.Critical,"Cheat-Treiber",   "'cheatdrv' Cheat-Kernel-Treiber."),
            (IndicatorType.FileNameKeyword, "hackdrv",          RiskLevel.Critical,"Cheat-Treiber",   "'hackdrv' Hack-Kernel-Treiber."),

            // ── DMA / Hardware cheat tools ────────────────────────────────────────
            (IndicatorType.FileNameKeyword, "fpga cheat",       RiskLevel.Critical,"DMA-Cheat",       "FPGA-DMA-Cheat im Dateinamen."),
            (IndicatorType.FileNameKeyword, "dma memory",       RiskLevel.High,    "DMA-Cheat",       "DMA-Memory-Tool im Dateinamen."),
            (IndicatorType.FileNameKeyword, "pciedma",          RiskLevel.High,    "DMA-Cheat",       "PCIe-DMA-Cheat-Tool."),
            (IndicatorType.FileNameKeyword, "screamer",         RiskLevel.High,    "DMA-Tool",        "Screamer-PCIe-DMA-Tool (von externen Cheats genutzt)."),
            (IndicatorType.FileNameKeyword, "dmaspy",           RiskLevel.High,    "DMA-Tool",        "DMA-Spy-Tool."),

            // ── More cheat content strings ────────────────────────────────────────
            (IndicatorType.ContentString, "tarkov cheat",       RiskLevel.Critical,"EFT-Cheat",       "Tarkov-Cheat im Datei-Inhalt."),
            (IndicatorType.ContentString, "eft esp",            RiskLevel.Critical,"EFT-Cheat",       "EFT-ESP im Datei-Inhalt."),
            (IndicatorType.ContentString, "loot esp",           RiskLevel.High,    "EFT-Cheat",       "Loot-ESP (EFT-typisch) im Datei-Inhalt."),
            (IndicatorType.ContentString, "pmclist",            RiskLevel.High,    "EFT-Cheat",       "'pmclist' (EFT-Spieler-Liste) im Datei-Inhalt."),
            (IndicatorType.ContentString, "rust aimbot",        RiskLevel.Critical,"Rust-Cheat",      "Rust-Aimbot im Datei-Inhalt."),
            (IndicatorType.ContentString, "rust esp",           RiskLevel.High,    "Rust-Cheat",      "Rust-ESP im Datei-Inhalt."),
            (IndicatorType.ContentString, "harvest nodes",      RiskLevel.High,    "Rust-Cheat",      "'harvest nodes' – Rust-Node-ESP im Datei-Inhalt."),
            (IndicatorType.ContentString, "r6 esp",             RiskLevel.High,    "R6-Cheat",        "R6-ESP im Datei-Inhalt."),
            (IndicatorType.ContentString, "apex aimbot",        RiskLevel.Critical,"Apex-Cheat",      "Apex-Aimbot im Datei-Inhalt."),
            (IndicatorType.ContentString, "apex esp",           RiskLevel.High,    "Apex-Cheat",      "Apex-ESP im Datei-Inhalt."),
            (IndicatorType.ContentString, "fortnite aimbot",    RiskLevel.High,    "Fortnite-Cheat",  "Fortnite-Aimbot im Datei-Inhalt."),
            (IndicatorType.ContentString, "epicgames bypass",   RiskLevel.Critical,"AC-Bypass",       "Epic-Games-Anti-Cheat-Bypass im Datei-Inhalt."),
            (IndicatorType.ContentString, "dma read",           RiskLevel.High,    "DMA-Cheat",       "'dma read' im Datei-Inhalt (DMA-Cheat-API)."),
            (IndicatorType.ContentString, "fpga mem",           RiskLevel.High,    "DMA-Cheat",       "FPGA-Speicher-Zugriff im Datei-Inhalt."),
            (IndicatorType.ContentString, "pci device read",    RiskLevel.High,    "DMA-Cheat",       "PCI-Device-Read (DMA) im Datei-Inhalt."),
            (IndicatorType.ContentString, "scatter read",       RiskLevel.High,    "DMA-Cheat",       "'scatter read' – DMA-Cheat-Technik im Datei-Inhalt."),
            (IndicatorType.ContentString, "byovd",              RiskLevel.Critical,"BYOVD",           "BYOVD-Token im Datei-Inhalt."),

            // ── More anti-detection & hooking strings ─────────────────────────────
            (IndicatorType.ContentString, "ssdt hook",          RiskLevel.Critical,"Rootkit",         "SSDT-Hook im Datei-Inhalt (Kernel-Rootkit)."),
            (IndicatorType.ContentString, "dkom",               RiskLevel.Critical,"Rootkit",         "DKOM-Technik im Datei-Inhalt (Prozess verstecken)."),
            (IndicatorType.ContentString, "eprocess",           RiskLevel.High,    "Kernel-Exploit",  "EPROCESS-Zugriff im Datei-Inhalt (Kernel-Manipulation)."),
            (IndicatorType.ContentString, "nt!_eprocess",       RiskLevel.Critical,"Kernel-Exploit",  "EPROCESS-Kernel-Struktur-Zugriff im Datei-Inhalt."),
            (IndicatorType.ContentString, "ActiveProcessLinks", RiskLevel.Critical,"Rootkit",         "Direkter Kernel-Listenzeiger-Zugriff – DKOM-Technik."),
            (IndicatorType.ContentString, "PsLoadedModuleList", RiskLevel.Critical,"Rootkit",         "Kernel-Modullisten-Zugriff (Treiber verstecken)."),
            (IndicatorType.ContentString, "KeServiceDescriptorTable",RiskLevel.Critical,"Rootkit",    "SSDT-Tabellen-Zugriff im Datei-Inhalt."),
            (IndicatorType.ContentString, "ntcreatethread",     RiskLevel.High,    "Injector",        "NtCreateThread-Injektionstechnik im Datei-Inhalt."),
            (IndicatorType.ContentString, "readprocessmemory",  RiskLevel.High,    "Externer-Cheat",  "ReadProcessMemory im Datei-Inhalt (externer Cheat)."),
            (IndicatorType.ContentString, "openprocess vm_read",RiskLevel.High,    "Externer-Cheat",  "OpenProcess+VM_READ im Datei-Inhalt."),
            (IndicatorType.ContentString, "virtualprotect ex",  RiskLevel.High,    "Injector",        "VirtualProtectEx – Remote-Memory-Manipulation."),
            (IndicatorType.ContentString, "disable page protection",RiskLevel.Critical,"Kernel-Exploit","Page-Schutz deaktivieren im Datei-Inhalt."),
            (IndicatorType.ContentString, "patchguard bypass",  RiskLevel.Critical,"Kernel-Exploit",  "PatchGuard-Bypass im Datei-Inhalt."),
            (IndicatorType.ContentString, "kpp bypass",         RiskLevel.Critical,"Kernel-Exploit",  "Kernel-Patch-Protection-Bypass im Datei-Inhalt."),

            // ── More known exact cheat / tool file names ──────────────────────────
            (IndicatorType.FileName, "evilcheats.dll",          RiskLevel.Critical,"EFT-Cheat",       "EvilCheats-EFT-DLL."),
            (IndicatorType.FileName, "ohwow.dll",               RiskLevel.Critical,"EFT-Cheat",       "OhWow-EFT-DLL."),
            (IndicatorType.FileName, "gamerpride.exe",          RiskLevel.Critical,"EFT-Cheat",       "GamerPride-EFT-Launcher."),
            (IndicatorType.FileName, "striker.exe",             RiskLevel.High,    "R6-Cheat",        "Striker-R6-Cheat."),
            (IndicatorType.FileName, "predatorlegends.exe",     RiskLevel.Critical,"Apex-Cheat",      "PredatorLegends-Apex-Cheat."),
            (IndicatorType.FileName, "rustez.exe",              RiskLevel.Critical,"Rust-Cheat",      "RustEZ-Cheat-Launcher."),
            (IndicatorType.FileName, "cpuz141_x64.sys",         RiskLevel.Critical,"BYOVD-Treiber",   "CPU-Z 1.41 Treiber – haeufig bei BYOVD-Angriffen."),
            (IndicatorType.FileName, "winio64.sys",             RiskLevel.Critical,"BYOVD-Treiber",   "WinIO64 – BYOVD-Exploit."),

            // ── Additional process names ───────────────────────────────────────────
            (IndicatorType.ProcessName, "evilcheats",           RiskLevel.Critical,"EFT-Cheat",       "EvilCheats-Prozess."),
            (IndicatorType.ProcessName, "ohwow",                RiskLevel.Critical,"EFT-Cheat",       "OhWow-EFT-Prozess."),
            (IndicatorType.ProcessName, "gamerpride",           RiskLevel.Critical,"EFT-Cheat",       "GamerPride-Prozess."),
            (IndicatorType.ProcessName, "predatorlegends",      RiskLevel.Critical,"Apex-Cheat",      "PredatorLegends-Prozess."),
            (IndicatorType.ProcessName, "rustez",               RiskLevel.Critical,"Rust-Cheat",      "RustEZ-Prozess."),
            (IndicatorType.ProcessName, "r5apex",               RiskLevel.Low,     "Game",            "Apex-Legends-Spielprozess (Zielerfassung)."),
            (IndicatorType.ProcessName, "KDU",                  RiskLevel.Critical,"Kernel-Tool",     "Kernel-Driver-Utility (KDU) – BYOVD-Tool."),
            (IndicatorType.ProcessName, "kdmapper",             RiskLevel.Critical,"Manual-Mapper",   "KDMapper-Prozess."),
            (IndicatorType.ProcessName, "TitanHide",            RiskLevel.Critical,"Anti-Debug",      "TitanHide-Rootkit-Debugger-Hide."),
            (IndicatorType.ProcessName, "ScyllaHide",           RiskLevel.High,    "Anti-Debug",      "ScyllaHide-Plugin (anti-debugger)."),
            (IndicatorType.ProcessName, "dmaspy",               RiskLevel.High,    "DMA-Tool",        "DMASpy-Prozess."),

            // ── More URL domains ──────────────────────────────────────────────────
            (IndicatorType.UrlDomainKeyword, "evilcheats",      RiskLevel.Critical,"EFT-Cheat-Shop",  "EvilCheats-Domain (EFT)."),
            (IndicatorType.UrlDomainKeyword, "ohwow",           RiskLevel.Critical,"EFT-Cheat-Shop",  "OhWow-Domain (EFT)."),
            (IndicatorType.UrlDomainKeyword, "gamerpride",      RiskLevel.Critical,"EFT-Cheat-Shop",  "GamerPride-Domain."),
            (IndicatorType.UrlDomainKeyword, "rustez",          RiskLevel.Critical,"Rust-Cheat-Shop", "RustEZ-Domain."),
            (IndicatorType.UrlDomainKeyword, "apexhacks",       RiskLevel.High,    "Apex-Cheat-Shop", "ApexHacks-Domain."),
            (IndicatorType.UrlDomainKeyword, "r6hacks",         RiskLevel.High,    "R6-Cheat-Shop",   "R6Hacks-Domain."),
            (IndicatorType.UrlDomainKeyword, "hydranx",         RiskLevel.High,    "Fortnite-Cheat",  "Hydranx-Domain."),
            (IndicatorType.UrlDomainKeyword, "predatorlegends", RiskLevel.High,    "Apex-Cheat-Shop", "PredatorLegends-Domain."),
            (IndicatorType.UrlDomainKeyword, "exvalid",         RiskLevel.High,    "EFT-Cheat-Shop",  "ExValid-Domain (EFT)."),
            (IndicatorType.UrlDomainKeyword, "strike.gg",       RiskLevel.High,    "R6-Cheat-Shop",   "Strike.gg (R6 Siege)."),
            (IndicatorType.UrlDomainKeyword, "gamerspride",     RiskLevel.High,    "EFT-Cheat-Shop",  "GamersPride-Domain."),
            (IndicatorType.UrlDomainKeyword, "pcileech",        RiskLevel.High,    "DMA-Tool",        "PCILeech-Domain (DMA-Tool)."),
            (IndicatorType.UrlDomainKeyword, "memprocfs",       RiskLevel.High,    "DMA-Tool",        "MemProcFS-Domain."),
            (IndicatorType.UrlDomainKeyword, "ddlcheats",       RiskLevel.High,    "Cheat-Shop",      "DDLCheats-Domain."),
            (IndicatorType.UrlDomainKeyword, "sxcheats",        RiskLevel.High,    "Cheat-Shop",      "SxCheats-Domain."),
            (IndicatorType.UrlDomainKeyword, "zerobypass",      RiskLevel.High,    "AC-Bypass",       "ZeroBypass-Domain."),
            (IndicatorType.UrlDomainKeyword, "skycheats",       RiskLevel.High,    "Cheat-Shop",      "SkyCheats-Domain."),
        };

        using var tx = conn.BeginTransaction();

        // Replace all builtin indicators so updates propagate to existing users.
        using (var del = conn.CreateCommand())
        {
            del.Transaction = tx;
            del.CommandText = "DELETE FROM indicators WHERE source='builtin-heuristic';";
            del.ExecuteNonQuery();
        }

        foreach (var s in seeds)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = @"
INSERT INTO indicators (type, pattern, risk, category, description, source, enabled, created_utc)
VALUES ($type, $pattern, $risk, $category, $description, 'builtin-heuristic', 1, $created);";
            cmd.Parameters.AddWithValue("$type", (int)s.type);
            cmd.Parameters.AddWithValue("$pattern", s.pattern);
            cmd.Parameters.AddWithValue("$risk", (int)s.risk);
            cmd.Parameters.AddWithValue("$category", s.category);
            cmd.Parameters.AddWithValue("$description", s.desc);
            cmd.Parameters.AddWithValue("$created", DateTime.UtcNow.ToString("O"));
            cmd.ExecuteNonQuery();
        }

        // Persist seed version so we don't re-run on next launch.
        using (var upd = conn.CreateCommand())
        {
            upd.Transaction = tx;
            upd.CommandText = "INSERT OR REPLACE INTO settings (key, value) VALUES ('builtin_indicator_version', $v);";
            upd.Parameters.AddWithValue("$v", CurrentVersion.ToString());
            upd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    /// <summary>The full DDL. Mirrored as docs-only Schema.sql for reference.</summary>
    public const string SchemaSql = @"
CREATE TABLE IF NOT EXISTS indicators (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    type         INTEGER NOT NULL,
    pattern      TEXT    NOT NULL,
    risk         INTEGER NOT NULL,
    category     TEXT    NOT NULL DEFAULT 'General',
    description  TEXT    NOT NULL DEFAULT '',
    source       TEXT    NOT NULL DEFAULT 'manual',
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_utc  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_indicators_type    ON indicators(type);
CREATE INDEX IF NOT EXISTS ix_indicators_enabled ON indicators(enabled);

CREATE TABLE IF NOT EXISTS scans (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    started_utc          TEXT    NOT NULL,
    finished_utc         TEXT    NOT NULL,
    files_scanned        INTEGER NOT NULL DEFAULT 0,
    processes_scanned    INTEGER NOT NULL DEFAULT 0,
    registry_keys_scanned INTEGER NOT NULL DEFAULT 0,
    result               INTEGER NOT NULL DEFAULT 3,
    machine_name         TEXT    NOT NULL DEFAULT '',
    os_version           TEXT    NOT NULL DEFAULT '',
    elevated             INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL,
    module          TEXT    NOT NULL,
    title           TEXT    NOT NULL,
    risk            INTEGER NOT NULL,
    location        TEXT    NOT NULL DEFAULT '',
    file_name       TEXT,
    sha256          TEXT,
    reason          TEXT    NOT NULL DEFAULT '',
    signed          INTEGER,
    detail          TEXT,
    recommendation  INTEGER NOT NULL DEFAULT 1,
    detected_utc    TEXT    NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS ix_findings_risk ON findings(risk);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hash_whitelist (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256      TEXT NOT NULL UNIQUE,
    note        TEXT NOT NULL DEFAULT '',
    added_by    TEXT NOT NULL DEFAULT '',
    created_utc TEXT NOT NULL
);
";
}
