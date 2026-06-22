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
        const int CurrentVersion = 2;
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
";
}
