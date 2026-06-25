using System.Diagnostics;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class RagePluginHookCheatScanModule : IScanModule
{
    public string Name => "RagePluginHook Cheat Detection Scan";
    public double Weight => 3.3;
    public int ParallelGroup => 4;

    // ── GTA V installation candidate paths ──
    private static readonly string[] GtaVSearchPaths =
    {
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Rockstar Games", "Grand Theft Auto V"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Rockstar Games", "Grand Theft Auto V"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Steam", "steamapps", "common", "Grand Theft Auto V"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Steam", "steamapps", "common", "Grand Theft Auto V"),
        @"C:\Games\Grand Theft Auto V",
        @"D:\Games\Grand Theft Auto V",
        @"E:\Games\Grand Theft Auto V",
        @"C:\Program Files\Grand Theft Auto V",
        @"D:\Program Files\Grand Theft Auto V",
        @"C:\GTA V",
        @"D:\GTA V",
        @"C:\GTAV",
        @"D:\GTAV",
    };

    // ── RPH cheat plugin DLL name signatures ──
    private static readonly (string name, RiskLevel risk, string reason)[] RphCheatPluginNames =
    {
        ("godmode",                 RiskLevel.Critical, "GodMode-Plugin für RPH"),
        ("god_mode",                RiskLevel.Critical, "GodMode-Plugin (Unterstrich-Variante)"),
        ("noclip",                  RiskLevel.High,     "NoClip-Plugin für RPH"),
        ("no_clip",                 RiskLevel.High,     "NoClip-Plugin (Unterstrich-Variante)"),
        ("teleport",                RiskLevel.High,     "Teleport-Plugin für RPH"),
        ("teleportanywhere",        RiskLevel.High,     "TeleportAnywhere-Plugin"),
        ("moneydrop",               RiskLevel.Critical, "MoneyDrop-Plugin für RPH"),
        ("money_drop",              RiskLevel.Critical, "MoneyDrop-Plugin (Unterstrich-Variante)"),
        ("moneyrecovery",           RiskLevel.Critical, "Money-Recovery-Plugin"),
        ("recovery",                RiskLevel.Critical, "Recovery-Plugin (GTA-Online-Geld)"),
        ("moneyhack",               RiskLevel.Critical, "MoneyHack-Plugin"),
        ("onlinebypass",            RiskLevel.Critical, "Online-Bypass-Plugin"),
        ("online_bypass",           RiskLevel.Critical, "Online-Bypass-Plugin (Unterstrich)"),
        ("anticheatbypass",         RiskLevel.Critical, "Anti-Cheat-Bypass-Plugin"),
        ("anticheatkill",           RiskLevel.Critical, "Anti-Cheat-Kill-Plugin"),
        ("bypassbattleye",          RiskLevel.Critical, "BattlEye-Bypass-Plugin"),
        ("trainerv",                RiskLevel.High,     "TrainerV-Plugin (bekannter Cheat-Trainer)"),
        ("simpletrainer",           RiskLevel.High,     "Simple Trainer für GTA V"),
        ("enhancednativetrainer",   RiskLevel.High,     "Enhanced Native Trainer (Online-Bypass)"),
        ("nativetrainer",           RiskLevel.High,     "Native Trainer (Cheat-Trainer)"),
        ("menyoobypass",            RiskLevel.Critical, "Menyoo-Bypass für GTA Online"),
        ("menyoo_online",           RiskLevel.Critical, "Menyoo Online-Patch"),
        ("networkpatch",            RiskLevel.Critical, "Netzwerk-Patch-Plugin"),
        ("packetmanipulation",      RiskLevel.Critical, "Paket-Manipulations-Plugin"),
        ("packet_manipulation",     RiskLevel.Critical, "Paket-Manipulations-Plugin (Unterstrich)"),
        ("sessioncontrol",          RiskLevel.High,     "Session-Kontroll-Plugin"),
        ("hostbypass",              RiskLevel.Critical, "Host-Bypass-Plugin"),
        ("spectate",                RiskLevel.High,     "Spectate-Plugin"),
        ("vehiclespawner",          RiskLevel.High,     "Vehicle-Spawner-Plugin"),
        ("weaponmod",               RiskLevel.High,     "Waffen-Mod-Plugin"),
        ("speedhack",               RiskLevel.Critical, "SpeedHack-Plugin für RPH"),
        ("immortal",                RiskLevel.Critical, "Immortal/GodMode-Plugin"),
        ("superrun",                RiskLevel.High,     "SuperRun-Plugin (Geschwindigkeits-Hack)"),
        ("superjump",               RiskLevel.High,     "SuperJump-Plugin"),
        ("wantedlevel",             RiskLevel.High,     "Wanted-Level-Manipulations-Plugin"),
        ("policebypass",            RiskLevel.High,     "Polizei-Bypass-Plugin"),
        ("modmenu",                 RiskLevel.High,     "ModMenu-Plugin"),
        ("cheatmenu",               RiskLevel.Critical, "Cheat-Menu-Plugin"),
        ("hackmenu",                RiskLevel.Critical, "Hack-Menu-Plugin"),
        ("onlinemod",               RiskLevel.Critical, "Online-Mod-Plugin"),
        ("moneylobby",              RiskLevel.Critical, "Money-Lobby-Plugin"),
        ("modlobby",                RiskLevel.Critical, "Mod-Lobby-Plugin"),
        ("hackedlobby",             RiskLevel.Critical, "Hacked-Lobby-Plugin"),
        ("rphmoneydrop",            RiskLevel.Critical, "RPH Money-Drop-Plugin"),
        ("rphbotnet",               RiskLevel.Critical, "RPH-Botnetz-Plugin"),
        ("rphbypass",               RiskLevel.Critical, "RPH-Bypass-Plugin"),
        ("rphcheat",                RiskLevel.Critical, "RPH-Cheat-Plugin"),
        ("rphhack",                 RiskLevel.Critical, "RPH-Hack-Plugin"),
        ("forcefield",              RiskLevel.High,     "Kraftfeld-Plugin (Schutzschild-Hack)"),
        ("invisibility",            RiskLevel.High,     "Unsichtbarkeits-Plugin"),
        ("aimbot",                  RiskLevel.Critical, "Aimbot-Plugin für RPH"),
        ("triggerbot",              RiskLevel.Critical, "Triggerbot-Plugin für RPH"),
        ("esp_plugin",              RiskLevel.Critical, "ESP-Plugin für RPH"),
    };

    // ── RPH config file suspicious settings ──
    private static readonly (string pattern, RiskLevel risk, string reason)[] RphConfigPatterns =
    {
        ("DisableAntiCheat=true",           RiskLevel.Critical, "Anti-Cheat-Deaktivierung in RPH-Config"),
        ("DisableAntiCheat=1",              RiskLevel.Critical, "Anti-Cheat-Deaktivierung in RPH-Config (1)"),
        ("BypassIntegrity=true",            RiskLevel.Critical, "Integritäts-Bypass in RPH-Config"),
        ("BypassIntegrity=1",               RiskLevel.Critical, "Integritäts-Bypass in RPH-Config (1)"),
        ("EnableOnlineBypasses=true",       RiskLevel.Critical, "Online-Bypass-Aktivierung in RPH-Config"),
        ("EnableOnlineBypasses=1",          RiskLevel.Critical, "Online-Bypass-Aktivierung in RPH-Config (1)"),
        ("DisableVerification=true",        RiskLevel.Critical, "Verifikations-Deaktivierung in RPH-Config"),
        ("DisableVerification=1",           RiskLevel.Critical, "Verifikations-Deaktivierung in RPH-Config (1)"),
        ("SkipSignatureCheck=true",         RiskLevel.Critical, "Signatur-Prüfung übersprungen"),
        ("SkipSignatureCheck=1",            RiskLevel.Critical, "Signatur-Prüfung übersprungen (1)"),
        ("AllowUnsignedPlugins=true",       RiskLevel.High,     "Unsignierte Plugins erlaubt"),
        ("AllowUnsignedPlugins=1",          RiskLevel.High,     "Unsignierte Plugins erlaubt (1)"),
        ("PatchBattlEye=true",              RiskLevel.Critical, "BattlEye-Patch in RPH-Config"),
        ("PatchBattlEye=1",                 RiskLevel.Critical, "BattlEye-Patch in RPH-Config (1)"),
        ("DisableRockstarEditor=true",      RiskLevel.High,     "Rockstar-Editor deaktiviert (Forensik-Vermeidung)"),
        ("DisableCloudSaves=true",          RiskLevel.High,     "Cloud-Saves deaktiviert (Anti-Forensik)"),
        ("IgnoreModConflicts=true",         RiskLevel.High,     "Mod-Konflikte ignoriert"),
        ("MoneyDrop=true",                  RiskLevel.Critical, "MoneyDrop in RPH-Config aktiviert"),
        ("GodMode=true",                    RiskLevel.Critical, "GodMode in RPH-Config aktiviert"),
        ("NoClip=true",                     RiskLevel.High,     "NoClip in RPH-Config aktiviert"),
        ("SpeedHack=true",                  RiskLevel.Critical, "SpeedHack in RPH-Config aktiviert"),
        ("WantedLevel=0",                   RiskLevel.High,     "Fahndungslevel auf 0 gesetzt"),
        ("NeverWanted=true",                RiskLevel.High,     "NeverWanted in RPH-Config aktiviert"),
        ("SessionType=Modder",              RiskLevel.Critical, "Session-Typ 'Modder' in RPH-Config"),
        ("bypass",                          RiskLevel.High,     "Bypass-Schlüsselwort in RPH-Config"),
        ("anticheat",                       RiskLevel.High,     "Anti-Cheat-Schlüsselwort in RPH-Config"),
        ("cheat",                           RiskLevel.High,     "Cheat-Schlüsselwort in RPH-Config"),
        ("exploit",                         RiskLevel.High,     "Exploit-Schlüsselwort in RPH-Config"),
    };

    // ── RPH log file suspicious entries ──
    private static readonly (string pattern, RiskLevel risk, string reason)[] RphLogPatterns =
    {
        ("online session",                  RiskLevel.High,     "Online-Session in RPH-Log erkannt"),
        ("GTA:Online",                      RiskLevel.High,     "GTA Online in RPH-Log"),
        ("GTA Online",                      RiskLevel.High,     "GTA Online Sitzung in RPH-Log"),
        ("Loading plugin",                  RiskLevel.Medium,   "Plugin-Laden im RPH-Log"),
        ("MoneyDrop",                       RiskLevel.Critical, "MoneyDrop-Aktivität in RPH-Log"),
        ("GodMode enabled",                 RiskLevel.Critical, "GodMode-Aktivierung in RPH-Log"),
        ("Teleport",                        RiskLevel.High,     "Teleport-Aktivität in RPH-Log"),
        ("bypass",                          RiskLevel.Critical, "Bypass-Aktivität in RPH-Log"),
        ("anticheat killed",                RiskLevel.Critical, "Anti-Cheat wurde in RPH-Log getötet"),
        ("anticheat triggered",             RiskLevel.Critical, "Anti-Cheat ausgelöst (vor Bypass)"),
        ("IntegrityCheck failed",           RiskLevel.Critical, "Integritätsprüfung gescheitert"),
        ("BattlEye",                        RiskLevel.Critical, "BattlEye-Referenz in RPH-Log"),
        ("Rockstar AC",                     RiskLevel.Critical, "Rockstar Anti-Cheat in RPH-Log"),
        ("FiveM detected",                  RiskLevel.Critical, "FiveM-Erkennung in RPH-Log (RPH+FiveM)"),
        ("CitizenFX",                       RiskLevel.High,     "CitizenFX-Referenz in RPH-Log"),
        ("Money added",                     RiskLevel.Critical, "Geld hinzugefügt (RPH-Log)"),
        ("Vehicle spawned",                 RiskLevel.High,     "Fahrzeug gespawnt (RPH-Log)"),
        ("Weapon given",                    RiskLevel.High,     "Waffe gegeben (RPH-Log)"),
        ("Player spawned",                  RiskLevel.High,     "Spieler gespawnt (RPH-Log)"),
        ("WantedLevel set to 0",            RiskLevel.High,     "Fahndungslevel auf 0 gesetzt (RPH-Log)"),
        ("Network hook",                    RiskLevel.Critical, "Netzwerk-Hook in RPH-Log"),
        ("Packet modified",                 RiskLevel.Critical, "Paket modifiziert (RPH-Log)"),
        ("recovery tool",                   RiskLevel.Critical, "Recovery-Tool in RPH-Log"),
        ("online money",                    RiskLevel.Critical, "Online-Geld-Referenz in RPH-Log"),
        ("modding online",                  RiskLevel.Critical, "Online-Modding in RPH-Log"),
        ("Error: Anti-Cheat",               RiskLevel.Critical, "Anti-Cheat-Fehler in RPH-Log (Trigger vor Bypass)"),
        ("Crash: Anti-Cheat",               RiskLevel.Critical, "Anti-Cheat-Crash in RPH-Log"),
        ("kicked by",                       RiskLevel.High,     "Kick-Ereignis in RPH-Log"),
        ("banned",                          RiskLevel.High,     "Bann-Ereignis in RPH-Log"),
        ("Detected by",                     RiskLevel.Critical, "Erkennungs-Ereignis in RPH-Log"),
        ("Aimbot",                          RiskLevel.Critical, "Aimbot-Referenz in RPH-Log"),
        ("ESP active",                      RiskLevel.Critical, "ESP-Aktivität in RPH-Log"),
    };

    // ── ASI loader detection patterns ──
    private static readonly string[] KnownAsiLoaderNames =
    {
        "dinput8.dll", "dsound.dll", "winmm.dll", "version.dll",
        "xinput9_1_0.dll", "d3d11.dll", "d3d10.dll",
        "ScriptHookV.dll", "ScriptHookVDotNet.dll", "ScriptHookVDotNet2.dll",
        "ScriptHookVDotNet3.dll",
        "asiloader.dll", "asi_loader.dll",
        "xliveless.dll",
        "OpenIV.ASI",
    };

    // ── RPH network hook plugin patterns ──
    private static readonly (string pattern, RiskLevel risk, string reason)[] NetworkHookPatterns =
    {
        ("NetworkSendPacket",               RiskLevel.Critical, "Netzwerk-Paket-Sende-Hook"),
        ("NetworkReceivePacket",            RiskLevel.Critical, "Netzwerk-Paket-Empfangs-Hook"),
        ("PacketHook",                      RiskLevel.Critical, "Paket-Hook-Referenz"),
        ("packet_hook",                     RiskLevel.Critical, "Paket-Hook-Referenz (Unterstrich)"),
        ("ModifyPacket",                    RiskLevel.Critical, "Paket-Modifikations-Funktion"),
        ("InjectPacket",                    RiskLevel.Critical, "Paket-Injektions-Funktion"),
        ("SpoofPacket",                     RiskLevel.Critical, "Paket-Spoofing-Funktion"),
        ("NetworkOverride",                 RiskLevel.Critical, "Netzwerk-Überschreibung"),
        ("SessionOverride",                 RiskLevel.Critical, "Session-Überschreibung"),
        ("rage::netEvent",                  RiskLevel.Critical, "RAGE Netzwerk-Event-Zugriff"),
        ("CNetworkSession",                 RiskLevel.Critical, "Netzwerk-Session-Klassen-Zugriff"),
        ("netObject",                       RiskLevel.High,     "Netzwerk-Objekt-Referenz"),
        ("syncTree",                        RiskLevel.High,     "Sync-Baum-Referenz (Netzwerk-Sync)"),
        ("netSyncTree",                     RiskLevel.High,     "Netzwerk-Sync-Baum-Referenz"),
        ("CNetObjPlayer",                   RiskLevel.High,     "Netzwerk-Spieler-Objekt-Zugriff"),
        ("gamer_handle",                    RiskLevel.High,     "Gamer-Handle-Manipulation"),
        ("NETWORK_GET_HOST_OF_SCRIPT",      RiskLevel.High,     "Host-Prüfung (Cheat-Muster)"),
        ("NETWORK_SESSION_GET_PRIVATE_SLOTS", RiskLevel.High,   "Private-Slot-Abfrage"),
        ("NetworkCloneObject",              RiskLevel.High,     "Netzwerk-Objekt-Klon"),
        ("SendScriptEvent",                 RiskLevel.High,     "Script-Event-Versand (Griefing)"),
        ("TriggerRemoteEvent",              RiskLevel.High,     "Remote-Event-Auslösung"),
        ("NETWORK_SEND_INVITE",             RiskLevel.High,     "Einladungs-Versand (Spam-Angriff)"),
        ("IPAddress",                       RiskLevel.High,     "IP-Adress-Abfrage (Deanonymisierung)"),
    };

    // ── Money drop / recovery artifact patterns ──
    private static readonly (string pattern, RiskLevel risk, string reason)[] MoneyDropPatterns =
    {
        ("moneyDrop",                       RiskLevel.Critical, "MoneyDrop-Funktion"),
        ("money_drop",                      RiskLevel.Critical, "MoneyDrop-Funktion (Unterstrich)"),
        ("GIVE_PLAYER_MONEY",               RiskLevel.Critical, "GIVE_PLAYER_MONEY-Native-Aufruf"),
        ("WALLET_BALANCE",                  RiskLevel.Critical, "Wallet-Balance-Manipulation"),
        ("STAT_SET_INT.*MONEY",             RiskLevel.Critical, "Money-Stat-Manipulation"),
        ("addCash",                         RiskLevel.Critical, "AddCash-Funktion"),
        ("setCash",                         RiskLevel.Critical, "SetCash-Funktion"),
        ("recovery_tool",                   RiskLevel.Critical, "Recovery-Tool-Referenz"),
        ("recoveryTool",                    RiskLevel.Critical, "RecoveryTool-Referenz"),
        ("money_lobby",                     RiskLevel.Critical, "Money-Lobby-Referenz"),
        ("cash_lobby",                      RiskLevel.Critical, "Cash-Lobby-Referenz"),
        ("modded_lobby",                    RiskLevel.Critical, "Modded-Lobby-Referenz"),
        ("MPPLY_BANK_BALANCE",              RiskLevel.Critical, "Bank-Balance-STAT-Manipulation"),
        ("MPPLY_WALLET_BALANCE",            RiskLevel.Critical, "Wallet-Balance-STAT-Manipulation"),
        ("SET_FAKE_STAT",                   RiskLevel.Critical, "Fake-STAT-Setzung"),
        ("STATS_SET_INT",                   RiskLevel.High,     "STATS_SET_INT-Aufruf"),
        ("stats_set_float",                 RiskLevel.High,     "STATS_SET_FLOAT-Aufruf"),
        ("GLOBAL_MONEY",                    RiskLevel.Critical, "Globale Geld-Variable"),
        ("global_offset",                   RiskLevel.High,     "Globaler Offset-Zugriff (Script-Variable-Hack)"),
        ("script_global",                   RiskLevel.High,     "Script-Global-Variable-Zugriff"),
        ("SCRIPT_THREAD_MONEY",             RiskLevel.Critical, "Script-Thread-Geld-Manipulation"),
        ("moneydrop_notify",                RiskLevel.Critical, "MoneyDrop-Benachrichtigung"),
        ("drop_cash",                       RiskLevel.Critical, "Drop-Cash-Funktion"),
        ("throw_money",                     RiskLevel.Critical, "Throw-Money-Funktion"),
        ("request_model.*briefcase",        RiskLevel.High,     "Koffer-Modell angefordert (MoneyDrop-Objekt)"),
        ("cash_collect",                    RiskLevel.High,     "Cash-Collect-Funktion"),
        ("collectible_money",               RiskLevel.High,     "Sammelbare-Geld-Referenz"),
        ("online_recovery",                 RiskLevel.Critical, "Online-Recovery-Referenz"),
        ("rank_bypass",                     RiskLevel.Critical, "Rang-Bypass-Referenz"),
        ("unlock_all",                      RiskLevel.Critical, "Unlock-All-Funktion"),
        ("CHAR_KIT",                        RiskLevel.High,     "Character-Kit-Manipulation"),
    };

    // ── RPH-based GTA Online bypass patches ──
    private static readonly (string pattern, RiskLevel risk, string reason)[] OnlineBypassPatterns =
    {
        ("PatchOnlineCheck",                RiskLevel.Critical, "Online-Prüfungs-Patch"),
        ("patch_anticheat",                 RiskLevel.Critical, "Anti-Cheat-Patch"),
        ("NOP_anticheat",                   RiskLevel.Critical, "Anti-Cheat-NOP-Patch"),
        ("NOP_integrity",                   RiskLevel.Critical, "Integritätsprüfungs-NOP-Patch"),
        ("bypass_rockstar",                 RiskLevel.Critical, "Rockstar-Bypass"),
        ("BYPASS_BANWAVE",                  RiskLevel.Critical, "Banwellen-Bypass"),
        ("PatchBanWave",                    RiskLevel.Critical, "Banwellen-Patch"),
        ("DisableBans",                     RiskLevel.Critical, "Bann-Deaktivierung"),
        ("SpoofRID",                        RiskLevel.Critical, "RID-Spoofing (Anonymisierung)"),
        ("SpoofIP",                         RiskLevel.Critical, "IP-Spoofing"),
        ("SpoofSCID",                       RiskLevel.Critical, "Social-Club-ID-Spoofing"),
        ("SpoofGamerTag",                   RiskLevel.Critical, "GamerTag-Spoofing"),
        ("HideCheat",                       RiskLevel.Critical, "Cheat-Verbergungs-Funktion"),
        ("AntiDetection",                   RiskLevel.Critical, "Anti-Erkennungs-Maßnahme"),
        ("evasion",                         RiskLevel.High,     "Ausweichungs-Logik"),
        ("Patcher",                         RiskLevel.High,     "Patcher-Referenz"),
        ("PatchMemory",                     RiskLevel.Critical, "Speicher-Patch-Funktion"),
        ("WriteProtectedMemory",            RiskLevel.Critical, "Schreibgeschützter-Speicher-Patch"),
        ("ForceSession",                    RiskLevel.High,     "Session-Erzwingungs-Funktion"),
        ("ForceFreemode",                   RiskLevel.High,     "Freimodus-Erzwingung"),
        ("FORCE_LOAD_SCRIPT",               RiskLevel.High,     "Script-Ladeverzwingung"),
        ("SkipAuthentication",              RiskLevel.Critical, "Authentifizierungs-Übersprung"),
        ("BypassAuthentication",            RiskLevel.Critical, "Authentifizierungs-Bypass"),
        ("bypass_sc",                       RiskLevel.Critical, "Social-Club-Bypass"),
        ("bypass_launcher",                 RiskLevel.Critical, "Launcher-Bypass"),
        ("CrackOnline",                     RiskLevel.Critical, "Online-Crack"),
        ("online_crack",                    RiskLevel.Critical, "Online-Crack-Referenz"),
    };

    // ── RPH console command cheat history patterns ──
    private static readonly (string pattern, RiskLevel risk, string reason)[] ConsoleCommandPatterns =
    {
        ("setmoney",                        RiskLevel.Critical, "SetMoney-Befehl in RPH-Konsole"),
        ("addmoney",                        RiskLevel.Critical, "AddMoney-Befehl in RPH-Konsole"),
        ("givemoney",                       RiskLevel.Critical, "GiveMoney-Befehl in RPH-Konsole"),
        ("godmode",                         RiskLevel.Critical, "GodMode-Befehl in RPH-Konsole"),
        ("god",                             RiskLevel.High,     "God-Befehl in RPH-Konsole"),
        ("noclip",                          RiskLevel.High,     "NoClip-Befehl in RPH-Konsole"),
        ("teleport",                        RiskLevel.High,     "Teleport-Befehl in RPH-Konsole"),
        ("spawnvehicle",                    RiskLevel.High,     "SpawnVehicle-Befehl in RPH-Konsole"),
        ("spawncar",                        RiskLevel.High,     "SpawnCar-Befehl in RPH-Konsole"),
        ("maxwanted=0",                     RiskLevel.High,     "MaxWanted=0 in RPH-Konsole"),
        ("neverwanted",                     RiskLevel.High,     "NeverWanted-Befehl in RPH-Konsole"),
        ("giveweapon",                      RiskLevel.High,     "GiveWeapon-Befehl in RPH-Konsole"),
        ("setammo",                         RiskLevel.High,     "SetAmmo-Befehl in RPH-Konsole"),
        ("infiniteammo",                    RiskLevel.High,     "InfiniteAmmo-Befehl in RPH-Konsole"),
        ("setrank",                         RiskLevel.Critical, "SetRank-Befehl in RPH-Konsole"),
        ("setlevel",                        RiskLevel.Critical, "SetLevel-Befehl in RPH-Konsole"),
        ("unlockalldlc",                    RiskLevel.Critical, "UnlockAllDLC-Befehl in RPH-Konsole"),
        ("recovery",                        RiskLevel.Critical, "Recovery-Befehl in RPH-Konsole"),
        ("moneydrop",                       RiskLevel.Critical, "MoneyDrop-Befehl in RPH-Konsole"),
        ("dropbriefcase",                   RiskLevel.Critical, "DropBriefcase-Befehl in RPH-Konsole"),
        ("aimbot",                          RiskLevel.Critical, "Aimbot-Befehl in RPH-Konsole"),
        ("spinbot",                         RiskLevel.Critical, "SpinBot-Befehl in RPH-Konsole"),
        ("forcehost",                       RiskLevel.High,     "ForceHost-Befehl in RPH-Konsole"),
        ("kickall",                         RiskLevel.Critical, "KickAll-Befehl in RPH-Konsole"),
        ("kickplayer",                      RiskLevel.Critical, "KickPlayer-Befehl in RPH-Konsole"),
        ("crashplayer",                     RiskLevel.Critical, "CrashPlayer-Befehl in RPH-Konsole"),
        ("freezeplayer",                    RiskLevel.High,     "FreezePlayer-Befehl in RPH-Konsole"),
        ("reportplayer",                    RiskLevel.High,     "ReportPlayer-Befehl (Griefing-Tool)"),
        ("orbital_cannon",                  RiskLevel.High,     "OrbitalCannon-Missbrauch-Befehl"),
        ("send_to_island",                  RiskLevel.High,     "SendToIsland-Befehl (Griefing)"),
        ("blow_up_cars",                    RiskLevel.High,     "BlowUpCars-Befehl (Griefing)"),
    };

    // ── FiveM-specific RPH abuse patterns ──
    private static readonly (string pattern, RiskLevel risk, string reason)[] FiveMRphAbusePatterns =
    {
        ("FiveM",                           RiskLevel.High,     "FiveM-Referenz in RPH-Kontext"),
        ("CitizenFX",                       RiskLevel.High,     "CitizenFX-Referenz in RPH-Plugin"),
        ("cfx://",                          RiskLevel.High,     "CFX-Protokoll in RPH-Plugin"),
        ("fivem_bypass",                    RiskLevel.Critical, "FiveM-Bypass in RPH-Plugin"),
        ("cfx_bypass",                      RiskLevel.Critical, "CFX-Bypass in RPH-Plugin"),
        ("FiveMAntiCheat",                  RiskLevel.Critical, "FiveM-Anti-Cheat-Referenz"),
        ("cfx_anticheat",                   RiskLevel.Critical, "CFX-Anti-Cheat in RPH-Plugin"),
        ("rage::scrThread",                 RiskLevel.Critical, "RAGE Script-Thread (tiefer Speicherzugriff)"),
        ("NativeCallContext",               RiskLevel.High,     "Native-Aufruf-Kontext (Script-Hook-Muster)"),
        ("SHVDN",                           RiskLevel.High,     "ScriptHookVDotNet-Referenz in RPH"),
        ("RPH+FiveM",                       RiskLevel.Critical, "Kombinierter RPH+FiveM-Angriff"),
        ("rph_fivem",                       RiskLevel.Critical, "RPH-FiveM-Kombinations-Plugin"),
        ("dual_hook",                       RiskLevel.Critical, "Dual-Hook-Konfiguration (RPH+SHV)"),
        ("hook_fivem",                      RiskLevel.Critical, "FiveM-Hook-Aktivierung via RPH"),
        ("inject_fivem",                    RiskLevel.Critical, "FiveM-Injektions-Plugin für RPH"),
    };

    // ── Registry keys for RPH ──
    private static readonly string[] RphRegistryKeys =
    {
        @"SOFTWARE\RagePluginHook",
        @"SOFTWARE\WOW6432Node\RagePluginHook",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RagePluginHook",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, "RagePluginHook", "Starte Scan...");

        var gtaVPaths = DiscoverGtaVPaths();

        if (gtaVPaths.Count == 0)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "GTA V nicht in Standardpfaden gefunden",
                Risk = RiskLevel.Low,
                Location = "GTA V Installationspfad",
                Reason = "GTA V wurde in keinem bekannten Standardpfad gefunden. " +
                         "RagePluginHook-spezifische Prüfungen wurden übersprungen. " +
                         "Falls GTA V an einem nicht-standardmäßigen Ort installiert ist, kann dies ein Fehlalarm sein.",
                Detail = "Geprüfte Pfade: " + string.Join(", ", GtaVSearchPaths.Take(4)) + " ..."
            });
            ctx.Report(1.0, "GTA V nicht gefunden", "Scan übersprungen");
            return;
        }

        foreach (var gtaPath in gtaVPaths)
        {
            ct.ThrowIfCancellationRequested();

            await ScanRphExecutable(ctx, gtaPath, ct);
            ctx.Report(0.12, "RPH-Executable", "RPH-Binary geprüft");

            await ScanRphPluginDirectory(ctx, gtaPath, ct);
            ctx.Report(0.24, "RPH-Plugins", "Plugin-Verzeichnis geprüft");

            await ScanRphConfigFiles(ctx, gtaPath, ct);
            ctx.Report(0.34, "RPH-Config", "Konfigurationsdateien geprüft");

            await ScanRphLogFiles(ctx, gtaPath, ct);
            ctx.Report(0.45, "RPH-Logs", "Log-Dateien geprüft");

            ScanAsiLoaderPresence(ctx, gtaPath, ct);
            ctx.Report(0.54, "ASI-Loader", "ASI-Loader geprüft");

            await ScanNetworkHookPlugins(ctx, gtaPath, ct);
            ctx.Report(0.62, "Netzwerk-Hook-Plugins", "Netzwerk-Hooks geprüft");

            await ScanMoneyDropArtifacts(ctx, gtaPath, ct);
            ctx.Report(0.70, "MoneyDrop-Artefakte", "MoneyDrop geprüft");

            await ScanOnlineBypassPlugins(ctx, gtaPath, ct);
            ctx.Report(0.78, "Online-Bypass-Plugins", "Online-Bypass geprüft");
        }

        ScanRphProcesses(ctx, ct);
        ctx.Report(0.86, "RPH-Prozesse", "Prozesse geprüft");

        ScanRphRegistryEntries(ctx, ct);
        ctx.Report(0.92, "RPH-Registry", "Registry geprüft");

        await ScanConsoleCommandHistory(ctx, gtaVPaths, ct);
        ctx.Report(1.0, "Konsolen-Verlauf", "Scan abgeschlossen");
    }

    private static List<string> DiscoverGtaVPaths()
    {
        var found = new List<string>();
        foreach (var candidate in GtaVSearchPaths)
        {
            if (Directory.Exists(candidate))
                found.Add(candidate);
        }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\WOW6432Node\Rockstar Games\Grand Theft Auto V");
            var installPath = key?.GetValue("InstallFolder")?.ToString();
            if (!string.IsNullOrEmpty(installPath) && Directory.Exists(installPath) &&
                !found.Contains(installPath, StringComparer.OrdinalIgnoreCase))
                found.Add(installPath);
        }
        catch { }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Rockstar Games\Grand Theft Auto V");
            var installPath = key?.GetValue("InstallFolder")?.ToString();
            if (!string.IsNullOrEmpty(installPath) && Directory.Exists(installPath) &&
                !found.Contains(installPath, StringComparer.OrdinalIgnoreCase))
                found.Add(installPath);
        }
        catch { }

        return found;
    }

    private async Task ScanRphExecutable(ScanContext ctx, string gtaPath, CancellationToken ct)
    {
        var rphExePath = Path.Combine(gtaPath, "RagePluginHook.exe");
        if (!File.Exists(rphExePath)) return;

        ctx.IncrementFiles();

        var sig = SignatureChecker.IsCheckable(rphExePath)
            ? SignatureChecker.CheckDetailed(rphExePath)
            : default;

        ctx.AddFinding(new Finding
        {
            Module = Name,
            Title = "RagePluginHook.exe im GTA-V-Verzeichnis gefunden",
            Risk = RiskLevel.High,
            Location = rphExePath,
            FileName = "RagePluginHook.exe",
            Sha256 = HashUtil.TryComputeSha256(rphExePath, ctx.Options.MaxHashFileSizeBytes),
            Signed = sig.IsTrusted,
            Reason = "RagePluginHook.exe ist im GTA-V-Verzeichnis vorhanden. RPH ist ein Plugin-Framework, " +
                     "das tiefen Eingriff in GTA V ermöglicht. Es wird für viele legitime Mods (LSPDFR) " +
                     "genutzt, aber auch als Grundlage für GTA-Online-Cheats missbraucht. " +
                     "Prüfe die installierten Plugins im Plugins/-Verzeichnis.",
            Detail = $"Pfad: {rphExePath} | Signierer: {sig.Signer ?? "unsigniert"}"
        });

        string content;
        try
        {
            using var fs = new FileStream(rphExePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs, Encoding.Latin1);
            content = await sr.ReadToEndAsync(ct);
        }
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }

        foreach (var (pattern, risk, reason) in OnlineBypassPatterns)
        {
            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"RPH-Executable enthält Online-Bypass-Muster: {pattern}",
                    Risk = RiskLevel.Critical,
                    Location = rphExePath,
                    FileName = "RagePluginHook.exe",
                    Sha256 = HashUtil.TryComputeSha256(rphExePath, ctx.Options.MaxHashFileSizeBytes),
                    Reason = $"RagePluginHook.exe enthält Online-Bypass-Muster '{pattern}': {reason}. " +
                             "Diese Muster in der RPH-Binary selbst deuten auf eine modifizierte " +
                             "Version hin, die explizit für GTA-Online-Cheats angepasst wurde.",
                    Detail = $"Muster: {pattern}"
                });
                break;
            }
        }
    }

    private async Task ScanRphPluginDirectory(ScanContext ctx, string gtaPath, CancellationToken ct)
    {
        var pluginsDir = Path.Combine(gtaPath, "Plugins");
        if (!Directory.Exists(pluginsDir)) return;

        string[] pluginFiles;
        try { pluginFiles = Directory.GetFiles(pluginsDir, "*.dll", SearchOption.AllDirectories); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var pluginFile in pluginFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileNameWithoutExtension(pluginFile).ToLowerInvariant();
            bool isLspdfrOrLegit = IsKnownLegitRphPlugin(fileName);

            foreach (var (pluginName, risk, reason) in RphCheatPluginNames)
            {
                if (fileName.Contains(pluginName, StringComparison.OrdinalIgnoreCase))
                {
                    var sig = SignatureChecker.IsCheckable(pluginFile)
                        ? SignatureChecker.CheckDetailed(pluginFile)
                        : default;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"RPH-Cheat-Plugin erkannt: {Path.GetFileName(pluginFile)}",
                        Risk = risk,
                        Location = pluginFile,
                        FileName = Path.GetFileName(pluginFile),
                        Sha256 = HashUtil.TryComputeSha256(pluginFile, ctx.Options.MaxHashFileSizeBytes),
                        Signed = sig.IsTrusted,
                        Reason = $"RPH-Plugin '{Path.GetFileName(pluginFile)}' entspricht bekanntem Cheat-Plugin-Namen " +
                                 $"'{pluginName}': {reason}. Dieser Plugin-Name ist typisch für GTA-V/Online-Cheats, " +
                                 "die über das RagePluginHook-Framework ausgeführt werden.",
                        Detail = $"Pfad: {pluginFile} | Legitim: {isLspdfrOrLegit}"
                    });
                    break;
                }
            }

            string content;
            try
            {
                using var fs = new FileStream(pluginFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs, Encoding.Latin1);
                content = await sr.ReadToEndAsync(ct);
            }
            catch (IOException) { continue; }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var (pattern, risk, reason) in NetworkHookPatterns)
            {
                if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Netzwerk-Hook-Artefakt in RPH-Plugin: {Path.GetFileName(pluginFile)}",
                        Risk = risk,
                        Location = pluginFile,
                        FileName = Path.GetFileName(pluginFile),
                        Sha256 = HashUtil.TryComputeSha256(pluginFile, ctx.Options.MaxHashFileSizeBytes),
                        Reason = $"RPH-Plugin '{Path.GetFileName(pluginFile)}' enthält Netzwerk-Hook-Muster " +
                                 $"'{pattern}': {reason}. Netzwerk-Hook-Plugins manipulieren GTA-Online-Pakete " +
                                 "direkt, um Anti-Cheat-Erkennung zu umgehen oder andere Spieler zu stören.",
                        Detail = $"Muster: {pattern}"
                    });
                    break;
                }
            }

            foreach (var (pattern, risk, reason) in MoneyDropPatterns)
            {
                if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"MoneyDrop-Artefakt in RPH-Plugin: {Path.GetFileName(pluginFile)}",
                        Risk = risk,
                        Location = pluginFile,
                        FileName = Path.GetFileName(pluginFile),
                        Sha256 = HashUtil.TryComputeSha256(pluginFile, ctx.Options.MaxHashFileSizeBytes),
                        Reason = $"RPH-Plugin '{Path.GetFileName(pluginFile)}' enthält MoneyDrop/Recovery-Muster " +
                                 $"'{pattern}': {reason}. Diese Muster treten in GTA-Online-Geld-Exploit-Plugins auf, " +
                                 "die illegitimes Geld erzeugen oder an andere Spieler verteilen.",
                        Detail = $"Muster: {pattern}"
                    });
                    break;
                }
            }

            foreach (var (pattern, risk, reason) in FiveMRphAbusePatterns)
            {
                if (!isLspdfrOrLegit && content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"RPH+FiveM-Kombinations-Plugin: {Path.GetFileName(pluginFile)}",
                        Risk = risk,
                        Location = pluginFile,
                        FileName = Path.GetFileName(pluginFile),
                        Sha256 = HashUtil.TryComputeSha256(pluginFile, ctx.Options.MaxHashFileSizeBytes),
                        Reason = $"RPH-Plugin '{Path.GetFileName(pluginFile)}' enthält FiveM-Referenz '{pattern}': {reason}. " +
                                 "Plugins, die sowohl RPH als auch FiveM referenzieren, können genutzt werden, " +
                                 "um RPH-Fähigkeiten innerhalb von FiveM-Sitzungen zu aktivieren.",
                        Detail = $"Muster: {pattern}"
                    });
                    break;
                }
            }
        }
    }

    private async Task ScanRphConfigFiles(ScanContext ctx, string gtaPath, CancellationToken ct)
    {
        var configPaths = new[]
        {
            Path.Combine(gtaPath, "RagePluginHook.ini"),
            Path.Combine(gtaPath, "RagePluginHook.xml"),
            Path.Combine(gtaPath, "RagePluginHook.cfg"),
            Path.Combine(gtaPath, "Plugins", "LSPDFR", "LSPDFR.ini"),
        };

        foreach (var configPath in configPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!File.Exists(configPath)) continue;
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(configPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct);
            }
            catch (IOException) { continue; }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var (pattern, risk, reason) in RphConfigPatterns)
            {
                if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdächtige RPH-Konfiguration: {Path.GetFileName(configPath)}",
                        Risk = risk,
                        Location = configPath,
                        FileName = Path.GetFileName(configPath),
                        Reason = $"RPH-Konfigurationsdatei '{Path.GetFileName(configPath)}' enthält verdächtiges Muster " +
                                 $"'{pattern}': {reason}. Diese Konfigurationseinstellungen deaktivieren explizit " +
                                 "Anti-Cheat-Mechanismen oder aktivieren bekannte Cheat-Funktionen.",
                        Detail = $"Muster: {pattern}"
                    });
                    break;
                }
            }
        }
    }

    private async Task ScanRphLogFiles(ScanContext ctx, string gtaPath, CancellationToken ct)
    {
        var logFiles = new[]
        {
            Path.Combine(gtaPath, "RagePluginHook.log"),
            Path.Combine(gtaPath, "RagePluginHook_crash.log"),
            Path.Combine(gtaPath, "RagePluginHook_old.log"),
            Path.Combine(gtaPath, "Plugins", "LSPDFR", "LSPDFR.log"),
        };

        foreach (var logFile in logFiles)
        {
            ct.ThrowIfCancellationRequested();
            if (!File.Exists(logFile)) continue;
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct);
            }
            catch (IOException) { continue; }
            catch (UnauthorizedAccessException) { continue; }

            var matchedPatterns = new List<(string pattern, RiskLevel risk, string reason)>();

            foreach (var entry in RphLogPatterns)
            {
                if (content.Contains(entry.pattern, StringComparison.OrdinalIgnoreCase))
                    matchedPatterns.Add(entry);
            }

            foreach (var (pattern, risk, reason) in matchedPatterns)
            {
                if (risk < RiskLevel.High) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Verdächtiger RPH-Log-Eintrag: '{pattern}'",
                    Risk = risk,
                    Location = logFile,
                    FileName = Path.GetFileName(logFile),
                    Reason = $"RPH-Logdatei '{Path.GetFileName(logFile)}' enthält verdächtigen Eintrag '{pattern}': {reason}. " +
                             "RPH-Logs protokollieren Plugin-Aktivitäten; Einträge zu Online-Sitzungen mit geladenen " +
                             "Cheat-Plugins oder Anti-Cheat-Auslösungen sind starke Indikatoren für aktives Cheating.",
                    Detail = $"Muster: {pattern} | Log: {Path.GetFileName(logFile)}"
                });
            }

            bool hasOnlineSession = content.Contains("online session", StringComparison.OrdinalIgnoreCase)
                || content.Contains("GTA:Online", StringComparison.OrdinalIgnoreCase)
                || content.Contains("GTA Online", StringComparison.OrdinalIgnoreCase);

            bool hasCheatPlugins = content.Contains("MoneyDrop", StringComparison.OrdinalIgnoreCase)
                || content.Contains("GodMode", StringComparison.OrdinalIgnoreCase)
                || content.Contains("Aimbot", StringComparison.OrdinalIgnoreCase)
                || content.Contains("bypass", StringComparison.OrdinalIgnoreCase);

            if (hasOnlineSession && hasCheatPlugins)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "RPH-Log zeigt Online-Session mit geladenen Cheat-Plugins",
                    Risk = RiskLevel.Critical,
                    Location = logFile,
                    FileName = Path.GetFileName(logFile),
                    Reason = "RPH-Logdatei zeigt, dass RagePluginHook in einer GTA-Online-Sitzung aktiv war " +
                             "und gleichzeitig Cheat-Plugins (MoneyDrop/GodMode/Aimbot/Bypass) geladen waren. " +
                             "Dies ist das stärkste Signal für aktives Online-Cheating via RPH.",
                    Detail = "Kombination: Online-Session + Cheat-Plugin-Aktivität erkannt"
                });
            }
        }
    }

    private void ScanAsiLoaderPresence(ScanContext ctx, string gtaPath, CancellationToken ct)
    {
        bool hasAsiLoader = false;
        bool hasRph = File.Exists(Path.Combine(gtaPath, "RagePluginHook.exe"));
        var foundAsiLoaders = new List<string>();

        foreach (var loaderName in KnownAsiLoaderNames)
        {
            ct.ThrowIfCancellationRequested();
            var loaderPath = Path.Combine(gtaPath, loaderName);
            if (!File.Exists(loaderPath)) continue;

            ctx.IncrementFiles();
            hasAsiLoader = true;
            foundAsiLoaders.Add(loaderName);

            bool isMicrosoftOrKnown = loaderName.Equals("dinput8.dll", StringComparison.OrdinalIgnoreCase)
                || loaderName.Equals("dsound.dll", StringComparison.OrdinalIgnoreCase)
                || loaderName.Equals("winmm.dll", StringComparison.OrdinalIgnoreCase)
                || loaderName.Equals("version.dll", StringComparison.OrdinalIgnoreCase);

            if (isMicrosoftOrKnown)
            {
                var sig = SignatureChecker.IsCheckable(loaderPath)
                    ? SignatureChecker.CheckDetailed(loaderPath)
                    : default;

                if (!sig.IsTrusted)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Nicht-Microsoft-{loaderName} im GTA-V-Verzeichnis (ASI-Loader)",
                        Risk = RiskLevel.High,
                        Location = loaderPath,
                        FileName = loaderName,
                        Sha256 = HashUtil.TryComputeSha256(loaderPath, ctx.Options.MaxHashFileSizeBytes),
                        Signed = sig.IsTrusted,
                        Reason = $"'{loaderName}' im GTA-V-Verzeichnis ist nicht von Microsoft signiert. " +
                                 "Diese System-DLLs werden häufig durch ASI-Loader ersetzt, die dann beliebige " +
                                 ".asi-Plugins laden und als Injection-Einstiegspunkt für Cheats dienen.",
                        Detail = sig.Signer is not null ? $"Signierer: {sig.Signer}" : "Unsigniert"
                    });
                }
            }
        }

        if (hasAsiLoader && hasRph && foundAsiLoaders.Count > 0)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "ASI-Loader + RagePluginHook Kombination erkannt",
                Risk = RiskLevel.High,
                Location = gtaPath,
                FileName = "RagePluginHook.exe",
                Reason = $"Sowohl ASI-Loader ({string.Join(", ", foundAsiLoaders)}) als auch RagePluginHook.exe " +
                         "sind im GTA-V-Verzeichnis vorhanden. Diese Kombination erlaubt das Laden von .asi-Plugins " +
                         "UND RPH-Plugins gleichzeitig, was den Umfang möglicher Cheat-Eingriffe erheblich erhöht.",
                Detail = $"ASI-Loader: {string.Join(", ", foundAsiLoaders)} | RPH: vorhanden"
            });
        }

        bool hasScriptHookV = File.Exists(Path.Combine(gtaPath, "ScriptHookV.dll"));
        if (hasScriptHookV && hasRph)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "ScriptHookV + RagePluginHook Dual-Hook erkannt",
                Risk = RiskLevel.High,
                Location = gtaPath,
                FileName = "ScriptHookV.dll",
                Sha256 = HashUtil.TryComputeSha256(Path.Combine(gtaPath, "ScriptHookV.dll"),
                                                    ctx.Options.MaxHashFileSizeBytes),
                Reason = "ScriptHookV und RagePluginHook sind gleichzeitig installiert. Diese Kombination " +
                         "(Dual-Hook) ermöglicht tiefere Eingriffe in GTA V: ScriptHookV gibt Zugriff auf " +
                         "natives, RPH auf das Plugin-System. Viele komplexe Cheat-Tools nutzen beide Hooks.",
                Detail = "Dual-Hook: ScriptHookV.dll + RagePluginHook.exe"
            });
        }
    }

    private async Task ScanNetworkHookPlugins(ScanContext ctx, string gtaPath, CancellationToken ct)
    {
        var networkPluginPaths = new[]
        {
            Path.Combine(gtaPath, "Plugins"),
            Path.Combine(gtaPath, "scripts"),
            Path.Combine(gtaPath, "mods"),
        };

        foreach (var pluginPath in networkPluginPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(pluginPath)) continue;

            string[] dllFiles;
            try { dllFiles = Directory.GetFiles(pluginPath, "*.dll", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var dll in dllFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(dll, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.Latin1);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                int networkPatternCount = 0;
                var networkMatches = new List<string>();

                foreach (var (pattern, risk, reason) in NetworkHookPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        networkPatternCount++;
                        networkMatches.Add(pattern);
                        if (networkPatternCount >= 3) break;
                    }
                }

                if (networkPatternCount >= 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Netzwerk-Hook-Plugin mit mehreren Indikatoren: {Path.GetFileName(dll)}",
                        Risk = networkPatternCount >= 3 ? RiskLevel.Critical : RiskLevel.High,
                        Location = dll,
                        FileName = Path.GetFileName(dll),
                        Sha256 = HashUtil.TryComputeSha256(dll, ctx.Options.MaxHashFileSizeBytes),
                        Reason = $"Plugin '{Path.GetFileName(dll)}' enthält {networkPatternCount} Netzwerk-Hook-Muster: " +
                                 $"{string.Join(", ", networkMatches)}. Netzwerk-Hook-Plugins manipulieren den " +
                                 "GTA-Online-Netzwerkverkehr direkt, um Anti-Cheat-Erkennungen zu umgehen " +
                                 "oder anderen Spielern Schaden zuzufügen.",
                        Detail = $"Netzwerk-Muster ({networkPatternCount}): {string.Join(", ", networkMatches)}"
                    });
                }
            }
        }
    }

    private async Task ScanMoneyDropArtifacts(ScanContext ctx, string gtaPath, CancellationToken ct)
    {
        var moneyDropSearchPaths = new[]
        {
            gtaPath,
            Path.Combine(gtaPath, "Plugins"),
            Path.Combine(gtaPath, "scripts"),
        };

        foreach (var searchPath in moneyDropSearchPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(searchPath)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(searchPath, "*.dll", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(searchPath, "*.cs", SearchOption.AllDirectories))
                    .Concat(Directory.EnumerateFiles(searchPath, "*.ini", SearchOption.AllDirectories));
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.Latin1);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var (pattern, risk, reason) in MoneyDropPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"MoneyDrop/Recovery-Artefakt: {Path.GetFileName(file)}",
                            Risk = risk,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Sha256 = HashUtil.TryComputeSha256(file, ctx.Options.MaxHashFileSizeBytes),
                            Reason = $"Datei '{Path.GetFileName(file)}' enthält MoneyDrop/Recovery-Muster '{pattern}': {reason}. " +
                                     "Diese Muster treten in Scripts auf, die GTA-Online-Geld illegal erzeugen oder " +
                                     "an andere Spieler verteilen (Money Drop Lobbys, Recovery-Tools).",
                            Detail = $"Muster: {pattern}"
                        });
                        break;
                    }
                }
            }
        }
    }

    private async Task ScanOnlineBypassPlugins(ScanContext ctx, string gtaPath, CancellationToken ct)
    {
        var bypassSearchPaths = new[]
        {
            gtaPath,
            Path.Combine(gtaPath, "Plugins"),
            Path.Combine(gtaPath, "scripts"),
            Path.Combine(gtaPath, "mods"),
        };

        foreach (var searchPath in bypassSearchPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(searchPath)) continue;

            string[] dllFiles;
            try { dllFiles = Directory.GetFiles(searchPath, "*.dll", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var dll in dllFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(dll, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.Latin1);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var (pattern, risk, reason) in OnlineBypassPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"GTA-Online-Bypass-Artefakt: {Path.GetFileName(dll)}",
                            Risk = risk,
                            Location = dll,
                            FileName = Path.GetFileName(dll),
                            Sha256 = HashUtil.TryComputeSha256(dll, ctx.Options.MaxHashFileSizeBytes),
                            Reason = $"DLL '{Path.GetFileName(dll)}' enthält GTA-Online-Bypass-Muster '{pattern}': {reason}. " +
                                     "Online-Bypass-Patches modifizieren GTA-V-Speicher, um Anti-Cheat-Checks, " +
                                     "Banwellen-Erkennung oder Session-Beschränkungen zu deaktivieren.",
                            Detail = $"Muster: {pattern}"
                        });
                        break;
                    }
                }
            }
        }
    }

    private void ScanRphProcesses(ScanContext ctx, CancellationToken ct)
    {
        var processes = ctx.GetProcessSnapshot();
        bool rphRunning = false;
        bool fiveMRunning = false;
        bool gtaRunning = false;

        foreach (var proc in processes)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementProcesses();

            var procName = proc.ProcessName;

            if (procName.Equals("RagePluginHook", StringComparison.OrdinalIgnoreCase))
            {
                rphRunning = true;
                string? path = null;
                try { path = proc.MainModule?.FileName; } catch { }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "RagePluginHook.exe läuft aktuell",
                    Risk = RiskLevel.High,
                    Location = path ?? "RagePluginHook.exe",
                    FileName = "RagePluginHook.exe",
                    Reason = "RagePluginHook.exe ist aktuell als aktiver Prozess vorhanden. " +
                             "RPH ermöglicht tiefe Eingriffe in GTA V zur Laufzeit. " +
                             "Ob es für legitime Mods (LSPDFR) oder Cheats genutzt wird, " +
                             "hängt von den geladenen Plugins ab.",
                    Detail = $"PID: {proc.Id} | Pfad: {path ?? "unbekannt"}"
                });
            }

            if (procName.Contains("GTA5", StringComparison.OrdinalIgnoreCase)
                || procName.Contains("GTAV", StringComparison.OrdinalIgnoreCase)
                || procName.Contains("Grand Theft Auto", StringComparison.OrdinalIgnoreCase))
                gtaRunning = true;

            if (procName.Contains("FiveM", StringComparison.OrdinalIgnoreCase)
                || procName.Contains("CitizenFX", StringComparison.OrdinalIgnoreCase))
                fiveMRunning = true;
        }

        if (rphRunning && fiveMRunning)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "RagePluginHook + FiveM gleichzeitig aktiv",
                Risk = RiskLevel.Critical,
                Location = "Laufende Prozesse",
                Reason = "RagePluginHook und FiveM laufen gleichzeitig. Diese Kombination wird aktiv " +
                         "für FiveM-Cheats genutzt: RPH lädt Plugins, die dann in den FiveM-Prozess " +
                         "injizieren oder CitizenFX-Anti-Cheat-Mechanismen umgehen.",
                Detail = "RPH: aktiv | FiveM: aktiv | Kombinations-Angriff möglich"
            });
        }

        if (rphRunning && gtaRunning)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "RagePluginHook in aktiver GTA-V-Sitzung erkannt",
                Risk = RiskLevel.High,
                Location = "Laufende Prozesse",
                Reason = "RagePluginHook und GTA V laufen gleichzeitig. RPH injiziert aktiv in den " +
                         "GTA-V-Prozess. Ob dies für legitime Mods oder Cheats genutzt wird, " +
                         "ist aus den Prozessnamen allein nicht bestimmbar.",
                Detail = "RPH: aktiv | GTA5: aktiv"
            });
        }
    }

    private void ScanRphRegistryEntries(ScanContext ctx, CancellationToken ct)
    {
        foreach (var regPath in RphRegistryKeys)
        {
            ct.ThrowIfCancellationRequested();

            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                    using var key = baseKey.OpenSubKey(regPath);
                    if (key is null) continue;

                    ctx.IncrementRegistryKeys();

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "RagePluginHook-Registrierungsschlüssel gefunden",
                        Risk = RiskLevel.Medium,
                        Location = @"HKLM\" + regPath,
                        Reason = $"Registry-Schlüssel '{regPath}' ist vorhanden. RagePluginHook ist installiert " +
                                 "und hat Registry-Einträge hinterlassen. Dies zeigt eine aktive RPH-Installation an.",
                        Detail = $"Registry-Pfad: {regPath} | View: {view}"
                    });

                    foreach (var valueName in key.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();

                        var valueData = key.GetValue(valueName)?.ToString() ?? "";

                        foreach (var (pattern, risk, reason) in RphConfigPatterns)
                        {
                            if (valueData.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Verdächtiger RPH-Registry-Wert: {valueName}",
                                    Risk = risk,
                                    Location = @"HKLM\" + regPath + @"\" + valueName,
                                    Reason = $"RPH-Registry-Wert '{valueName}' enthält Cheat-Muster '{pattern}': {reason}. " +
                                             "Cheat-relevante Einstellungen in der Registry können auf modifizierte " +
                                             "RPH-Konfigurationen hinweisen.",
                                    Detail = $"Wert: {valueData.Substring(0, Math.Min(200, valueData.Length))}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }
        }
    }

    private async Task ScanConsoleCommandHistory(ScanContext ctx, List<string> gtaVPaths, CancellationToken ct)
    {
        var historyPaths = new List<string>();

        foreach (var gtaPath in gtaVPaths)
        {
            historyPaths.Add(Path.Combine(gtaPath, "RagePluginHook_console_history.txt"));
            historyPaths.Add(Path.Combine(gtaPath, "console_history.txt"));
            historyPaths.Add(Path.Combine(gtaPath, "cmd_history.log"));
            historyPaths.Add(Path.Combine(gtaPath, "Plugins", "LSPDFR", "console.log"));
        }

        foreach (var historyFile in historyPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!File.Exists(historyFile)) continue;
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(historyFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct);
            }
            catch (IOException) { continue; }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var (pattern, risk, reason) in ConsoleCommandPatterns)
            {
                if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cheat-Konsolenbefehl in Verlauf: '{pattern}'",
                        Risk = risk,
                        Location = historyFile,
                        FileName = Path.GetFileName(historyFile),
                        Reason = $"Konsolen-Verlaufsdatei '{Path.GetFileName(historyFile)}' enthält Cheat-Befehl " +
                                 $"'{pattern}': {reason}. RPH-Konsolenbefehle werden direkt in der Spiel-Konsole " +
                                 "eingegeben; ihr Verlauf zeigt, welche Cheat-Funktionen manuell aktiviert wurden.",
                        Detail = $"Befehl: {pattern}"
                    });
                }
            }
        }
    }

    private static bool IsKnownLegitRphPlugin(string fileNameLower)
    {
        return fileNameLower.Contains("lspdfr", StringComparison.OrdinalIgnoreCase)
            || fileNameLower.Contains("traffic policer", StringComparison.OrdinalIgnoreCase)
            || fileNameLower.Contains("stopstheped", StringComparison.OrdinalIgnoreCase)
            || fileNameLower.Contains("ragemp", StringComparison.OrdinalIgnoreCase)
            || fileNameLower.Equals("ragebaseplugin", StringComparison.OrdinalIgnoreCase)
            || fileNameLower.Equals("rageplugincommon", StringComparison.OrdinalIgnoreCase)
            || fileNameLower.Equals("rageplugincore", StringComparison.OrdinalIgnoreCase)
            || fileNameLower.Contains("policesmartradio", StringComparison.OrdinalIgnoreCase)
            || fileNameLower.Contains("bodycam", StringComparison.OrdinalIgnoreCase)
            || fileNameLower.Contains("assorted_callouts", StringComparison.OrdinalIgnoreCase)
            || fileNameLower.Contains("ultimate_backup", StringComparison.OrdinalIgnoreCase);
    }
}
