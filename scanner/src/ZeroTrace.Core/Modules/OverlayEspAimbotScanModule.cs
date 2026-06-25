using System.Diagnostics;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class OverlayEspAimbotScanModule : IScanModule
{
    public string Name => "Overlay ESP/Aimbot Detection Scan";
    public double Weight => 3.4;
    public int ParallelGroup => 4;

    // ── Known overlay/ESP DLL names and keywords ──
    private static readonly string[] SuspiciousOverlayDllNames =
    {
        "overlay", "esp", "render", "draw", "hack",
        "aimbot", "aim_bot", "aim-bot",
        "wallhack", "wall_hack", "wh_",
        "triggerbot", "trigger_bot",
        "spinbot", "spin_bot",
        "bunnyhop", "bhop", "bunny_hop",
        "cheat", "cheatengine",
        "external", "externalesp",
        "d3dhook", "d3d_hook", "d3d11hook", "d3d12hook",
        "openglhook", "vulkanhook",
        "gdiplus_hook", "gdi_hook",
        "bitblt_hook",
        "present_hook", "swapchain",
        "imgui_cheat", "imguicheat",
        "imguihack", "imgui_hack",
        "reshade_cheat", "reshade_hack",
        "specialk_cheat", "skcheat",
        "rtss_hook", "rivatuner_hook",
        "fraps_hook",
        "nv_hook", "nvidia_hook",
        "obs_hook", "obs_cheat",
        "discord_hook", "discord_esp",
        "screenreader", "screen_reader",
        "pixel_reader", "pixelbot",
        "color_bot", "colorbot",
        "triggercolor", "trigger_color",
        "autohotkey_aimbot", "ahk_aimbot",
        "python_aimbot", "pyaimbot",
        "opencv_aimbot", "cv2_aimbot",
        "pyautogui_bot", "pynput_bot",
        "window_capture", "windowcapture",
        "gdi_overlay", "gdi_esp",
        "dwm_hook", "desktop_window_manager_hook",
        "magnify_hook", "magnification_hook",
        "crosshair_cheat", "crosshairx",
        "recoilpad", "recoil_pad", "recoil_script",
        "norecoil", "no_recoil",
        "rapidfire", "rapid_fire",
        "autofire", "auto_fire",
        "antirecoil", "anti_recoil",
    };

    // ── ImGui artifact patterns ──
    private static readonly (string pattern, RiskLevel risk, string reason)[] ImGuiArtifactPatterns =
    {
        ("ImGui::Begin(",                   RiskLevel.High,     "ImGui-Fenster-Erstell-Aufruf (Cheat-Menu-Muster)"),
        ("ImGui::End()",                    RiskLevel.High,     "ImGui-Fenster-Schließ-Aufruf"),
        ("ImGui::Checkbox(",                RiskLevel.High,     "ImGui-Checkbox (Cheat-Einstellungs-UI)"),
        ("ImGui::SliderFloat(",             RiskLevel.High,     "ImGui-Slider (Cheat-Wert-Einstellung)"),
        ("ImGui::ColorPicker",              RiskLevel.High,     "ImGui-Farbwahl (ESP-Farb-Einstellung)"),
        ("ESP Color",                       RiskLevel.Critical, "ESP-Farb-Beschriftung in ImGui-UI"),
        ("Aimbot",                          RiskLevel.Critical, "Aimbot-Beschriftung in ImGui-UI"),
        ("Wallhack",                        RiskLevel.Critical, "Wallhack-Beschriftung in ImGui-UI"),
        ("Triggerbot",                      RiskLevel.Critical, "Triggerbot-Beschriftung in ImGui-UI"),
        ("BunnyHop",                        RiskLevel.High,     "BunnyHop-Beschriftung in ImGui-UI"),
        ("SpinBot",                         RiskLevel.Critical, "SpinBot-Beschriftung in ImGui-UI"),
        ("NoRecoil",                        RiskLevel.High,     "NoRecoil-Beschriftung in ImGui-UI"),
        ("RapidFire",                       RiskLevel.High,     "RapidFire-Beschriftung in ImGui-UI"),
        ("GodMode",                         RiskLevel.Critical, "GodMode-Beschriftung in ImGui-UI"),
        ("ImGui_ImplDX11_Init",             RiskLevel.High,     "ImGui DirectX11-Initialisierung"),
        ("ImGui_ImplDX12_Init",             RiskLevel.High,     "ImGui DirectX12-Initialisierung"),
        ("ImGui_ImplVulkan_Init",           RiskLevel.High,     "ImGui Vulkan-Initialisierung"),
        ("ImGui_ImplOpenGL3_Init",          RiskLevel.High,     "ImGui OpenGL3-Initialisierung"),
        ("ImGui_ImplWin32_Init",            RiskLevel.High,     "ImGui Win32-Backend-Initialisierung"),
        ("DX11Present",                     RiskLevel.High,     "D3D11 Present-Hook-Referenz"),
        ("DX12Present",                     RiskLevel.High,     "D3D12 Present-Hook-Referenz"),
        ("VkQueuePresentKHR",               RiskLevel.High,     "Vulkan Queue Present-Hook"),
        ("wglSwapBuffers",                  RiskLevel.High,     "OpenGL SwapBuffers-Hook"),
        ("HookPresent",                     RiskLevel.Critical, "Present-Hook-Einrichtung"),
        ("PresentHook",                     RiskLevel.Critical, "Present-Hook-Einrichtung (Variante)"),
        ("kiero",                           RiskLevel.High,     "Kiero-Hook-Bibliothek (ImGui-Rendering)"),
        ("minhook",                         RiskLevel.High,     "MinHook-Referenz in ImGui-Kontext"),
        ("detours",                         RiskLevel.High,     "Detours-Bibliothek in ImGui-Kontext"),
        ("polyhook",                        RiskLevel.High,     "PolyHook-Bibliothek in ImGui-Kontext"),
    };

    // ── imgui.ini suspicious content patterns ──
    private static readonly (string pattern, RiskLevel risk, string reason)[] ImGuiIniPatterns =
    {
        ("[ESP]",               RiskLevel.Critical, "ESP-Sektion in imgui.ini"),
        ("[Aimbot]",            RiskLevel.Critical, "Aimbot-Sektion in imgui.ini"),
        ("[Wallhack]",          RiskLevel.Critical, "Wallhack-Sektion in imgui.ini"),
        ("[Triggerbot]",        RiskLevel.Critical, "Triggerbot-Sektion in imgui.ini"),
        ("[Spinbot]",           RiskLevel.Critical, "Spinbot-Sektion in imgui.ini"),
        ("[Cheat]",             RiskLevel.Critical, "Cheat-Sektion in imgui.ini"),
        ("[Hack]",              RiskLevel.High,     "Hack-Sektion in imgui.ini"),
        ("[NoRecoil]",          RiskLevel.High,     "NoRecoil-Sektion in imgui.ini"),
        ("[BunnyHop]",          RiskLevel.High,     "BunnyHop-Sektion in imgui.ini"),
        ("[GodMode]",           RiskLevel.Critical, "GodMode-Sektion in imgui.ini"),
        ("[RapidFire]",         RiskLevel.High,     "RapidFire-Sektion in imgui.ini"),
        ("[Radar]",             RiskLevel.High,     "Radar-Sektion in imgui.ini (ESP-Muster)"),
        ("[Overlay]",           RiskLevel.High,     "Overlay-Sektion in imgui.ini"),
        ("BoxESP",              RiskLevel.Critical, "BoxESP-Einstellung in imgui.ini"),
        ("SkeletonESP",         RiskLevel.Critical, "SkeletonESP-Einstellung in imgui.ini"),
        ("HealthBar",           RiskLevel.High,     "HealthBar-ESP-Einstellung in imgui.ini"),
        ("NameESP",             RiskLevel.High,     "NameESP-Einstellung in imgui.ini"),
        ("DistanceESP",         RiskLevel.High,     "DistanceESP-Einstellung in imgui.ini"),
        ("SnapLine",            RiskLevel.High,     "SnapLine-ESP-Einstellung in imgui.ini"),
        ("SilentAim",           RiskLevel.Critical, "SilentAim-Einstellung in imgui.ini"),
        ("AimFOV",              RiskLevel.Critical, "AimFOV-Einstellung in imgui.ini"),
        ("AimSmooth",           RiskLevel.Critical, "AimSmooth-Einstellung in imgui.ini"),
        ("BoneAim",             RiskLevel.Critical, "BoneAim-Einstellung in imgui.ini"),
    };

    // ── ReShade cheat preset/shader patterns ──
    private static readonly (string pattern, RiskLevel risk, string reason)[] ReShadeCheatPatterns =
    {
        ("ReShade_Cheat",               RiskLevel.Critical, "ReShade-Cheat-Preset-Bezeichnung"),
        ("ESP_Shader",                  RiskLevel.Critical, "ESP-Shader in ReShade"),
        ("Wallhack_Shader",             RiskLevel.Critical, "Wallhack-Shader in ReShade"),
        ("DepthBuffer_ESP",             RiskLevel.Critical, "Tiefenpuffer-basierter ESP in ReShade"),
        ("FullBright",                  RiskLevel.High,     "FullBright-Shader (Wallhack-Hilfsmittel)"),
        ("NoFog",                       RiskLevel.High,     "NoFog-Shader (Sichtweiten-Manipulation)"),
        ("ThermalVision",               RiskLevel.High,     "Thermalbild-Shader (ESP-Hilfsmittel)"),
        ("NightVision_Hack",            RiskLevel.High,     "Nachtsicht-Hack-Shader"),
        ("HighlightPlayers",            RiskLevel.Critical, "Spieler-Hervorhebungs-Shader"),
        ("PlayerOutline",               RiskLevel.Critical, "Spieler-Umriss-Shader (ESP)"),
        ("BoundingBox",                 RiskLevel.Critical, "Bounding-Box-Shader (ESP)"),
        ("XRay",                        RiskLevel.High,     "X-Ray-Shader (Wallhack-Muster)"),
        ("GlowESP",                     RiskLevel.Critical, "Glow-ESP-Shader"),
        ("ChamsShader",                 RiskLevel.Critical, "Chams-Shader (Spieler-durch-Wände sichtbar)"),
        ("PreProcess=Cheat",            RiskLevel.Critical, "Cheat-PreProcess-Preset"),
        ("technique ESP",               RiskLevel.Critical, "ESP-Technik in ReShade-Preset"),
        ("technique Aimbot",            RiskLevel.Critical, "Aimbot-Technik in ReShade-Preset"),
    };

    // ── SpecialK (SK) cheat abuse patterns ──
    private static readonly (string pattern, RiskLevel risk, string reason)[] SpecialKCheatPatterns =
    {
        ("CheatEngine",                 RiskLevel.Critical, "CheatEngine-Referenz in SK-Konfiguration"),
        ("ESP=true",                    RiskLevel.Critical, "ESP-Aktivierung in SK-Config"),
        ("Aimbot=true",                 RiskLevel.Critical, "Aimbot-Aktivierung in SK-Config"),
        ("InjectDLL",                   RiskLevel.Critical, "DLL-Injektion via SpecialK"),
        ("BlacklistAntiCheat",          RiskLevel.Critical, "Anti-Cheat-Blacklistierung in SK"),
        ("BypassAntiCheat",             RiskLevel.Critical, "Anti-Cheat-Bypass in SK-Config"),
        ("DisableIntegrity",            RiskLevel.Critical, "Integritätsprüfung deaktiviert via SK"),
        ("HookD3D11Present",            RiskLevel.High,     "D3D11 Present-Hook via SK"),
        ("HookVulkan",                  RiskLevel.High,     "Vulkan-Hook via SK"),
        ("OverlayCheat",                RiskLevel.Critical, "Overlay-Cheat-Flag in SK-Config"),
        ("ExternalESP",                 RiskLevel.Critical, "Externer ESP via SK"),
    };

    // ── Python-based aimbot script patterns ──
    private static readonly (string pattern, RiskLevel risk, string reason)[] PythonAimbotPatterns =
    {
        ("import cv2",                  RiskLevel.High,     "OpenCV-Import (Screen-Reader-Aimbot-Muster)"),
        ("import pyautogui",            RiskLevel.High,     "PyAutoGUI-Import (Aimbot-Steuerungs-Bibliothek)"),
        ("import pynput",               RiskLevel.High,     "Pynput-Import (Tastatur/Maus-Steuerung für Aimbot)"),
        ("import mss",                  RiskLevel.High,     "MSS-Import (Screen-Capture für Aimbot)"),
        ("import win32api",             RiskLevel.High,     "Win32API-Import (Windows-Eingabe-Steuerung)"),
        ("import mouse",                RiskLevel.High,     "Mouse-Bibliothek-Import (Aimbot-Steuerung)"),
        ("cv2.inRange(",                RiskLevel.High,     "Farb-Bereichs-Erkennung (Color-Bot)"),
        ("cv2.findContours(",           RiskLevel.High,     "Kontur-Erkennung (Spieler-Erkennung)"),
        ("cv2.matchTemplate(",          RiskLevel.High,     "Template-Matching (Spieler-Erkennung)"),
        ("pyautogui.moveTo(",           RiskLevel.High,     "Maus-Bewegungs-Steuerung (Aimbot)"),
        ("pyautogui.click(",            RiskLevel.High,     "Auto-Klick (Triggerbot)"),
        ("win32api.mouse_event(",       RiskLevel.High,     "Direkte Maus-Event-Injektion"),
        ("ctypes.windll.user32.mouse_event", RiskLevel.High, "User32 Maus-Event-Injektion"),
        ("SendInput(",                  RiskLevel.High,     "SendInput für Maus-/Tastatur-Injektion"),
        ("aimbot",                      RiskLevel.Critical, "Aimbot-Schlüsselwort in Python-Skript"),
        ("triggerbot",                  RiskLevel.Critical, "Triggerbot-Schlüsselwort in Python-Skript"),
        ("color_detection",             RiskLevel.High,     "Farberkennung für Aimbot"),
        ("enemy_color",                 RiskLevel.High,     "Feind-Farbe-Erkennung (Color-Bot)"),
        ("snap_to_enemy",               RiskLevel.Critical, "Snap-zu-Feind (Aimbot)"),
        ("aim_at_player",               RiskLevel.Critical, "Auf-Spieler-Zielen (Aimbot)"),
        ("get_player_position",         RiskLevel.High,     "Spieler-Position-Abfrage"),
        ("screen_capture",              RiskLevel.High,     "Screen-Capture für Aimbot"),
        ("pixel_color",                 RiskLevel.High,     "Pixel-Farb-Abfrage (Color-Bot)"),
        ("fov_circle",                  RiskLevel.High,     "FOV-Kreis (Aimbot-Radius-Einstellung)"),
        ("smoothing",                   RiskLevel.High,     "Glättungs-Parameter (Aimbot)"),
        ("headshot",                    RiskLevel.High,     "Headshot-Ziel-Einstellung"),
        ("bone_id",                     RiskLevel.High,     "Knochen-ID (Aimbot-Ziel-Knochen)"),
        ("prediction",                  RiskLevel.High,     "Schuss-Vorhersage (Aimbot)"),
        ("recoil_control",              RiskLevel.High,     "Rückstoß-Kontrolle"),
        ("anti_recoil",                 RiskLevel.High,     "Anti-Recoil-Skript"),
        ("rapid_fire",                  RiskLevel.High,     "Rapid-Fire-Skript"),
    };

    // ── External ESP process detection: process names ──
    private static readonly string[] ExternalEspProcessNames =
    {
        "external_esp", "externalesp", "esp_external",
        "aimbot_external", "external_aimbot",
        "overlay_esp", "esp_overlay",
        "hack_external", "external_hack",
        "cheat_external", "external_cheat",
        "wallhack_external", "external_wallhack",
        "pixel_aimbot", "colorbot_external",
        "screen_aimbot", "screenaimbot",
        "gdiesp", "gdi_esp", "gdi_overlay",
        "radar_external", "external_radar",
        "memory_reader", "memoryreader",
        "process_reader", "processreader",
        "game_overlay", "gameoverlay",
        "csgo_external", "valorant_external",
        "apex_external", "fortnite_external",
        "rust_external", "tarkov_external",
        "pubg_external", "bf_external",
        "rainbow_external", "r6_external",
        "warzone_external", "cod_external",
        "gta_external", "fivem_external",
        "triggerbot", "trigger_bot",
        "legitbot", "legit_bot",
        "ragebot", "rage_bot",
        "hvh_bot", "hvhbot",
        "skinchanger", "skin_changer",
        "bhop_external", "bunnyhop_external",
    };

    // ── GDI screenshot aimbot patterns ──
    private static readonly (string pattern, RiskLevel risk, string reason)[] GdiAimbotPatterns =
    {
        ("BitBlt(",                         RiskLevel.High,     "BitBlt-Bildschirmaufnahme (GDI-Aimbot)"),
        ("CreateCompatibleBitmap(",         RiskLevel.High,     "Kompatible Bitmap für GDI-Capture"),
        ("CreateCompatibleDC(",             RiskLevel.High,     "Kompatibles DC für GDI-Capture"),
        ("GetPixel(",                       RiskLevel.High,     "Pixel-Farb-Abfrage (Color-Bot-Muster)"),
        ("SetCursorPos(",                   RiskLevel.High,     "Direkte Mauszeiger-Position (Aimbot)"),
        ("mouse_event(",                    RiskLevel.High,     "Direkte Maus-Event-Injektion"),
        ("SendInput(",                      RiskLevel.High,     "SendInput für Maus-/Tastatur-Injektion"),
        ("GetForegroundWindow(",            RiskLevel.High,     "Vordergrundfenster-Abfrage (Aimbot-Target)"),
        ("FindWindowA(",                    RiskLevel.High,     "Fenster-Suche nach Name (External-Cheat)"),
        ("FindWindowW(",                    RiskLevel.High,     "Fenster-Suche nach Name (Unicode)"),
        ("OpenProcess(",                    RiskLevel.High,     "Prozess-Öffnung (Memory-Reader)"),
        ("ReadProcessMemory(",              RiskLevel.Critical, "Prozess-Speicher-Lesezugriff"),
        ("WriteProcessMemory(",             RiskLevel.Critical, "Prozess-Speicher-Schreibzugriff"),
        ("VirtualAllocEx(",                 RiskLevel.Critical, "Remote-Speicherallokation (Injektion)"),
        ("CreateRemoteThread(",             RiskLevel.Critical, "Remote-Thread-Erstellung (Injektion)"),
        ("NtReadVirtualMemory",             RiskLevel.Critical, "NT-Native-Speicher-Lesezugriff"),
        ("NtWriteVirtualMemory",            RiskLevel.Critical, "NT-Native-Speicher-Schreibzugriff"),
        ("MapViewOfFile(",                  RiskLevel.High,     "Datei-Mapping (Shared-Memory-Cheat)"),
        ("CreateFileMapping(",              RiskLevel.High,     "Datei-Mapping-Objekt (Shared-Memory)"),
        ("GetWindowDC(",                    RiskLevel.High,     "Fenster-DC-Abfrage (GDI-Overlay)"),
        ("ReleaseDC(",                      RiskLevel.Medium,   "DC-Freigabe nach GDI-Capture"),
        ("StretchBlt(",                     RiskLevel.High,     "StretchBlt-Bildschirmaufnahme"),
        ("PrintWindow(",                    RiskLevel.High,     "PrintWindow-Capture (Umgehung von GDI-Schutz)"),
        ("GetDIBits(",                      RiskLevel.High,     "DIBits-Abfrage (Pixel-Analyse)"),
    };

    // ── D3D Present hook DLL export signatures ──
    private static readonly (string pattern, RiskLevel risk, string reason)[] D3dPresentHookPatterns =
    {
        ("D3D11Present",                RiskLevel.Critical, "D3D11 Present-Hook-Export"),
        ("D3D12Present",                RiskLevel.Critical, "D3D12 Present-Hook-Export"),
        ("D3D9Present",                 RiskLevel.Critical, "D3D9 Present-Hook-Export"),
        ("D3DXPresent",                 RiskLevel.Critical, "D3DX Present-Hook-Export"),
        ("VkPresent",                   RiskLevel.Critical, "Vulkan Present-Hook-Export"),
        ("OpenGLPresent",               RiskLevel.Critical, "OpenGL Present-Hook-Export"),
        ("SwapChain_Present",           RiskLevel.Critical, "SwapChain Present-Hook-Export"),
        ("HookedPresent",               RiskLevel.Critical, "Gehookter Present-Export"),
        ("oPresent",                    RiskLevel.High,     "Original-Present-Zeiger (Hook-Muster)"),
        ("trampoline_present",          RiskLevel.Critical, "Trampolin-Present-Hook"),
        ("IDXGISwapChain",              RiskLevel.High,     "DXGI SwapChain-Referenz"),
        ("ID3D11Device",                RiskLevel.High,     "D3D11 Device-Referenz"),
        ("ID3D12CommandQueue",          RiskLevel.High,     "D3D12 CommandQueue-Referenz"),
        ("ImGui_ImplDX",                RiskLevel.High,     "ImGui DirectX-Integration"),
        ("kiero::init",                 RiskLevel.High,     "Kiero-Hook-Initialisierung"),
        ("VMTHook",                     RiskLevel.Critical, "VMT-Hook (Virtual-Method-Table-Hook)"),
        ("vtable_hook",                 RiskLevel.Critical, "VTable-Hook-Muster"),
        ("VTableHook",                  RiskLevel.Critical, "VTable-Hook-Klasse"),
    };

    // ── RTSS (RivaTuner Statistics Server) abuse patterns ──
    private static readonly (string pattern, RiskLevel risk, string reason)[] RtssAbusePatterns =
    {
        ("RTSSHooksDX",                 RiskLevel.High,     "RTSS DirectX-Hook-Referenz"),
        ("RTSSSharedMemory",            RiskLevel.High,     "RTSS Shared-Memory-Zugriff"),
        ("RTSS_ESP",                    RiskLevel.Critical, "RTSS-basierter ESP"),
        ("RTSSCheat",                   RiskLevel.Critical, "RTSS-Cheat-Referenz"),
        ("RTSSPlugin_Cheat",            RiskLevel.Critical, "RTSS-Plugin-Cheat"),
        ("OSD_Cheat",                   RiskLevel.High,     "OSD-Cheat-Nutzung via RTSS"),
        ("RivaTuner_Hack",              RiskLevel.Critical, "RivaTuner-Hack-Referenz"),
        ("RTSS_Hook_Bypass",            RiskLevel.Critical, "RTSS-Hook-Bypass"),
        ("CustomOverlay=Cheat",         RiskLevel.Critical, "Cheat-Overlay in RTSS-Konfiguration"),
        ("PluginPath.*cheat",           RiskLevel.Critical, "Cheat-Plugin-Pfad in RTSS-Config"),
    };

    // ── Discord overlay cheat abuse patterns ──
    private static readonly (string pattern, RiskLevel risk, string reason)[] DiscordOverlayCheatPatterns =
    {
        ("DiscordHook",                 RiskLevel.High,     "Discord-Hook-Referenz"),
        ("discord_overlay_cheat",       RiskLevel.Critical, "Discord-Overlay-Cheat"),
        ("discord_esp",                 RiskLevel.Critical, "Discord-ESP-Referenz"),
        ("GameOverlayRenderer",         RiskLevel.High,     "Game-Overlay-Renderer-Hook"),
        ("DiscordESP",                  RiskLevel.Critical, "Discord-ESP-Artefakt"),
        ("overlay_inject",              RiskLevel.Critical, "Overlay-Injektions-Muster"),
        ("DiscordRenderer",             RiskLevel.High,     "Discord-Renderer-Hook"),
        ("OverlayHookDX11",             RiskLevel.High,     "Overlay-DX11-Hook via Discord"),
        ("OverlayHookDX12",             RiskLevel.High,     "Overlay-DX12-Hook via Discord"),
        ("discord.*bypass",             RiskLevel.Critical, "Discord-Bypass-Muster"),
    };

    // ── Suspicious process names scanning game memory ──
    private static readonly (string keyword, string game, RiskLevel risk)[] MemoryReaderProcessPatterns =
    {
        ("csgo",       "CS:GO/CS2",      RiskLevel.Critical),
        ("cs2",        "CS2",            RiskLevel.Critical),
        ("valorant",   "Valorant",       RiskLevel.Critical),
        ("apex",       "Apex Legends",   RiskLevel.Critical),
        ("fortnite",   "Fortnite",       RiskLevel.Critical),
        ("warzone",    "Call of Duty",   RiskLevel.Critical),
        ("tarkov",     "EFT",            RiskLevel.Critical),
        ("rust",       "Rust",           RiskLevel.Critical),
        ("pubg",       "PUBG",           RiskLevel.Critical),
        ("r6",         "Rainbow Six",    RiskLevel.Critical),
        ("fivem",      "FiveM",          RiskLevel.Critical),
        ("gtav",       "GTA V",          RiskLevel.Critical),
        ("overwatch",  "Overwatch",      RiskLevel.Critical),
        ("battleye",   "BattlEye-Spiel", RiskLevel.Critical),
        ("easyanticheat", "EAC-Spiel",   RiskLevel.Critical),
    };

    // ── Crosshair overlay apps with aimbot-trigger potential ──
    private static readonly string[] CrosshairOverlayAimbotNames =
    {
        "crosshairx", "cross_hair_x",
        "crosshair_cheat", "aim_crosshair",
        "triggerbot_crosshair", "crosshair_trigger",
        "recoilpad", "recoil_script",
        "aimcontrol", "aim_control",
        "customcrosshair", "custom_crosshair",
        "crosshair_overlay", "overlay_crosshair",
        "xhairbot", "crosshairbot",
        "AutoTrigger", "autotrigger",
        "TriggerAssist", "triggerassist",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);

        ctx.Report(0.0, "Overlay ESP/Aimbot", "Starte Scan...");

        await ScanOverlayDllFiles(ctx, localAppData, appData, userProfile, ct);
        ctx.Report(0.12, "Overlay-DLLs", "DLL-Scan abgeschlossen");

        await ScanImGuiArtifacts(ctx, localAppData, appData, userProfile, documents, desktop, ct);
        ctx.Report(0.22, "ImGui-Artefakte", "ImGui-Scan abgeschlossen");

        await ScanReShadeCheatPresets(ctx, localAppData, userProfile, ct);
        ctx.Report(0.32, "ReShade-Cheats", "ReShade-Scan abgeschlossen");

        await ScanSpecialKCheatAbuse(ctx, localAppData, ct);
        ctx.Report(0.42, "SpecialK-Missbrauch", "SpecialK-Scan abgeschlossen");

        await ScanPythonAimbotScripts(ctx, userProfile, documents, desktop, ct);
        ctx.Report(0.52, "Python-Aimbot-Skripte", "Python-Skript-Scan abgeschlossen");

        ScanExternalEspProcesses(ctx, ct);
        ctx.Report(0.62, "Externe ESP-Prozesse", "Prozess-Scan abgeschlossen");

        await ScanGdiAimbotArtifacts(ctx, localAppData, appData, userProfile, ct);
        ctx.Report(0.72, "GDI-Aimbot-Artefakte", "GDI-Scan abgeschlossen");

        await ScanD3DPresentHookDlls(ctx, localAppData, ct);
        ctx.Report(0.80, "D3D-Present-Hook-DLLs", "D3D-Scan abgeschlossen");

        await ScanRtssAbuseArtifacts(ctx, localAppData, ct);
        ctx.Report(0.87, "RTSS-Missbrauch", "RTSS-Scan abgeschlossen");

        await ScanDiscordOverlayCheatAbuse(ctx, localAppData, ct);
        ctx.Report(0.93, "Discord-Overlay-Missbrauch", "Discord-Scan abgeschlossen");

        ScanCrosshairOverlayAimbotApps(ctx, ct);
        ctx.Report(1.0, "Crosshair-Overlay-Apps", "Scan abgeschlossen");
    }

    private async Task ScanOverlayDllFiles(ScanContext ctx, string localAppData, string appData,
        string userProfile, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(localAppData, "Temp"),
            appData,
            localAppData,
        };

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            string[] dllFiles;
            try { dllFiles = Directory.GetFiles(root, "*.dll", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var dllFile in dllFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var fileName = Path.GetFileNameWithoutExtension(dllFile).ToLowerInvariant();
                foreach (var suspName in SuspiciousOverlayDllNames)
                {
                    if (fileName.Contains(suspName, StringComparison.OrdinalIgnoreCase))
                    {
                        var sig = SignatureChecker.IsCheckable(dllFile)
                            ? SignatureChecker.CheckDetailed(dllFile)
                            : default;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdächtige Overlay/ESP-DLL: {Path.GetFileName(dllFile)}",
                            Risk = RiskLevel.High,
                            Location = dllFile,
                            FileName = Path.GetFileName(dllFile),
                            Sha256 = HashUtil.TryComputeSha256(dllFile, ctx.Options.MaxHashFileSizeBytes),
                            Signed = sig.IsTrusted,
                            Reason = $"DLL '{Path.GetFileName(dllFile)}' enthält verdächtigen Namen-Token '{suspName}'. " +
                                     "Overlay- und ESP-DLLs werden in Spielprozesse injiziert oder als externe " +
                                     "Overlay-Fenster genutzt, um Spielerinformationen über Wände hinweg anzuzeigen.",
                            Detail = sig.Signer is not null ? $"Signierer: {sig.Signer}" : "Unsigniert"
                        });
                        break;
                    }
                }

                string content;
                try
                {
                    using var fs = new FileStream(dllFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.Latin1);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var (pattern, risk, reason) in D3dPresentHookPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"D3D Present-Hook-Artefakt in DLL: {Path.GetFileName(dllFile)}",
                            Risk = risk,
                            Location = dllFile,
                            FileName = Path.GetFileName(dllFile),
                            Sha256 = HashUtil.TryComputeSha256(dllFile, ctx.Options.MaxHashFileSizeBytes),
                            Reason = $"DLL '{Path.GetFileName(dllFile)}' enthält D3D Present-Hook-Muster '{pattern}': {reason}. " +
                                     "Present-Hooks werden genutzt, um ESP/Overlay-Rendering in den Render-Frame " +
                                     "des Spiels einzuschleusen, ohne ein separates Fenster zu öffnen.",
                            Detail = $"Muster: {pattern}"
                        });
                        break;
                    }
                }
            }
        }
    }

    private async Task ScanImGuiArtifacts(ScanContext ctx, string localAppData, string appData,
        string userProfile, string documents, string desktop, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            userProfile, localAppData, appData, documents, desktop
        };

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> iniFiles;
            try
            {
                iniFiles = Directory.EnumerateFiles(root, "imgui.ini", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var iniFile in iniFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var parentDir = Path.GetDirectoryName(iniFile) ?? "";
                bool isKnownLegitApp = parentDir.Contains("Notepad", StringComparison.OrdinalIgnoreCase)
                    || parentDir.Contains("ImHex", StringComparison.OrdinalIgnoreCase)
                    || parentDir.Contains("Cheat Engine", StringComparison.OrdinalIgnoreCase);

                string content;
                try
                {
                    using var fs = new FileStream(iniFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var (pattern, risk, reason) in ImGuiIniPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ImGui.ini mit Cheat-Konfiguration: {iniFile}",
                            Risk = risk,
                            Location = iniFile,
                            FileName = Path.GetFileName(iniFile),
                            Reason = $"imgui.ini enthält Cheat-Sektion/Einstellung '{pattern}': {reason}. " +
                                     "ImGui ist die verbreitetste Bibliothek für Cheat-Menüs; eine imgui.ini " +
                                     "mit ESP/Aimbot-Sektionen zeigt ein aktiv konfiguriertes Cheat-Tool an.",
                            Detail = $"Pfad: {iniFile} | Muster: {pattern}"
                        });
                        break;
                    }
                }

                if (!isKnownLegitApp && content.Length > 100 &&
                    content.Contains("[Window]", StringComparison.OrdinalIgnoreCase))
                {
                    foreach (var (pattern, risk, reason) in ImGuiArtifactPatterns)
                    {
                        if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"ImGui-Cheat-Artefakt in Konfigurationsdatei: {Path.GetFileName(iniFile)}",
                                Risk = risk,
                                Location = iniFile,
                                FileName = Path.GetFileName(iniFile),
                                Reason = $"imgui.ini enthält ImGui-Cheat-Muster '{pattern}': {reason}. " +
                                         "Dieses Muster tritt in Konfigurationsdateien von ImGui-basierten " +
                                         "Cheat-Tools auf, die Present-Hooks für Overlay-Rendering verwenden.",
                                Detail = $"Muster: {pattern}"
                            });
                            break;
                        }
                    }
                }
            }
        }
    }

    private async Task ScanReShadeCheatPresets(ScanContext ctx, string localAppData, string userProfile, CancellationToken ct)
    {
        var reShadeSearchRoots = new List<string>();

        try
        {
            reShadeSearchRoots.AddRange(Directory.GetDirectories(userProfile, "reshade*", SearchOption.AllDirectories)
                .Take(20));
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        var steamAppsPath = Path.Combine(localAppData, "..", "Roaming", "Steam", "steamapps", "common");
        if (!Directory.Exists(steamAppsPath))
            steamAppsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                                          "Steam", "steamapps", "common");
        if (Directory.Exists(steamAppsPath))
            reShadeSearchRoots.Add(steamAppsPath);

        foreach (var searchRoot in reShadeSearchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(searchRoot)) continue;

            IEnumerable<string> reShadeFiles;
            try
            {
                reShadeFiles = Directory.EnumerateFiles(searchRoot, "ReShade.ini", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(searchRoot, "*.preset", SearchOption.AllDirectories))
                    .Concat(Directory.EnumerateFiles(searchRoot, "*.fx", SearchOption.AllDirectories));
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var reShadeFile in reShadeFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(reShadeFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var (pattern, risk, reason) in ReShadeCheatPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ReShade-Cheat-Artefakt: {Path.GetFileName(reShadeFile)}",
                            Risk = risk,
                            Location = reShadeFile,
                            FileName = Path.GetFileName(reShadeFile),
                            Reason = $"ReShade-Datei '{Path.GetFileName(reShadeFile)}' enthält Cheat-Muster '{pattern}': {reason}. " +
                                     "ReShade-basierte Cheats nutzen benutzerdefinierte Shader, um Spieler durch Wände " +
                                     "sichtbar zu machen oder andere visuelle Cheat-Effekte zu erzeugen.",
                            Detail = $"Muster: {pattern} | Datei: {Path.GetFileName(reShadeFile)}"
                        });
                        break;
                    }
                }
            }
        }
    }

    private async Task ScanSpecialKCheatAbuse(ScanContext ctx, string localAppData, CancellationToken ct)
    {
        var skConfigPaths = new[]
        {
            Path.Combine(localAppData, "SpecialK"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "SpecialK"),
        };

        foreach (var skPath in skConfigPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(skPath)) continue;

            string[] skConfigFiles;
            try { skConfigFiles = Directory.GetFiles(skPath, "*.ini", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var configFile in skConfigFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(configFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var (pattern, risk, reason) in SpecialKCheatPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"SpecialK-Cheat-Missbrauch in Config: {Path.GetFileName(configFile)}",
                            Risk = risk,
                            Location = configFile,
                            FileName = Path.GetFileName(configFile),
                            Reason = $"SpecialK-Konfigurationsdatei '{Path.GetFileName(configFile)}' enthält Cheat-Muster " +
                                     $"'{pattern}': {reason}. SpecialK (SK) ist ein legitimes Framework, kann aber für " +
                                     "DLL-Injection, Anti-Cheat-Bypass und Overlay-Cheats missbraucht werden.",
                            Detail = $"Muster: {pattern}"
                        });
                        break;
                    }
                }
            }
        }
    }

    private async Task ScanPythonAimbotScripts(ScanContext ctx, string userProfile,
        string documents, string desktop, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            desktop,
            documents,
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Scripts"),
            Path.Combine(userProfile, "Aimbot"),
            Path.Combine(userProfile, "Cheat"),
            Path.Combine(userProfile, "Bot"),
        };

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> pyFiles;
            try
            {
                pyFiles = Directory.EnumerateFiles(root, "*.py", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var pyFile in pyFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(pyFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                int matchCount = 0;
                var matchedPatterns = new List<string>();

                foreach (var (pattern, risk, reason) in PythonAimbotPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        matchCount++;
                        matchedPatterns.Add(pattern);
                        if (matchCount >= 3) break;
                    }
                }

                if (matchCount >= 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Python-Aimbot-Skript erkannt: {Path.GetFileName(pyFile)}",
                        Risk = matchCount >= 3 ? RiskLevel.Critical : RiskLevel.High,
                        Location = pyFile,
                        FileName = Path.GetFileName(pyFile),
                        Reason = $"Python-Skript '{Path.GetFileName(pyFile)}' enthält mehrere Aimbot-Muster " +
                                 $"({matchCount} Treffer): {string.Join(", ", matchedPatterns)}. " +
                                 "Python-basierte Aimbots nutzen OpenCV, PyAutoGUI oder ähnliche Bibliotheken, " +
                                 "um Spieler per Screen-Capture zu erkennen und Mausbewegungen zu automatisieren.",
                        Detail = $"Übereinstimmende Muster: {string.Join(", ", matchedPatterns)}"
                    });
                }
            }
        }
    }

    private void ScanExternalEspProcesses(ScanContext ctx, CancellationToken ct)
    {
        var processes = ctx.GetProcessSnapshot();

        foreach (var proc in processes)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementProcesses();

            var procName = proc.ProcessName.ToLowerInvariant();
            foreach (var espName in ExternalEspProcessNames)
            {
                if (procName.Contains(espName, StringComparison.OrdinalIgnoreCase))
                {
                    string? path = null;
                    try { path = proc.MainModule?.FileName; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Externer ESP/Aimbot-Prozess erkannt: {proc.ProcessName}",
                        Risk = RiskLevel.Critical,
                        Location = path ?? proc.ProcessName,
                        FileName = proc.ProcessName + ".exe",
                        Reason = $"Laufender Prozess '{proc.ProcessName}' entspricht bekanntem externen ESP/Aimbot-Namen " +
                                 $"'{espName}'. Externe Cheats lesen den Spielspeicher aus einem separaten Prozess " +
                                 "und zeichnen ESP/Overlay-Informationen auf dem Bildschirm.",
                        Detail = $"PID: {proc.Id} | Pfad: {path ?? "unbekannt"}"
                    });
                    break;
                }
            }

            foreach (var (keyword, game, risk) in MemoryReaderProcessPatterns)
            {
                if (procName.Contains("reader", StringComparison.OrdinalIgnoreCase) &&
                    procName.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    string? path = null;
                    try { path = proc.MainModule?.FileName; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdächtiger Speicher-Leseprozess für {game}: {proc.ProcessName}",
                        Risk = risk,
                        Location = path ?? proc.ProcessName,
                        FileName = proc.ProcessName + ".exe",
                        Reason = $"Prozess '{proc.ProcessName}' deutet auf einen Speicher-Leser für {game} hin. " +
                                 "Externe Cheats lesen Spielspeicher, um Spieler-Positionen zu ermitteln " +
                                 "und an ein Overlay oder einen Aimbot zu übertragen.",
                        Detail = $"PID: {proc.Id}"
                    });
                    break;
                }
            }
        }
    }

    private async Task ScanGdiAimbotArtifacts(ScanContext ctx, string localAppData,
        string appData, string userProfile, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(localAppData, "Temp"),
            appData,
        };

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> exeFiles;
            try
            {
                exeFiles = Directory.EnumerateFiles(root, "*.exe", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(root, "*.dll", SearchOption.AllDirectories));
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var binFile in exeFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(binFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.Latin1);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                int gdiMatchCount = 0;
                var gdiMatches = new List<string>();

                foreach (var (pattern, risk, reason) in GdiAimbotPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        gdiMatchCount++;
                        gdiMatches.Add(pattern);
                        if (gdiMatchCount >= 4) break;
                    }
                }

                if (gdiMatchCount >= 3)
                {
                    var sig = SignatureChecker.IsCheckable(binFile)
                        ? SignatureChecker.CheckDetailed(binFile)
                        : default;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"GDI-Aimbot/Screen-Reader-Muster: {Path.GetFileName(binFile)}",
                        Risk = gdiMatchCount >= 4 ? RiskLevel.Critical : RiskLevel.High,
                        Location = binFile,
                        FileName = Path.GetFileName(binFile),
                        Sha256 = HashUtil.TryComputeSha256(binFile, ctx.Options.MaxHashFileSizeBytes),
                        Signed = sig.IsTrusted,
                        Reason = $"Binary '{Path.GetFileName(binFile)}' enthält {gdiMatchCount} GDI-/Speicher-Aimbot-Muster: " +
                                 $"{string.Join(", ", gdiMatches)}. GDI-Aimbots nehmen Screenshots des Spiels auf, " +
                                 "analysieren Farben/Konturen und injizieren Mausbewegungen ohne Spielprozess-Injektion.",
                        Detail = $"Muster ({gdiMatchCount}): {string.Join(", ", gdiMatches)}"
                    });
                }
            }
        }
    }

    private async Task ScanD3DPresentHookDlls(ScanContext ctx, string localAppData, CancellationToken ct)
    {
        var gameDirectories = new List<string>();

        var steamCommonPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                                            "Steam", "steamapps", "common");
        if (Directory.Exists(steamCommonPath))
        {
            try
            {
                gameDirectories.AddRange(Directory.GetDirectories(steamCommonPath).Take(30));
            }
            catch (UnauthorizedAccessException) { }
        }

        gameDirectories.Add(Path.Combine(localAppData, "FiveM", "FiveM.app"));

        foreach (var gameDir in gameDirectories)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(gameDir)) continue;

            string[] dllFiles;
            try { dllFiles = Directory.GetFiles(gameDir, "*.dll", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var dllFile in dllFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(dllFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.Latin1);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var (pattern, risk, reason) in D3dPresentHookPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        var sig = SignatureChecker.IsCheckable(dllFile)
                            ? SignatureChecker.CheckDetailed(dllFile)
                            : default;

                        bool isMicrosoftSigned = sig.IsTrusted && sig.Signer is not null &&
                            sig.Signer.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);

                        if (isMicrosoftSigned) break;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"D3D Present-Hook in Spiel-DLL: {Path.GetFileName(dllFile)}",
                            Risk = risk,
                            Location = dllFile,
                            FileName = Path.GetFileName(dllFile),
                            Sha256 = HashUtil.TryComputeSha256(dllFile, ctx.Options.MaxHashFileSizeBytes),
                            Signed = sig.IsTrusted,
                            Reason = $"DLL '{Path.GetFileName(dllFile)}' im Spielverzeichnis enthält Present-Hook-Muster " +
                                     $"'{pattern}': {reason}. Present-Hooks ermöglichen Overlay-Rendering im Spielframe, " +
                                     "ohne ein separates Fenster zu öffnen - die häufigste Methode für injizierte ESP-Cheats.",
                            Detail = $"Muster: {pattern} | Spielverzeichnis: {Path.GetFileName(gameDir)}"
                        });
                        break;
                    }
                }
            }
        }
    }

    private async Task ScanRtssAbuseArtifacts(ScanContext ctx, string localAppData, CancellationToken ct)
    {
        var rtssPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                         "RivaTuner Statistics Server"),
            Path.Combine(localAppData, "RTSS"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RTSS"),
        };

        foreach (var rtssPath in rtssPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(rtssPath)) continue;

            IEnumerable<string> rtssFiles;
            try
            {
                rtssFiles = Directory.EnumerateFiles(rtssPath, "*.cfg", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(rtssPath, "*.ini", SearchOption.AllDirectories))
                    .Concat(Directory.EnumerateFiles(rtssPath, "*.dll", SearchOption.AllDirectories));
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var rtssFile in rtssFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(rtssFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.Latin1);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var (pattern, risk, reason) in RtssAbusePatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"RTSS-Cheat-Missbrauch: {Path.GetFileName(rtssFile)}",
                            Risk = risk,
                            Location = rtssFile,
                            FileName = Path.GetFileName(rtssFile),
                            Reason = $"RTSS-Datei '{Path.GetFileName(rtssFile)}' enthält Cheat-Muster '{pattern}': {reason}. " +
                                     "RivaTuner Statistics Server kann für Overlay-Cheats missbraucht werden, da es " +
                                     "privilegierten Zugriff auf DirectX-Hooks hat.",
                            Detail = $"Muster: {pattern}"
                        });
                        break;
                    }
                }
            }
        }
    }

    private async Task ScanDiscordOverlayCheatAbuse(ScanContext ctx, string localAppData, CancellationToken ct)
    {
        var discordPaths = new[]
        {
            Path.Combine(localAppData, "Discord"),
            Path.Combine(localAppData, "DiscordCanary"),
            Path.Combine(localAppData, "DiscordPTB"),
        };

        foreach (var discordPath in discordPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(discordPath)) continue;

            IEnumerable<string> discordDlls;
            try
            {
                discordDlls = Directory.EnumerateFiles(discordPath, "*.dll", SearchOption.AllDirectories)
                    .Where(f => Path.GetFileName(f).StartsWith("discord", StringComparison.OrdinalIgnoreCase)
                             || Path.GetFileName(f).Contains("overlay", StringComparison.OrdinalIgnoreCase)
                             || Path.GetFileName(f).Contains("hook", StringComparison.OrdinalIgnoreCase));
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var dll in discordDlls)
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

                foreach (var (pattern, risk, reason) in DiscordOverlayCheatPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        var sig = SignatureChecker.IsCheckable(dll)
                            ? SignatureChecker.CheckDetailed(dll)
                            : default;

                        bool isDiscordSigned = sig.IsTrusted && sig.Signer is not null &&
                            sig.Signer.Contains("Discord", StringComparison.OrdinalIgnoreCase);

                        if (isDiscordSigned) break;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Discord-Overlay-Cheat-Artefakt: {Path.GetFileName(dll)}",
                            Risk = risk,
                            Location = dll,
                            FileName = Path.GetFileName(dll),
                            Sha256 = HashUtil.TryComputeSha256(dll, ctx.Options.MaxHashFileSizeBytes),
                            Signed = sig.IsTrusted,
                            Reason = $"Discord-DLL '{Path.GetFileName(dll)}' enthält Cheat-Muster '{pattern}': {reason}. " +
                                     "Der Discord-Overlay hat privilegierten D3D-Hook-Zugriff; durch Modifikation " +
                                     "seiner DLLs können Cheats ohne eigene Hook-Einrichtung ESP rendern.",
                            Detail = $"Muster: {pattern} | Signierer: {sig.Signer ?? "keiner"}"
                        });
                        break;
                    }
                }
            }
        }
    }

    private void ScanCrosshairOverlayAimbotApps(ScanContext ctx, CancellationToken ct)
    {
        var processes = ctx.GetProcessSnapshot();

        foreach (var proc in processes)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementProcesses();

            var procName = proc.ProcessName;
            foreach (var crosshairName in CrosshairOverlayAimbotNames)
            {
                if (procName.Contains(crosshairName, StringComparison.OrdinalIgnoreCase))
                {
                    string? path = null;
                    try { path = proc.MainModule?.FileName; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Crosshair-Overlay-App mit Aimbot-Potential erkannt: {proc.ProcessName}",
                        Risk = RiskLevel.High,
                        Location = path ?? proc.ProcessName,
                        FileName = proc.ProcessName + ".exe",
                        Reason = $"Prozess '{proc.ProcessName}' entspricht bekanntem Crosshair-Overlay-/Triggerbot-Namen '{crosshairName}'. " +
                                 "Einige Crosshair-Overlay-Applikationen bieten Triggerbot-Funktionalität oder " +
                                 "werden zur Tarnung von Aimbot-Programmen genutzt.",
                        Detail = $"PID: {proc.Id} | Pfad: {path ?? "unbekannt"}"
                    });
                    break;
                }
            }
        }
    }
}
