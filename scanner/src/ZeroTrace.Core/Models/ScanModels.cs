namespace ZeroTrace.Core.Models;

/// <summary>
/// User-configurable scan parameters. Persisted in the settings table so the
/// UI and engine share one source of truth.
/// </summary>
public sealed class ScanOptions
{
    /// <summary>Which profile this option set was created from. Informational only.</summary>
    public ScanProfile Profile { get; set; } = ScanProfile.Standard;

    public bool ScanDrives { get; set; } = true;
    public bool ScanProcesses { get; set; } = true;
    public bool ScanAutostart { get; set; } = true;
    public bool ScanFiveM { get; set; } = true;
    public bool ScanRegistry { get; set; } = true;
    public bool ScanDownloads { get; set; } = true;

    /// <summary>
    /// When true, the local browser history (Chromium family + Firefox) is
    /// checked for visits to cheat/reseller domains. Only matching hosts are
    /// ever recorded; the rest of the history is never stored or transmitted.
    /// </summary>
    public bool ScanBrowserHistory { get; set; } = true;
    public bool ScanSecurityTimeline { get; set; } = true;
    public bool ScanPowerShell { get; set; } = true;
    public bool ScanKernelDrivers { get; set; } = true;
    public bool ScanExecutionHistory { get; set; } = true;
    public bool ScanDmaRisk { get; set; } = true;
    public bool ScanInventory { get; set; } = true;
    public bool ScanRemnants { get; set; } = true;
    public bool ScanTamper { get; set; } = true;
    public bool ScanForensicTraces { get; set; } = true;
    public bool ScanUsnJournal { get; set; } = true;
    public bool ScanNetwork { get; set; } = true;
    public bool ScanOverlay { get; set; } = true;
    public bool ScanWmiPersistence { get; set; } = true;
    public bool ScanScheduledTasks { get; set; } = true;
    public bool ScanUsbDevices { get; set; } = true;
    public bool ScanDllHijack { get; set; } = true;
    public bool ScanBrowserExtensions { get; set; } = true;
    public bool ScanRootCertificates { get; set; } = true;
    public bool ScanVirtualMachine { get; set; } = true;
    public bool ScanHiddenDrivers { get; set; } = true;
    public bool ScanMemory { get; set; } = true;

    /// <summary>
    /// When true (default), the last module searches for strings saved on the
    /// dashboard and bundled as "zerotrace.strings" next to the exe. If the
    /// sidecar file is absent the module exits immediately without scanning.
    /// </summary>
    public bool ScanCustomStrings { get; set; } = true;

    /// <summary>When true, previously logged-in Steam accounts are read from
    /// loginusers.vdf and checked for alt-account patterns and cheat indicators.</summary>
    public bool ScanSteam { get; set; } = true;

    /// <summary>When true, the Discord client's local cache is parsed for guild
    /// (server) memberships. Guild names are classified against cheat- and
    /// reseller-keyword lists; matches are reported as findings and the flagged
    /// guilds appear in the dashboard "Discord Server" panel.</summary>
    public bool ScanDiscordGuilds { get; set; } = true;

    /// <summary>Scan Add/Remove Programs registry hives for known cheat tool names.</summary>
    public bool ScanInstalledSoftware { get; set; } = true;

    /// <summary>Scan Windows Prefetch files for previously executed cheat binaries.</summary>
    public bool ScanPrefetch { get; set; } = true;

    /// <summary>Enumerate named pipes and check known cheat mutex names.</summary>
    public bool ScanNamedResources { get; set; } = true;

    /// <summary>Scan Windows Clipboard history entries for cheat strings and domains.</summary>
    public bool ScanClipboard { get; set; } = true;

    /// <summary>Scan %APPDATA% and %LOCALAPPDATA% directory names for cheat tool folders.</summary>
    public bool ScanAppData { get; set; } = true;

    /// <summary>
    /// Flag running processes that execute from user-writable locations (Temp, Downloads,
    /// AppData, Desktop) and carry no Authenticode signature, plus catch processes
    /// masquerading as Windows system binaries from wrong paths.
    /// </summary>
    public bool ScanSuspiciousExecutables { get; set; } = true;

    /// <summary>
    /// Compare NtQuerySystemInformation (NT kernel) vs Toolhelp32 vs WMI process lists.
    /// Discrepancies indicate DKOM-hidden processes (rootkit / cheat loader).
    /// </summary>
    public bool ScanDkom { get; set; } = true;

    /// <summary>
    /// Enumerate all system-wide process handles and flag external processes with
    /// PROCESS_VM_READ access to active game processes (external cheat pattern).
    /// Requires elevation; skipped silently if not elevated.
    /// </summary>
    public bool ScanHandles { get; set; } = true;

    /// <summary>
    /// Inspect first bytes of critical ntdll.dll / win32u.dll syscall stubs.
    /// A JMP, INT3, or other non-standard prologue indicates a syscall hook
    /// (rootkit / anti-detection layer redirecting kernel calls).
    /// </summary>
    public bool ScanSyscallHooks { get; set; } = true;

    /// <summary>
    /// Communicate with the ZeroTrace ring-0 kernel driver (ZeroTraceDriver.sys)
    /// via DeviceIoControl to obtain detections that cannot be faked from
    /// userland: DKOM-hidden processes, SSDT hooks, ghost kernel modules, and
    /// suspicious kernel callbacks. If the driver is not loaded this module
    /// exits cleanly with an informational finding.
    /// </summary>
    public bool ScanKernelBridge { get; set; } = true;

    /// <summary>
    /// Detect whether ZeroTrace itself is being debugged or reverse-engineered
    /// (IsDebuggerPresent, debug heap flags, hardware breakpoints DR0–DR3,
    /// known analysis-tool processes). A Critical finding means the scan may
    /// have been observed or tampered with by an adversary.
    /// </summary>
    public bool ScanAntiAnalysis { get; set; } = true;

    /// <summary>
    /// Submit collected file hashes to the ZeroTrace cloud indicator database
    /// for cross-reference against global cheat tool blocklists. Opt-in only:
    /// disabled by default because it requires outbound HTTPS connectivity and
    /// explicit user consent to transmit hash data.
    /// </summary>
    public bool ScanCloudAnalysis { get; set; } = false;

    /// <summary>Detect cleared or manipulated Windows event logs (EventID 1102/104,
    /// abnormally short log spans, audit policy tampering).</summary>
    public bool ScanEventLogTamper { get; set; } = true;

    /// <summary>Scan Windows Defender and AV exclusion lists for entries added by
    /// cheat tools to prevent AV from detecting their injected DLLs.</summary>
    public bool ScanAvExclusions { get; set; } = true;

    /// <summary>Detect HWID spoofer tools, drivers, and manipulated hardware
    /// serial numbers (disk, BIOS, MAC address anomalies).</summary>
    public bool ScanHwidSpoofer { get; set; } = true;

    /// <summary>Detect process injection indicators: suspicious DLLs in game/system
    /// processes, orphaned private executable memory regions (shellcode).</summary>
    public bool ScanProcessInjection { get; set; } = true;

    /// <summary>Detect macro and input-automation software used for triggerbot,
    /// rapid-fire, no-recoil, and aim-assist scripts (AHK, Interception, G-Hub).</summary>
    public bool ScanMacroSoftware { get; set; } = true;

    /// <summary>Scan NTFS Alternate Data Streams in high-risk directories for
    /// hidden executable content or cheat configuration data.</summary>
    public bool ScanNtfsAds { get; set; } = true;

    /// <summary>Detect packet capture drivers and tools (WinPcap, Npcap, WinDivert)
    /// used by network-ESP cheats to intercept game server packets.</summary>
    public bool ScanPacketCapture { get; set; } = true;

    /// <summary>Scan Import Address Table (IAT) of the scanner process for hooks
    /// that redirect API calls — a cheat anti-detection layer.</summary>
    public bool ScanIatHooks { get; set; } = true;

    /// <summary>Detect NTFS file timestamp manipulation (timestomping) — cheats
    /// overwrite creation/modification dates to evade forensic timeline analysis.</summary>
    public bool ScanTimestampManipulation { get; set; } = true;

    /// <summary>Detect hypervisors and virtual machine environments that may be
    /// used to bypass kernel-level anti-cheat protection (HVCI bypass).</summary>
    public bool ScanHypervisor { get; set; } = true;

    /// <summary>Walk Windows Shellbag registry entries for previously-visited cheat
    /// tool folders (kiddion, 2take1, cherax, memprocfs, etc.).</summary>
    public bool ScanShellbags { get; set; } = true;

    /// <summary>Decode UserAssist ROT13 registry entries for program execution history
    /// and flag known cheat tool executables that were run in the past.</summary>
    public bool ScanUserAssist { get; set; } = true;

    /// <summary>Parse Windows Firewall rules for cheat-keyword names, apps in temp
    /// paths, or rules that block anti-cheat services.</summary>
    public bool ScanFirewallRules { get; set; } = true;

    /// <summary>Check Volume Shadow Copy count and VSS service state; detect vssadmin
    /// delete commands in PowerShell history (anti-forensic VSS wipe).</summary>
    public bool ScanVolumeShadow { get; set; } = true;

    /// <summary>Detect abuse of Windows Accessibility binaries (Sticky Keys / sethc.exe
    /// backdoor via IFEO debugger or binary replacement) for cheat persistence.</summary>
    public bool ScanAccessibilityAbuse { get; set; } = true;

    /// <summary>Detect credential stealer artifacts: known stealer processes, output
    /// files (passwords.txt, tokens.txt), browser DB copies in Temp, Discord LevelDB
    /// clones, Steam ssfn token files, and Telegram tdata copies.</summary>
    public bool ScanCredentialTheft { get; set; } = true;

    /// <summary>Detect COM object hijacking via HKCU CLSID overrides — a technique
    /// cheats use to inject DLLs into elevated processes without admin rights.</summary>
    public bool ScanComHijack { get; set; } = true;

    /// <summary>Scan FiveM plugin/citizen directories and Garry's Mod autorun/addons
    /// for malicious LUA scripts containing cheat function patterns.</summary>
    public bool ScanLuaScripts { get; set; } = true;

    /// <summary>Check Steam game installations for ASI loader files, unsigned proxy
    /// DLLs (dinput8.dll, d3d9.dll), and tampered anti-cheat binaries.</summary>
    public bool ScanGameIntegrity { get; set; } = true;

    /// <summary>Scan MuiCache registry for previously executed cheat tool binaries
    /// (persists after file deletion — strong forensic artifact).</summary>
    public bool ScanMuiCache { get; set; } = true;

    /// <summary>Scan Windows RecentDocs registry and Recent LNK files for recently
    /// opened cheat scripts, ASI files, or cheat configuration files.</summary>
    public bool ScanRecentDocs { get; set; } = true;

    /// <summary>Scan Windows Error Reporting crash dumps for cheat tool process
    /// names, paths, and faulting module names (crash artifacts survive deletion).</summary>
    public bool ScanWerArtifacts { get; set; } = true;

    /// <summary>Detect processes with dangerous token privileges enabled:
    /// SeDebugPrivilege (memory read/write), SeLoadDriverPrivilege (kernel driver loading).</summary>
    public bool ScanTokenPrivileges { get; set; } = true;

    /// <summary>Scan Amcache hive for previously executed cheat binaries
    /// (includes SHA-1 hash and execution timestamp even after deletion).</summary>
    public bool ScanAmcache { get; set; } = true;

    /// <summary>Enumerate live kernel modules via NtQuerySystemInformation and flag
    /// drivers not in System32, in suspicious paths, or matching known cheat tool names.</summary>
    public bool ScanLoadedKernelModules { get; set; } = true;

    /// <summary>Detect anti-debugging techniques in running processes (ProcessDebugFlags,
    /// NtGlobalFlag debug heap) indicating cheat loaders hiding their behavior.</summary>
    public bool ScanAntiDebugEvasion { get; set; } = true;

    /// <summary>Query DNS cache for cheat distribution/license server domains and
    /// scan hosts file for anti-cheat domain blocks or cheat CDN entries.</summary>
    public bool ScanDnsHistory { get; set; } = true;

    /// <summary>Scan environment variables for cheat tool artifacts and PATH hijacking
    /// (user-writable directory before System32 enabling DLL search order abuse).</summary>
    public bool ScanEnvironmentVariables { get; set; } = true;

    /// <summary>Deep-scan all Run/RunOnce/RunServices persistence keys, Winlogon Shell/Userinit,
    /// and Active Setup for cheat persistence, LOLBIN abuse, and obfuscated commands.</summary>
    public bool ScanRegistryRunHistory { get; set; } = true;

    /// <summary>Verify Authenticode signatures of DLLs loaded in game processes —
    /// detect unsigned, self-signed, or expired certificates (cheat injection artifacts).</summary>
    public bool ScanSignatureVerification { get; set; } = true;

    /// <summary>Detect disabled kernel security features: Test Signing Mode, NoIntegrityChecks,
    /// HVCI off, Secure Boot off, vulnerable driver blocklist disabled.</summary>
    public bool ScanBootConfig { get; set; } = true;

    /// <summary>Scan threads in game processes for start addresses in private RWX memory
    /// (shellcode injection via CreateRemoteThread pattern).</summary>
    public bool ScanThreadStartAddress { get; set; } = true;

    /// <summary>Deep-scan Windows services for cheat keywords, BYOVD driver registrations,
    /// missing binaries (tombstones), and suspicious service binary paths.</summary>
    public bool ScanSuspiciousServices { get; set; } = true;

    /// <summary>Detect active TCP connections from game processes to unusual external IPs
    /// and connections from processes with cheat keywords in their name.</summary>
    public bool ScanNetworkConnections { get; set; } = true;

    /// <summary>Hash files in high-risk directories (Temp, Downloads, Desktop) and compare
    /// against a blocklist of known cheat tool SHA-256 hashes.</summary>
    public bool ScanKnownHashes { get; set; } = true;

    /// <summary>Deep-scan PowerShell execution history for download cradles, AMSI bypass,
    /// AV disabling, shadow copy deletion, and cheat-specific commands.</summary>
    public bool ScanPowerShellHistoryDeep { get; set; } = true;

    /// <summary>Detect heap spray and large private RWX memory allocations in game processes
    /// indicative of shellcode injection, cheat overlays, or ESP buffer allocation.</summary>
    public bool ScanHeapSpray { get; set; } = true;

    /// <summary>Scan Windows certificate trust stores for unauthorized root CAs, self-signed
    /// certificates, and certificates with cheat-keyword subjects added by cheat tools.</summary>
    public bool ScanCertificateTrust { get; set; } = true;

    /// <summary>Detect malicious font drivers (ring-0 persistence), PE files disguised as fonts
    /// in per-user font directory, and font registry entries pointing to suspicious paths.</summary>
    public bool ScanInstalledFonts { get; set; } = true;

    /// <summary>Enumerate all named pipes and flag those matching cheat tool IPC communication
    /// channel naming patterns (loader↔DLL bridge, radar socket, DMA data pipe).</summary>
    public bool ScanNamedPipes { get; set; } = true;

    /// <summary>Deep-scan Security/System/PowerShell event logs for process creation of cheat
    /// tools (4688), service install (4697/7045), AC service stopped (7036), PS scripts (4104).</summary>
    public bool ScanEventLogDeep { get; set; } = true;

    /// <summary>Detect malicious use of AppInit_DLLs registry mechanism to inject DLLs
    /// into every User32-importing process, including games. Also checks LoadAppInit_DLLs
    /// and RequireSignedAppInit_DLLs security settings.</summary>
    public bool ScanAppInitDlls { get; set; } = true;

    /// <summary>Detect unauthorized LSA authentication packages, Security Support Providers,
    /// and notification packages running in lsass.exe — used for credential theft and persistence.</summary>
    public bool ScanLsaPlugins { get; set; } = true;

    /// <summary>Detect malicious print monitor and print processor DLLs running as SYSTEM
    /// in spoolsv.exe — a stealthy persistence technique used by cheat tools and APT groups.</summary>
    public bool ScanPrintSpoolerPersistence { get; set; } = true;

    /// <summary>Scan Windows Object Manager namespace (\BaseNamedObjects\) for named Sections,
    /// Events, Semaphores, and Mutants with cheat-keyword names used for IPC between cheat components.</summary>
    public bool ScanMemoryMappedFiles { get; set; } = true;

    /// <summary>Detect custom application compatibility shim databases (SDB files) used for
    /// DLL injection and API hooking without requiring admin privileges or code modification.</summary>
    public bool ScanAppCompatShims { get; set; } = true;

    /// <summary>Detect Subject Interface Package (SIP) and Trust Provider DLL hijacking used to
    /// bypass Authenticode signature verification — makes unsigned binaries appear signed.</summary>
    public bool ScanSipProviders { get; set; } = true;

    /// <summary>Comprehensive scan of Image File Execution Options (IFEO) for debugger hijacking
    /// of game/anti-cheat executables, VerifierDll injection, and GlobalFlag manipulation.</summary>
    public bool ScanImageFileExecutionOptions { get; set; } = true;

    /// <summary>Detect KnownDLLs registry hijacking and SafeDllSearchMode disabled — both allow
    /// replacing critical Windows DLLs for all processes without replacing files on disk.</summary>
    public bool ScanKnownDllsHijack { get; set; } = true;

    /// <summary>Detect Winlogon Shell/Userinit/GinaDLL/TaskMan/Notify hijacking for persistence —
    /// runs at every login in the security context of the logged-on user or SYSTEM.</summary>
    public bool ScanWinlogonHijack { get; set; } = true;

    /// <summary>Scan svchost.exe service groups for unknown or non-system DLL-based services
    /// hosted inside the trusted svchost.exe process as a stealth persistence mechanism.</summary>
    public bool ScanSvcHostGroups { get; set; } = true;

    /// <summary>Check integrity and status of installed anti-cheat systems (EasyAntiCheat,
    /// BattlEye, Vanguard, FACEIT, ESEA) for tampering, disabling, or AC-bypass processes.</summary>
    public bool ScanAntiCheatStatus { get; set; } = true;

    /// <summary>Deep scan WMI event subscriptions (ActiveScriptEventConsumer,
    /// CommandLineEventConsumer) in root\subscription and root\default namespaces for
    /// fileless cheat persistence that survives reboots.</summary>
    public bool ScanWmiSubscriptionDeep { get; set; } = true;

    /// <summary>Detect direct syscall stubs in game processes (SysWhispers/Hell's Gate patterns)
    /// and ntdll.dll double-loading used to bypass Anti-Cheat userland hooks in ntdll.</summary>
    public bool ScanDirectSyscalls { get; set; } = true;

    /// <summary>Deep scan of Scheduled Task XML files in System32\Tasks for encoded PowerShell
    /// commands, LOLBIN launchers, non-system paths, and cheat-keyword task names.</summary>
    public bool ScanTaskSchedulerDeep { get; set; } = true;

    /// <summary>Detect file association and shell command hijacking (exefile, batfile, vbsfile)
    /// in HKCU\Classes — an admin-free technique to intercept every EXE launch.</summary>
    public bool ScanFileAssociationHijack { get; set; } = true;

    /// <summary>Deep scan of all user/common startup folders for hidden scripts, suspicious
    /// file types, and cheat-keyword entries that run at every login.</summary>
    public bool ScanStartupFolderDeep { get; set; } = true;

    /// <summary>Read physical sector 0 of all fixed drives to detect MBR/VBR bootkit
    /// infections used to load unsigned drivers before the OS and bypass all anti-cheat.</summary>
    public bool ScanBootSector { get; set; } = true;

    /// <summary>Scan PE headers of game process modules for module stomping (zeroed headers),
    /// packer section names (UPX/Themida/VMProtect), and PE timestamp mismatches vs disk.</summary>
    public bool ScanPEHeaderAnomalies { get; set; } = true;

    /// <summary>Search user-accessible directories for credential dump artifacts: LSASS dumps,
    /// SAM/NTDS copies, .kirbi Kerberos tickets, Mimikatz output files, and NTLM hash files.</summary>
    public bool ScanSensitiveDataAccess { get; set; } = true;

    /// <summary>Enumerate all active UDP sockets with process attribution; flag suspicious ports
    /// and cheat-keyword process names (DMA radar, ESP overlay, C2 channels use UDP).</summary>
    public bool ScanUdpSockets { get; set; } = true;

    /// <summary>Detect advanced registry hijacking: BHOs, HKCU shell extensions, protocol handlers,
    /// desktop namespace extensions, and Session Manager SubSystems outside System32.</summary>
    public bool ScanRegistryHijack { get; set; } = true;

    /// <summary>
    /// When false (default) the drive module only walks targeted, high-signal
    /// directories (profile, temp, downloads, appdata). When true it walks the
    /// whole drive root for the configured extensions. Far slower.
    /// </summary>
    public bool DeepDriveScan { get; set; } = false;

    /// <summary>Explicit drive letters to scan, e.g. "C", "D". Empty = all fixed drives.</summary>
    public List<string> Drives { get; set; } = new();

    /// <summary>File extensions (lower-case, with dot) considered relevant for hashing.</summary>
    public List<string> RelevantExtensions { get; set; } = new()
    {
        ".exe", ".dll", ".sys", ".bin", ".dat", ".cfg", ".ini",
        ".lua", ".luac", ".asi", ".js", ".node", ".zip", ".rar", ".7z"
    };

    /// <summary>Directories that are never descended into during enumeration.</summary>
    public List<string> ExcludedDirectoryNames { get; set; } = new()
    {
        // Windows internals — signed, huge, and never contain cheats
        "Windows", "$Recycle.Bin", "System Volume Information",
        "WinSxS",                  // Side-by-side assembly store (GBs of signed DLLs)
        "SoftwareDistribution",    // Windows Update download cache (all MS-signed)
        "DriverStore",             // Driver package staging (all signed)
        "servicing",               // Windows Update servicing stack
        "Packages",                // UWP app packages
        "WindowsApps",             // UWP installed apps
        // Vendor software trees — skip to avoid mass false positives on unsigned installers
        "Program Files", "Program Files (x86)",
        // High-volume developer/tool directories with no cheat relevance
        "node_modules",            // npm package trees
        ".git",                    // Git repository object store
        "__pycache__",             // Python bytecode cache
        "NuGetPackages",           // NuGet package cache
        // Browser/app caches — random web content, very noisy
        "INetCache",               // IE / Edge web cache
        "Temporary Internet Files",
        "GPUCache",                // GPU shader / pipeline caches
        "Code Cache",              // Chromium V8 compiled cache
        "CrashReports",            // Crash dump directories
        "CrashPad",                // Chromium crash handler
    };

    /// <summary>Maximum recursion depth for the deep drive scan.</summary>
    public int MaxDepth { get; set; } = 12;

    /// <summary>Files larger than this (bytes) are not hashed (default 200 MB).</summary>
    public long MaxHashFileSizeBytes { get; set; } = 200L * 1024 * 1024;

    /// <summary>
    /// Per-module time budget in seconds. If a single module runs longer (e.g. it
    /// hangs on a locked file or an unresponsive WMI provider), it is cancelled
    /// and skipped so the overall scan can never freeze. 0 disables the limit.
    /// </summary>
    public int ModuleTimeoutSeconds { get; set; } = 240;
}

public static class ScanProfiles
{
    public static ScanOptions Quick() => new ScanOptions
    {
        Profile = ScanProfile.Quick,
        ScanProcesses = true,
        ScanAutostart = true,
        ScanRegistry = true,
        ScanDownloads = true,
        ScanBrowserHistory = true,
        ScanDrives = true,
        ScanFiveM = true,
        ScanNetwork = true,
        ScanScheduledTasks = true,
        ScanInstalledSoftware = true,
        // All memory/deep/slow modules off
        ScanMemory = false,
        ScanUsnJournal = false,
        ScanDmaRisk = false,
        ScanRemnants = false,
        ScanForensicTraces = false,
        ScanWmiPersistence = false,
        ScanHiddenDrivers = false,
        ScanTamper = false,
        ScanVirtualMachine = false,
        ScanDllHijack = false,
        ScanOverlay = false,
        ScanPrefetch = false,
        ScanPowerShell = false,
        ScanSecurityTimeline = false,
        ScanBrowserExtensions = false,
        ScanRootCertificates = false,
        ScanUsbDevices = false,
        ScanExecutionHistory = false,
        ScanCustomStrings = false,
        ScanSteam = false,
        ScanDiscordGuilds = true,
        ScanKernelDrivers = false,
        ScanNamedResources = false,
        ScanClipboard = false,
        ScanAppData = false,
        ScanSuspiciousExecutables = true,
        ScanDkom = false,
        ScanHandles = false,
        ScanSyscallHooks = true,
        ScanKernelBridge = true,    // fast — just open device + 1 IOCTL
        ScanAntiAnalysis = true,    // fast — only API calls
        ScanCloudAnalysis = false,  // always off in Quick (requires network + consent)
        ScanEventLogTamper = true,  // registry + event reader — fast
        ScanAvExclusions = true,    // registry only — fast
        ScanHwidSpoofer = false,    // WMI calls — slow
        ScanProcessInjection = false, // heavy P/Invoke — slow
        ScanMacroSoftware = true,   // fast — process + registry check
        ScanNtfsAds = false,        // file walk — slow
        ScanPacketCapture = true,   // fast — registry + process check
        ScanIatHooks = true,        // fast — in-process only
        ScanTimestampManipulation = false, // file walk — slow
        ScanHypervisor = true,      // CPUID + WMI — fast
        ScanShellbags = false,      // registry walk — medium
        ScanUserAssist = true,      // registry — fast
        ScanFirewallRules = true,   // registry parse — fast
        ScanVolumeShadow = true,    // WMI + service — fast
        ScanAccessibilityAbuse = true, // registry + file — fast
        ScanCredentialTheft = false, // file walk — slow
        ScanComHijack = true,       // registry — fast
        ScanLuaScripts = false,     // file walk — slow
        ScanGameIntegrity = false,  // game root walk — slow
        ScanMuiCache = true,        // registry — fast
        ScanRecentDocs = true,      // registry + LNK files — fast
        ScanWerArtifacts = true,    // text file read — fast
        ScanTokenPrivileges = true, // process token query — medium
        ScanAmcache = false,        // hive read — slow
        ScanLoadedKernelModules = true, // NT syscall — fast
        ScanAntiDebugEvasion = true, // NT syscall — fast
        ScanDnsHistory = true,      // DNS cache API — fast
        ScanEnvironmentVariables = true, // registry — fast
        ScanRegistryRunHistory = true,   // registry — fast
        ScanSignatureVerification = false, // process module walk — slow
        ScanBootConfig = true,           // registry — fast
        ScanThreadStartAddress = false,  // NT thread query — slow
        ScanSuspiciousServices = true,   // registry + WMI — fast
        ScanNetworkConnections = true,   // IP helper API — fast
        ScanKnownHashes = false,         // file hashing — slow
        ScanPowerShellHistoryDeep = true, // text file read — fast
        ScanHeapSpray = false,           // memory walk — slow
        ScanCertificateTrust = true,    // cert store — fast
        ScanInstalledFonts = true,      // registry + files — fast
        ScanNamedPipes = true,          // pipe enum — fast
        ScanEventLogDeep = false,       // event log read — slow
        ScanAppInitDlls = true,           // registry — fast
        ScanLsaPlugins = true,            // registry — fast
        ScanPrintSpoolerPersistence = true, // registry — fast
        ScanMemoryMappedFiles = true,     // NT syscall — fast
        ScanAppCompatShims = true,        // registry + file — fast
        ScanSipProviders = true,          // registry — fast
        ScanImageFileExecutionOptions = true, // registry — fast
        ScanKnownDllsHijack = true,       // registry — fast
        ScanWinlogonHijack = true,        // registry — fast
        ScanSvcHostGroups = true,         // registry — fast
        ScanAntiCheatStatus = true,       // process + file — fast
        ScanWmiSubscriptionDeep = true,   // WMI query — medium
        ScanDirectSyscalls = false,       // memory walk — slow
        ScanTaskSchedulerDeep = false,    // file read — slow
        ScanFileAssociationHijack = true, // registry — fast
        ScanStartupFolderDeep = true,     // small folder — fast
        ScanBootSector = false,           // disk sector read — slow
        ScanPEHeaderAnomalies = false,    // memory walk — slow
        ScanSensitiveDataAccess = false,  // file walk — slow
        ScanUdpSockets = true,            // IP helper API — fast
        ScanRegistryHijack = true,        // registry — fast
        DeepDriveScan = false,
        ModuleTimeoutSeconds = 60,
    };

    public static ScanOptions Standard() => new ScanOptions(); // defaults

    public static ScanOptions Deep() => new ScanOptions
    {
        Profile = ScanProfile.Deep,
        // All true (inherit defaults) plus:
        DeepDriveScan = true,
        ModuleTimeoutSeconds = 600,
        MaxDepth = 20,
    };

    public static ScanOptions FromProfile(ScanProfile profile) => profile switch
    {
        ScanProfile.Quick    => Quick(),
        ScanProfile.Deep     => Deep(),
        _                    => Standard(),
    };
}

/// <summary>Progress snapshot emitted via IProgress during a scan.</summary>
public sealed class ScanProgress
{
    public ScanPhase Phase { get; set; } = ScanPhase.Running;
    public string Module { get; set; } = string.Empty;
    public string CurrentItem { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;

    /// <summary>Overall completion 0-100.</summary>
    public double Percent { get; set; }

    public long FilesScanned { get; set; }
    public long ProcessesScanned { get; set; }
    public long RegistryKeysScanned { get; set; }
    public int FindingsCount { get; set; }
}

/// <summary>Aggregate result of one completed (or aborted) scan.</summary>
public sealed class ScanReport
{
    public long Id { get; set; }
    public DateTime StartedUtc { get; set; }
    public DateTime FinishedUtc { get; set; }
    public TimeSpan Duration => FinishedUtc - StartedUtc;

    public long FilesScanned { get; set; }
    public long ProcessesScanned { get; set; }
    public long RegistryKeysScanned { get; set; }

    public ScanPhase Result { get; set; } = ScanPhase.Completed;
    public string MachineName { get; set; } = Environment.MachineName;
    public string OsVersion { get; set; } = Environment.OSVersion.VersionString;
    public bool Elevated { get; set; }

    /// <summary>The profile that was used for this scan.</summary>
    public ScanProfile Profile { get; set; } = ScanProfile.Standard;

    /// <summary>Read-only PC information for the dashboard (system, HWID, etc.).</summary>
    public SystemSnapshot System { get; set; } = new();

    /// <summary>Read-only host inventory for the dashboard panels (processes,
    /// drivers, VM detection, recording software, USB history).</summary>
    public HostInventory Inventory { get; set; } = new();

    public List<Finding> Findings { get; set; } = new();

    /// <summary>Short code shown to the user and sent to the dashboard so the
    /// organizer can match this scan to the right person.</summary>
    public string Pin { get; set; } = "";

    /// <summary>Guaranteed-minimum summary value: were any findings detected.</summary>
    public bool AnomaliesFound => Findings.Count > 0;

    public int CriticalCount => Findings.Count(f => f.Risk == RiskLevel.Critical);
    public int HighCount => Findings.Count(f => f.Risk == RiskLevel.High);
    public int MediumCount => Findings.Count(f => f.Risk == RiskLevel.Medium);
    public int LowCount => Findings.Count(f => f.Risk == RiskLevel.Low);
}
