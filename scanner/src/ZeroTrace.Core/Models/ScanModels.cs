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

    /// <summary>Scan Steam/Epic game installation directories for proxy DLL injection files
    /// (version.dll, dinput8.dll, dxgi.dll, etc.) placed to intercept DLL load order.</summary>
    public bool ScanGameDirectoryInjection { get; set; } = true;

    /// <summary>Detect crypto-miner processes, persistence registry keys, and miner executable
    /// files/config.json with pool/wallet indicators on disk.</summary>
    public bool ScanCryptoMiner { get; set; } = true;

    /// <summary>Check Early Launch Anti-Malware (ELAM) driver load policy, wdboot.sys service
    /// start type, and LSA BootDriverFlags for signs of ELAM bypass.</summary>
    public bool ScanElamDriver { get; set; } = true;

    /// <summary>Detect known Remote Access Tools (TeamViewer, AnyDesk, RustDesk, VNC, reverse
    /// shells), RDP enabled with NLA disabled, and unauthorized RDP group members.</summary>
    public bool ScanRemoteAccessTools { get; set; } = true;

    /// <summary>Detect process hollowing (RunPE): private executable memory regions with MZ headers,
    /// PE size mismatches between disk and memory indicating in-place image replacement.</summary>
    public bool ScanProcessHollowing { get; set; } = true;

    /// <summary>Enumerate Windows kernel object directories (\BaseNamedObjects, \Device, \Driver)
    /// for cheat-keyword named objects and known BYOVD driver/device names.</summary>
    public bool ScanKernelObjects { get; set; } = true;

    /// <summary>Detect network share misconfigurations: SMBv1 enabled, suspicious shares,
    /// mapped drives to IP addresses, and null-session (anonymous) share access.</summary>
    public bool ScanNetworkShares { get; set; } = true;

    /// <summary>Detect DLL load order hijacking: writable directories before System32 in PATH,
    /// proxy DLLs in PATH directories, and ExcludeFromKnownDlls overrides.</summary>
    public bool ScanDllLoadOrderHijack { get; set; } = true;

    /// <summary>Detect anti-debugging and anti-analysis techniques: running debugger processes
    /// (x64dbg, Cheat Engine, IDA), ntdll PE header erasure, and IFEO page heap on games.</summary>
    public bool ScanAntiDebugTechniques { get; set; } = true;

    /// <summary>Detect token impersonation and privilege escalation: non-system processes with
    /// SeDebugPrivilege/SeTcbPrivilege/SeLoadDriverPrivilege enabled.</summary>
    public bool ScanTokenImpersonation { get; set; } = true;

    /// <summary>Integrity-level based token abuse detection: enumerate processes running with
    /// SYSTEM mandatory integrity level (S-1-16-16384) that are not known legitimate system services,
    /// and detect impersonation tokens (TokenType=2) held by non-system processes. Complements
    /// ScanTokenImpersonation with integrity-label based analysis.</summary>
    public bool ScanTokenIntegrityAbuse { get; set; } = true;

    /// <summary>Check PowerShell security configuration: Script Block Logging, Module Logging,
    /// Execution Policy, PS v2 downgrade vector, AMSI provider integrity, and transcription.</summary>
    public bool ScanPowerShellSecurity { get; set; } = true;

    /// <summary>Scan for NTFS Alternate Data Streams hiding executable code or large payloads
    /// in non-executable files across user temp/desktop/download directories.</summary>
    public bool ScanAlternativeDataStreams { get; set; } = true;

    /// <summary>Check Virtualization-Based Security (VBS), HVCI, and Credential Guard status —
    /// critical OS security features that block kernel-level cheats and credential theft.</summary>
    public bool ScanVbsHvci { get; set; } = true;

    /// <summary>Detect process memory protection anomalies: RWX private regions with MZ headers,
    /// aggregate RWX allocation volume in game/injection-target processes.</summary>
    public bool ScanMemoryProtection { get; set; } = true;

    /// <summary>Detect WER (Windows Error Reporting) and crash handler hijacking: WER disabled,
    /// full memory dump config, AeDebug non-standard debugger, WerFault IFEO hijack.</summary>
    public bool ScanWerFaultHijack { get; set; } = true;

    /// <summary>Detect Windows Defender deeper tampering: real-time protection off, behavior/script
    /// monitoring disabled, Defender services disabled, signature age, network/folder protection.</summary>
    public bool ScanWindowsDefenderTamper { get; set; } = true;

    /// <summary>Detect code signing bypass: vulnerable driver blocklist disabled, CI.dll integrity,
    /// unknown WDAC policy files, test signing mode, UMCI policy options.</summary>
    public bool ScanCodeSigningBypass { get; set; } = true;

    /// <summary>Detect DNS hijacking: custom DoH servers, unknown DNS server IPs, HOSTS file
    /// blocking anti-cheat domains, DNS client service disabled.</summary>
    public bool ScanDnsConfiguration { get; set; } = true;

    /// <summary>Detect GPU-based cheat infrastructure: DirectX debug runtime enabled, suspicious
    /// GPU DLLs (ReShade) in game processes, Python/CUDA cheat compute processes.</summary>
    public bool ScanGpuProcesses { get; set; } = true;

    /// <summary>Check Protected Process Light (PPL) integrity: anti-cheat/LSASS processes
    /// that should be PPL but aren't, and detect PPL-killer tools (PPLKiller, EDRSandBlast).</summary>
    public bool ScanProtectedProcesses { get; set; } = true;

    /// <summary>Scan for files with HIDDEN+SYSTEM attributes in user directories and
    /// reparse points in the driver directory that indicate rootkit file hiding.</summary>
    public bool ScanHiddenFiles { get; set; } = true;

    /// <summary>Verify loaded module code section integrity in game processes by comparing
    /// .text section bytes against on-disk PE and detecting module stomping (zeroed headers).</summary>
    public bool ScanLoadedModuleIntegrity { get; set; } = true;

    /// <summary>Enumerate active RPC endpoints for cheat-keyword annotations, external (non-LRPC)
    /// servers with unknown annotations, and known cheat-software interface UUIDs.</summary>
    public bool ScanRpcEndpoints { get; set; } = true;

    /// <summary>Detect KernelCallbackTable hijacking: verify PEB.KCT and all entries in
    /// Win32 processes point to mapped image memory, not private/anonymous shellcode regions.</summary>
    public bool ScanKernelCallbackTable { get; set; } = true;

    /// <summary>Detect VEH/SEH exception handler chain manipulation: scan ntdll .data section
    /// for exception handler structures pointing to private executable memory (persistent backdoor).</summary>
    public bool ScanExceptionHandlerChain { get; set; } = true;

    /// <summary>Detect APC injection and Early-Bird APC: game process threads with Win32 start
    /// addresses in private executable memory (shellcode via QueueUserAPC / NtQueueApcThread).</summary>
    public bool ScanApcInjection { get; set; } = true;

    /// <summary>Detect TLS callback abuse: PE module TLS directory entries in game processes
    /// pointing to private/anonymous memory (loader-level shellcode before OEP/DllMain).</summary>
    public bool ScanTlsCallbacks { get; set; } = true;

    /// <summary>Detect AtomBombing injection: scan global atom table for shellcode patterns,
    /// binary-dense entries, and abnormal atom counts indicative of payload staging.</summary>
    public bool ScanAtomBombing { get; set; } = true;

    /// <summary>Detect Reflective DLL Injection: scan game process virtual memory for private
    /// executable regions containing valid MZ/PE headers not listed in the process module table.</summary>
    public bool ScanReflectiveDllInjection { get; set; } = true;

    /// <summary>Detect Process Doppelganging and Herpaderping: running processes whose image
    /// file on disk is missing, too small, or no longer a valid PE (post-run overwrite).</summary>
    public bool ScanProcessDoppelganging { get; set; } = true;

    /// <summary>Detect PPID (Parent Process ID) spoofing: processes claiming impossible or
    /// suspicious parent PIDs via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS manipulation.</summary>
    public bool ScanPpidSpoofing { get; set; } = true;

    /// <summary>Detect inline (byte-patch) hooks in critical DLL exports (ntdll, kernel32,
    /// kernelbase, win32u): compare first 16 bytes in game process memory vs on-disk PE
    /// and flag JMP/CALL/INT3 patches on high-value functions (NtOpenProcess, EtwEventWrite, etc.).</summary>
    public bool ScanInlineHooks { get; set; } = true;

    /// <summary>Detect ETW (Event Tracing for Windows) tampering: compare EtwEventWrite and
    /// related ntdll functions in memory vs on-disk; detect stopped kernel/security ETW sessions.</summary>
    public bool ScanEtwTamper { get; set; } = true;

    /// <summary>Detect hardware breakpoints (DR0–DR3) set in game process threads: cheats use
    /// CPU debug registers to intercept API calls without modifying any code bytes in memory.</summary>
    public bool ScanHardwareBreakpoints { get; set; } = true;

    /// <summary>Scan private executable memory regions in game processes for known shellcode
    /// byte signatures: msfvenom x64 stager, CobaltStrike beacon, SysWhispers syscall stubs,
    /// PEB-walking patterns, Shikata-ga-nai XOR decoder, Donut header, Tartarus Gate, and more.</summary>
    public bool ScanShellcodeSignatures { get; set; } = true;

    /// <summary>Scan game configuration files for cheat console commands and cheat keywords:
    /// CS2/CSGO autoexec.cfg, Apex/PUBG/Fortnite GameUserSettings.ini, Dota 2/TF2/GMod scripts,
    /// and Steam userdata localconfig.vdf for suspicious launch options.</summary>
    public bool ScanGameConfigManipulation { get; set; } = true;

    /// <summary>Extract ASCII and UTF-16 LE strings from private process memory in game processes
    /// and match against HIGH-confidence indicators (known cheat domains, DMA tool strings, Telegram
    /// bot API URLs, Discord webhook URLs) and MEDIUM indicators (license check patterns, debug tool
    /// names, cheat feature strings, kernel communication artifacts).</summary>
    public bool ScanProcessMemoryStrings { get; set; } = true;

    /// <summary>Inspect Import Address Tables of non-system modules loaded in game processes for
    /// dangerous function combinations: VirtualAllocEx+WriteProcessMemory+CreateRemoteThread,
    /// NtCreateSection+NtMapViewOfSection+NtCreateThreadEx, SetThreadContext+SuspendThread, etc.</summary>
    public bool ScanSuspiciousImports { get; set; } = true;

    /// <summary>Detect section-based (NtMapViewOfSection) code injection: executable MEM_MAPPED
    /// regions in game processes with no valid on-disk backing file — cheats use NtCreateSection +
    /// NtMapViewOfSection to share shellcode without calling WriteProcessMemory.</summary>
    public bool ScanMmapCodeInjection { get; set; } = true;

    /// <summary>Detect threads hidden from debuggers via NtSetInformationThread(ThreadHideFromDebugger)
    /// and ghost threads visible in Toolhelp snapshots but not in System.Diagnostics.Process —
    /// injected cheat threads hide themselves to avoid AC analysis.</summary>
    public bool ScanHiddenThreads { get; set; } = true;

    /// <summary>Detect API hashing stubs in game process private executable memory: PEB-walk
    /// patterns, ROR/ROL hash loops, CALL$+5 get-RIP tricks, SysWhispers stubs, direct SYSCALL+RET
    /// — sophisticated cheats resolve API addresses by hash to avoid static import analysis.</summary>
    public bool ScanApiHashing { get; set; } = true;

    /// <summary>Registry forensic timestamp analysis: inspect LastWriteTime of persistence keys
    /// (Run, Services, IFEO, AppInit_DLLs, WMI, LSA, SIP providers) for recent modifications
    /// indicating cheat tool installation or anti-cheat tampering within the last 72 hours.</summary>
    public bool ScanRegistryTimestamps { get; set; } = true;

    /// <summary>Detect ntdll.dll and other critical system DLLs loaded more than once in game
    /// processes — a hook bypass technique where the second copy is loaded directly from disk
    /// with no anti-cheat hook patches applied. Also flags system DLLs from non-system paths.</summary>
    public bool ScanNtdllDoubleLoad { get; set; } = true;

    /// <summary>Detect anti-dump protections on loaded modules in game processes: erased MZ/PE
    /// headers (zeroed to hinder memory dumping), invalid SizeOfImage, PE signature deletion,
    /// and NATIVE subsystem in non-driver DLLs indicating packed or manually mapped payloads.</summary>
    public bool ScanAntiDumpProtection { get; set; } = true;

    /// <summary>Read the PEB of game processes for debug-mode indicators: BeingDebugged flag,
    /// NtGlobalFlag debug heap bits (0x70), page-heap enabled flag — cheats and their loaders
    /// set or exploit these to detect and evade analysis tools and anti-cheat hooks.</summary>
    public bool ScanPebAnomalies { get; set; } = true;

    /// <summary>Detect module stomping in game processes: compare the first 256 bytes of each
    /// loaded module's .text section in memory against the on-disk PE file — >60% mismatch
    /// indicates a different PE payload was written over a legitimate loaded module.</summary>
    public bool ScanModuleStomping { get; set; } = true;

    /// <summary>Detect external ESP/radar overlay windows: transparent topmost layered windows
    /// from non-game processes positioned over the game window, and D3D hook DLLs (ReShade,
    /// d3d11 proxy, overlay_ DLLs) loaded inside game process address space.</summary>
    public bool ScanExternalOverlay { get; set; } = true;

    /// <summary>Scan known installation paths (Desktop, Downloads, Temp, AppData, Program Files)
    /// for cheat tool folder names, known cheat DLL/EXE files, BYOVD driver files, ASI files,
    /// and cheat configuration files — detects installation and file remnants of 50+ cheat tools.</summary>
    public bool ScanCheatFileArtifacts { get; set; } = true;

    /// <summary>Detect running anti-cheat bypass tools, AC bypass services registered in Windows,
    /// AC bypass files on disk, and known vulnerable BYOVD drivers registered as services —
    /// specifically targeting VAC/EAC/BattlEye/Vanguard/FACEIT bypass utilities.</summary>
    public bool ScanAcBypassTools { get; set; } = true;

    /// <summary>Detect abnormal memory allocation patterns in game processes: massive RWX regions
    /// (>50 MB single allocation), high total private executable memory volume (>200 MB), many
    /// small private executable allocations (shellcode stager pattern), and guard page removal.</summary>
    public bool ScanMemoryAllocatorAnomaly { get; set; } = true;

    /// <summary>Detect suspicious parent-child process tree relationships: anti-cheat processes
    /// spawning command interpreters, game processes spawning LOLBINs (mshta/wscript/certutil/rundll32),
    /// and LOLBIN chains indicating cheat loaders executing code under trusted process names.</summary>
    public bool ScanSuspiciousChildProcesses { get; set; } = true;

    /// <summary>Verify Steam API DLL integrity in game processes: compare steam_api64.dll export
    /// function prologues in memory against on-disk PE, detect Steam emulator DLLs (Goldberg,
    /// CreamAPI, SmokeAPI, Koaloader) replacing the legitimate Valve steam_api to bypass VAC/DRM.</summary>
    public bool ScanSteamApiIntegrity { get; set; } = true;

    /// <summary>Detect processes with open PROCESS_VM_READ handles on game processes by enumerating
    /// all system handles via NtQuerySystemInformation — the core technique used by external cheats
    /// (ESP, aimbot, radar) to continuously read game state from another process.</summary>
    public bool ScanGameMemoryReadAccess { get; set; } = true;

    /// <summary>Detect code caves in loaded module .text sections of game processes: runs of 32+
    /// zeroed (0x00) or NOP (0x90) bytes within otherwise functional code that differ from the
    /// on-disk PE at the same offset — proving shellcode was written then cleared/overwritten
    /// to evade memory dump analysis while retaining the cave for future use.</summary>
    public bool ScanCodeCaves { get; set; } = true;

    /// <summary>Detect Layered Service Provider (LSP) DLLs in the Winsock2 catalog: non-system
    /// provider DLLs inserted into Protocol_Catalog9 or NameSpace_Catalog5 to intercept all
    /// network traffic from game processes — used for network-level radar cheats, packet
    /// injection, and traffic analysis. Flags non-system providers, missing DLL remnants,
    /// and known cheat/proxy tool names in the catalog.</summary>
    public bool ScanLspProviders { get; set; } = true;

    /// <summary>Detect VirtualProtect abuse in game processes: MEM_IMAGE pages (module-backed)
    /// whose current protection is PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY — evidence
    /// that a hook installer called VirtualProtect to make a .text section writable before
    /// patching a JMP/CALL byte sequence. Also detects AllocationProtect vs Protect mismatches
    /// indicating permanent or transient protection changes on loaded modules.</summary>
    public bool ScanVirtualProtectAbuse { get; set; } = true;

    /// <summary>Detect debuggers attached to game processes via kernel-level signals:
    /// ProcessDebugPort (class 7), ProcessDebugObjectHandle (class 30), and ProcessDebugFlags
    /// (class 31) via NtQueryInformationProcess. Unlike PEB.BeingDebugged (trivially cleared),
    /// these kernel-side indicators cannot be spoofed without a driver — any match confirms
    /// Cheat Engine, x64dbg, WinDbg, or a debugger-based cheat tool is actively attached.</summary>
    public bool ScanDebuggerAttach { get; set; } = true;

    /// <summary>Detect .NET CLR Profiler injection: COR_ENABLE_PROFILING=1 combined with a
    /// COR_PROFILER CLSID pointing to a non-Microsoft DLL in HKLM/HKCU registry or system
    /// environment. The CLR Profiler API loads arbitrary DLLs into every .NET process at
    /// startup without WriteProcessMemory — Unity games, Source engine, and .NET-based games
    /// are all vulnerable to this injection vector. Also checks CORECLR_PROFILER for .NET Core.</summary>
    public bool ScanCorProfilerInjection { get; set; } = true;

    /// <summary>Detect processes using SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) to
    /// hide their windows from screenshots and screen recordings: cheat overlays (ESP, radar,
    /// crosshair) use this API to remain invisible to tournament capture tools, OBS, and
    /// Windows Game Bar while still being visible to the player on the physical monitor.</summary>
    public bool ScanScreenCaptureBlocking { get; set; } = true;

    /// <summary>Detect staged shellcode in game processes: private executable regions whose
    /// AllocationProtect was PAGE_EXECUTE_READWRITE (write phase) but current Protect has been
    /// hardened to PAGE_EXECUTE_READ or PAGE_EXECUTE (execution phase). This RWX→RX pattern is
    /// used by sophisticated loaders to hide shellcode/injected DLL payloads after writing —
    /// harder to detect than persistent RWX regions. Also checks for MZ/PE headers and known
    /// shellcode opcodes in the first bytes of the region.</summary>
    public bool ScanStagedShellcode { get; set; } = true;

    /// <summary>Query the kernel pool tag table via NtQuerySystemInformation(SystemPoolTagInformation)
    /// and cross-reference against known cheat/BYOVD driver pool tags: mhyp (mhyprot2), RTCO
    /// (RTCore64/MSI Afterburner), WiDv (WinDivert), GDRV (Gigabyte BYOVD), CPUZ, WinRing0,
    /// AsIO, and more. Tags with active allocations but no matching registered driver indicate
    /// a hidden or deleted kernel module attempting to evade detection.</summary>
    public bool ScanKernelPoolTags { get; set; } = true;

    /// <summary>Detect suspicious Windows Job Object restrictions on game and anti-cheat
    /// processes: IsProcessInJob + QueryInformationJobObject to find CPU time limits,
    /// working set caps, kill-on-close flags, and UI restrictions applied to AC processes
    /// by cheat tools attempting to hobble the anti-cheat while keeping the game running.</summary>
    public bool ScanJobObjectRestrictions { get; set; } = true;

    /// <summary>Detect Export Address Table (EAT) hooks in ntdll.dll, kernel32.dll, and
    /// kernelbase.dll loaded in game processes: read the in-memory EAT and verify each
    /// high-value export's function VA falls within the module's mapped range. Any export
    /// pointer redirected outside the module indicates an EAT hook — more stealthy than
    /// inline hooks and used by advanced cheat tools to intercept API calls without
    /// modifying function bytes.</summary>
    public bool ScanExportAddressTableHooks { get; set; } = true;

    /// <summary>Detect running processes whose executable file on disk has been deleted:
    /// a self-deleting cheat loader that launches, maps itself, then deletes its disk copy
    /// to prevent forensic analysis. Queries the image path of every process and verifies
    /// the file still exists on disk. Also flags processes running with suspicious file
    /// extensions (.tmp, .dat) indicating file-extension camouflage.</summary>
    public bool ScanDeletedProcessBinary { get; set; } = true;

    /// <summary>Detect suspicious input device filter drivers and virtual HID devices used
    /// for aimbot/no-recoil automation: inspects HKLM\Services for Interception, vJoy, ViGEm,
    /// Logitech filter abuse; HID class filters (UpperFilters/LowerFilters) for kernel-level
    /// input interception drivers; and HID device enumeration for virtual mouse/keyboard devices
    /// that inject hardware-level synthetic input events bypassing software AC hooks.</summary>
    public bool ScanInputDeviceFilter { get; set; } = true;

    /// <summary>Detect network-based ESP/radar cheats: enumerate all TCP connections and
    /// identify non-game, non-system processes connecting to the same remote IP addresses
    /// as the active game process. External radar cheats duplicate game server connections
    /// to receive game state packets — any unexpected process sharing a game server IP is
    /// highly suspicious. Also detects suspicious UDP socket ownership patterns.</summary>
    public bool ScanNetworkGameServerSnoop { get; set; } = true;

    /// <summary>Detect packed, virtualized, or obfuscated DLLs loaded in game processes:
    /// inspects PE section names for known packer signatures (VMProtect .vmp0/.vmp1, UPX,
    /// Themida .themida/.wl, Enigma .enigma, Obsidium .obsidium, ASPack, PECompact, MPRESS).
    /// Cheat tools use commercial protectors to impede reverse engineering and evade AV —
    /// packed non-system modules in game processes are strong indicators of cheat presence.</summary>
    public bool ScanPackedModules { get; set; } = true;

    /// <summary>Detect Windows UAC bypass artifacts in HKCU registry: fodhelper (ms-settings),
    /// EventViewer (mscfile), sdclt, WSReset, and other auto-elevate hijacking techniques that
    /// cheat loaders use to gain elevated privileges without triggering a UAC prompt. Any HKCU
    /// shell command override for trusted elevated processes pointing to a non-system path
    /// indicates an active or recently-used UAC bypass cheat loader.</summary>
    public bool ScanUacBypassArtifacts { get; set; } = true;

    /// <summary>Verify anti-cheat service registrations for tampering: EasyAntiCheat, BattlEye,
    /// Vanguard (VGC/VGK), FACEIT, ESEA, XIGNCODE3 — check ImagePath points to the expected
    /// directory, service is not set to Disabled, and the binary file exists on disk. Cheat
    /// tools redirect AC service ImagePath to fake/missing binaries or set StartType=Disabled
    /// to prevent the AC from loading at game startup.</summary>
    public bool ScanAntiCheatServiceIntegrity { get; set; } = true;

    /// <summary>Detect cheat tools installed as Vulkan implicit or explicit layers: reads
    /// HKLM/HKCU SOFTWARE\Khronos\Vulkan\ImplicitLayers registry to find non-system Vulkan
    /// layer JSON manifests. Implicit layers are loaded into every Vulkan-enabled game
    /// automatically without the application's knowledge — abused by cheat overlays (ESP,
    /// crosshair, radar) to access the full graphics pipeline. Validates manifest paths,
    /// reads the "name" field from layer JSON, and flags cheat-keyword names and paths.</summary>
    public bool ScanVulkanLayerInjection { get; set; } = true;

    /// <summary>Detect non-system processes listening on loopback TCP/UDP ports — a hallmark
    /// of cheat IPC channels. Cheat architectures split into multiple processes (DMA reader,
    /// ESP renderer, radar bridge) that communicate over localhost sockets to share game state
    /// without touching the game process directly. Flags processes in the empirically observed
    /// cheat IPC port range (13337–13999) and processes with cheat-keyword names listening
    /// on any loopback port. Uses GetExtendedTcpTable(LISTENER) and GetExtendedUdpTable.</summary>
    public bool ScanLoopbackListeners { get; set; } = true;

    /// <summary>Enumerate all running process command lines via WMI Win32_Process and flag
    /// processes started with cheat-specific arguments (--inject, --esp, --bypass, --pid=,
    /// --dll=) or cheat tool names as parameters. Also detects LOLBIN-based download cradles
    /// (certutil -decode, mshta http://, wscript //B) and obfuscated PowerShell (-enc,
    /// -EncodedCommand, IEX download) used by cheat loaders to fetch and execute payloads
    /// while appearing as legitimate Windows processes.</summary>
    public bool ScanProcessCommandLines { get; set; } = true;

    /// <summary>Detect DirectX/DXGI debug layer activation and D3D registry overrides:
    /// EnableDebugLayer, ForceWARP (GPU bypass via software rasterizer), DXGI debug interface,
    /// and GPU-based validation — all intended only for game developers, never for end users.
    /// Cheat tools exploit D3D debug facilities to hook IDXGISwapChain::Present for overlay
    /// rendering (ESP, radar, crosshair) and intercept GPU resource creation. Also checks
    /// HKCU UserGpuPreferences for cheat-keyword app entries and D3D plugin DLL registrations
    /// outside of SDK paths.</summary>
    public bool ScanDirectXDebugLayer { get; set; } = true;

    /// <summary>Detect non-system processes with SeDebugPrivilege actively enabled (not just
    /// present but SE_PRIVILEGE_ENABLED via AdjustTokenPrivileges). SeDebugPrivilege grants
    /// PROCESS_ALL_ACCESS to any process, bypassing security checks — it is the single most
    /// powerful prerequisite for external cheats (memory readers, aimbot, ESP). Legitimate
    /// holders are fewer than 5 system processes; any unexpected enabled SeDebug indicates
    /// a cheat tool, DMA reader, or debugger-based cheat actively prepared to access game memory.
    /// Uses OpenProcessToken + GetTokenInformation(TokenPrivileges) on all running processes.</summary>
    public bool ScanSeDebugPrivilege { get; set; } = true;

    /// <summary>Detect RawAccel kernel driver (mouse sensitivity manipulation for aim assistance),
    /// Graficaster companion tool, and povohat mouse acceleration driver. RawAccel modifies
    /// mouse input at the HID driver level — invisible to in-game sensitivity settings and
    /// software AC. Checks service registry, filesystem, and running processes.</summary>
    public bool ScanRawAccelDriver { get; set; } = true;

    /// <summary>Scan filesystem (System32\drivers, Temp, Downloads, AppData, game directories)
    /// for known vulnerable BYOVD driver files: mhyprot2.sys, RTCore64.sys, WinRing0x64.sys,
    /// gdrv.sys, dbutil_2_3.sys, cpuz143.sys, AsIO3.sys, and 30+ more documented BYOVD
    /// drivers used by cheat tools for Ring-0 access to kernel memory.</summary>
    public bool ScanVulnerableDriverFiles { get; set; } = true;

    /// <summary>Forensic scan of Windows registry search/navigation history: TypedURLs (address
    /// bar history), WordWheelQuery (Explorer file search), RunMRU (Win+R dialog), and
    /// OpenSavePidlMRU (file-picker dialog history). All persist after browser/file cleanup
    /// and are primary forensic sources used by Ocean/detect.ac.</summary>
    public bool ScanSearchHistoryForensics { get; set; } = true;

    /// <summary>Scan %TEMP% and Downloads for staged cheat payload artifacts: DLL files with
    /// cheat names, injector executables, cheat config JSON/INI with CVars (aimbot_fov,
    /// esp_enabled), injection log files (injected=true, bypass active), and license token
    /// files. Cheat loaders routinely leave these staging artifacts behind.</summary>
    public bool ScanCheatPayloadStaging { get; set; } = true;

    /// <summary>Scan Windows Notification Platform database (wpndatabase.db) for cheat-related
    /// toast notification content; check Windows.old directory for cheat remnants from previous
    /// Windows installation; byte-grep Windows Search index (Windows.edb) for cheat file paths
    /// indexed before deletion.</summary>
    public bool ScanWindowsNotificationForensics { get; set; } = true;

    /// <summary>Scan Steam userdata for cheat correlation: sharedconfig.vdf workshop subscriptions
    /// with cheat-keyword mod names, Steam Cloud save files (remote/) containing cheat CVars,
    /// and Steam config files for cheat-related settings. Steam Cloud syncs cheat configs across
    /// reinstalls — a high-value forensic source.</summary>
    public bool ScanSteamUserdataForensics { get; set; } = true;

    /// <summary>Scan game directories (Steam, Epic, user-specified) for BepInEx, Unity Doorstop,
    /// and MelonLoader code injection frameworks. Detects: doorstop_config.ini (enabled=true),
    /// winhttp.dll Doorstop proxy in game root, BepInEx/plugins/ DLLs with cheat keywords,
    /// and MelonLoader Mods/ directory with suspicious DLLs. These mod frameworks are the
    /// dominant cheat injection vector in Unity games — they load arbitrary code at game startup
    /// with full access to game logic, networking, and player data without process injection.</summary>
    public bool ScanBepInExDoorstop { get; set; } = true;

    /// <summary>Audit Windows Defender exclusion paths for actual suspicious content: walks
    /// each excluded directory and checks for cheat-keyword files, known BYOVD driver files
    /// (mhyprot2.sys, RTCore64.sys, WinRing0.sys, etc.), and unsigned executables in high-risk
    /// paths (Temp, Downloads, AppData). A cheat tool that added an AV exclusion for its own
    /// directory leaves a double artifact — the exclusion registry entry plus the cheat files
    /// are still on disk, AV-protected from removal. Extends the base AV exclusion scan with
    /// active filesystem verification of the excluded locations.</summary>
    public bool ScanAvExclusionActivePaths { get; set; } = true;

    /// <summary>Enumerate Windows Filtering Platform (WFP) callout drivers via FwpmCalloutEnum0.
    /// WFP callout drivers intercept all network packets at the kernel level — cheat tools use
    /// them to silently duplicate game server UDP traffic for radar cheats (without touching the
    /// game process) and to block anti-cheat update/telemetry servers. Flags unknown persistent
    /// WFP callout providers not matching a whitelist of Windows built-in and known legitimate
    /// security software (VPN clients, EDR products, Windows Defender NIS driver).</summary>
    public bool ScanWfpFilters { get; set; } = true;

    /// <summary>Check process mitigation policies of known game and anti-cheat processes via
    /// GetProcessMitigationPolicy. Flags game/AC processes with DEP, ASLR, or both disabled —
    /// BYOVD kernel drivers can call NtSetInformationProcess(ProcessMitigationPolicy) to strip
    /// CFG/DEP/ACG from a game process before injecting a cheat DLL, leaving the weakened
    /// mitigation state as a detectable artifact after injection completes.</summary>
    public bool ScanProcessMitigations { get; set; } = true;

    /// <summary>Scan Cryptographic Service Provider (CSP) and CNG provider registry entries
    /// for malicious DLL registrations outside System32. CSP/CNG providers are loaded into
    /// every process that performs cryptographic operations — including SSL/TLS and Authenticode
    /// validation. Cheat tools and MITM tools register fake providers to intercept anti-cheat
    /// TLS communications, fake certificate validation for unsigned drivers, or weaken system
    /// randomness. Checks HKLM/HKCU Cryptography\Defaults\Provider and CNG provider paths.</summary>
    public bool ScanCryptoApiProviders { get; set; } = true;

    /// <summary>Detect Steam API emulator configurations in game directories: Goldberg emulator
    /// (steam_emu.ini, steam_interfaces.txt, local_save/), CreamAPI (cream_api.ini), SmokeAPI,
    /// Koaloader (Koaloader.config.json), ALI213, and EMPRESS. Steam emulators replace
    /// steam_api64.dll to bypass Valve Anti-Cheat (VAC), unlock DLC without purchase, or
    /// remove Steam authentication entirely. Scans all Steam library paths from libraryfolders.vdf.</summary>
    public bool ScanSteamEmulators { get; set; } = true;

    /// <summary>Detect HKCU AppInit_DLLs injection — loads arbitrary DLLs into every GUI
    /// process WITHOUT administrator privileges. While HKLM AppInit_DLLs require admin, the
    /// HKCU variant (HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs)
    /// allows any user to inject DLLs into every USER32-importing process including games.
    /// No legitimate software uses HKCU AppInit_DLLs — any entry is strong evidence of cheat
    /// injection. Also extends HKLM AppInit_DLLs check for non-system DLLs.</summary>
    public bool ScanHkcuAppInitDlls { get; set; } = true;

    /// <summary>Detect Windows Application Compatibility Layer abuse: AppCompatFlags\Layers
    /// registry entries forcing RUNASADMIN on cheat loaders (auto-elevate without UAC prompt),
    /// compat layers on anti-cheat binaries (can break AC integrity checks), __COMPAT_LAYER=
    /// RunAsInvoker environment variable (forces auto-elevating processes to run without UAC),
    /// and Compatibility Assistant artifacts for previously executed cheat tools. Three distinct
    /// techniques that cheat loaders use to bypass UAC or tamper with AC execution.</summary>
    public bool ScanCompatibilityLayerBypass { get; set; } = true;

    /// <summary>Enumerate \BaseNamedObjects and \Sessions\1\BaseNamedObjects for 100+ known
    /// cheat tool mutex/event/semaphore/section names. Named kernel objects persist until
    /// all handles are closed, making them reliable forensic indicators even after the
    /// cheat process exits.</summary>
    public bool ScanKnownCheatMutexExt { get; set; } = true;

    /// <summary>Scan registry for 60+ exact artifact entries left by known cheat tools:
    /// Xenos/GH injectors, Cheat Engine, HWID spoofers, GTA V menus (Kiddion, 2Take1,
    /// Stand, Cherax, Midnight), CS2/Valorant cheat suites, BYOVD service registrations
    /// (WinRing0, RTCORE64, gdrv, cpuz, AsIO3).</summary>
    public bool ScanCheatToolRegistryArtifacts { get; set; } = true;

    /// <summary>Scan System32, SysWOW64, Windows\Temp, System32\drivers, and Steam game
    /// directories for unexpected NTFS reparse points (junctions and symlinks). Cheat tools
    /// use NTFS junctions to redirect driver paths or replace game DLLs without touching
    /// the originals. Uses DeviceIoControl(FSCTL_GET_REPARSE_POINT) to read targets.</summary>
    public bool ScanNtfsReparsePoints { get; set; } = true;

    /// <summary>Detect misuse of Windows Subsystem for Linux (WSL) for cheat execution.
    /// Checks installed WSL distributions for suspicious names, scans WSL rootfs paths
    /// for known cheat binary names, and detects running WSL processes with suspicious
    /// command lines. WSL-based cheats evade Windows AC by running in the Linux kernel.</summary>
    public bool ScanWslAbuse { get; set; } = true;

    /// <summary>Scan game configuration files (CS2 autoexec.cfg, Apex Legends local.cfg,
    /// Battlefield PROF_SAVE_profile, etc.) for cheat-enabling CVars like r_drawothermodels,
    /// mat_wireframe, enable_skeleton_draw, and universal cheat keywords. Also scans
    /// Steam userdata per-game cfg directories.</summary>
    public bool ScanGameConfigCheats { get; set; } = true;

    /// <summary>Detect layered+transparent overlay windows from non-legitimate processes
    /// (classic ESP/radar overlay pattern) and processes with hook-related characteristics
    /// that could install WH_KEYBOARD_LL/WH_MOUSE_LL hooks for triggerbot/no-recoil.
    /// Uses EnumWindows + GetWindowLongPtr(GWL_EXSTYLE) for overlay detection.</summary>
    public bool ScanGlobalInputHooks { get; set; } = true;

    /// <summary>Scan HID mouse device class registry for non-legitimate upper/lower filter drivers
    /// (HID-level no-recoil cheats install as filter drivers to intercept all mouse events),
    /// unusual mouse acceleration curve values (SmoothMouseXCurve/SmoothMouseYCurve),
    /// and abnormal MouseSensitivity/MouseSpeed registry settings.</summary>
    public bool ScanMouseAccelerationCheat { get; set; } = true;

    /// <summary>Enumerate \Device\NamedPipe via NtQueryDirectoryObject for 60+ known cheat
    /// tool IPC pipe names (Gamesense, Onetap, Fatality, Kiddion, 2Take1, PCILeech, DMA
    /// patterns) and suspicious auto-generated pipe names with cheat-related prefixes.
    /// Named pipes are the primary cheat IPC channel between loader and injected DLL.</summary>
    public bool ScanNamedPipeCheatIpc { get; set; } = true;

    /// <summary>Scan AppData, Temp, Desktop, and game directories for cheat tool installer
    /// artifacts: license/token files (.lic, .token), config files with cheat CVars,
    /// log files with cheat activation strings, auto-updater manifests, injector-staged DLLs
    /// in Temp, and directories named after known cheat tools.</summary>
    public bool ScanCheatInstallerArtifacts { get; set; } = true;

    /// <summary>Detect sleep-obfuscated cheat DLLs (Ekko/Foliage/Deathsleep patterns) that
    /// XOR-encrypt themselves and change memory permissions to RW (not executable) while sleeping.
    /// Uses VirtualQueryEx to find large private RW-only committed regions with high entropy
    /// (Shannon > 7.2 bits/byte) in game processes, combined with encrypted PE header detection.</summary>
    public bool ScanSleepMasking { get; set; } = true;

    /// <summary>Enumerate all ESTABLISHED outbound TCP connections via GetExtendedTcpTable
    /// (TCP_TABLE_OWNER_PID_ALL) and check against known cheat protocol ports (41337, 31337,
    /// etc.), connections from cheat-named processes, and processes from suspicious paths with
    /// high-numbered remote ports. Complements DNS cache analysis with live connection data.</summary>
    public bool ScanActiveCheatConnections { get; set; } = true;

    /// <summary>Detect DirectX (D3D11/D3D12/DXGI) virtual function table hooks in game processes.
    /// ESP/overlay cheats hook IDXGISwapChain::Present() (vtable slot 8) to draw wallhack boxes
    /// every frame. Detection reads cross-process vtable arrays and flags entries pointing to
    /// anonymous private executable memory instead of known DX DLLs. Requires elevation.</summary>
    public bool ScanDxVtableHooks { get; set; } = true;

    /// <summary>Detect malicious EFI/UEFI NVRAM variables used by boot-level HWID spoofers
    /// and cheat loaders. Checks EFI Boot* entries for unexpected boot managers, vendor-specific
    /// GUID namespaces matching known cheat spoofer DXE drivers, and known cheat variable names
    /// via GetFirmwareEnvironmentVariable(). Also checks BootExecute registry for pre-boot entries.</summary>
    public bool ScanEfiVariables { get; set; } = true;

    /// <summary>Read the Windows DNS client cache via DnsGetCacheDataTable (dnsapi.dll) and
    /// analyze all resolved domains against 60+ known cheat suite C2/license server domains,
    /// cheat marketplace domains, suspicious TLD patterns, and domain label keywords.
    /// DNS cache persists after browser history deletion and is a reliable forensic source.</summary>
    public bool ScanDnsCacheExtended { get; set; } = true;

    /// <summary>Detect network adapter anomalies used by DMA cheats and radar cheats: promiscuous
    /// mode adapters (packet sniffing), DMA hardware (FPGA/PCILeech) registered as network devices,
    /// MAC address spoofing (locally-administered bit on physical adapters), NpCap/WinPcap without
    /// legitimate capture applications, and FPGA PCI device IDs in the device registry.</summary>
    public bool ScanSuspiciousNetworkAdapters { get; set; } = true;

    /// <summary>Detect anti-cheat processes (EasyAntiCheat, BattlEye, Vanguard, FACEIT) running with
    /// IDLE or BELOW_NORMAL CPU priority class, or with process affinity pinned to a single CPU core
    /// on multi-core systems. SetPriorityClass and SetProcessAffinityMask require no elevation —
    /// cheat loaders use them to throttle AC scanning threads and isolate AC to one core.</summary>
    public bool ScanAcPriorityAbuse { get; set; } = true;

    /// <summary>Detect anti-cheat process threads in SUSPENDED state via NtQuerySystemInformation
    /// (SystemProcessInformation). The 'thread-freeze bypass' technique calls SuspendThread() on
    /// every AC thread — the AC process remains alive (server sees heartbeat) but all scan
    /// routines are frozen. All or majority of AC threads suspended = critical finding.</summary>
    public bool ScanSuspendedAcThreads { get; set; } = true;

    /// <summary>Cross-reference PEB.Ldr.InLoadOrderModuleList (raw ReadProcessMemory walk) against
    /// EnumProcessModulesEx results in game processes. Modules visible in EnumProcessModulesEx
    /// but absent from the Ldr doubly-linked list were manually mapped (reflective DLL injection /
    /// manual map) without the Windows loader — the classic technique to hide injected DLLs
    /// from snapshot-based detection tools. Requires elevation.</summary>
    public bool ScanPebLdrInconsistency { get; set; } = true;

    /// <summary>Detect DirectInput 8 (dinput8.dll) vtable hooks in game processes: scans the DX
    /// IDirectInputDevice8 vtable for GetDeviceState (slot 9) and GetDeviceData (slot 10) pointers
    /// that fall outside dinput8.dll's mapped range. Aimbot/no-recoil cheats hook these slots to
    /// intercept and modify raw mouse input before the game reads it. Requires elevation.</summary>
    public bool ScanDirectInputVtableHooks { get; set; } = true;

    /// <summary>Forensic scan of Windows Jump List files
    /// (%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms and
    /// CustomDestinations) for cheat-tool keywords in embedded LNK paths. Jump Lists persist
    /// after deletion of the original cheat file — a primary forensic source used by Ocean
    /// and detect.ac. Fast: greps raw file bytes for UTF-16 LE encoded paths.</summary>
    public bool ScanJumpListForensics { get; set; } = true;

    /// <summary>Scan cloud-sync folders (OneDrive, Dropbox, Google Drive, MEGA, iCloud) inside
    /// the user profile for cheat directories and cheat-keyword filenames with sensitive
    /// extensions (.asi, .luac, .lic, .sys). Cheats backed up to cloud storage survive
    /// reformats and persist as cloud-side metadata even after local deletion.</summary>
    public bool ScanCloudSyncCheatArtifacts { get; set; } = true;

    /// <summary>Forensic scan of the Windows Activity Timeline database
    /// (%LOCALAPPDATA%\ConnectedDevicesPlatform\&lt;AAD&gt;\ActivitiesCache.db) for cheat-tool
    /// keywords in launched-application history. The timeline DB persists ~30 days by default
    /// and survives normal cheat uninstallation — a high-signal source used by Ocean/detect.ac.</summary>
    public bool ScanTimelineActivity { get; set; } = true;

    /// <summary>Detect USB aim-assist hardware: Cronus Zen/Max, XIM Apex/Matrix/4, MaxAim DI,
    /// Titan One/Two, ReaSnow S1, Brook Universal Fighting Board, KeyMander. Matches VID/PID
    /// pairs against the Windows USB/HID enumeration registry hive — persists after device
    /// is unplugged.</summary>
    public bool ScanAimAssistHardware { get; set; } = true;

    /// <summary>Forensic scan of $Recycle.Bin\&lt;SID&gt; for $I metadata files that reveal the
    /// original paths of deleted cheat tools. $I files persist after emptying the bin until
    /// the file itself is overwritten — extracts cheat-keyword-matching original paths.</summary>
    public bool ScanRecycleBinForensics { get; set; } = true;

    /// <summary>Scan %USERPROFILE%\AppData\LocalLow for cheat directories and signature files.
    /// LocalLow is overlooked by manual cleanup attempts (Explorer hides AppData) and is
    /// deliberately used by cheats for license tokens and config that survive uninstalls.</summary>
    public bool ScanAppDataLocalLow { get; set; } = true;

    /// <summary>Detect Driver Signature Enforcement (DSE) bypass: BCD testsigning=Yes,
    /// nointegritychecks=Yes, DISABLE_INTEGRITY_CHECKS loadoptions, custom WDAC CI policy
    /// files, Secure Boot disabled, and recent bcdedit.exe execution via Prefetch.
    /// Indicates BYOVD / unsigned cheat driver loading capability.</summary>
    public bool ScanDseBypass { get; set; } = true;

    /// <summary>Scan saved Wi-Fi profiles (C:\ProgramData\Microsoft\Wlansvc\Profiles via netsh
    /// fallback) for SSIDs matching cheat-LAN, Wi-Fi Pineapple, and rogue-AP patterns. WLAN
    /// profiles persist forever unless manually deleted — a forensic correlator for past
    /// shared-network access with banned accounts.</summary>
    public bool ScanWifiHistory { get; set; } = true;

    /// <summary>Scan browser bookmark files (Chromium-family Bookmarks JSON + Firefox
    /// places.sqlite) for entries pointing to cheat marketplaces and known cheat-suite
    /// domains. Bookmarks survive "Clear browsing history" — permanent record of user
    /// interest in cheat tools used by Ocean/detect.ac.</summary>
    public bool ScanBrowserBookmarks { get; set; } = true;

    /// <summary>Scan Discord LevelDB / HTTP cache for cheat-community server artifacts,
    /// cheat vendor names, and invite fragments. Discord is the primary distribution
    /// channel for cheat licenses and support — artifacts persist in local storage.
    /// Used by Ocean / detect.ac.</summary>
    public bool ScanDiscordCheatArtifacts { get; set; } = true;

    /// <summary>Scan Telegram Desktop tdata / downloads for cheat-vendor keywords.
    /// Telegram is increasingly used for anonymous cheat key distribution and DMA
    /// firmware delivery. Cached message data persists after UI deletion.</summary>
    public bool ScanTelegramArtifacts { get; set; } = true;

    /// <summary>Scan Razer Synapse, Logitech G Hub, SteelSeries GG, Corsair iCUE and
    /// AutoHotKey script files for no-recoil / triggerbot macro patterns. Macro-based
    /// cheats operate at HID level, invisible to in-game AC. Ocean / detect.ac scan
    /// macro profiles as a standard forensic source.</summary>
    public bool ScanMacroSoftware { get; set; } = true;

    /// <summary>Scan Steam localconfig.vdf for suspicious launch parameters (-insecure,
    /// +sv_cheats), cheat-keyword app names in Steam library manifests, and
    /// loginusers.vdf for cheat-keyword account names.</summary>
    public bool ScanSteamCheatCorrelation { get; set; } = true;

    /// <summary>Scan Nvidia GeForce Experience / Shadowplay clip file names for cheat
    /// keywords (aimbot_clip, wallhack_clip) and GFE config/log files for cheat
    /// references. Clip names with cheat keywords are direct evidence.</summary>
    public bool ScanShadowplayArtifacts { get; set; } = true;

    /// <summary>Detect virtual audio devices (VB-Audio Virtual Cable, VAC2, Voicemeeter)
    /// used to route audio signals in DMA cheat setups. Virtual audio cables route radar
    /// beep signals from an external cheat PC to trigger actions on the gaming PC.</summary>
    public bool ScanVirtualAudioDevices { get; set; } = true;

    /// <summary>Detect GPU compute / AI aimbot indicators: Python processes with YOLO/
    /// OnnxRuntime libraries, AI aimbot project directories (trigon, vision-aim, etc.),
    /// pip-installed packages (ultralytics, bettercam, dxcam, mss) that are exclusively
    /// used in AI-based aimbot setups.</summary>
    public bool ScanGpuComputeCheat { get; set; } = true;

    /// <summary>Scan OBS Studio scene collections and profiles for cheat-related source
    /// names (ESP overlay, radar window, cheat menu window capture). OBS is used to hide
    /// cheat overlays from streams while keeping them visible in-game.</summary>
    public bool ScanObsConfiguration { get; set; } = true;

    /// <summary>Scan MSI Afterburner profiles and RivaTuner Statistics Server plugin
    /// registry for cheat-related macro targets and third-party plugin DLLs loaded via
    /// RTSS's kernel injection mechanism.</summary>
    public bool ScanAfterburnerRtss { get; set; } = true;

    /// <summary>Detect known cheat-adjacent tools installed or executed: Process Hacker,
    /// HWID Spoofers/Changers, VAC/EAC/BattlEye bypass utilities, and AC-killer scripts.
    /// Also checks Prefetch for prior execution of these tools.</summary>
    public bool ScanCheatTools { get; set; } = true;

    /// <summary>Detect network artifacts of multi-PC cheat setups: SMB shares named
    /// "radar" or "esp", VPN adapters (Hamachi/ZeroTier/Tailscale) used to connect
    /// external cheat PCs, and network MRU with cheat-keyword paths.</summary>
    public bool ScanNetworkCheatSetup { get; set; } = true;

    /// <summary>Detect VMware / VirtualBox / Hyper-V / WSL2 used for hypervisor cheats
    /// (run below Windows kernel, invisible to AC) or as deployment environment for
    /// AI aimbots (WSL2 + Python + CUDA). VM driver services are checked.</summary>
    public bool ScanVmHypervisor { get; set; } = true;

    /// <summary>Mine Windows Event Logs (System, Security, CodeIntegrity/Operational)
    /// for cheat-specific events: Event 7045 (new kernel driver service), 1102 (Security
    /// log cleared), 4719 (audit policy disabled), CodeIntegrity 3065/3066 (driver
    /// blocked — DSE bypass attempt). Ocean/detect.ac mine EVTX as primary forensic source.</summary>
    public bool ScanEventLogCheat { get; set; } = true;

    /// <summary>Detect debuggers and reverse-engineering tools running or installed:
    /// x64dbg, WinDbg, IDA Pro, Scylla, ReClass, x32dbg. On gaming PCs these tools
    /// indicate cheat development or AC reverse-engineering. Checks running processes,
    /// installed software registry, and Prefetch for prior execution.</summary>
    public bool ScanAntiDebugTools { get; set; } = true;

    /// <summary>Scan Windows Task Scheduler XML files (%SystemRoot%\System32\Tasks)
    /// and TaskCache registry for cheat-related task names and elevated tasks running
    /// from AppData/Temp paths. Cheat loaders use scheduled tasks for auto-start
    /// persistence without UAC prompts.</summary>
    public bool ScanScheduledTaskCheat { get; set; } = true;

    /// <summary>Scan PowerShell PSReadLine history, profile scripts, and transcripts
    /// for Defender-exclusion commands, cheat download URLs, AMSI bypass code, and
    /// obfuscated execution. PowerShell history is a primary forensic signal for
    /// cheat setup steps (Set-MpPreference, bcdedit, Invoke-WebRequest to cheat sites).</summary>
    public bool ScanPowerShellHistory { get; set; } = true;

    /// <summary>Detect Special K (DirectX wrapper for cheat injection via Lua scripting
    /// and texture replacement) and ReShade (depth buffer access = wallhack-style ESP).
    /// Scans for SK installation directories, registry, and dxgi.dll/d3d9.dll placed
    /// directly in competitive game directories (DLL hijacking injection).</summary>
    public bool ScanSpecialKReShade { get; set; } = true;

    /// <summary>Detect FPS unlockers and game exploit executors: Roblox exploit executors
    /// (Synapse X, KRNL, JJSploit, Fluxus, Script-Ware), speed hackers, and FPS cap
    /// removers. Checks installed software, running processes, Prefetch, and AppData
    /// directories for executor extraction paths.</summary>
    public bool ScanFpsUnlockerExploits { get; set; } = true;

    /// <summary>Scan Windows Clipboard History (%LOCALAPPDATA%\Microsoft\Windows\Clipboard)
    /// for cheat license keys, cheat download URLs, and injection commands. Clipboard
    /// history persists across reboots until manually cleared — direct evidence of
    /// copying cheat-related content.</summary>
    public bool ScanClipboardHistory { get; set; } = true;

    /// <summary>Detect anti-cheat service tampering: BattlEye (BEService), EAC, Vanguard
    /// (vgc), PunkBuster services set to Disabled or changed from Automatic to Manual.
    /// Also checks if AC service executables are suspiciously small (patched/replaced) and
    /// if expected AC processes are not running despite being configured to auto-start.</summary>
    public bool ScanAcServiceTamper { get; set; } = true;

    /// <summary>Correlate game account proliferation with ban-cycling: counts Steam accounts
    /// in loginusers.vdf, Valorant config dirs, Epic account references. Multiple accounts
    /// on one hardware = HWID spoofer usage implied (Vanguard/BE ban by hardware ID).</summary>
    public bool ScanAccountCorrelation { get; set; } = true;

    /// <summary>Check Volume Shadow Copy Service (VSS) state and shadow copy availability.
    /// Disabled VSS or no shadow copies on a mature system = anti-forensic cleanup.
    /// Cheat cleanup scripts delete shadow copies to prevent forensic file recovery.
    /// Also checks Prefetch for vssadmin/wmic shadow deletion commands.</summary>
    public bool ScanShadowCopyState { get; set; } = true;

    /// <summary>Scan browser history SQLite files (Chrome, Edge, Brave, Firefox places.sqlite)
    /// for cryptocurrency payment processor + cheat domain keyword combinations (coingate +
    /// gamesense, nowpayments + onetap, etc.). Also detects crypto wallet software directories
    /// (MetaMask extension data, Exodus, Electrum, Monero) — exclusively used by cheat vendors
    /// for anonymous payment processing. Ocean / detect.ac scan browser history for purchase trails.</summary>
    public bool ScanCryptoPayment { get; set; } = true;

    /// <summary>Detect Windows Defender / antivirus tampering via registry: DisableAntiSpyware=1,
    /// DisableRealtimeMonitoring=1, Defender Exclusions paths/processes containing cheat DLL names,
    /// TamperProtection registry value not equal to 5 (disabled by BYOVD driver), and SmartScreen
    /// EnableSmartScreen=0. Cheat loaders disable Defender before injecting to avoid detection.</summary>
    public bool ScanAntiVirusTamper { get; set; } = true;

    /// <summary>Scan Steam game installation directories (CS2, CSGO, Rust, GTA V, EFT, Battlefield,
    /// DayZ, VALORANT) across multiple Steam library paths for: .asi loader files, suspicious proxy
    /// DLL names (dinput8.dll, cheat.dll, aimbot.dll), cheat keywords in config files (.cfg/.ini),
    /// and NTFS symbolic links redirecting DLL loads to alternate cheat versions.</summary>
    public bool ScanGameFileIntegrity { get; set; } = true;

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
        ScanGameDirectoryInjection = false, // game dir walk — slow
        ScanCryptoMiner = true,           // process + registry — fast
        ScanElamDriver = true,            // registry — fast
        ScanRemoteAccessTools = true,     // process + registry — fast
        ScanProcessHollowing = false,     // memory scan — slow
        ScanKernelObjects = true,         // NtQueryDirectoryObject — fast
        ScanNetworkShares = true,         // registry + NetShareEnum — fast
        ScanDllLoadOrderHijack = true,    // registry + PATH check — fast
        ScanAntiDebugTechniques = false,  // process memory scan — slow
        ScanTokenImpersonation = false,   // process handle + token — slow
        ScanTokenIntegrityAbuse = true,   // integrity level check on running procs — fast
        ScanPowerShellSecurity = true,    // registry — fast
        ScanAlternativeDataStreams = false, // file walk — slow
        ScanVbsHvci = true,              // registry — fast
        ScanMemoryProtection = false,    // process memory walk — slow
        ScanWerFaultHijack = true,       // registry — fast
        ScanWindowsDefenderTamper = true, // registry — fast
        ScanCodeSigningBypass = true,    // registry + file stat — fast
        ScanDnsConfiguration = true,     // registry + hosts file — fast
        ScanGpuProcesses = true,         // process + registry — fast
        ScanProtectedProcesses = true,   // NtQueryInformationProcess — fast
        ScanHiddenFiles = false,         // file walk — slow
        ScanLoadedModuleIntegrity = false, // process memory compare — slow
        ScanRpcEndpoints = true,         // RPC API — fast
        ScanKernelCallbackTable = false, // process memory scan — slow
        ScanExceptionHandlerChain = false, // process memory scan — slow
        ScanApcInjection = false,          // thread handle + memory scan — slow
        ScanTlsCallbacks = false,          // process module memory scan — slow
        ScanAtomBombing = true,            // atom table enumeration — fast
        ScanReflectiveDllInjection = false, // virtual memory walk — slow
        ScanProcessDoppelganging = true,    // file stat + process query — fast
        ScanPpidSpoofing = true,            // NtQueryInformationProcess — fast
        ScanInlineHooks = false,            // process + disk read — slow
        ScanEtwTamper = true,              // ntdll comparison + ETW query — medium
        ScanHardwareBreakpoints = false,    // thread suspend+context — slow
        ScanShellcodeSignatures = false,    // process memory walk — slow
        ScanGameConfigManipulation = true,  // file read — fast
        ScanProcessMemoryStrings = false,   // process memory walk — slow
        ScanSuspiciousImports = false,      // process module walk + ReadProcessMemory — slow
        ScanMmapCodeInjection = false,      // VirtualQueryEx walk — slow
        ScanHiddenThreads = false,          // thread enumeration + suspend — slow
        ScanApiHashing = false,             // process memory walk — slow
        ScanRegistryTimestamps = true,      // registry timestamp read — fast
        ScanNtdllDoubleLoad = false,        // module enumeration — slow
        ScanAntiDumpProtection = false,     // process memory read — slow
        ScanPebAnomalies = false,           // NtQueryInformationProcess + ReadProcessMemory — slow
        ScanModuleStomping = false,         // process+disk compare — very slow
        ScanExternalOverlay = true,         // window enumeration + module check — fast
        ScanCheatFileArtifacts = false,     // recursive file walk — slow
        ScanAcBypassTools = true,           // process + registry check — fast
        ScanMemoryAllocatorAnomaly = false, // full VirtualQueryEx walk — slow
        ScanSuspiciousChildProcesses = true, // process tree query — fast
        ScanSteamApiIntegrity = false,      // process memory compare — slow
        ScanGameMemoryReadAccess = true,    // NtQuerySystemInformation — medium
        ScanCodeCaves = false,              // process+disk compare — slow
        ScanLspProviders = true,            // registry read — fast
        ScanVirtualProtectAbuse = false,    // process memory walk — slow
        ScanDebuggerAttach = true,          // NtQueryInformationProcess — fast
        ScanCorProfilerInjection = true,    // registry + env var — fast
        ScanScreenCaptureBlocking = true,   // EnumWindows + GetWindowDisplayAffinity — fast
        ScanStagedShellcode = false,        // process memory walk — slow
        ScanKernelPoolTags = true,          // NtQuerySystemInformation class 5 — fast
        ScanJobObjectRestrictions = true,   // IsProcessInJob + job query — fast
        ScanExportAddressTableHooks = false, // process EAT read — slow
        ScanDeletedProcessBinary = true,    // process + file stat — fast
        ScanInputDeviceFilter = true,       // registry — fast
        ScanNetworkGameServerSnoop = true,  // IP helper API — fast
        ScanPackedModules = false,          // process module walk — slow
        ScanUacBypassArtifacts = true,      // HKCU registry — fast
        ScanAntiCheatServiceIntegrity = true, // registry — fast
        ScanVulkanLayerInjection = true,      // registry + JSON file read — fast
        ScanLoopbackListeners = true,         // GetExtendedTcpTable/UdpTable — fast
        ScanProcessCommandLines = false,      // WMI Win32_Process query — slow
        ScanDirectXDebugLayer = true,         // registry — fast
        ScanSeDebugPrivilege = true,          // OpenProcessToken on all procs — medium
        ScanBepInExDoorstop = false,          // game directory walk — slow
        ScanAvExclusionActivePaths = true,    // registry + targeted dir scan — medium
        ScanWfpFilters = true,                // FwpmCalloutEnum0 via BFE — fast
        ScanProcessMitigations = true,        // GetProcessMitigationPolicy on game procs — fast
        ScanCryptoApiProviders = true,        // registry — fast
        ScanSteamEmulators = false,           // game directory walk — slow
        ScanHkcuAppInitDlls = true,           // registry — fast
        ScanCompatibilityLayerBypass = true,  // registry + env var — fast
        ScanKnownCheatMutexExt = true,        // NtQueryDirectoryObject — fast
        ScanCheatToolRegistryArtifacts = true, // registry artifact scan — fast
        ScanNtfsReparsePoints = false,         // filesystem walk — slow
        ScanWslAbuse = true,                   // registry + process check — fast
        ScanGameConfigCheats = false,          // game cfg file walk — slow
        ScanGlobalInputHooks = true,           // EnumWindows + process enum — fast
        ScanEfiVariables = true,              // GetFirmwareEnvironmentVariable — fast
        ScanDnsCacheExtended = true,          // DnsGetCacheDataTable — fast
        ScanSuspiciousNetworkAdapters = true, // GetAdaptersInfo + registry — fast
        ScanTokenIntegrityAbuse = true,       // integrity level check — fast
        ScanMouseAccelerationCheat = true,    // HID registry check — fast
        ScanNamedPipeCheatIpc = true,         // NtQueryDirectoryObject \Device\NamedPipe — fast
        ScanCheatInstallerArtifacts = false,  // filesystem scan — slow
        ScanSleepMasking = false,             // VirtualQueryEx memory scan — slow
        ScanActiveCheatConnections = true,    // GetExtendedTcpTable ALL — fast
        ScanDxVtableHooks = false,            // cross-process vtable read — slow
        ScanAcPriorityAbuse = true,           // GetPriorityClass + GetProcessAffinityMask — fast
        ScanSuspendedAcThreads = true,        // NtQuerySystemInformation class 5 — fast
        ScanPebLdrInconsistency = false,      // ReadProcessMemory walk — slow; elevation required
        ScanDirectInputVtableHooks = false,   // cross-process dinput8.dll scan — slow
        ScanJumpListForensics = true,         // small folder, byte-grep — fast (Ocean/detect.ac signature)
        ScanCloudSyncCheatArtifacts = false,  // potentially huge cloud folder walk — slow
        ScanTimelineActivity = true,          // single .db file byte-grep — fast (Ocean/detect.ac signature)
        ScanAimAssistHardware = true,         // USB/HID enum registry — fast
        ScanRecycleBinForensics = true,       // small $I files — fast
        ScanAppDataLocalLow = true,           // small folder — fast
        ScanDseBypass = true,                 // registry + bcdedit + Prefetch stat — fast
        ScanWifiHistory = true,               // netsh wlan show profiles — fast
        ScanBrowserBookmarks = true,          // bookmark JSON parse — fast
        ScanDiscordCheatArtifacts = true,     // LevelDB byte-grep — bounded
        ScanTelegramArtifacts = true,         // tdata byte-grep — bounded
        ScanMacroSoftware = true,             // JSON profile + AHK scan — fast
        ScanSteamCheatCorrelation = true,     // localconfig.vdf + ACF — fast
        ScanShadowplayArtifacts = true,       // clip file names — fast
        ScanVirtualAudioDevices = true,       // registry enum — fast
        ScanGpuComputeCheat = true,           // process + pip packages + dirs — fast
        ScanObsConfiguration = true,          // OBS JSON config scan — fast
        ScanAfterburnerRtss = true,           // Afterburner/RTSS config + registry — fast
        ScanCheatTools = true,                // installed software + Prefetch — fast
        ScanNetworkCheatSetup = true,         // SMB shares + network adapters — fast
        ScanVmHypervisor = true,              // VM software + drivers — fast
        ScanEventLogCheat = true,             // EVTX event ID mining — bounded
        ScanAntiDebugTools = true,            // RE tools installed/running — fast
        ScanScheduledTaskCheat = true,        // Task XML + TaskCache — fast
        ScanPowerShellHistory = true,         // PSReadLine history + profiles — fast
        ScanSpecialKReShade = true,           // SK install dirs + game dir DLL check — fast
        ScanFpsUnlockerExploits = true,       // installed software + Prefetch + AppData — fast
        ScanClipboardHistory = true,          // clipboard DB byte-grep — fast
        ScanAcServiceTamper = true,           // AC service registry + process check — fast
        ScanAccountCorrelation = true,        // loginusers.vdf + Riot config dirs — fast
        ScanShadowCopyState = true,           // vssadmin + VSS registry — fast
        ScanCryptoPayment = true,             // browser history byte-grep — bounded
        ScanAntiVirusTamper = true,           // Defender registry check — fast
        ScanGameFileIntegrity = false,        // game directory file walk — slow
        ScanRawAccelDriver = true,            // service registry + process check — fast
        ScanVulnerableDriverFiles = false,    // recursive filesystem scan — slow
        ScanSearchHistoryForensics = true,    // registry forensic keys — fast (Ocean signature)
        ScanCheatPayloadStaging = false,      // Temp/Downloads file walk — slow
        ScanWindowsNotificationForensics = true, // wpndatabase.db byte-grep — fast
        ScanSteamUserdataForensics = false,   // Steam userdata walk — slow
        DeepDriveScan = false,
        // No per-module timeout — every Quick module runs to completion. Quick stays
        // fast because slow modules are individually disabled above, not because they
        // get cut off mid-scan.
        ModuleTimeoutSeconds = 0,
    };

    public static ScanOptions Standard() => new ScanOptions(); // defaults

    public static ScanOptions Deep() => new ScanOptions
    {
        Profile = ScanProfile.Deep,
        // All true (inherit defaults) plus:
        DeepDriveScan = true,
        // No per-module timeout — every module runs to completion. Slow memory
        // walks, full drive scans, and hash baselines are never cut off mid-scan.
        ModuleTimeoutSeconds = 0,
        // Practical recursion ceiling: real-world cheat installs never nest
        // deeper than ~5–7 levels. 14 covers every observed cheat layout with
        // huge margin and skips the long tail of node_modules / package-cache
        // trees that 20 would walk for nothing.
        MaxDepth = 14,
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
