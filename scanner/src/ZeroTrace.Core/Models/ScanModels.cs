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
