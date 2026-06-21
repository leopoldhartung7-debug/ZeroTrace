namespace ZeroTrace.Core.Models;

/// <summary>
/// User-configurable scan parameters. Persisted in the settings table so the
/// UI and engine share one source of truth.
/// </summary>
public sealed class ScanOptions
{
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

    /// <summary>
    /// When true, the Windows hosts file is checked for entries that block
    /// (loopback) or redirect anti-cheat / game / launcher domains.
    /// </summary>
    public bool ScanHostsFile { get; set; } = true;
    public bool ScanOverlay { get; set; } = true;
    public bool ScanWmiPersistence { get; set; } = true;
    public bool ScanMemory { get; set; } = true;

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
        "Windows", "$Recycle.Bin", "System Volume Information",
        "WinSxS", "Program Files", "Program Files (x86)"
    };

    /// <summary>Maximum recursion depth for the deep drive scan.</summary>
    public int MaxDepth { get; set; } = 12;

    /// <summary>Files larger than this (bytes) are not hashed (default 200 MB).</summary>
    public long MaxHashFileSizeBytes { get; set; } = 200L * 1024 * 1024;
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
