namespace ZeroTrace.Core.Models;

/// <summary>One running process for the dashboard "Executable List".</summary>
public sealed class ProcInfo
{
    public int Pid { get; set; }
    public string Name { get; set; } = "";
    public string? Path { get; set; }
    public bool? Signed { get; set; }
    public bool Elevated { get; set; }
    public string? CompileDate { get; set; }
}

/// <summary>One loaded kernel driver for the dashboard "Loaded Drivers".</summary>
public sealed class DriverInfo
{
    public string Name { get; set; } = "";
    public string? Path { get; set; }
    public bool? Signed { get; set; }
    public bool Running { get; set; }
}

/// <summary>A removable/USB storage device seen on the machine.</summary>
public sealed class UsbInfo
{
    public string Name { get; set; } = "";
    public string? Serial { get; set; }
}

/// <summary>A Steam account found in the local loginusers.vdf.</summary>
public sealed class SteamAccountInfo
{
    public string SteamId { get; set; } = "";
    public string AccountName { get; set; } = "";
    public string PersonaName { get; set; } = "";
    public bool MostRecent { get; set; }
}

/// <summary>One Discord guild (server) the local user is a member of,
/// recovered from the Discord client's local cache.</summary>
public sealed class DiscordGuildInfo
{
    public string Name { get; set; } = "";
    public string Id { get; set; } = "";
    /// <summary>"clean" | "reselling" | "cheat" — set by DiscordScanModule.</summary>
    public string Flag { get; set; } = "clean";
    /// <summary>The single keyword that triggered the flag, for explainability.</summary>
    public string? MatchedKeyword { get; set; }
}

/// <summary>Discord account info recovered from the local client cache.</summary>
public sealed class DiscordAccountInfo
{
    public string UserId { get; set; } = "";
    public string Username { get; set; } = "";
    public string Discriminator { get; set; } = "";
    public string? Email { get; set; }
    public string? GlobalName { get; set; }
}

/// <summary>Virtual-machine detection result.</summary>
public sealed class VmInfo
{
    public bool Detected { get; set; }
    public string Verdict { get; set; } = "Keine VM-Indikatoren";
    public List<string> Indicators { get; set; } = new();
}

/// <summary>
/// Read-only host inventory that feeds the dashboard panels (Executable List,
/// Loaded Drivers, Admin-Executed, Recording Software, VM Detection, USB
/// Activity).
/// </summary>
public sealed class HostInventory
{
    public List<ProcInfo> Processes { get; set; } = new();
    public List<ProcInfo> AdminExecuted { get; set; } = new();
    public List<DriverInfo> Drivers { get; set; } = new();
    public List<string> RecordingSoftware { get; set; } = new();
    public VmInfo Vm { get; set; } = new();
    public List<UsbInfo> UsbDevices { get; set; } = new();
    public List<SteamAccountInfo> SteamAccounts { get; set; } = new();
    public List<DiscordGuildInfo> DiscordGuilds { get; set; } = new();
    public DiscordAccountInfo? DiscordAccount { get; set; }
}
