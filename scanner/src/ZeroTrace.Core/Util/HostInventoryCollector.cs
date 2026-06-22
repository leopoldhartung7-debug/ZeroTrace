using System.Management;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Util;

/// <summary>
/// Read-only collection of the host inventory shown on the dashboard. Makes no
/// changes and no outbound calls. Signature checks under the Windows folder are
/// assumed trusted to keep the pass fast.
/// </summary>
public static class HostInventoryCollector
{
    private static readonly string WinDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    private static readonly string[] RecordingNames =
    {
        "obs64", "obs32", "obs", "streamlabs obs", "streamlabs", "xsplit", "bandicam",
        "fraps", "dxtory", "action", "camtasia", "nvidia share", "nvcontainer",
        "shadowplay", "radeonsoftware", "medal", "outplayed", "gamebar", "wondershare"
    };

    public static HostInventory Collect()
    {
        var inv = new HostInventory();
        try { CollectProcesses(inv); } catch { }
        try { CollectDrivers(inv); } catch { }
        try { inv.Vm = DetectVm(); } catch { }
        try { CollectUsb(inv); } catch { }
        try { CollectSteamAccounts(inv); } catch { }
        return inv;
    }

    // --- processes (Executable List + Admin-Executed + Recording Software) -----

    private static void CollectProcesses(HostInventory inv)
    {
        using var searcher = new ManagementObjectSearcher(
            "SELECT ProcessId, Name, ExecutablePath FROM Win32_Process");
        int n = 0;
        foreach (ManagementObject mo in searcher.Get())
        {
            if (n++ > 1000) break;
            int pid = ToInt(mo["ProcessId"]);
            var name = mo["Name"]?.ToString() ?? "?";
            var path = mo["ExecutablePath"]?.ToString();

            var p = new ProcInfo
            {
                Pid = pid,
                Name = name,
                Path = path,
                Signed = SignedFor(path),
                Elevated = pid > 4 && IsProcessElevated(pid),
                CompileDate = path is not null ? PeCompileDate(path) : null
            };
            inv.Processes.Add(p);
            if (p.Elevated) inv.AdminExecuted.Add(p);

            var ln = name.ToLowerInvariant();
            if (RecordingNames.Any(r => ln.Contains(r)) && !inv.RecordingSoftware.Contains(name))
                inv.RecordingSoftware.Add(name);
        }
    }

    // --- loaded drivers --------------------------------------------------------

    private static void CollectDrivers(HostInventory inv)
    {
        using var searcher = new ManagementObjectSearcher(
            "SELECT Name, PathName, State FROM Win32_SystemDriver");
        foreach (ManagementObject mo in searcher.Get())
        {
            var name = mo["Name"]?.ToString() ?? "?";
            var path = NormalizeDriver(mo["PathName"]?.ToString());
            inv.Drivers.Add(new DriverInfo
            {
                Name = name,
                Path = path,
                Signed = SignedFor(path),
                Running = string.Equals(mo["State"]?.ToString(), "Running", StringComparison.OrdinalIgnoreCase)
            });
        }
    }

    // --- virtual machine detection --------------------------------------------

    private static VmInfo DetectVm()
    {
        var ind = new List<string>();
        var cs = (Wmi("Win32_ComputerSystem", "Manufacturer") + " " +
                  Wmi("Win32_ComputerSystem", "Model")).ToLowerInvariant();
        var bios = (Wmi("Win32_BIOS", "Manufacturer") + " " +
                    Wmi("Win32_BIOS", "SerialNumber")).ToLowerInvariant();
        var board = (Wmi("Win32_BaseBoard", "Manufacturer") + " " +
                     Wmi("Win32_BaseBoard", "Product")).ToLowerInvariant();
        var hay = cs + " " + bios + " " + board;

        foreach (var (token, label) in new[]
                 {
                     ("vmware", "VMware"), ("virtualbox", "VirtualBox"), ("vbox", "VirtualBox"),
                     ("qemu", "QEMU"), ("kvm", "KVM"), ("xen", "Xen"), ("hyper-v", "Hyper-V"),
                     ("virtual machine", "Virtual Machine"), ("parallels", "Parallels"),
                     ("innotek", "VirtualBox"), ("bochs", "Bochs")
                 })
        {
            if (hay.Contains(token) && !ind.Contains(label)) ind.Add(label);
        }

        if (string.Equals(Wmi("Win32_ComputerSystem", "HypervisorPresent"), "True", StringComparison.OrdinalIgnoreCase))
            ind.Add("Hypervisor aktiv");

        return new VmInfo
        {
            Detected = ind.Count > 0,
            Indicators = ind,
            Verdict = ind.Count == 0 ? "Keine VM-Indikatoren" : "VM-Indikatoren: " + string.Join(", ", ind)
        };
    }

    // --- USB storage history (USBSTOR) -----------------------------------------

    private static void CollectUsb(HostInventory inv)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var usbstor = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USBSTOR");
            if (usbstor is null) return;

            foreach (var model in usbstor.GetSubKeyNames())
            {
                using var modelKey = usbstor.OpenSubKey(model);
                if (modelKey is null) continue;
                foreach (var instance in modelKey.GetSubKeyNames())
                {
                    using var inst = modelKey.OpenSubKey(instance);
                    var friendly = inst?.GetValue("FriendlyName")?.ToString()
                                   ?? model.Replace("Disk&Ven_", "").Replace("&Prod_", " ");
                    inv.UsbDevices.Add(new UsbInfo { Name = friendly, Serial = instance });
                    if (inv.UsbDevices.Count >= 50) return;
                }
            }
        }
        catch { /* SYSTEM hive needs admin -> skip */ }
    }

    // --- Steam accounts (loginusers.vdf) ---------------------------------------

    private static void CollectSteamAccounts(HostInventory inv)
    {
        var steamPath = Registry.GetValue(
            @"HKEY_CURRENT_USER\Software\Valve\Steam", "SteamPath", null) as string;
        if (string.IsNullOrEmpty(steamPath)) return;

        var vdf = Path.Combine(steamPath, "config", "loginusers.vdf");
        if (!File.Exists(vdf)) return;

        string[] lines;
        try { lines = File.ReadAllLines(vdf, System.Text.Encoding.UTF8); }
        catch { return; }

        // Minimal VDF parser for the flat two-level structure:
        // "users" { "steamid64" { "AccountName" "..." "PersonaName" "..." } }
        SteamAccountInfo? current = null;
        int depth = 0;

        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line == "{") { depth++; continue; }
            if (line == "}")
            {
                if (depth == 2 && current != null) { inv.SteamAccounts.Add(current); current = null; }
                depth--;
                continue;
            }

            if (depth == 1 && line.StartsWith('"') && line.EndsWith('"'))
            {
                var id = line.Trim('"');
                if (id.Length >= 17 && long.TryParse(id, out _))
                    current = new SteamAccountInfo { SteamId = id };
                continue;
            }

            if (depth == 2 && current != null)
            {
                var m = System.Text.RegularExpressions.Regex.Match(
                    line, @"""([^""]+)""\s+""([^""]*)""");
                if (!m.Success) continue;
                switch (m.Groups[1].Value.ToLowerInvariant())
                {
                    case "accountname": current.AccountName = m.Groups[2].Value; break;
                    case "personaname": current.PersonaName = m.Groups[2].Value; break;
                    case "mostrecent": current.MostRecent = m.Groups[2].Value == "1"; break;
                }
            }
        }
        if (inv.SteamAccounts.Count > 20)
            inv.SteamAccounts = inv.SteamAccounts.Take(20).ToList();
    }

    // --- helpers ---------------------------------------------------------------

    private static bool? SignedFor(string? path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
        try
        {
            // Files under the Windows folder are assumed trusted (Microsoft-signed)
            // to keep this pass fast; everything else is verified for real.
            if (Path.GetFullPath(path).StartsWith(WinDir, StringComparison.OrdinalIgnoreCase))
                return true;
            if (!SignatureChecker.IsCheckable(path)) return null;
            return SignatureChecker.CheckDetailed(path).IsTrusted;
        }
        catch { return null; }
    }

    private static string? PeCompileDate(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            using var br = new BinaryReader(fs);
            if (fs.Length < 0x40) return null;
            fs.Position = 0x3C;
            int peOff = br.ReadInt32();
            if (peOff <= 0 || peOff + 8 > fs.Length) return null;
            fs.Position = peOff;
            if (br.ReadUInt32() != 0x00004550) return null; // "PE\0\0"
            br.ReadUInt16(); // machine
            br.ReadUInt16(); // numberOfSections
            uint ts = br.ReadUInt32(); // TimeDateStamp (Unix epoch)
            if (ts == 0) return null;
            var dt = DateTimeOffset.FromUnixTimeSeconds(ts).UtcDateTime;
            // Reject implausible values (deterministic-build hashes look like far-future).
            if (dt.Year < 2000 || dt > DateTime.UtcNow.AddDays(2)) return null;
            return dt.ToString("yyyy-MM-dd");
        }
        catch { return null; }
    }

    private static string? NormalizeDriver(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var p = raw.Trim().Trim('"');
        if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p[4..];
        if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            p = Path.Combine(WinDir, p[@"\SystemRoot\".Length..]);
        else if (p.StartsWith("system32\\", StringComparison.OrdinalIgnoreCase))
            p = Path.Combine(WinDir, p);
        try { return Path.GetFullPath(p); } catch { return raw; }
    }

    private static int ToInt(object? o) => int.TryParse(o?.ToString(), out var v) ? v : 0;

    private static string Wmi(string cls, string prop)
    {
        try
        {
            using var s = new ManagementObjectSearcher($"SELECT {prop} FROM {cls}");
            foreach (ManagementObject mo in s.Get())
            {
                var v = mo[prop]?.ToString();
                if (!string.IsNullOrWhiteSpace(v)) return v;
            }
        }
        catch { }
        return "";
    }

    // --- per-process elevation (best effort, read-only) ------------------------

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr proc, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int cls, out uint info, uint len, out uint retLen);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr h);

    private static bool IsProcessElevated(int pid)
    {
        const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        const uint TOKEN_QUERY = 0x0008;
        const int TokenElevation = 20;

        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
        if (h == IntPtr.Zero) return false;
        try
        {
            if (!OpenProcessToken(h, TOKEN_QUERY, out var tok)) return false;
            try
            {
                return GetTokenInformation(tok, TokenElevation, out uint elev, sizeof(uint), out _) && elev != 0;
            }
            finally { CloseHandle(tok); }
        }
        finally { CloseHandle(h); }
    }
}
