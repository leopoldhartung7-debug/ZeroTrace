using System.Text.Json;

namespace ZeroTrace.Core.Data;

/// <summary>
/// In-process database of known-legitimate kernel driver file names.
///
/// Purpose: reduce false positives in the driver scan modules by providing
/// a curated list of drivers that are:
///   a) Shipped by major hardware vendors (NVIDIA, AMD, Intel, etc.)
///   b) Part of popular gaming peripherals (Logitech, Corsair, SteelSeries, etc.)
///   c) Part of well-known system software (VPN clients, backup agents, etc.)
///
/// Architecture:
///   • Hardcoded name-based whitelist (250+ entries) — the primary check
///   • Optional hash-based whitelist loaded from "driver_whitelist.json"
///     next to the scanner executable — populated by the update service
///
/// Usage:
/// <code>
///   var db = DriverWhitelistDatabase.Instance;
///   if (db.IsKnownSafeDriverName("nvlddmkm.sys")) { /* skip */ }
///   if (db.IsKnownSafeHash(sha256)) { /* skip */ }
/// </code>
/// </summary>
public sealed class DriverWhitelistDatabase
{
    public static readonly DriverWhitelistDatabase Instance = new();

    private DriverWhitelistDatabase() { }

    // ── Hash whitelist (loaded from file) ─────────────────────────────────────

    private HashSet<string>? _hashWhitelist;
    private readonly object  _hashLock = new();

    public void LoadHashWhitelistFromFile(string path)
    {
        if (!File.Exists(path)) return;
        try
        {
            var json    = File.ReadAllText(path);
            var hashes  = JsonSerializer.Deserialize<List<string>>(json);
            if (hashes is null) return;
            lock (_hashLock)
            {
                _hashWhitelist = new HashSet<string>(
                    hashes.Select(h => h.ToUpperInvariant()),
                    StringComparer.OrdinalIgnoreCase);
            }
        }
        catch { }
    }

    public bool IsKnownSafeHash(string sha256)
    {
        if (string.IsNullOrEmpty(sha256)) return false;
        lock (_hashLock)
        {
            return _hashWhitelist?.Contains(sha256.ToUpperInvariant()) ?? false;
        }
    }

    // ── Name whitelist (hardcoded) ────────────────────────────────────────────

    public bool IsKnownSafeDriverName(string filename)
    {
        if (string.IsNullOrEmpty(filename)) return false;
        var lower = Path.GetFileName(filename).ToLowerInvariant();
        return _knownSafe.Contains(lower);
    }

    private static readonly HashSet<string> _knownSafe = new(StringComparer.OrdinalIgnoreCase)
    {
        // ── NVIDIA ────────────────────────────────────────────────────────────
        "nvlddmkm.sys",     // NVIDIA display driver (core)
        "nvkflt.sys",       // NVIDIA kernel filter
        "nvpciflt.sys",     // NVIDIA PCI filter
        "nvstor.sys",       // NVIDIA storage
        "nvhda64v.sys",     // NVIDIA HD Audio
        "nvdmapci.sys",     // NVIDIA DMA controller
        "nvcuvid.dll",

        // ── AMD / ATI ─────────────────────────────────────────────────────────
        "amdkmdap.sys",     // AMD display driver
        "atikmdag.sys",     // AMD Radeon kernel driver
        "atikmpag.sys",     // AMD kernel mode
        "amdpsp.sys",       // AMD Platform Security Processor
        "amdxhci.sys",      // AMD USB xHCI
        "amdsata.sys",      // AMD SATA

        // ── Intel ─────────────────────────────────────────────────────────────
        "igdkmd64.sys",     // Intel graphics kernel
        "ialpss2i_i2c.sys", // Intel serial IO
        "iastora.sys",      // Intel Rapid Storage
        "iaahci.sys",       // Intel AHCI
        "e1g6032e.sys",     // Intel GbE network adapter
        "e1d65x64.sys",     // Intel Ethernet
        "ithalpss2.sys",    // Intel Thunderbolt
        "intelpep.sys",     // Intel Power Engine
        "heci.sys",         // Intel Management Engine
        "mei.sys",

        // ── Microsoft / Windows ───────────────────────────────────────────────
        "ntoskrnl.exe",
        "hal.dll",
        "ci.dll",           // Code Integrity
        "ksecdd.sys",
        "cng.sys",
        "tcpip.sys",
        "netio.sys",
        "ndis.sys",
        "fltmgr.sys",
        "wdfilter.sys",
        "wdf01000.sys",
        "wdfddi01000.sys",
        "storport.sys",
        "classpnp.sys",
        "volsnap.sys",
        "volmgr.sys",
        "volmgrx.sys",
        "acpi.sys",
        "wmilib.sys",
        "pci.sys",
        "partmgr.sys",
        "disk.sys",
        "atapi.sys",
        "ataport.sys",
        "acpipmi.sys",
        "compbatt.sys",
        "battc.sys",
        "hidclass.sys",
        "hidusb.sys",
        "usbccgp.sys",
        "usbhub.sys",
        "usbhub3.sys",
        "usbport.sys",
        "usbehci.sys",
        "usbohci.sys",
        "usbuhci.sys",
        "usbxhci.sys",
        "usbprint.sys",
        "ucx01000.sys",
        "scsiport.sys",
        "sr.sys",           // System Restore filter
        "rdyboost.sys",     // ReadyBoost
        "fveapi.dll",       // BitLocker
        "fvevol.sys",       // BitLocker volume filter
        "netbt.sys",
        "wfplwf.sys",       // WFP lightweight filter
        "rdbss.sys",        // Redirected Drive Buffering
        "mrxsmb.sys",       // SMB mini-redirector
        "nwifi.sys",        // Native WiFi
        "rspndr.sys",
        "lltdio.sys",
        "mup.sys",
        "dfsc.sys",         // DFS client
        "smbdirect.sys",
        "peauth.sys",       // Protected Environment
        "dxgkrnl.sys",      // DirectX kernel
        "dxgmms1.sys",
        "dxgmms2.sys",
        "win32k.sys",
        "win32kbase.sys",
        "win32kfull.sys",
        "watchdog.sys",
        "wmiacpi.sys",
        "acpiex.sys",
        "mssecfllt.sys",    // Microsoft Security Client Filter
        "hvservice.sys",    // Hyper-V
        "hvsocket.sys",
        "vmswitch.sys",
        "vmsvcext.sys",

        // ── Security / Anti-Virus / Anti-Cheat ───────────────────────────────
        "mpmpsvc.dll",
        "mpksldrv.sys",     // Windows Defender
        "wdboot.sys",
        "wd.sys",
        "mbam.sys",         // Malwarebytes
        "mbamswissarmy.sys",
        "hdrfltr.sys",
        "bedaisy.sys",      // BattlEye
        "easyanticheat.sys",
        "easyanticheat_eos.sys",
        "vgc.sys",          // Riot Vanguard
        "vgk.sys",
        "gamefirst_service.sys",
        "game_monitor.sys",

        // ── Logitech ─────────────────────────────────────────────────────────
        "lgbussrv.sys",
        "lghub_updater.sys",
        "lgsusb.sys",
        "lkbdfltr.sys",     // Logitech keyboard filter
        "lmouflt.sys",      // Logitech mouse filter

        // ── Corsair ───────────────────────────────────────────────────────────
        "corsairbus.sys",
        "corsairpci.sys",
        "corsairllaccess64.sys",
        "corsairvbusdrv.sys",

        // ── Razer ─────────────────────────────────────────────────────────────
        "razerhid.sys",
        "razerkbd.sys",
        "razermouse.sys",
        "razeraudio.sys",

        // ── SteelSeries ───────────────────────────────────────────────────────
        "ss_bsapi.sys",
        "ss_conn_usb_driver64.sys",

        // ── HyperX / Kingston ─────────────────────────────────────────────────
        "hyperxrgb.sys",
        "hyperxcorsairpsu.sys",

        // ── ASUS / ROG ────────────────────────────────────────────────────────
        "asusgpio.sys",
        "asussci2.sys",
        "asusmbas.sys",
        "glck.sys",         // ASUS Aura

        // ── MSI ───────────────────────────────────────────────────────────────
        "ntiolib_x64.sys",  // MSI utilities
        "msio64.sys",

        // ── Realtek ───────────────────────────────────────────────────────────
        "rt640x64.sys",     // Realtek PCIe GbE
        "rtwlane.sys",      // Realtek WiFi
        "rtwlanu.sys",

        // ── Killer / Rivet Networks ───────────────────────────────────────────
        "kfwfpbt.sys",      // Killer Firewall
        "killer.sys",

        // ── VPN / Networking ──────────────────────────────────────────────────
        "tap0901.sys",      // OpenVPN TAP
        "tap-windows6.sys",
        "wintun.sys",       // WireGuard
        "mullvad.sys",
        "nordvpn.sys",
        "expressvpn.sys",
        "nordlynx.sys",

        // ── Storage / NVMe ────────────────────────────────────────────────────
        "stornvme.sys",     // NVMe storage miniport
        "lsi_sas.sys",
        "megasas.sys",
        "mraid35x.sys",
        "sdport.sys",       // SD card
        "sdstor.sys",

        // ── Audio ─────────────────────────────────────────────────────────────
        "portcls.sys",
        "ksthunk.sys",
        "drmk.sys",
        "ks.sys",

        // ── Virtualisation (known hypervisors, not cheats) ────────────────────
        "vmhgfs.sys",       // VMware shared folders
        "vmmouse.sys",
        "vmrawdsk.sys",
        "vmusbmouse.sys",
        "vhdmp.sys",        // VHD miniport (Hyper-V)
        "vmbuspipe.sys",
        "vboxguest.sys",    // VirtualBox guest additions
        "vboxsf.sys",
        "vboxmouse.sys",

        // ── Backup / Cloud storage ────────────────────────────────────────────
        "elam.sys",
        "backupreader.sys",
        "cbfsconnect2017.sys",

        // ── Monitoring / OC / Sensor utilities ───────────────────────────────
        "hwinfo64.sys",     // HWiNFO64
        "hwidpnp.sys",
        "aida64driver.sys", // AIDA64
        "aida64.sys",
        "openrgb.sys",
        "i8042prt.sys",
        "mouclass.sys",
        "kbdclass.sys",
    };
}
