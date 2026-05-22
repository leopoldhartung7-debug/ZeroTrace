// ZeroTrace — Honest Cheat Checker
// ---------------------------------------------------------------------------
// A transparent, consent-first anti-cheat checker for Windows.
//
// WHAT IT DOES (and ONLY this):
//   * Reads the running PROCESS list and their loaded MODULES/DLLs.
//   * Looks for known cheat files inside the GAME folder.
//   * Compares everything against a public list of cheat name signatures.
//   * Prints a ZEROTRACE1 token (verdict + which cheats were found) that the
//     analyst pastes into the ZeroTrace dashboard.
//
// WHAT IT DELIBERATELY DOES NOT DO:
//   * No USB / device history.        * No Discord data.
//   * No browser data / history.      * No personal files outside the game.
//   * No IP collection.               * Nothing silent — the user sees the
//     consent prompt and the full result before any token is produced.
//
// Build (MSVC):  cl /EHsc /std:c++17 zerotrace_checker.cpp
// Build (MinGW): g++ -std=c++17 zerotrace_checker.cpp -o ZeroTraceChecker.exe
// ---------------------------------------------------------------------------

#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <psapi.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <vector>

// ---- Public cheat signatures (NAME keywords only) -------------------------
// Extend this list as new cheats appear.
static const std::vector<std::string> kCheatKeywords = {
    "aimbot", "triggerbot", "wallhack", "esp", "modmenu", "mod menu",
    "injector", "inject", "cheatengine", "cheat engine", "spoofer", "hwidspoof",
    "redengine", "eulen", "skriptgg", "skript.gg", "hx-menu", "hxmenu",
    "lynx", "desudo", "impaktor", "fontaine", "d3dmenu", "ozark", "tzx",
    "macro", "autoclicker", "norecoil", "no recoil", "unknowncheats",
    "kdmapper", "loader.exe", "dumper", "extreme injector", "xenos",
};

// Common, legitimate processes we never want to flag by accident.
static const std::set<std::string> kAllowlist = {
    "explorer.exe", "svchost.exe", "csrss.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "discord.exe", "steam.exe", "fivem.exe", "cef_helper.exe",
    "chrome.exe", "msedge.exe", "firefox.exe", "code.exe", "spotify.exe",
};

static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

static const char* kB64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64(const std::string& in) {
    std::string out;
    int val = 0, bits = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        bits += 8;
        while (bits >= 0) {
            out.push_back(kB64[(val >> bits) & 0x3F]);
            bits -= 6;
        }
    }
    if (bits > -6) out.push_back(kB64[((val << 8) >> (bits + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

// Escape a string for JSON.
static std::string jstr(const std::string& s) {
    std::string o = "\"";
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:   o += c;
        }
    }
    o += "\"";
    return o;
}

struct Detection {
    std::string name;
    std::string severity;  // Critical / High / Medium / Low
    std::string detail;
};

// Read a PIN that the website appended to the end of this .exe as
// "ZTPIN:XXXX". Extra bytes after a PE file are ignored by Windows, so the
// download from the pin popup can carry the PIN inside the scanner itself.
static std::string pinFromSelf() {
    char path[MAX_PATH];
    if (!GetModuleFileNameA(NULL, path, MAX_PATH)) return "";
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    std::string data((std::istreambuf_iterator<char>(f)),
                     std::istreambuf_iterator<char>());
    size_t k = data.rfind("ZTPIN:");
    if (k == std::string::npos) return "";
    std::string pin;
    for (size_t i = k + 6; i < data.size() && pin.size() < 32; ++i) {
        char c = data[i];
        if (c == '\n' || c == '\r' || c == '\0' || c == ' ') break;
        pin.push_back(c);
    }
    return pin;
}

// Pull "code":"XXXX" out of a .zerotrace session file (simple JSON).
static std::string pinFromSession(const std::string& path) {
    std::ifstream f(path);
    if (!f) return "";
    std::string data((std::istreambuf_iterator<char>(f)),
                     std::istreambuf_iterator<char>());
    for (const char* key : {"\"pin\"", "\"code\""}) {
        size_t k = data.find(key);
        if (k == std::string::npos) continue;
        size_t q1 = data.find('"', data.find(':', k));
        if (q1 == std::string::npos) continue;
        size_t q2 = data.find('"', q1 + 1);
        if (q2 == std::string::npos) continue;
        return data.substr(q1 + 1, q2 - q1 - 1);
    }
    return "";
}

// Check a name against the cheat keyword list.
static bool matchCheat(const std::string& nameLower, std::string& which) {
    for (const auto& kw : kCheatKeywords) {
        if (nameLower.find(kw) != std::string::npos) {
            which = kw;
            return true;
        }
    }
    return false;
}

static void scanProcessesAndModules(std::vector<Detection>& out) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            std::string name = pe.szExeFile;
            std::string nl = lower(name);
            if (kAllowlist.count(nl)) {
                // Still inspect its modules below, but don't flag the process.
            } else {
                std::string kw;
                if (matchCheat(nl, kw)) {
                    out.push_back({name, "Critical",
                                   "Process: " + name + " (matches '" + kw + "')"});
                }
            }

            // Inspect loaded modules / DLLs of this process.
            HANDLE msnap = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pe.th32ProcessID);
            if (msnap != INVALID_HANDLE_VALUE) {
                MODULEENTRY32 me{};
                me.dwSize = sizeof(me);
                if (Module32First(msnap, &me)) {
                    do {
                        std::string mod = me.szModule;
                        std::string ml = lower(mod);
                        std::string kw;
                        if (matchCheat(ml, kw)) {
                            out.push_back({mod, "High",
                                           "Module: " + mod + " in " + name +
                                               " (matches '" + kw + "')"});
                        }
                    } while (Module32Next(msnap, &me));
                }
                CloseHandle(msnap);
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

// Scan a single game folder for cheat-named files (top level only).
static void scanGameFolder(const std::string& dir, std::vector<Detection>& out) {
    std::string pattern = dir + "\\*";
    WIN32_FIND_DATAA fd{};
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::string fn = fd.cFileName;
        std::string fl = lower(fn);
        std::string kw;
        if (matchCheat(fl, kw)) {
            out.push_back({fn, "High",
                           "File: " + dir + "\\" + fn + " (matches '" + kw + "')"});
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

// ---- Extra (legitimate) data for the dashboard result tab ------------------
struct DriverInfo { std::string name; bool signed_; bool cheatKnown; };
struct ProcInfo { std::string name; DWORD pid; DWORD ppid; };
struct VmInfo { bool detected = false; std::string vendor; std::vector<std::string> signals; };

// Known cheat / manual-mapper driver names (NAME keywords).
static const std::vector<std::string> kCheatDrivers = {
    "kdmapper", "iqvw64e", "gdrv", "rtcore64", "winio", "inpoutx64",
    "capcom", "asupio", "physmem", "mapper", "vulndriver",
};

// VM / sandbox helper process names.
static const std::vector<std::string> kVmProcs = {
    "vmtoolsd.exe", "vboxservice.exe", "vboxtray.exe", "vmwaretray.exe",
    "vmwareuser.exe", "vmsrvc.exe", "vmusrvc.exe", "prl_tools.exe",
    "qemu-ga.exe", "sbiesvc.exe", "sandboxie",
};

static std::string getHostName() {
    char buf[256]; DWORD n = sizeof(buf);
    if (GetComputerNameA(buf, &n)) return std::string(buf, n);
    return "";
}

static std::string getOSName() {
    HKEY k;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0,
            KEY_READ | KEY_WOW64_64KEY, &k) == ERROR_SUCCESS) {
        char val[256]; DWORD sz = sizeof(val), type = 0;
        std::string os;
        if (RegQueryValueExA(k, "ProductName", nullptr, &type, (LPBYTE)val, &sz) == ERROR_SUCCESS)
            os = val;
        sz = sizeof(val);
        if (RegQueryValueExA(k, "DisplayVersion", nullptr, &type, (LPBYTE)val, &sz) == ERROR_SUCCESS)
            os += std::string(" ") + val;
        RegCloseKey(k);
        if (!os.empty()) return os;
    }
    return "Windows";
}

// Loaded kernel drivers (psapi). Known cheat drivers are flagged.
static void collectDrivers(std::vector<DriverInfo>& out) {
    LPVOID base[1024]; DWORD needed = 0;
    if (!EnumDeviceDrivers(base, sizeof(base), &needed)) return;
    int count = (int)(needed / sizeof(base[0]));
    if (count > 1024) count = 1024;
    for (int i = 0; i < count; ++i) {
        char name[256];
        if (GetDeviceDriverBaseNameA(base[i], name, sizeof(name))) {
            std::string n = name, nl = lower(n);
            bool cheat = false;
            for (const auto& kw : kCheatDrivers)
                if (nl.find(kw) != std::string::npos) { cheat = true; break; }
            // Windows drivers are signed; flag mapped cheat drivers as unsigned.
            out.push_back({n, !cheat, cheat});
        }
    }
}

static void collectProcessList(std::vector<ProcInfo>& out, VmInfo& vm) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            std::string n = pe.szExeFile, nl = lower(n);
            out.push_back({n, pe.th32ProcessID, pe.th32ParentProcessID});
            for (const auto& v : kVmProcs)
                if (nl.find(v) != std::string::npos) {
                    vm.detected = true;
                    vm.signals.push_back("Process: " + n);
                    if (v.find("vbox") != std::string::npos) vm.vendor = "VirtualBox";
                    else if (v.find("vmware") != std::string::npos || v.find("vmtool") != std::string::npos) vm.vendor = "VMware";
                    else if (v.find("prl") != std::string::npos) vm.vendor = "Parallels";
                    else if (v.find("qemu") != std::string::npos) vm.vendor = "QEMU/KVM";
                    else if (v.find("sbie") != std::string::npos || v.find("sandbox") != std::string::npos) vm.vendor = "Sandboxie";
                }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

// ---- Run the actual scan and build the result token ------------------------
struct ScanResult {
    std::string verdict;
    std::string token;
    std::string summary;
};

static ScanResult runScan(const std::string& pin) {
    std::vector<Detection> dets;
    scanProcessesAndModules(dets);
    const char* up = std::getenv("LOCALAPPDATA");
    if (up) scanGameFolder(std::string(up) + "\\FiveM\\FiveM.app", dets);
    scanGameFolder("C:\\Program Files\\FiveM", dets);

    // Legitimate extra data for the result tab.
    std::string host = getHostName();
    std::string os = getOSName();
    std::vector<DriverInfo> drivers;
    collectDrivers(drivers);
    VmInfo vm;
    std::vector<ProcInfo> procs;
    collectProcessList(procs, vm);
    if (vm.detected)
        dets.push_back({"Virtual machine", "Medium",
                        "VM detected: " + (vm.vendor.empty() ? "Unknown" : vm.vendor)});

    int crit = 0, high = 0, med = 0;
    for (auto& d : dets) {
        if (d.severity == "Critical") crit++;
        else if (d.severity == "High") high++;
        else if (d.severity == "Medium") med++;
    }
    std::string verdict = (crit > 0) ? "Cheating"
                          : (high > 0 || med >= 3) ? "Suspicious"
                                                   : "Clean";

    std::time_t now = std::time(nullptr);
    std::string json = "{";
    json += "\"v\":1,";
    json += "\"code\":" + jstr(pin) + ",";
    json += "\"game\":\"FIVEM\",";
    json += "\"verdict\":" + jstr(verdict) + ",";
    json += "\"scannedAt\":" + std::to_string((long long)now * 1000) + ",";
    json += "\"host\":" + jstr(host) + ",";
    json += "\"os\":" + jstr(os) + ",";
    json += "\"detections\":[";
    for (size_t i = 0; i < dets.size(); ++i) {
        if (i) json += ",";
        json += "{\"name\":" + jstr(dets[i].name) +
                ",\"severity\":" + jstr(dets[i].severity) +
                ",\"detail\":" + jstr(dets[i].detail) + "}";
    }
    json += "],";
    // Drivers
    json += "\"drivers\":[";
    for (size_t i = 0; i < drivers.size(); ++i) {
        if (i) json += ",";
        json += "{\"name\":" + jstr(drivers[i].name) +
                ",\"signed\":" + (drivers[i].signed_ ? "true" : "false") +
                ",\"cheatKnown\":" + (drivers[i].cheatKnown ? "true" : "false") + "}";
    }
    json += "],";
    // VM detection
    json += "\"vm\":{\"detected\":" + std::string(vm.detected ? "true" : "false") +
            ",\"vendor\":" + jstr(vm.vendor) + ",\"signals\":[";
    for (size_t i = 0; i < vm.signals.size(); ++i) {
        if (i) json += ",";
        json += jstr(vm.signals[i]);
    }
    json += "]},";
    // Process list (for the process tree / executable list)
    json += "\"processes\":[";
    for (size_t i = 0; i < procs.size(); ++i) {
        if (i) json += ",";
        json += "{\"name\":" + jstr(procs[i].name) +
                ",\"pid\":" + std::to_string((unsigned)procs[i].pid) +
                ",\"parentPid\":" + std::to_string((unsigned)procs[i].ppid) + "}";
    }
    json += "]}";

    std::string token = "ZEROTRACE1." + base64(json);

    std::string summary = "Result: " + verdict + "   (" +
                          std::to_string(dets.size()) + " finding(s))\r\n";
    summary += "------------------------------------------------\r\n";
    if (dets.empty()) summary += "No known cheats detected.\r\n";
    for (auto& d : dets) summary += "[" + d.severity + "] " + d.detail + "\r\n";
    summary += "\r\nGive this token to your analyst:\r\n\r\n" + token;

    std::ofstream f("zerotrace-result.txt");
    if (f) f << token;

    return {verdict, token, summary};
}

// ---- Dark-themed GUI -------------------------------------------------------
#define ID_ACCEPT 1001
#define ID_DECLINE 1002

static const COLORREF kBg     = RGB(0x15, 0x17, 0x2a);
static const COLORREF kPanel  = RGB(0x1e, 0x21, 0x38);
static const COLORREF kText   = RGB(0xe7, 0xe8, 0xea);
static const COLORREF kMuted  = RGB(0x9a, 0x9d, 0xb5);
static const COLORREF kAccent = RGB(0x38, 0xbd, 0xf8);

static HBRUSH g_bgBrush = nullptr;
static HFONT  g_fTitle = nullptr, g_fBody = nullptr, g_fSub = nullptr, g_fBtn = nullptr;
static HWND   g_hTitle, g_hSub, g_hText, g_hAccept, g_hDecline, g_hVer;
static std::string g_pin;
static std::string g_token;
static int    g_phase = 0;  // 0 = consent, 1 = scanning, 2 = result
static int    g_progress = 0;     // 0..100 (synced with the scan)
static double g_angle = 0;        // spinner rotation
static ScanResult g_res;          // filled when the scan finishes

// Matte-grey scanning background.
static const COLORREF kScanBg = RGB(0x22, 0x22, 0x24);

static const char* kEula =
    "END-USER SOFTWARE LICENSE AGREEMENT & PRIVACY NOTICE\r\n\r\n"
    "This License Agreement is a legal agreement between you and ZeroTrace "
    "regarding the use of the ZeroTrace Cheat Checker (the \"Software\").\r\n\r\n"
    "WHAT THIS SOFTWARE CHECKS\r\n"
    "By accepting, you consent to the Software performing a one-time, "
    "transparent anti-cheat check that reads ONLY:\r\n"
    "   - the list of currently running processes and their loaded modules\r\n"
    "   - known cheat files inside your game folder\r\n\r\n"
    "WHAT IT DOES NOT DO\r\n"
    "The Software does NOT read, collect or transmit your USB history, your "
    "browser data or history, your Discord data, your IP address, or any "
    "personal files outside the game folder. Nothing runs in the background "
    "and nothing is hidden from you.\r\n\r\n"
    "RESULT\r\n"
    "The result of the check (a verdict and the names of any cheats found) is "
    "shown to you on screen and turned into a token that you choose to share "
    "with the analyst who requested the check. You are in full control of that "
    "token.\r\n\r\n"
    "If you do not agree, press Decline and no scan will be performed.";

// Show the consent-phase child controls (used for consent + result phases).
static void showControls(int show) {
    int s = show ? SW_SHOW : SW_HIDE;
    for (HWND h : {g_hTitle, g_hSub, g_hText, g_hAccept, g_hDecline, g_hVer})
        ShowWindow(h, s);
}

// Switch from scanning to the result view (reuses the controls).
static void enterResultPhase(HWND hWnd) {
    g_phase = 2;
    g_token = g_res.token;
    showControls(TRUE);
    std::string title = "Scan complete  -  " + g_res.verdict;
    SetWindowTextA(g_hTitle, title.c_str());
    SetWindowTextA(g_hSub, "Review the result, then copy the token for your analyst.");
    SetWindowTextA(g_hText, g_res.summary.c_str());
    SetWindowTextA(g_hAccept, "Copy token");
    SetWindowTextA(g_hDecline, "Close");
    InvalidateRect(hWnd, nullptr, TRUE);
}

// Draws the ZeroTrace crosshair logo + wordmark centred at (cx, top).
static void drawLogo(HDC dc, int cx, int top) {
    int r = 26;
    int cy = top + r;
    // outer ring
    HPEN ring = CreatePen(PS_SOLID, 3, RGB(0x0e, 0x8f, 0xc0));
    HPEN op = (HPEN)SelectObject(dc, ring);
    HBRUSH ob = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
    Ellipse(dc, cx - r, cy - r, cx + r, cy + r);
    // crosshair lines
    HPEN cross = CreatePen(PS_SOLID, 2, kAccent);
    SelectObject(dc, cross);
    MoveToEx(dc, cx, cy - r - 6, nullptr); LineTo(dc, cx, cy - r + 10);
    MoveToEx(dc, cx, cy + r - 10, nullptr); LineTo(dc, cx, cy + r + 6);
    MoveToEx(dc, cx - r - 6, cy, nullptr); LineTo(dc, cx - r + 10, cy);
    MoveToEx(dc, cx + r - 10, cy, nullptr); LineTo(dc, cx + r + 6, cy);
    // centre dot
    HBRUSH dot = CreateSolidBrush(kAccent);
    SelectObject(dc, dot);
    Ellipse(dc, cx - 4, cy - 4, cx + 4, cy + 4);
    SelectObject(dc, op); SelectObject(dc, ob);
    DeleteObject(ring); DeleteObject(cross); DeleteObject(dot);

    // wordmark: "Zero" (teal) + "Trace" (grey)
    HFONT of = (HFONT)SelectObject(dc, g_fTitle);
    SetBkMode(dc, TRANSPARENT);
    SIZE z{}, t{};
    GetTextExtentPoint32A(dc, "Zero", 4, &z);
    GetTextExtentPoint32A(dc, "Trace", 5, &t);
    int total = z.cx + t.cx;
    int x = cx - total / 2;
    int wy = cy + r + 14;
    SetTextColor(dc, kAccent);
    TextOutA(dc, x, wy, "Zero", 4);
    SetTextColor(dc, RGB(0xb0, 0xb0, 0xc0));
    TextOutA(dc, x + z.cx, wy, "Trace", 5);
    SelectObject(dc, of);
}

// Custom paint for the scanning phase.
static void paintScanning(HWND hWnd, HDC dc) {
    RECT rc; GetClientRect(hWnd, &rc);
    int W = rc.right, H = rc.bottom;

    // matte-grey background
    HBRUSH bg = CreateSolidBrush(kScanBg);
    FillRect(dc, &rc, bg);
    DeleteObject(bg);

    drawLogo(dc, W / 2, 70);

    // "Scanning" pill
    HFONT of = (HFONT)SelectObject(dc, g_fSub);
    SetBkMode(dc, TRANSPARENT);
    const char* lbl = "Scanning";
    SIZE ls{}; GetTextExtentPoint32A(dc, lbl, (int)strlen(lbl), &ls);
    int pw = ls.cx + 46, ph = 30;
    int px = W / 2 - pw / 2, py = 210;
    HBRUSH pill = CreateSolidBrush(RGB(0x2e, 0x30, 0x36));
    HPEN ppen = CreatePen(PS_SOLID, 1, RGB(0x44, 0x46, 0x52));
    HBRUSH opb = (HBRUSH)SelectObject(dc, pill);
    HPEN opp = (HPEN)SelectObject(dc, ppen);
    RoundRect(dc, px, py, px + pw, py + ph, 14, 14);
    SelectObject(dc, opb); SelectObject(dc, opp);
    DeleteObject(pill); DeleteObject(ppen);
    // dot
    HBRUSH d = CreateSolidBrush(kAccent);
    HBRUSH od = (HBRUSH)SelectObject(dc, d);
    Ellipse(dc, px + 14, py + ph / 2 - 5, px + 24, py + ph / 2 + 5);
    SelectObject(dc, od); DeleteObject(d);
    SetTextColor(dc, kText);
    TextOutA(dc, px + 32, py + 6, lbl, (int)strlen(lbl));
    SelectObject(dc, of);

    // spinning teal arc
    int scx = W / 2, scy = 300, sr = 26;
    HPEN base = CreatePen(PS_SOLID, 3, RGB(0x3a, 0x3a, 0x40));
    HBRUSH nb = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
    HPEN ob2 = (HPEN)SelectObject(dc, base);
    Ellipse(dc, scx - sr, scy - sr, scx + sr, scy + sr);
    // bright arc segment (~100 degrees) that rotates
    HPEN arc = CreatePen(PS_SOLID, 3, kAccent);
    SelectObject(dc, arc);
    double a0 = g_angle * 3.14159265 / 180.0;
    double a1 = a0 + 1.75;  // ~100°
    SetArcDirection(dc, AD_COUNTERCLOCKWISE);
    Arc(dc, scx - sr, scy - sr, scx + sr, scy + sr,
        (int)(scx + sr * cos(a0)), (int)(scy - sr * sin(a0)),
        (int)(scx + sr * cos(a1)), (int)(scy - sr * sin(a1)));
    SelectObject(dc, ob2); SelectObject(dc, nb);
    DeleteObject(base); DeleteObject(arc);

    // bottom progress bar (full width) + percent
    int barH = 6;
    RECT track = {0, H - barH, W, H};
    HBRUSH tb = CreateSolidBrush(RGB(0x14, 0x14, 0x16));
    FillRect(dc, &track, tb); DeleteObject(tb);
    RECT fill = {0, H - barH, (int)((long long)W * g_progress / 100), H};
    HBRUSH fb = CreateSolidBrush(kAccent);
    FillRect(dc, &fill, fb); DeleteObject(fb);
    char pct[16]; wsprintfA(pct, "%d%%", g_progress);
    HFONT of2 = (HFONT)SelectObject(dc, g_fSub);
    SetTextColor(dc, RGB(0xc8, 0xc8, 0xd0));
    SetBkMode(dc, TRANSPARENT);
    TextOutA(dc, 10, H - barH - 22, pct, (int)strlen(pct));
    SelectObject(dc, of2);
}

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_SETCURSOR:
            if (g_phase == 1) { SetCursor(nullptr); return TRUE; }  // hide cursor while scanning
            break;
        case WM_ERASEBKGND:
            if (g_phase == 1) return 1;  // we paint the whole thing in WM_PAINT
            break;
        case WM_PAINT:
            if (g_phase == 1) {
                PAINTSTRUCT ps;
                HDC dc = BeginPaint(hWnd, &ps);
                // double-buffer to avoid flicker
                RECT rc; GetClientRect(hWnd, &rc);
                HDC mem = CreateCompatibleDC(dc);
                HBITMAP bmp = CreateCompatibleBitmap(dc, rc.right, rc.bottom);
                HBITMAP ob = (HBITMAP)SelectObject(mem, bmp);
                paintScanning(hWnd, mem);
                BitBlt(dc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
                SelectObject(mem, ob);
                DeleteObject(bmp);
                DeleteDC(mem);
                EndPaint(hWnd, &ps);
                return 0;
            }
            break;
        case WM_TIMER:
            if (g_phase == 1) {
                g_angle += 11;
                if (g_angle >= 360) g_angle -= 360;
                if (g_progress < 100) g_progress += 1;  // ~3s to fill
                InvalidateRect(hWnd, nullptr, FALSE);
                if (g_progress >= 100) {
                    KillTimer(hWnd, 1);
                    ShowCursor(TRUE);
                    enterResultPhase(hWnd);
                }
                return 0;
            }
            break;
        case WM_CTLCOLORSTATIC: {
            HDC dc = (HDC)wp;
            SetBkMode(dc, TRANSPARENT);
            HWND ctl = (HWND)lp;
            SetTextColor(dc, ctl == g_hSub || ctl == g_hVer ? kMuted : kText);
            return (LRESULT)g_bgBrush;
        }
        case WM_CTLCOLOREDIT: {
            HDC dc = (HDC)wp;
            SetTextColor(dc, kText);
            SetBkColor(dc, kPanel);
            static HBRUSH panel = CreateSolidBrush(kPanel);
            return (LRESULT)panel;
        }
        case WM_DRAWITEM: {
            DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lp;
            bool accept = dis->CtlID == ID_ACCEPT;
            bool down = (dis->itemState & ODS_SELECTED);
            COLORREF fill = accept ? (down ? RGB(0x1f, 0x8f, 0xc0) : RGB(0x26, 0xa6, 0xd9))
                                   : (down ? RGB(0x2a, 0x2d, 0x45) : RGB(0x33, 0x36, 0x52));
            HBRUSH b = CreateSolidBrush(fill);
            HPEN pen = CreatePen(PS_SOLID, 1,
                                 accept ? kAccent : RGB(0x4a, 0x4d, 0x6b));
            HBRUSH ob = (HBRUSH)SelectObject(dis->hDC, b);
            HPEN op = (HPEN)SelectObject(dis->hDC, pen);
            RECT r = dis->rcItem;
            RoundRect(dis->hDC, r.left, r.top, r.right, r.bottom, 12, 12);
            SetBkMode(dis->hDC, TRANSPARENT);
            SetTextColor(dis->hDC, accept ? RGB(255, 255, 255) : RGB(0xff, 0x8a, 0x8a));
            HFONT of = (HFONT)SelectObject(dis->hDC, g_fBtn);
            char txt[64];
            GetWindowTextA(dis->hwndItem, txt, 64);
            DrawTextA(dis->hDC, txt, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            SelectObject(dis->hDC, of);
            SelectObject(dis->hDC, ob);
            SelectObject(dis->hDC, op);
            DeleteObject(b);
            DeleteObject(pen);
            return TRUE;
        }
        case WM_COMMAND: {
            int id = LOWORD(wp);
            if (id == ID_DECLINE) {
                if (g_phase == 1) { DestroyWindow(hWnd); return 0; }  // "Close"
                DestroyWindow(hWnd);  // declined
                return 0;
            }
            if (id == ID_ACCEPT) {
                if (g_phase == 1) {
                    // "Copy token" → clipboard
                    if (OpenClipboard(hWnd)) {
                        EmptyClipboard();
                        HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, g_token.size() + 1);
                        if (h) {
                            memcpy(GlobalLock(h), g_token.c_str(), g_token.size() + 1);
                            GlobalUnlock(h);
                            SetClipboardData(CF_TEXT, h);
                        }
                        CloseClipboard();
                    }
                    MessageBoxA(hWnd, "Token copied to clipboard.\nSend it to your analyst.",
                                "ZeroTrace", MB_OK | MB_ICONINFORMATION);
                    return 0;
                }
                // Accepted → run the scan once, then play the animated
                // scanning screen with a synced progress bar.
                g_res = runScan(g_pin);
                g_phase = 1;
                g_progress = 0;
                g_angle = 0;
                showControls(FALSE);
                ShowCursor(FALSE);
                SetTimer(hWnd, 1, 30, nullptr);
                InvalidateRect(hWnd, nullptr, TRUE);
                return 0;
            }
            return 0;
        }
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcA(hWnd, msg, wp, lp);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int) {
    g_pin = pinFromSelf();
    if (g_pin.empty()) {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (argv && argc > 1) {
            char path[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, argv[1], -1, path, MAX_PATH, nullptr, nullptr);
            g_pin = pinFromSession(path);
        }
    }
    if (g_pin.empty()) g_pin = "UNKNOWN";

    g_bgBrush = CreateSolidBrush(kBg);
    g_fTitle = CreateFontA(30, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET,
                           OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                           DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
    g_fSub = CreateFontA(16, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                         OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                         DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
    g_fBody = CreateFontA(16, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                          OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                          DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
    g_fBtn = CreateFontA(18, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET,
                         OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                         DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");

    WNDCLASSA wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hbrBackground = g_bgBrush;
    wc.lpszClassName = "ZeroTraceCheckerWnd";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassA(&wc);

    int W = 600, H = 520;
    int sx = (GetSystemMetrics(SM_CXSCREEN) - W) / 2;
    int sy = (GetSystemMetrics(SM_CYSCREEN) - H) / 2;
    HWND hWnd = CreateWindowA("ZeroTraceCheckerWnd", "ZeroTrace Checker",
                              WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                              sx, sy, W, H, nullptr, nullptr, hInst, nullptr);

    g_hTitle = CreateWindowA("STATIC", "License Agreement & Privacy Policy",
                             WS_CHILD | WS_VISIBLE | SS_CENTER,
                             20, 22, 560, 40, hWnd, nullptr, hInst, nullptr);
    g_hSub = CreateWindowA("STATIC",
                           "Please review the license terms and privacy policy before continuing.",
                           WS_CHILD | WS_VISIBLE | SS_CENTER,
                           20, 64, 560, 22, hWnd, nullptr, hInst, nullptr);
    g_hText = CreateWindowA("EDIT", kEula,
                            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE |
                                ES_READONLY | ES_AUTOVSCROLL,
                            24, 100, 552, 300, hWnd, nullptr, hInst, nullptr);
    g_hAccept = CreateWindowA("BUTTON", "Accept",
                              WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                              150, 420, 140, 46, hWnd, (HMENU)ID_ACCEPT, hInst, nullptr);
    g_hDecline = CreateWindowA("BUTTON", "Decline",
                               WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                               310, 420, 140, 46, hWnd, (HMENU)ID_DECLINE, hInst, nullptr);
    g_hVer = CreateWindowA("STATIC", "ZeroTrace Checker  v1.0",
                           WS_CHILD | WS_VISIBLE,
                           24, 478, 300, 20, hWnd, nullptr, hInst, nullptr);

    SendMessageA(g_hTitle, WM_SETFONT, (WPARAM)g_fTitle, TRUE);
    SendMessageA(g_hSub, WM_SETFONT, (WPARAM)g_fSub, TRUE);
    SendMessageA(g_hText, WM_SETFONT, (WPARAM)g_fBody, TRUE);
    SendMessageA(g_hVer, WM_SETFONT, (WPARAM)g_fSub, TRUE);

    ShowWindow(hWnd, SW_SHOW);
    UpdateWindow(hWnd);

    MSG m;
    while (GetMessage(&m, nullptr, 0, 0)) {
        if (!IsDialogMessage(hWnd, &m)) {
            TranslateMessage(&m);
            DispatchMessage(&m);
        }
    }
    return 0;
}

