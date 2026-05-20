#include "scanner.hpp"
#include "signatures.hpp"
#include "report.hpp"

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <softpub.h>
#include <wintrust.h>
#include <algorithm>
#include <filesystem>
#include <cstdio>

#pragma comment(lib, "wintrust")
#pragma comment(lib, "advapi32")

namespace fs = std::filesystem;

static std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}

static std::string Narrow(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string out(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), out.data(), n, nullptr, nullptr);
    return out;
}

static std::string HostName() {
    wchar_t buf[256]; DWORD len = 256;
    if (GetComputerNameW(buf, &len)) return Narrow(buf);
    return "unknown";
}

static std::string OsString() {
    typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    RTL_OSVERSIONINFOW v{ sizeof(v) };
    auto h = GetModuleHandleW(L"ntdll");
    if (h) {
        auto p = (RtlGetVersionPtr)GetProcAddress(h, "RtlGetVersion");
        if (p && p(&v) == 0)
            return "Windows " + std::to_string(v.dwMajorVersion) +
                   "." + std::to_string(v.dwMinorVersion) +
                   " (build " + std::to_string(v.dwBuildNumber) + ")";
    }
    return "Windows";
}

// Returns true if the file has a valid Authenticode signature.
static bool IsSigned(const std::wstring& path) {
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = path.c_str();

    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.pFile = &fi;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);
    return status == ERROR_SUCCESS;
}

static void MatchSignatures(const std::wstring& haystackLower,
                            const std::string& evidence,
                            std::vector<Detection>& out) {
    for (const auto& s : KnownSignatures()) {
        if (haystackLower.find(s.needle) != std::wstring::npos) {
            out.push_back({ s.name, s.type, s.severity, evidence });
        }
    }
}

// FILETIME (stored as 8 REG_BINARY bytes) -> "YYYY-MM-DD HH:MM:SS" (UTC).
static std::string FormatFileTime(const BYTE* raw, DWORD len) {
    if (len < sizeof(FILETIME)) return {};
    FILETIME ft{};
    memcpy(&ft, raw, sizeof(ft));
    if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0) return {};
    SYSTEMTIME st{};
    if (!FileTimeToSystemTime(&ft, &st)) return {};
    char buf[32];
    sprintf_s(buf, "%04d-%02d-%02d %02d:%02d:%02d",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static std::string ReadStringValue(HKEY key, const wchar_t* name) {
    wchar_t buf[512]; DWORD cb = sizeof(buf), type = 0;
    if (RegQueryValueExW(key, name, nullptr, &type,
                         reinterpret_cast<BYTE*>(buf), &cb) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ)) {
        buf[(cb / sizeof(wchar_t)) % 512] = 0;
        return Narrow(buf);
    }
    return {};
}

// Reads a timestamp from USBSTOR\...\Properties\{GUID}\<id> (last arrival/removal).
static std::string ReadUsbTimestamp(HKEY serialKey, const wchar_t* propId) {
    HKEY props{};
    if (RegOpenKeyExW(serialKey,
            L"Properties\\{83da6326-97a6-4088-9453-a1923f573b29}",
            0, KEY_READ, &props) != ERROR_SUCCESS)
        return {};
    HKEY slot{};
    std::string out;
    if (RegOpenKeyExW(props, propId, 0, KEY_READ, &slot) == ERROR_SUCCESS) {
        BYTE data[64]; DWORD cb = sizeof(data), type = 0;
        if (RegQueryValueExW(slot, L"(Default)", nullptr, &type, data, &cb) == ERROR_SUCCESS ||
            RegQueryValueExW(slot, L"", nullptr, &type, data, &cb) == ERROR_SUCCESS)
            out = FormatFileTime(data, cb);
        RegCloseKey(slot);
    }
    RegCloseKey(props);
    return out;
}

// Enumerate removable/USB storage history and currently-mounted contents.
static void ScanUsbHistory(std::vector<UsbDevice>& out) {
    // 1. Historical devices from SYSTEM\CurrentControlSet\Enum\USBSTOR
    HKEY usbstor{};
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
            0, KEY_READ, &usbstor) == ERROR_SUCCESS) {
        wchar_t cls[256]; DWORD ci = 0, clen;
        while (clen = 256, RegEnumKeyExW(usbstor, ci++, cls, &clen,
                   nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            if (ci > 256) break;
            HKEY clsKey{};
            if (RegOpenKeyExW(usbstor, cls, 0, KEY_READ, &clsKey) != ERROR_SUCCESS) continue;
            wchar_t ser[256]; DWORD si = 0, slen;
            while (slen = 256, RegEnumKeyExW(clsKey, si++, ser, &slen,
                       nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                if (si > 256) break;
                HKEY serKey{};
                if (RegOpenKeyExW(clsKey, ser, 0, KEY_READ, &serKey) != ERROR_SUCCESS) continue;
                UsbDevice d;
                d.device = ReadStringValue(serKey, L"FriendlyName");
                if (d.device.empty()) d.device = Narrow(cls);
                d.serial = Narrow(ser);
                std::string arrived = ReadUsbTimestamp(serKey, L"0066");
                std::string removed = ReadUsbTimestamp(serKey, L"0067");
                if (!removed.empty() && removed >= arrived) {
                    d.action = "Removed"; d.time = removed;
                } else if (!arrived.empty()) {
                    d.action = "Connected"; d.time = arrived;
                } else {
                    d.action = "Seen"; d.time = ReadUsbTimestamp(serKey, L"0064");
                }
                out.push_back(std::move(d));
                RegCloseKey(serKey);
                if (out.size() > 64) break;
            }
            RegCloseKey(clsKey);
            if (out.size() > 64) break;
        }
        RegCloseKey(usbstor);
    }

    // 2. Currently-mounted removable volumes: list top-level contents.
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26 && mask; ++i, mask >>= 1) {
        if (!(mask & 1)) continue;
        wchar_t root[4] = { wchar_t(L'A' + i), L':', L'\\', 0 };
        if (GetDriveTypeW(root) != DRIVE_REMOVABLE) continue;
        UsbDevice d;
        wchar_t label[64]{};
        GetVolumeInformationW(root, label, 64, nullptr, nullptr, nullptr, nullptr, 0);
        d.device = (label[0] ? Narrow(label) + " " : std::string()) +
                   "(" + std::string(1, char('A' + i)) + ":)";
        d.serial = std::string(1, char('A' + i)) + ":\\";
        d.action = "Mounted";
        std::error_code ec;
        int seen = 0;
        for (auto it = fs::directory_iterator(
                 root, fs::directory_options::skip_permission_denied, ec);
             it != fs::directory_iterator() && seen < 200; it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            d.contents.push_back(it->path().filename().string());
            ++seen;
        }
        out.push_back(std::move(d));
    }
}

static bool LooksPrintable(const std::string& s) {
    if (s.size() < 2 || s.size() > 100) return false;
    for (unsigned char c : s)
        if (c < 0x20 && c != '\t') return false;
    return true;
}

// Extracts Discord guild names cached locally (no network, no token use).
// Discord serialises guild rows as ..."id":"<snowflake>","name":"<server>"...
static void ScanDiscordServers(std::vector<DiscordServer>& out) {
    wchar_t appdata[MAX_PATH];
    if (!GetEnvironmentVariableW(L"APPDATA", appdata, MAX_PATH)) return;

    const wchar_t* clients[] = { L"discord", L"discordcanary", L"discordptb" };
    std::vector<fs::path> roots;
    for (auto* c : clients) {
        fs::path base = fs::path(appdata) / c;
        roots.push_back(base / L"Local Storage" / L"leveldb");
        std::error_code ec;
        fs::path idb = base / L"IndexedDB";
        if (fs::exists(idb, ec))
            for (auto it = fs::directory_iterator(idb, fs::directory_options::skip_permission_denied, ec);
                 it != fs::directory_iterator(); it.increment(ec)) {
                if (ec) { ec.clear(); continue; }
                if (it->is_directory(ec)) roots.push_back(it->path());
            }
    }

    std::vector<std::string> seen;
    size_t totalBytes = 0;
    for (const auto& dir : roots) {
        std::error_code ec;
        if (!fs::exists(dir, ec)) continue;
        for (auto it = fs::directory_iterator(dir, fs::directory_options::skip_permission_denied, ec);
             it != fs::directory_iterator(); it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            if (!it->is_regular_file(ec)) continue;
            std::wstring ext = ToLower(it->path().extension().wstring());
            if (ext != L".ldb" && ext != L".log") continue;
            if (totalBytes > 64u * 1024 * 1024) return;

            FILE* f = nullptr;
            if (_wfopen_s(&f, it->path().wstring().c_str(), L"rb") || !f) continue;
            std::string buf;
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            fseek(f, 0, SEEK_SET);
            if (sz > 0) {
                long cap = sz < 16 * 1024 * 1024 ? sz : 16 * 1024 * 1024;
                buf.resize(cap);
                size_t got = fread(buf.data(), 1, cap, f);
                buf.resize(got);
                totalBytes += got;
            }
            fclose(f);

            const std::string K = "\"id\":\"";
            size_t pos = 0;
            while ((pos = buf.find(K, pos)) != std::string::npos && out.size() < 100) {
                size_t i = pos + K.size();
                size_t d = i;
                while (d < buf.size() && buf[d] >= '0' && buf[d] <= '9') ++d;
                size_t digits = d - i;
                const std::string NK = "\",\"name\":\"";
                if (digits >= 17 && digits <= 20 && buf.compare(d, NK.size(), NK) == 0) {
                    size_t ns = d + NK.size();
                    size_t ne = buf.find('"', ns);
                    if (ne != std::string::npos && ne - ns <= 100) {
                        std::string name = buf.substr(ns, ne - ns);
                        std::string id = buf.substr(i, digits);
                        if (LooksPrintable(name) &&
                            std::find(seen.begin(), seen.end(), name) == seen.end()) {
                            seen.push_back(name);
                            out.push_back({ name, id });
                        }
                    }
                }
                pos = i;
            }
        }
    }
}

// Walks installed browser extensions (Chrome / Edge / Brave / Opera /
// Vivaldi) and flags any whose manifest "name" contains common cheat
// keywords. Best-effort, read-only, bounded.
static void ScanBrowserExtensions(std::vector<Detection>& out) {
    static const std::string KW[] = {
        "cheat", "hack", "aimbot", "auto-clicker", "autoclicker", "spoofer",
        "esp ", "trigger bot", "wallhack", "macro", "injector", "bypass",
        "cracked", "exploit", "anti-detect",
    };
    wchar_t localApp[MAX_PATH];
    if (!GetEnvironmentVariableW(L"LOCALAPPDATA", localApp, MAX_PATH)) return;
    const std::vector<fs::path> roots = {
        fs::path(localApp) / L"Google" / L"Chrome" / L"User Data" / L"Default" / L"Extensions",
        fs::path(localApp) / L"Microsoft" / L"Edge" / L"User Data" / L"Default" / L"Extensions",
        fs::path(localApp) / L"BraveSoftware" / L"Brave-Browser" / L"User Data" / L"Default" / L"Extensions",
        fs::path(localApp) / L"Vivaldi" / L"User Data" / L"Default" / L"Extensions",
        fs::path(localApp) / L"Opera Software" / L"Opera Stable" / L"Extensions",
    };
    int seen = 0;
    for (const auto& root : roots) {
        std::error_code ec;
        if (!fs::exists(root, ec)) continue;
        for (auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            if (it.depth() > 4) it.disable_recursion_pending();
            if (!it->is_regular_file(ec)) continue;
            if (it->path().filename() != L"manifest.json") continue;
            if (++seen > 600) return;

            FILE* f = nullptr;
            if (_wfopen_s(&f, it->path().wstring().c_str(), L"rb") || !f) continue;
            std::string buf;
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            fseek(f, 0, SEEK_SET);
            if (sz > 0 && sz < 256 * 1024) {
                buf.resize(sz);
                size_t got = fread(buf.data(), 1, sz, f);
                buf.resize(got);
            }
            fclose(f);
            if (buf.empty()) continue;

            // Pull out the "name" value (best-effort).
            const std::string nk = "\"name\"";
            size_t p = buf.find(nk);
            if (p == std::string::npos) continue;
            p = buf.find('"', p + nk.size());
            if (p == std::string::npos) continue;
            size_t e = buf.find('"', p + 1);
            if (e == std::string::npos || e - p > 200) continue;
            std::string name = buf.substr(p + 1, e - p - 1);
            std::string low = name;
            std::transform(low.begin(), low.end(), low.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            for (const auto& kw : KW) {
                if (low.find(kw) != std::string::npos) {
                    out.push_back({
                        "Suspicious browser extension",
                        "Browser",
                        "Medium",
                        "Extension: " + name,
                    });
                    break;
                }
            }
        }
    }
}

ScanResult RunScan(const std::function<void(float, const std::string&)>& progress) {
    ScanResult r;
    r.host = HostName();
    r.os = OsString();

    DWORD fivemPid = 0;

    // ---- 1. Process enumeration --------------------------------------
    progress(0.10f, "Enumerating processes...");
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe{ sizeof(pe) };
        if (Process32FirstW(snap, &pe)) {
            do {
                r.processCount++;
                std::wstring nameLow = ToLower(pe.szExeFile);

                if (nameLow == L"fivem.exe" || nameLow == L"fivem_b2802_gtaprocess.exe" ||
                    nameLow.find(L"fivem") != std::wstring::npos) {
                    if (nameLow.find(L"fivem") != std::wstring::npos && fivemPid == 0) {
                        fivemPid = pe.th32ProcessID;
                        r.fivemRunning = true;
                    }
                }

                std::wstring fullPath;
                HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (ph) {
                    wchar_t buf[MAX_PATH]; DWORD sz = MAX_PATH;
                    if (QueryFullProcessImageNameW(ph, 0, buf, &sz)) fullPath = buf;
                    CloseHandle(ph);
                }
                std::wstring lowAll = nameLow + L" " + ToLower(fullPath);

                for (const auto& bad : SuspiciousProcessNames()) {
                    if (nameLow.find(bad) != std::wstring::npos) {
                        r.detections.push_back({ "Analysis/Debug Tool", "Tool", "Medium",
                            "Process: " + Narrow(pe.szExeFile) });
                        break;
                    }
                }
                MatchSignatures(lowAll, "Process: " + Narrow(pe.szExeFile), r.detections);
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }

    // ---- 2. Modules loaded inside FiveM -------------------------------
    progress(0.40f, "Inspecting FiveM modules...");
    if (fivemPid) {
        HANDLE ms = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, fivemPid);
        if (ms != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me{ sizeof(me) };
            if (Module32FirstW(ms, &me)) {
                do {
                    r.moduleCount++;
                    std::wstring path = me.szExePath;
                    std::wstring low = ToLower(path);
                    MatchSignatures(low, "Module: " + Narrow(me.szModule), r.detections);

                    // Unsigned, non-system DLL injected into the game = heuristic flag.
                    std::wstring sysdir; sysdir.resize(MAX_PATH);
                    GetSystemDirectoryW(sysdir.data(), MAX_PATH);
                    bool inSystem = low.find(L"\\windows\\") != std::wstring::npos;
                    if (!inSystem && !IsSigned(path)) {
                        r.detections.push_back({ "Unsigned Injected Module", "Heuristic", "High",
                            "Module: " + Narrow(me.szModule) });
                    }
                } while (Module32NextW(ms, &me));
            }
            CloseHandle(ms);
        }
    }

    // ---- 3. Window / overlay heuristics -------------------------------
    progress(0.65f, "Scanning windows & overlays...");
    EnumWindows([](HWND hwnd, LPARAM lp) -> BOOL {
        auto* det = reinterpret_cast<std::vector<Detection>*>(lp);
        if (!IsWindowVisible(hwnd)) return TRUE;
        wchar_t title[256]{};
        GetWindowTextW(hwnd, title, 256);
        if (title[0]) {
            std::wstring low = ToLower(title);
            MatchSignatures(low, "Window: " + Narrow(title), *det);
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&r.detections));

    // ---- 4. File-system artifacts -------------------------------------
    progress(0.85f, "Scanning drop locations...");
    std::vector<std::wstring> dirs;
    wchar_t env[MAX_PATH];
    if (GetEnvironmentVariableW(L"TEMP", env, MAX_PATH)) dirs.push_back(env);
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", env, MAX_PATH)) dirs.push_back(env);
    if (GetEnvironmentVariableW(L"USERPROFILE", env, MAX_PATH))
        dirs.push_back(std::wstring(env) + L"\\Downloads");

    for (const auto& d : dirs) {
        std::error_code ec;
        if (!fs::exists(d, ec)) continue;
        int seen = 0;
        for (auto it = fs::recursive_directory_iterator(
                 d, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            if (++seen > 8000) break;            // safety bound
            if (it.depth() > 3) it.disable_recursion_pending();
            if (!it->is_regular_file(ec)) continue;
            std::wstring low = ToLower(it->path().filename().wstring());
            MatchSignatures(low, "File: " + it->path().filename().string(), r.detections);
        }
    }

    // ---- 5. USB / removable storage history ---------------------------
    progress(0.90f, "Scanning USB device history...");
    ScanUsbHistory(r.usb);

    progress(0.92f, "Resolving network address...");
    r.ip = FetchPublicIp();

    progress(0.93f, "Reading Discord server cache...");
    ScanDiscordServers(r.discordServers);

    progress(0.94f, "Scanning browser extensions...");
    ScanBrowserExtensions(r.detections);

    // ---- 6. De-duplicate & decide verdict -----------------------------
    progress(0.95f, "Compiling report...");
    std::vector<Detection> uniq;
    for (auto& d : r.detections) {
        bool dup = false;
        for (auto& u : uniq)
            if (u.name == d.name && u.detail == d.detail) { dup = true; break; }
        if (!dup) uniq.push_back(d);
    }
    r.detections = std::move(uniq);

    bool high = false, med = false;
    for (auto& d : r.detections) {
        if (d.severity == "Critical" || d.severity == "High") high = true;
        else med = true;
    }
    r.verdict = high ? "Cheating" : med ? "Suspicious" : "Clean";

    progress(1.0f, "Done");
    return r;
}
