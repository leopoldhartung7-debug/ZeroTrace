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

#include <algorithm>
#include <cctype>
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

int main(int argc, char** argv) {
    SetConsoleTitleA("ZeroTrace Cheat Checker");

    std::string pin;
    if (argc > 1) pin = pinFromSession(argv[1]);

    std::cout << "============================================\n";
    std::cout << "        ZeroTrace - Cheat Checker\n";
    std::cout << "============================================\n\n";
    std::cout << "This tool will check, ONLY:\n";
    std::cout << "  - your running processes and loaded modules\n";
    std::cout << "  - known cheat files inside your game folder\n\n";
    std::cout << "It does NOT read your USB history, browser data,\n";
    std::cout << "Discord, personal files or IP. The full result is\n";
    std::cout << "shown to you here before any token is created.\n\n";

    if (pin.empty()) {
        std::cout << "Enter the PIN from your analyst: ";
        std::getline(std::cin, pin);
    } else {
        std::cout << "Session PIN: " << pin << "\n";
    }

    std::cout << "\nDo you consent to this cheat check? (y/n): ";
    std::string ans;
    std::getline(std::cin, ans);
    if (ans.empty() || (ans[0] != 'y' && ans[0] != 'Y')) {
        std::cout << "\nCancelled. No scan was performed.\n";
        return 0;
    }

    std::cout << "\nScanning processes and modules...\n";
    std::vector<Detection> dets;
    scanProcessesAndModules(dets);

    std::cout << "Scanning game folders for cheat files...\n";
    char* up = nullptr;
    size_t len = 0;
    _dupenv_s(&up, &len, "LOCALAPPDATA");
    if (up) {
        scanGameFolder(std::string(up) + "\\FiveM\\FiveM.app", dets);
        free(up);
    }
    scanGameFolder("C:\\Program Files\\FiveM", dets);

    // ---- Verdict ----
    int crit = 0, high = 0, med = 0, low = 0;
    for (auto& d : dets) {
        if (d.severity == "Critical") crit++;
        else if (d.severity == "High") high++;
        else if (d.severity == "Medium") med++;
        else low++;
    }
    std::string verdict = (crit > 0) ? "Cheating"
                          : (high > 0 || med >= 3) ? "Suspicious"
                                                   : "Clean";

    std::cout << "\n--------------------------------------------\n";
    std::cout << "Result: " << verdict << "  (" << dets.size()
              << " finding(s))\n";
    std::cout << "--------------------------------------------\n";
    for (auto& d : dets)
        std::cout << "  [" << d.severity << "] " << d.detail << "\n";
    if (dets.empty()) std::cout << "  No known cheats detected.\n";

    // ---- Build token JSON ----
    std::time_t now = std::time(nullptr);
    std::string json = "{";
    json += "\"v\":1,";
    json += "\"code\":" + jstr(pin) + ",";
    json += "\"game\":\"FIVEM\",";
    json += "\"verdict\":" + jstr(verdict) + ",";
    json += "\"scannedAt\":" + std::to_string((long long)now * 1000) + ",";
    json += "\"detections\":[";
    for (size_t i = 0; i < dets.size(); ++i) {
        if (i) json += ",";
        json += "{\"name\":" + jstr(dets[i].name) +
                ",\"severity\":" + jstr(dets[i].severity) +
                ",\"detail\":" + jstr(dets[i].detail) + "}";
    }
    json += "]}";

    std::string token = "ZEROTRACE1." + base64(json);

    std::cout << "\nCopy this token and give it to your analyst:\n\n";
    std::cout << token << "\n\n";

    // Also save it next to the exe for convenience.
    std::ofstream out("zerotrace-result.txt");
    if (out) out << token;
    std::cout << "(also saved to zerotrace-result.txt)\n\n";

    std::cout << "Press Enter to close...";
    std::string dummy;
    std::getline(std::cin, dummy);
    return 0;
}
