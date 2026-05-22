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

#include <algorithm>
#include <cctype>
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

// ---- Run the actual scan and build the result token ------------------------
struct ScanResult {
    std::string verdict;
    std::string token;
    std::string summary;  // human-readable lines for the result window
};

static ScanResult runScan(const std::string& pin) {
    std::vector<Detection> dets;
    scanProcessesAndModules(dets);
    const char* up = std::getenv("LOCALAPPDATA");
    if (up) scanGameFolder(std::string(up) + "\\FiveM\\FiveM.app", dets);
    scanGameFolder("C:\\Program Files\\FiveM", dets);

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
    json += "\"detections\":[";
    for (size_t i = 0; i < dets.size(); ++i) {
        if (i) json += ",";
        json += "{\"name\":" + jstr(dets[i].name) +
                ",\"severity\":" + jstr(dets[i].severity) +
                ",\"detail\":" + jstr(dets[i].detail) + "}";
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
static int    g_phase = 0;  // 0 = consent, 1 = result

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

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
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
                // Accepted → run the scan and switch to the result phase.
                SetWindowTextA(g_hTitle, "Scanning your system...");
                SetWindowTextA(g_hSub, "Checking processes, modules and game files.");
                UpdateWindow(hWnd);
                ScanResult sr = runScan(g_pin);
                g_token = sr.token;
                g_phase = 1;
                std::string title = "Scan complete  -  " + sr.verdict;
                SetWindowTextA(g_hTitle, title.c_str());
                SetWindowTextA(g_hSub, "Review the result, then copy the token for your analyst.");
                SetWindowTextA(g_hText, sr.summary.c_str());
                SetWindowTextA(g_hAccept, "Copy token");
                SetWindowTextA(g_hDecline, "Close");
                InvalidateRect(g_hAccept, nullptr, TRUE);
                InvalidateRect(g_hDecline, nullptr, TRUE);
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

