#include "scanner.hpp"
#include "signatures.hpp"

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <softpub.h>
#include <wintrust.h>
#include <algorithm>
#include <filesystem>

#pragma comment(lib, "wintrust")

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

    // ---- 5. De-duplicate & decide verdict -----------------------------
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
