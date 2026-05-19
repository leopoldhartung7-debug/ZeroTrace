#include "report.hpp"

#include <windows.h>
#include <winhttp.h>
#include <ctime>
#include <sstream>

#pragma comment(lib, "winhttp")

static std::string JsonEscape(const std::string& s) {
    std::string o;
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    sprintf_s(buf, "\\u%04x", c);
                    o += buf;
                } else {
                    o += c;
                }
        }
    }
    return o;
}

std::string BuildJson(const std::string& sessionCode, const ScanResult& r) {
    std::ostringstream j;
    j << "{\"v\":1,"
      << "\"code\":\"" << JsonEscape(sessionCode) << "\","
      << "\"game\":\"FIVEM\","
      << "\"host\":\"" << JsonEscape(r.host) << "\","
      << "\"os\":\"" << JsonEscape(r.os) << "\","
      << "\"ip\":\"" << JsonEscape(r.ip) << "\","
      << "\"verdict\":\"" << JsonEscape(r.verdict) << "\","
      << "\"fivemRunning\":" << (r.fivemRunning ? "true" : "false") << ","
      << "\"processCount\":" << r.processCount << ","
      << "\"moduleCount\":" << r.moduleCount << ","
      << "\"scannedAt\":" << static_cast<long long>(time(nullptr)) * 1000 << ","
      << "\"detections\":[";
    for (size_t i = 0; i < r.detections.size(); ++i) {
        const auto& d = r.detections[i];
        if (i) j << ",";
        j << "{\"name\":\"" << JsonEscape(d.name) << "\","
          << "\"type\":\"" << JsonEscape(d.type) << "\","
          << "\"severity\":\"" << JsonEscape(d.severity) << "\","
          << "\"detail\":\"" << JsonEscape(d.detail) << "\"}";
    }
    j << "],\"usb\":[";
    for (size_t i = 0; i < r.usb.size(); ++i) {
        const auto& u = r.usb[i];
        if (i) j << ",";
        j << "{\"device\":\"" << JsonEscape(u.device) << "\","
          << "\"serial\":\"" << JsonEscape(u.serial) << "\","
          << "\"action\":\"" << JsonEscape(u.action) << "\","
          << "\"time\":\"" << JsonEscape(u.time) << "\","
          << "\"contents\":[";
        for (size_t k = 0; k < u.contents.size(); ++k) {
            if (k) j << ",";
            j << "\"" << JsonEscape(u.contents[k]) << "\"";
        }
        j << "]}";
    }
    j << "]}";
    return j.str();
}

static std::string Base64(const std::string& in) {
    static const char* T =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, bits = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        bits += 8;
        while (bits >= 0) {
            out.push_back(T[(val >> bits) & 0x3F]);
            bits -= 6;
        }
    }
    if (bits > -6) out.push_back(T[((val << 8) >> (bits + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

std::string BuildToken(const std::string& sessionCode, const ScanResult& r) {
    return "OCEAN1." + Base64(BuildJson(sessionCode, r));
}

std::string FetchPublicIp() {
    HINTERNET s = WinHttpOpen(L"OceanScanner/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!s) return {};
    std::string ip;
    HINTERNET c = WinHttpConnect(s, L"api.ipify.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET h = c ? WinHttpOpenRequest(c, L"GET", L"/", nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) : nullptr;
    if (h) {
        if (WinHttpSendRequest(h, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
            WinHttpReceiveResponse(h, nullptr)) {
            DWORD avail = 0;
            char buf[128];
            while (WinHttpQueryDataAvailable(h, &avail) && avail) {
                DWORD got = 0;
                DWORD want = avail < sizeof(buf) - 1 ? avail : sizeof(buf) - 1;
                if (!WinHttpReadData(h, buf, want, &got) || got == 0) break;
                ip.append(buf, got);
                if (ip.size() > 64) break;
            }
        }
        WinHttpCloseHandle(h);
    }
    if (c) WinHttpCloseHandle(c);
    WinHttpCloseHandle(s);
    // Trim whitespace; reject anything that is obviously not an IP literal.
    while (!ip.empty() && (ip.back() == '\n' || ip.back() == '\r' || ip.back() == ' '))
        ip.pop_back();
    for (char ch : ip)
        if (!(ch == '.' || ch == ':' || (ch >= '0' && ch <= '9') ||
              (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')))
            return {};
    return ip;
}

bool UploadJson(const std::wstring& url, const std::string& json, std::string& err) {
    URL_COMPONENTS uc{}; uc.dwStructSize = sizeof(uc);
    wchar_t host[256]{}, path[1024]{};
    uc.lpszHostName = host; uc.dwHostNameLength = 256;
    uc.lpszUrlPath = path;  uc.dwUrlPathLength = 1024;
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc)) { err = "Invalid URL"; return false; }

    HINTERNET s = WinHttpOpen(L"OceanScanner/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!s) { err = "WinHttpOpen failed"; return false; }

    HINTERNET c = WinHttpConnect(s, host, uc.nPort, 0);
    bool https = uc.nScheme == INTERNET_SCHEME_HTTPS;
    HINTERNET h = c ? WinHttpOpenRequest(c, L"POST", path, nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        https ? WINHTTP_FLAG_SECURE : 0) : nullptr;

    bool ok = false;
    if (h) {
        const wchar_t* hdr = L"Content-Type: application/json\r\n";
        if (WinHttpSendRequest(h, hdr, -1L, (LPVOID)json.data(),
                (DWORD)json.size(), (DWORD)json.size(), 0) &&
            WinHttpReceiveResponse(h, nullptr)) {
            DWORD code = 0, len = sizeof(code);
            WinHttpQueryHeaders(h,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &code, &len, WINHTTP_NO_HEADER_INDEX);
            ok = code >= 200 && code < 300;
            if (!ok) err = "HTTP " + std::to_string(code);
        } else {
            err = "Request failed (" + std::to_string(GetLastError()) + ")";
        }
        WinHttpCloseHandle(h);
    }
    if (c) WinHttpCloseHandle(c);
    WinHttpCloseHandle(s);
    return ok;
}
