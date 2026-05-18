#pragma once
#include <string>
#include <vector>

// Known FiveM cheat / menu indicators. Names are publicly known in the
// FiveM anti-cheat community and used here purely for DETECTION.
struct Signature {
    const wchar_t* needle;   // lowercase substring to match
    const char*    name;     // human-readable cheat name
    const char*    type;     // category
    const char*    severity; // Low | Medium | High | Critical
};

inline const std::vector<Signature>& KnownSignatures() {
    static const std::vector<Signature> sigs = {
        { L"eulen",        "Eulen",        "Paid Menu",      "Critical" },
        { L"redengine",    "RedENGINE",    "Paid Menu",      "Critical" },
        { L"tzx",          "TZ / TaZ",     "Paid Menu",      "High"     },
        { L"hammafia",     "Hammafia",     "Paid Menu",      "High"     },
        { L"lynx",         "Lynx",         "Paid Menu",      "High"     },
        { L"skript.gg",    "Skript.gg",    "Paid Menu",      "High"     },
        { L"brutan",       "Brutan",       "Paid Menu",      "High"     },
        { L"desudo",       "Desudo",       "Free Menu",      "Medium"   },
        { L"impulse",      "Impulse",      "Paid Menu",      "High"     },
        { L"absolute",     "Absolute",     "Paid Menu",      "High"     },
        { L"cobra",        "Cobra",        "Paid Menu",      "High"     },
        { L"phantomx",     "Phantom-X",    "Paid Menu",      "High"     },
        { L"lumia",        "Lumia",        "Paid Menu",      "High"     },
        { L"d3dmenu",      "Generic D3D Menu", "Injected UI", "High"    },
        { L"injector",     "Generic Injector", "Loader",     "High"     },
        { L"cheatengine",  "Cheat Engine", "Memory Tool",    "Medium"   },
        { L"extreme injector", "Xenos/Extreme Injector", "Loader", "High" },
        { L"fivem-cheat",  "Generic FiveM Cheat", "Unknown", "Medium"   },
        { L"hwid spoof",   "HWID Spoofer", "Spoofer",        "High"     },
        { L"spoofer",      "HWID Spoofer", "Spoofer",        "High"     },
    };
    return sigs;
}

// Process names that should never be running during a clean session.
inline const std::vector<std::wstring>& SuspiciousProcessNames() {
    static const std::vector<std::wstring> p = {
        L"cheatengine", L"x64dbg", L"x32dbg", L"ollydbg", L"ida",
        L"processhacker", L"extreme injector", L"xenos", L"reclass",
        L"httpdebugger", L"fiddler", L"wireshark", L"hxd",
    };
    return p;
}
