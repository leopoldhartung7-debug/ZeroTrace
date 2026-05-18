# Ocean FiveM Scanner (C++)

A consent-based usermode anti-cheat **screenshare** tool for FiveM, with a
Dear ImGui (DirectX 11) UI. It scans the local machine for known cheat
indicators and produces a signed result **token** that the server admin
imports on the website (Pins → Import Result).

> ⚠️ Usermode scanners **cannot** detect kernel-mode, DMA or external
> (second-PC) cheats. Treat results as indicators, not absolute proof.
> Only run this with the user's consent (that's what the session code is for).

## What it checks

- Running processes + full image paths (known cheat / loader / debug-tool names)
- Modules loaded **inside** the FiveM process (signature match)
- Unsigned, non-system DLLs injected into FiveM (Authenticode via WinVerifyTrust)
- Visible window titles (cheat menu / overlay heuristics)
- Common drop locations: `%TEMP%`, `%LOCALAPPDATA%`, `Downloads`
- Aggregated verdict: Clean / Suspicious / Cheating

## Build (Windows, x64)

Prerequisites: **Visual Studio 2022** (Desktop C++), **CMake ≥ 3.20**, **vcpkg**.

```bat
:: 1. install the UI dependency
vcpkg install imgui[dx11-binding,win32-binding]:x64-windows-static

:: 2. configure + build
cd scanner
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=C:/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows-static
cmake --build build --config Release
```

The executable is `scanner/build/Release/OceanScanner.exe`.

## Usage (end-to-end)

1. **Admin** opens the website → **Pins** → **Create Pin**. The 8-char pin
   code is the **session code**.
2. **User** runs `OceanScanner.exe`, enters that code, accepts the consent
   notice, and presses **Start Scan**.
3. The tool shows the verdict + detections and a `OCEAN1.…` token.
4. User sends the token back; **admin** pastes it on the website
   (**Pins → Import Result**). The pin, dashboard and activity log update
   automatically — no backend required.
5. *(Optional)* If you run your own backend, paste its URL in the tool and
   press **Upload** to POST the JSON directly (`POST … application/json`).

## Token format

`OCEAN1.` + Base64( JSON ):

```json
{ "v":1, "code":"F1T5F8C0", "game":"FIVEM", "host":"PC-01",
  "os":"Windows 10 (build 19045)", "verdict":"Cheating",
  "fivemRunning":true, "processCount":142, "moduleCount":88,
  "scannedAt":1700000000000,
  "detections":[ { "name":"Eulen","type":"Paid Menu",
                   "severity":"Critical","detail":"Process: eulen.exe" } ] }
```

## Files

| File | Purpose |
|------|---------|
| `src/main.cpp` | ImGui/DX11 UI + scan threading |
| `src/scanner.*` | Detection logic |
| `src/report.*` | JSON + Base64 token + optional WinHTTP upload |
| `src/signatures.hpp` | Known FiveM cheat signatures |
