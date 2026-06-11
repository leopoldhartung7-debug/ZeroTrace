@echo off
setlocal EnableDelayedExpansion
title ZeroTrace - Automatischer Build
color 0A
echo.
echo  ============================================================
echo   ZeroTrace - Automatischer Build
echo  ============================================================
echo.

REM --- .NET an allen bekannten Stellen suchen ---
call :FIND_DOTNET
if defined DOTNET_EXE goto BUILD

REM --- Weg 1: winget (Windows 10/11 eingebaut) ---
echo [INFO] .NET 8 SDK wird installiert (winget)...
winget install --id Microsoft.DotNet.SDK.8 --silent --accept-source-agreements --accept-package-agreements
call :FIND_DOTNET
if defined DOTNET_EXE goto BUILD

REM --- Weg 2: PowerShell mit TLS 1.2 erzwingen ---
echo [INFO] Versuche Download mit PowerShell (TLS 1.2)...
set INSTALLER=%TEMP%\dotnet-install.ps1
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://dot.net/v1/dotnet-install.ps1' -OutFile '%INSTALLER%'"

if exist "%INSTALLER%" (
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
      "& '%INSTALLER%' -Channel 8.0 -InstallDir '%LOCALAPPDATA%\Microsoft\dotnet'"
    set PATH=%LOCALAPPDATA%\Microsoft\dotnet;%PATH%
    call :FIND_DOTNET
)
if defined DOTNET_EXE goto BUILD

REM --- Kein Weg hat funktioniert ---
echo.
echo  [!] .NET 8 SDK konnte nicht automatisch installiert werden.
echo.
echo      Bitte manuell installieren (ca. 200 MB):
echo      https://dotnet.microsoft.com/download/dotnet/8.0
echo.
echo      Danach dieses Skript nochmal ausfuehren.
echo.
start https://dotnet.microsoft.com/download/dotnet/8.0
pause
exit /b 1

REM --- Bauen ---
:BUILD
echo [OK] .NET gefunden: 
"%DOTNET_EXE%" --version
echo.
echo [BUILD] Kompiliere ZeroTrace (dauert 1-2 Min.)...
echo.

"%DOTNET_EXE%" publish "%~dp0src\ZeroTrace.App\ZeroTrace.App.csproj" ^
  -c Release ^
  -r win-x64 ^
  --self-contained true ^
  -p:PublishSingleFile=true ^
  -p:IncludeNativeLibrariesForSelfExtract=true ^
  -p:EnableCompressionInSingleFile=true ^
  -p:DebugType=none ^
  -o "%~dp0dist" ^
  --nologo

if %errorlevel% neq 0 (
    echo.
    echo  [FEHLER] Build fehlgeschlagen. Fehlermeldung oben lesen.
    pause
    exit /b 1
)

if exist "%~dp0dist\ZeroTrace.App.exe" (
    move /y "%~dp0dist\ZeroTrace.App.exe" "%~dp0dist\ZeroTrace.exe" >nul
)

echo.
echo  ============================================================
echo   FERTIG! -> dist\ZeroTrace.exe
echo   Bitte als Administrator starten.
echo  ============================================================
echo.
explorer "%~dp0dist"
pause
exit /b 0

REM --- Hilfsfunktion: dotnet an allen bekannten Pfaden suchen ---
:FIND_DOTNET
set DOTNET_EXE=
where dotnet >nul 2>&1
if %errorlevel%==0 ( for /f "tokens=*" %%p in ('where dotnet') do set DOTNET_EXE=%%p & goto :EOF )
if exist "%LOCALAPPDATA%\Microsoft\dotnet\dotnet.exe" set DOTNET_EXE=%LOCALAPPDATA%\Microsoft\dotnet\dotnet.exe & goto :EOF
if exist "%ProgramFiles%\dotnet\dotnet.exe"           set DOTNET_EXE=%ProgramFiles%\dotnet\dotnet.exe & goto :EOF
if exist "%ProgramFiles(x86)%\dotnet\dotnet.exe"      set DOTNET_EXE=%ProgramFiles(x86)%\dotnet\dotnet.exe & goto :EOF
goto :EOF
