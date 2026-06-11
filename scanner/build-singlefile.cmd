@echo off
REM ============================================================
REM  ZeroTrace - Single-File Build ("alles als eine Datei")
REM  Erzeugt EINE eigenstaendige ZeroTrace.exe (kein .NET noetig).
REM  Voraussetzung: .NET 8 SDK + Windows.
REM ============================================================
setlocal
set CONFIG=Release
set RID=win-x64

echo [ZeroTrace] Single-File-Build wird erstellt...
dotnet publish src\ZeroTrace.App\ZeroTrace.App.csproj ^
  -c %CONFIG% -r %RID% --self-contained true ^
  -p:PublishSingleFile=true ^
  -p:IncludeNativeLibrariesForSelfExtract=true ^
  -p:EnableCompressionInSingleFile=true ^
  -p:DebugType=none ^
  -o publish

echo.
echo [ZeroTrace] Fertig. Ergebnis: publish\ZeroTrace.exe
endlocal
