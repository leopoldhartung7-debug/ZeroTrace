using System.Diagnostics;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Reporting;

/// <summary>
/// Removes everything ZeroTrace placed on this PC, on explicit user request.
///
/// This is a user-triggered action (a visible "entfernen" button), not an
/// automatic post-scan wipe: the person sees their results first and chooses to
/// clean up. It deletes the local data folder immediately and schedules deletion
/// of the running executable, which Windows cannot delete while it is in use.
/// </summary>
public static class SelfUninstaller
{
    /// <summary>
    /// Deletes the data folder now and writes a tiny batch script that removes the
    /// executable once the app has exited. The caller should shut the app down
    /// right after invoking this.
    /// </summary>
    public static void RemoveEverything()
    {
        // 1) Local data: database, WAL/SHM files and exported reports.
        TryDeleteDirectory(KnownPaths.AppDataDir);

        // 2) The executable itself. A process can't delete its own running image,
        //    so a short-lived batch waits for exit, removes the file, then removes
        //    itself. This is the standard, visible cleanup approach - no hidden
        //    persistence is created.
        var exePath = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
            return;

        var exeDir = Path.GetDirectoryName(exePath)!;
        var batPath = Path.Combine(Path.GetTempPath(), "zerotrace_cleanup.bat");

        // Wait briefly, delete the exe; if the folder is now empty, remove it too;
        // finally the script deletes itself.
        var script =
            "@echo off\r\n" +
            "ping 127.0.0.1 -n 3 >nul\r\n" +
            $"del /f /q \"{exePath}\" >nul 2>&1\r\n" +
            $"rmdir \"{exeDir}\" >nul 2>&1\r\n" +
            "del /f /q \"%~f0\" >nul 2>&1\r\n";

        File.WriteAllText(batPath, script);

        Process.Start(new ProcessStartInfo
        {
            FileName = batPath,
            CreateNoWindow = true,
            UseShellExecute = false,
            WindowStyle = ProcessWindowStyle.Hidden
        });
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
                Directory.Delete(path, recursive: true);
        }
        catch
        {
            // Best effort - a locked file (e.g. open report) must not crash cleanup.
        }
    }
}
