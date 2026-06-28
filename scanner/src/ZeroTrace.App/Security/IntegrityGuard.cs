using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace ZeroTrace.App.Security;

/// <summary>
/// Lightweight startup hardening for the ZeroTrace scanner.
///
/// This is NOT cryptographically uncrackable — anything that ships to a
/// player's machine can eventually be defeated by a determined reverser.
/// What it does provide:
///   * Refuses to run while a managed debugger is attached.
///   * Refuses to run when a process with a known reverse-engineering
///     tool name is open in the same session (dnSpy, ILSpy, x64dbg,
///     Cheat Engine, …). Frustrates casual tampering during a scan.
///   * Computes its own on-disk SHA-256 once at startup and stores it for
///     subsequent integrity checks; a background thread compares the live
///     hash every few seconds. If the file is patched while running the
///     scanner closes itself.
///
/// Designed to fail SILENTLY in legitimate scenarios (debugger not
/// attached, no reverser open, exe untouched) and never crash the app on
/// permission errors.
/// </summary>
public static class IntegrityGuard
{
    private static readonly string[] HostileProcessNames =
    [
        "dnspy", "dnspy-x86", "dnspy.console",
        "ilspy", "ilspycmd",
        "x64dbg", "x32dbg", "ollydbg",
        "ida", "ida64", "ida32",
        "cheatengine-x86_64", "cheatengine-i386",
        "windbg", "windbgx", "scyllahide",
        "processhacker", "processhacker2",
        "fiddler", "wireshark",
        "httpdebuggerpro", "httpdebuggerui", "httpdebuggersvc",
        "de4dot", "reflector", "justdecompile",
    ];

    private static string? _exePath;
    private static byte[]? _baselineHash;
    private static CancellationTokenSource? _watcherCts;

    /// <summary>
    /// Runs the startup hardening checks. Returns true if it is safe to
    /// continue, false if the launch should be aborted (the caller is
    /// expected to shut down the app gracefully).
    /// </summary>
    public static bool EnsureSafeToRun()
    {
        try
        {
            if (Debugger.IsAttached || Debugger.IsLogging())
                return false;

            if (IsRemoteDebuggerAttached())
                return false;

            if (IsHostileToolingOpen())
                return false;

            CaptureBaselineHash();
            StartTamperWatcher();
            return true;
        }
        catch
        {
            // Never let the hardening itself crash the app — fall through
            // and let the scanner run as normal.
            return true;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool isDebugged);

    private static bool IsRemoteDebuggerAttached()
    {
        try
        {
            return CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, out var dbg) && dbg;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsHostileToolingOpen()
    {
        try
        {
            var processes = Process.GetProcesses();
            foreach (var p in processes)
            {
                string name;
                try { name = p.ProcessName.ToLowerInvariant(); }
                catch { continue; }
                if (HostileProcessNames.Any(h => name == h || name.StartsWith(h + ".")))
                    return true;
            }
        }
        catch
        {
            // OS denied us the process list — be permissive.
        }
        return false;
    }

    private static void CaptureBaselineHash()
    {
        try
        {
            _exePath = Environment.ProcessPath;
            if (string.IsNullOrEmpty(_exePath) || !File.Exists(_exePath)) return;
            using var fs = File.OpenRead(_exePath);
            _baselineHash = SHA256.HashData(fs);
        }
        catch
        {
            _exePath = null;
            _baselineHash = null;
        }
    }

    private static void StartTamperWatcher()
    {
        if (_exePath is null || _baselineHash is null) return;
        _watcherCts = new CancellationTokenSource();
        var token = _watcherCts.Token;
        _ = Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(7), token).ConfigureAwait(false);
                    if (!File.Exists(_exePath)) continue;
                    using var fs = File.OpenRead(_exePath);
                    var current = SHA256.HashData(fs);
                    if (!current.SequenceEqual(_baselineHash))
                    {
                        // The exe was patched while running — bail out.
                        Environment.Exit(0);
                    }
                }
                catch (OperationCanceledException) { /* shutdown */ }
                catch
                {
                    // Locked file or transient I/O — skip this tick.
                }
            }
        }, token);
    }

    public static void Stop() => _watcherCts?.Cancel();
}
