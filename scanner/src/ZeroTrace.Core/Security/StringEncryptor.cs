using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace ZeroTrace.Core.Security;

/// <summary>
/// Provides runtime XOR-encryption for sensitive indicator strings so they do
/// not appear as plaintext in the scanner binary.
///
/// The key is derived per-machine from the Windows machine GUID stored in the
/// registry (HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid), salted with a
/// build-time constant. This means:
///   • Strings are not readable by static analysis of the .exe
///   • The key is different on every machine, so memory dumps from one machine
///     cannot be used to decrypt strings on another
///   • The decrypted strings only live in memory during active scanning
///
/// Usage — encrypted byte arrays are stored as constants:
/// <code>
///   private static readonly byte[] EncEvilCheats = StringEncryptor.Enc("evilcheats.com");
///   private static string GetDomain() => StringEncryptor.Dec(EncEvilCheats);
/// </code>
/// The Enc() method is used at authoring time (build script or unit test) to
/// pre-compute the encrypted arrays. Dec() decrypts at runtime.
/// </summary>
public static class StringEncryptor
{
    // 32-byte build-time salt — change this value for each release build
    private static readonly byte[] _salt =
    {
        0x5A, 0x65, 0x72, 0x6F, 0x54, 0x72, 0x61, 0x63,
        0x65, 0x41, 0x6E, 0x74, 0x69, 0x43, 0x68, 0x65,
        0x61, 0x74, 0x42, 0x75, 0x69, 0x6C, 0x64, 0x4B,
        0x65, 0x79, 0x32, 0x30, 0x32, 0x35, 0x61, 0x61
    };

    private static byte[]? _derivedKey;
    private static readonly object _keyLock = new();

    // ── Key derivation ────────────────────────────────────────────────────────

    private static byte[] DerivedKey
    {
        get
        {
            if (_derivedKey is not null) return _derivedKey;
            lock (_keyLock)
            {
                if (_derivedKey is not null) return _derivedKey;
                _derivedKey = DeriveKey();
            }
            return _derivedKey;
        }
    }

    private static byte[] DeriveKey()
    {
        string machineId = GetMachineGuid();
        var idBytes = Encoding.UTF8.GetBytes(machineId);

        // PBKDF2 with 10 000 iterations — fast enough for startup,
        // expensive enough to slow brute-force key recovery
        using var rfc = new Rfc2898DeriveBytes(idBytes, _salt, 10_000, HashAlgorithmName.SHA256);
        return rfc.GetBytes(32);
    }

    private static string GetMachineGuid()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Cryptography", writable: false);
            return key?.GetValue("MachineGuid") as string ?? "fallback-no-machine-guid";
        }
        catch
        {
            return "fallback-registry-error";
        }
    }

    // ── Encryption / Decryption ───────────────────────────────────────────────

    /// <summary>Encrypt a plaintext string to a byte array (authoring-time use).</summary>
    public static byte[] Enc(string plaintext)
    {
        var key   = DerivedKey;
        var bytes = Encoding.UTF8.GetBytes(plaintext);
        var out2  = new byte[bytes.Length];
        for (int i = 0; i < bytes.Length; i++)
            out2[i] = (byte)(bytes[i] ^ key[i % key.Length]);
        return out2;
    }

    /// <summary>Decrypt a previously encrypted byte array back to a string.</summary>
    public static string Dec(byte[] encrypted)
    {
        var key     = DerivedKey;
        var decrypted = new byte[encrypted.Length];
        for (int i = 0; i < encrypted.Length; i++)
            decrypted[i] = (byte)(encrypted[i] ^ key[i % key.Length]);
        return Encoding.UTF8.GetString(decrypted);
    }

    /// <summary>Decrypt and immediately zero the decrypted buffer after converting
    /// to string (minimizes the window the plaintext lives in managed memory).</summary>
    public static string DecAndWipe(byte[] encrypted)
    {
        var key   = DerivedKey;
        var buf   = new byte[encrypted.Length];
        for (int i = 0; i < encrypted.Length; i++)
            buf[i] = (byte)(encrypted[i] ^ key[i % key.Length]);
        string result = Encoding.UTF8.GetString(buf);
        CryptographicOperations.ZeroMemory(buf);
        return result;
    }

    /// <summary>
    /// Compute a machine-specific HMAC-SHA256 of the given value.
    /// Used to generate privacy-preserving machine IDs for telemetry.
    /// </summary>
    public static string HmacMachineId(string value)
    {
        using var hmac = new HMACSHA256(DerivedKey);
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
