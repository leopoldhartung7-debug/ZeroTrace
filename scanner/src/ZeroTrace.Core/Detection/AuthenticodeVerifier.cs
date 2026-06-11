using System.Runtime.InteropServices;

namespace ZeroTrace.Core.Detection;

/// <summary>
/// Real Authenticode trust verification using the documented Windows WinVerifyTrust
/// API plus catalog-signature lookup. This replaces the old "an embedded certificate
/// exists" assumption, which produced two kinds of error:
///
///   * False negatives: a self-signed / tampered / expired binary carried a
///     certificate and was therefore treated as "signed" (trust-lowering).
///   * False positives: Windows system DLLs that are signed via a security
///     <i>catalog</i> (no embedded signature) looked "unsigned".
///
/// Verification runs fully offline (no revocation network calls) to stay fast and
/// to honour the project's "no internet lookups" rule. Any failure degrades
/// gracefully to <see cref="TrustStatus.Unsigned"/> rather than throwing, so the
/// scan can never be aborted by an unreadable file.
///
/// Still only a heuristic input, never proof.
/// </summary>
public static class AuthenticodeVerifier
{
    public enum TrustStatus
    {
        /// <summary>No embedded signature and no catalog entry.</summary>
        Unsigned,

        /// <summary>A signature is present but Windows does not trust it
        /// (self-signed, broken chain, tampered, expired, explicitly distrusted).
        /// In a user-writable path this is at least as suspicious as unsigned.</summary>
        SignedUntrusted,

        /// <summary>Validly signed and trusted (embedded Authenticode or catalog).</summary>
        Trusted
    }

    public readonly record struct Result(TrustStatus Status, bool CatalogSigned);

    public static Result Verify(string path)
    {
        try
        {
            uint res = VerifyEmbedded(path);
            if (res == 0) return new Result(TrustStatus.Trusted, false);

            // No embedded signature -> the file may still be catalog-signed (typical
            // for in-box Windows binaries and many redistributables).
            if (res is TRUST_E_NOSIGNATURE or TRUST_E_SUBJECT_FORM_UNKNOWN or TRUST_E_PROVIDER_UNKNOWN)
            {
                if (VerifyCatalog(path)) return new Result(TrustStatus.Trusted, true);
                return new Result(TrustStatus.Unsigned, false);
            }

            // A signature exists but is not trusted.
            return new Result(TrustStatus.SignedUntrusted, false);
        }
        catch
        {
            return new Result(TrustStatus.Unsigned, false);
        }
    }

    // ---- WinVerifyTrust (embedded) -----------------------------------------

    private static uint VerifyEmbedded(string path)
    {
        IntPtr strPtr = Marshal.StringToCoTaskMemUni(path);
        IntPtr pFile = IntPtr.Zero;
        IntPtr pData = IntPtr.Zero;
        try
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = strPtr,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };
            pFile = Marshal.AllocCoTaskMem(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fileInfo, pFile, false);

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pInfo = pFile,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
            };
            pData = Marshal.AllocCoTaskMem(Marshal.SizeOf<WINTRUST_DATA>());
            Marshal.StructureToPtr(data, pData, false);

            var action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            uint res = WinVerifyTrust(IntPtr.Zero, ref action, pData);

            // Always release the state data WinVerifyTrust allocated.
            var close = Marshal.PtrToStructure<WINTRUST_DATA>(pData);
            close.dwStateAction = WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(close, pData, false);
            WinVerifyTrust(IntPtr.Zero, ref action, pData);

            return res;
        }
        finally
        {
            if (pData != IntPtr.Zero) Marshal.FreeCoTaskMem(pData);
            if (pFile != IntPtr.Zero) Marshal.FreeCoTaskMem(pFile);
            if (strPtr != IntPtr.Zero) Marshal.FreeCoTaskMem(strPtr);
        }
    }

    // ---- Catalog signature lookup ------------------------------------------

    private static bool VerifyCatalog(string path)
    {
        IntPtr hCatAdmin = IntPtr.Zero;
        IntPtr hCatInfo = IntPtr.Zero;
        try
        {
            // Prefer the SHA-256 catalog context; fall back to the legacy context.
            bool acquired;
            try
            {
                acquired = CryptCATAdminAcquireContext2(
                    ref hCatAdmin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0);
            }
            catch (EntryPointNotFoundException)
            {
                acquired = CryptCATAdminAcquireContext(ref hCatAdmin, IntPtr.Zero, 0);
            }
            if (!acquired || hCatAdmin == IntPtr.Zero) return false;

            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            IntPtr hFile = fs.SafeFileHandle.DangerousGetHandle();

            // Two passes: first ask for the required size, then for the bytes.
            uint hashSize = 0;
            CalcHash(hCatAdmin, hFile, ref hashSize, IntPtr.Zero);
            if (hashSize == 0) return false;

            IntPtr hashPtr = Marshal.AllocHGlobal((int)hashSize);
            try
            {
                if (!CalcHash(hCatAdmin, hFile, ref hashSize, hashPtr)) return false;

                hCatInfo = CryptCATAdminEnumCatalogFromHash(
                    hCatAdmin, hashPtr, hashSize, 0, IntPtr.Zero);
                if (hCatInfo == IntPtr.Zero) return false;

                var ci = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
                if (!CryptCATCatalogInfoFromContext(hCatInfo, ref ci, 0)) return false;

                var memberTag = BytesToHex(hashPtr, (int)hashSize);
                return VerifyAgainstCatalog(ci.wszCatalogFile, memberTag, path,
                    hashPtr, hashSize);
            }
            finally
            {
                Marshal.FreeHGlobal(hashPtr);
            }
        }
        catch
        {
            return false;
        }
        finally
        {
            if (hCatInfo != IntPtr.Zero && hCatAdmin != IntPtr.Zero)
                CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            if (hCatAdmin != IntPtr.Zero)
                CryptCATAdminReleaseContext(hCatAdmin, 0);
        }
    }

    private static bool CalcHash(IntPtr hCatAdmin, IntPtr hFile, ref uint size, IntPtr buffer)
    {
        try { return CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref size, buffer, 0); }
        catch (EntryPointNotFoundException)
        {
            return CryptCATAdminCalcHashFromFileHandle(hFile, ref size, buffer, 0);
        }
    }

    private static bool VerifyAgainstCatalog(
        string catalogFile, string memberTag, string memberFile,
        IntPtr hash, uint hashLen)
    {
        IntPtr pCat = IntPtr.Zero, pTag = IntPtr.Zero, pMember = IntPtr.Zero, pInfo = IntPtr.Zero, pData = IntPtr.Zero;
        try
        {
            pCat = Marshal.StringToCoTaskMemUni(catalogFile);
            pTag = Marshal.StringToCoTaskMemUni(memberTag);
            pMember = Marshal.StringToCoTaskMemUni(memberFile);

            var cat = new WINTRUST_CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                dwCatalogVersion = 0,
                pcwszCatalogFilePath = pCat,
                pcwszMemberTag = pTag,
                pcwszMemberFilePath = pMember,
                hMemberFile = IntPtr.Zero,
                pbCalculatedFileHash = hash,
                cbCalculatedFileHash = hashLen,
                pcCatalogContext = IntPtr.Zero,
                hCatAdmin = IntPtr.Zero
            };
            pInfo = Marshal.AllocCoTaskMem(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
            Marshal.StructureToPtr(cat, pInfo, false);

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_CATALOG,
                pInfo = pInfo,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
            };
            pData = Marshal.AllocCoTaskMem(Marshal.SizeOf<WINTRUST_DATA>());
            Marshal.StructureToPtr(data, pData, false);

            var action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            uint res = WinVerifyTrust(IntPtr.Zero, ref action, pData);

            var close = Marshal.PtrToStructure<WINTRUST_DATA>(pData);
            close.dwStateAction = WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(close, pData, false);
            WinVerifyTrust(IntPtr.Zero, ref action, pData);

            return res == 0;
        }
        finally
        {
            if (pData != IntPtr.Zero) Marshal.FreeCoTaskMem(pData);
            if (pInfo != IntPtr.Zero) Marshal.FreeCoTaskMem(pInfo);
            if (pMember != IntPtr.Zero) Marshal.FreeCoTaskMem(pMember);
            if (pTag != IntPtr.Zero) Marshal.FreeCoTaskMem(pTag);
            if (pCat != IntPtr.Zero) Marshal.FreeCoTaskMem(pCat);
        }
    }

    private static string BytesToHex(IntPtr ptr, int len)
    {
        var bytes = new byte[len];
        Marshal.Copy(ptr, bytes, 0, len);
        return Convert.ToHexString(bytes); // upper-case hex, as catalog member tags expect
    }

    // ---- constants ---------------------------------------------------------

    private static Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_CHOICE_CATALOG = 2;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x00000010;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;

    private const uint TRUST_E_NOSIGNATURE = 0x800B0100;
    private const uint TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003;
    private const uint TRUST_E_PROVIDER_UNKNOWN = 0x800B0001;

    // ---- P/Invoke ----------------------------------------------------------

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern uint WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, IntPtr pWVTData);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext(
        ref IntPtr phCatAdmin, IntPtr pgSubsystem, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptCATAdminAcquireContext2(
        ref IntPtr phCatAdmin, IntPtr pgSubsystem,
        [MarshalAs(UnmanagedType.LPWStr)] string? pwszHashAlgorithm,
        IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle(
        IntPtr hFile, ref uint pcbHash, IntPtr pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, IntPtr pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin, IntPtr pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATCatalogInfoFromContext(
        IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(
        IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pInfo;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }
}
