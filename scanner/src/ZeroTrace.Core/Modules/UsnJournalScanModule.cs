using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Reads the NTFS USN change journal (read-only) to recover recent file
/// create/delete activity — including cheats that were created and then deleted.
/// File names are matched against the indicators. Requires administrator rights
/// and an NTFS volume; otherwise it degrades to nothing. Feeds the dashboard's
/// "MFT Records" / file-activity view. Nothing is written.
/// </summary>
public sealed class UsnJournalScanModule : IScanModule
{
    public string Name => "NTFS-Aenderungsjournal";
    public double Weight => 0.6;

    private int _emitted;
    private const int MaxFindings = 80;

    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_RW = 0x1 | 0x2;
    private const uint OPEN_EXISTING = 3;
    private const uint FSCTL_QUERY_USN_JOURNAL = 0x000900f4;
    private const uint FSCTL_ENUM_USN_DATA = 0x000900b3;
    private const uint USN_REASON_FILE_CREATE = 0x00000100;
    private const uint USN_REASON_FILE_DELETE = 0x00000200;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
        IntPtr sec, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(SafeFileHandle h, uint code,
        byte[] inBuf, int inSize, byte[] outBuf, int outSize, out int returned, IntPtr overlapped);

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        try { ScanVolume(ctx, 'C', ct); } catch { }
        ctx.Report(1.0, "USN", "Aenderungsjournal geprueft");
        return Task.CompletedTask;
    }

    private void ScanVolume(ScanContext ctx, char letter, CancellationToken ct)
    {
        using var h = CreateFileW($@"\\.\{letter}:", GENERIC_READ, FILE_SHARE_RW,
            IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h.IsInvalid) return;

        // 1) query journal for the valid USN range
        var jd = new byte[64];
        if (!DeviceIoControl(h, FSCTL_QUERY_USN_JOURNAL, null!, 0, jd, jd.Length, out _, IntPtr.Zero))
            return;
        long nextUsn = BitConverter.ToInt64(jd, 16); // NextUsn field

        // 2) enumerate records: MFT_ENUM_DATA_V0 { StartFRN(8)=0, LowUsn(8)=0, HighUsn(8)=NextUsn }
        var input = new byte[24];
        Buffer.BlockCopy(BitConverter.GetBytes(0L), 0, input, 0, 8);
        Buffer.BlockCopy(BitConverter.GetBytes(0L), 0, input, 8, 8);
        Buffer.BlockCopy(BitConverter.GetBytes(nextUsn), 0, input, 16, 8);

        var outBuf = new byte[64 * 1024];
        int guard = 0;
        while (guard++ < 4000)
        {
            if (ct.IsCancellationRequested || _emitted >= MaxFindings) return;
            if (!DeviceIoControl(h, FSCTL_ENUM_USN_DATA, input, input.Length,
                    outBuf, outBuf.Length, out int returned, IntPtr.Zero))
                return;
            if (returned <= 8) return;

            // first 8 bytes = next StartFileReferenceNumber for the following call
            long nextStart = BitConverter.ToInt64(outBuf, 0);
            int pos = 8;
            while (pos + 60 <= returned)
            {
                int recLen = BitConverter.ToInt32(outBuf, pos);
                if (recLen <= 0 || pos + recLen > returned) break;

                uint reason = BitConverter.ToUInt32(outBuf, pos + 40);
                long ts = BitConverter.ToInt64(outBuf, pos + 32);
                ushort nameLen = BitConverter.ToUInt16(outBuf, pos + 56);
                ushort nameOff = BitConverter.ToUInt16(outBuf, pos + 58);

                if (nameLen > 0 && pos + nameOff + nameLen <= returned)
                {
                    var name = Encoding.Unicode.GetString(outBuf, pos + nameOff, nameLen);
                    EvaluateName(ctx, name, reason, ts);
                }
                pos += recLen;
            }

            Buffer.BlockCopy(BitConverter.GetBytes(nextStart), 0, input, 0, 8);
        }
    }

    private void EvaluateName(ScanContext ctx, string fileName, uint reason, long fileTime)
    {
        if (_emitted >= MaxFindings) return;
        var ind = ctx.Matcher.MatchFileName(fileName)
                  ?? ctx.Matcher.MatchFileNameKeyword(fileName);
        if (ind is null) return;

        bool created = (reason & USN_REASON_FILE_CREATE) != 0;
        bool deleted = (reason & USN_REASON_FILE_DELETE) != 0;
        string what = deleted ? "geloescht" : created ? "erstellt" : "geaendert";
        string when;
        try { when = DateTime.FromFileTimeUtc(fileTime).ToLocalTime().ToString("yyyy-MM-dd HH:mm"); }
        catch { when = "?"; }

        _emitted++;
        ctx.AddFinding(new Finding
        {
            Module = Name,
            Title = $"Datei-Aktivitaet ({what}): {ind.Category}",
            Risk = ind.Risk,
            Location = fileName,
            FileName = fileName,
            Reason = $"Das NTFS-Aenderungsjournal verzeichnet die Datei '{fileName}' als {what}. " +
                     $"Sie entspricht dem Indikator '{ind.Pattern}'. {ind.Description}",
            Detail = $"Zeit: {when}"
        });
    }
}
