// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
namespace DnSpySql;

/// <summary>
/// Data appended after the end of the PE image (the "overlay"). The loader never maps it, and compilers never emit it,
/// so in a .NET assembly it is almost always a dropper payload, an encrypted config, a second PE, or padding added to
/// push the file past scanners' size limits. An Authenticode certificate table also lives past the image; it is
/// legitimate and is not counted as overlay data.
/// </summary>
/// <param name="Entropy">Of the data before any trailing zero padding.</param>
/// <param name="Padding">Trailing zero bytes, included in <paramref name="Size"/>.</param>
public sealed record OverlayInfo(long Offset, long Size, double Entropy, string Kind, long? EmbeddedPe, long Padding, long CertificateSize)
{
    /// <summary>One line for modules.overlay, or null when the overlay is only alignment slack.</summary>
    public string? Anomaly =>
        Size < 512 && Kind == "zero padding" ? null
        : $"overlay: {Overlay.Bytes(Size)} appended after the image at 0x{Offset:X}"
          + (CertificateSize > 0 ? " (besides the Authenticode certificate table)" : "")
          + (Kind == "zero padding" ? ": zero padding" + (Size >= 1 << 20 ? " (inflates the file past scanners' size limits)" : "")
             : $": {Kind}, entropy {Entropy:F2}"
               + (EmbeddedPe is long pe && pe != Offset ? $", embedded PE at 0x{pe:X}" : "")
               + (Padding >= 1 << 20 ? $", then {Overlay.Bytes(Padding)} of zero padding (inflates the file past scanners' size limits)" : ""));
}

public static class Overlay
{
    /// <summary>The overlay of a PE file, or null when nothing follows the image (or the headers are unreadable).</summary>
    public static OverlayInfo? Analyze(byte[] b)
    {
        long end, certOff = 0, certSize = 0;
        try
        {
            int pe = BitConverter.ToInt32(b, 0x3C);
            if (pe <= 0 || pe + 0x18 > b.Length || BitConverter.ToUInt32(b, pe) != 0x4550) return null;
            int sections = BitConverter.ToUInt16(b, pe + 6), optSize = BitConverter.ToUInt16(b, pe + 0x14), opt = pe + 0x18;
            bool pe32Plus = BitConverter.ToUInt16(b, opt) == 0x20B;
            end = BitConverter.ToUInt32(b, opt + 0x3C); // SizeOfHeaders
            for (int i = 0; i < sections; i++)
            {
                int o = opt + optSize + 40 * i;
                uint rawSize = BitConverter.ToUInt32(b, o + 16), raw = BitConverter.ToUInt32(b, o + 20);
                if (rawSize > 0) end = Math.Max(end, (long)raw + rawSize);
            }
            int dirs = opt + (pe32Plus ? 0x70 : 0x60);
            if (BitConverter.ToUInt32(b, opt + (pe32Plus ? 0x6C : 0x5C)) > 4) // NumberOfRvaAndSizes covers the security directory
            {
                // The security directory holds a file offset, not an RVA.
                certOff = BitConverter.ToUInt32(b, dirs + 4 * 8);
                certSize = BitConverter.ToUInt32(b, dirs + 4 * 8 + 4);
            }
        }
        catch (ArgumentException) { return null; }
        if (end >= b.Length) return null;

        // The certificate table is normally the whole overlay or sits at its start; anything else is appended data.
        long start = end, stop = b.Length;
        if (certSize > 0 && certOff >= end && certOff < stop)
        {
            long certEnd = Math.Min(stop, certOff + certSize);
            if (certOff == start) start = certEnd;
            else if (certEnd == stop) stop = certOff;
            else certSize = 0; // certificate in the middle: report the whole overlay
        }
        else certSize = 0;
        if (start >= stop) return null;

        var all = b.AsSpan((int)start, (int)(stop - start));
        var data = all[..(all.LastIndexOfAnyExcept((byte)0) + 1)];
        if (data.IsEmpty) return new OverlayInfo(start, all.Length, 0, "zero padding", null, all.Length, certSize);
        double entropy = Entropy(data);
        long? embedded = FindPe(data) is int at and >= 0 ? start + at : null;
        return new OverlayInfo(start, all.Length, entropy, Kind(data, entropy), embedded, all.Length - data.Length, certSize);
    }

    static string Kind(ReadOnlySpan<byte> d, double entropy)
    {
        if (IsPe(d, 0)) return "embedded PE";
        if (d.StartsWith("PK\x03\x04"u8)) return "ZIP archive";
        if (d.StartsWith(new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C })) return "7-Zip archive";
        if (d.StartsWith("Rar!"u8)) return "RAR archive";
        if (d.StartsWith(new byte[] { 0x1F, 0x8B })) return "gzip data";
        if (d.StartsWith("MSCF"u8)) return "CAB archive";
        if (d.StartsWith("%PDF"u8)) return "PDF document";
        if (entropy > 7.2) return "encrypted or compressed data";
        if (IsText(d.Trim((byte)0))) return "text";
        if (entropy < 1.0) return "low-entropy filler";
        return "data";
    }

    static bool IsText(ReadOnlySpan<byte> d)
    {
        int printable = 0;
        foreach (var x in d) if (x is >= 0x20 and < 0x7F or (byte)'\t' or (byte)'\n' or (byte)'\r') printable++;
        return printable >= d.Length * 0.95;
    }

    internal static double Entropy(ReadOnlySpan<byte> d)
    {
        var counts = new long[256];
        foreach (var x in d) counts[x]++;
        double e = 0;
        foreach (var c in counts) if (c > 0) { var p = (double)c / d.Length; e -= p * Math.Log2(p); }
        return e;
    }

    /// <summary>Offset of the first "MZ" that leads to a "PE\0\0" header, or -1.</summary>
    static int FindPe(ReadOnlySpan<byte> d)
    {
        for (int from = 0; ;)
        {
            int i = d[from..].IndexOf("MZ"u8);
            if (i < 0) return -1;
            if (IsPe(d, from + i)) return from + i;
            from += i + 1;
        }
    }

    static bool IsPe(ReadOnlySpan<byte> d, int at)
    {
        if (at + 0x40 > d.Length || d[at] != 'M' || d[at + 1] != 'Z') return false;
        int lfanew = BitConverter.ToInt32(d.Slice(at + 0x3C, 4));
        return lfanew is >= 0x40 and < 0x1000 && at + lfanew + 4 <= d.Length && d.Slice(at + lfanew, 4).SequenceEqual("PE\0\0"u8);
    }

    public static string Bytes(long n) =>
        n >= 1 << 20 ? $"{n / (double)(1 << 20):F1} MB" : n >= 1 << 10 ? $"{n / 1024.0:F1} KB" : $"{n} bytes";
}
