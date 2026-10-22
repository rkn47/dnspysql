// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Sql;
using dnlib.DotNet;
using dnlib.DotNet.Resources;

namespace DnSpySql.Tables;

/// <summary>
/// Images inside an assembly, as dnSpy previews them (dnSpy/Documents/TreeView/Resources: ImageResourceNode,
/// SerializedImageResourceElementNode, SerializedImageListStreamerResourceElementNode): image manifest resources,
/// images in .resources files, and serialized System.Drawing.Bitmap/Icon and WinForms ImageListStreamer objects.
/// Serialized objects are never deserialized (BinaryFormatter can run code): the image bytes are located in the NRBF
/// stream and checked against image signatures. The image bytes are handed out as they are (data); decoding them is left
/// to the caller.
/// </summary>
public static class ImageTables
{
    public sealed record ImageRow(LoadedModule M, Resource R, int ResIndex, string? Element, string Source, string? TypeName, byte[] Data, ImageInfo Info);

    public sealed record ImageInfo(string Format, int? Width, int? Height, int? Frames, int? BitsPerPixel);

    public static void Register(Session s)
    {
        var ws = s.Ws;
        s.Db.Register(new Table<ImageRow>("resource_images",
                "Images in resources (dnSpy's image previews): image manifest resources, images in .resources files, and serialized " +
                "Bitmap/Icon/ImageListStreamer objects (read without deserializing). data is the image file, as the resource holds it") { Domain = "resources" }
            .Source(c => ws.Modules(c).SelectMany(Images))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Text("resource", r => r.R.Name.String)
            .Int("resource_handle", r => r.M.H(0x28000000 | (uint)(r.ResIndex + 1)))
            .Text("element", r => r.Element, doc: "name inside the .resources file (NULL for a whole resource)")
            .Text("source", r => r.Source, doc: "resource | resource_element | serialized | imagelist")
            .Text("type_name", r => r.TypeName, doc: "serialized type (System.Drawing.Bitmap, ...)")
            .Text("format", r => r.Info.Format, doc: "png | bmp | gif | jpeg | ico | cur | imagelist")
            .Int("width", r => r.Info.Width)
            .Int("height", r => r.Info.Height)
            .Int("frames", r => r.Info.Frames, doc: "icon entries / ImageList images")
            .Int("bits_per_pixel", r => r.Info.BitsPerPixel)
            .Int("size", r => r.Data.Length)
            .Blob("data", r => r.Data, doc: "the image file, as the resource holds it")
            .Estimate(50, 5));
    }

    // ---- finding images ------------------------------------------------------------------------------------------------

    static IEnumerable<ImageRow> Images(LoadedModule m)
    {
        var list = m.Module.Resources;
        for (int i = 0; i < list.Count; i++)
        {
            if (list[i] is not EmbeddedResource er) continue;
            byte[] bytes;
            try { bytes = er.CreateReader().ToArray(); } catch (Exception) { continue; }
            if (Info(bytes) is { } info) { yield return new ImageRow(m, er, i, null, "resource", null, bytes, info); continue; }
            if (ResourceTables.ReadSet(m, er) is not { } set) continue;
            foreach (var e in set.ResourceElements)
            {
                switch (e.ResourceData)
                {
                    case BuiltInResourceData { Data: byte[] b } when Info(b) is { } bi:
                        yield return new ImageRow(m, er, i, e.Name, "resource_element", null, b, bi);
                        break;
                    case BinaryResourceData bd when bd.TypeName.StartsWith("System.Windows.Forms.ImageListStreamer", StringComparison.Ordinal):
                        if (NrbfByteArrays(bd.Data).FirstOrDefault() is { } il && ImageList(il) is var (ild, ili))
                            yield return new ImageRow(m, er, i, e.Name, "imagelist", bd.TypeName, ild, ili);
                        break;
                    case BinaryResourceData bd:
                        if (NrbfByteArrays(bd.Data).Select(x => (x, info: Info(x))).FirstOrDefault(x => x.info != null) is { x: { } img, info: { } ii })
                            yield return new ImageRow(m, er, i, e.Name, "serialized", bd.TypeName, img, ii);
                        break;
                }
            }
        }
    }

    // byte[] values in a .NET binary-serialization (NRBF) stream: ArraySinglePrimitive records (type 15) of Byte (2).
    // A scan rather than a parse, so a malformed stream cannot do more than yield nothing.
    internal static IEnumerable<byte[]> NrbfByteArrays(byte[] d)
    {
        for (int i = 0; i + 10 <= d.Length; i++)
        {
            if (d[i] != 15 || d[i + 9] != 2) continue;
            int len = BitConverter.ToInt32(d, i + 5);
            if (len <= 0 || len > d.Length - i - 10) continue; // (not i + 10 + len: that overflows for a hostile length)
            yield return d.AsSpan(i + 10, len).ToArray();
            i += 9 + len;
        }
    }

    // ---- image headers -------------------------------------------------------------------------------------------------

    public static ImageInfo? Info(byte[] b)
    {
        if (b.Length < 12) return null;
        bool Starts(params byte[] m) => b.AsSpan(0, m.Length).SequenceEqual(m);
        static int Be32(byte[] b, int i) => b[i] << 24 | b[i + 1] << 16 | b[i + 2] << 8 | b[i + 3];
        if (Starts(0x89, 0x50, 0x4E, 0x47) && b.Length >= 26)
        {
            int bits = b[24], color = b[25];
            int ch = color switch { 0 => 1, 2 => 3, 3 => 1, 4 => 2, 6 => 4, _ => 1 };
            return new ImageInfo("png", Be32(b, 16), Be32(b, 20), 1, bits * ch);
        }
        if (Starts(0x47, 0x49, 0x46, 0x38)) return new ImageInfo("gif", BitConverter.ToUInt16(b, 6), BitConverter.ToUInt16(b, 8), null, null);
        if (Starts(0xFF, 0xD8, 0xFF))
        {
            for (int i = 2; i + 9 < b.Length;)
            {
                if (b[i] != 0xFF) { i++; continue; }
                byte mk = b[i + 1];
                if (mk is >= 0xC0 and <= 0xC3) return new ImageInfo("jpeg", b[i + 7] << 8 | b[i + 8], b[i + 5] << 8 | b[i + 6], 1, b[i + 4] * b[i + 9]);
                if (mk is 0xD8 or 0x01 or (>= 0xD0 and <= 0xD7)) { i += 2; continue; }
                i += 2 + (b[i + 2] << 8 | b[i + 3]);
            }
            return new ImageInfo("jpeg", null, null, 1, null);
        }
        if (Starts(0x42, 0x4D) && b.Length >= 30 && BitConverter.ToUInt32(b, 2) is var fsz && fsz <= b.Length + 16 && fsz >= 26)
        {
            uint dib = BitConverter.ToUInt32(b, 14);
            if (dib == 12) return new ImageInfo("bmp", BitConverter.ToUInt16(b, 18), BitConverter.ToUInt16(b, 20), 1, BitConverter.ToUInt16(b, 24));
            // the height is negative for a top-down image (and int.MinValue in a hostile one, which Math.Abs(int) throws on)
            if (dib >= 40) return new ImageInfo("bmp", BitConverter.ToInt32(b, 18), (int)Math.Min(Math.Abs((long)BitConverter.ToInt32(b, 22)), int.MaxValue), 1, BitConverter.ToUInt16(b, 28));
        }
        if ((Starts(0, 0, 1, 0) || Starts(0, 0, 2, 0)) && BitConverter.ToUInt16(b, 4) is var n and > 0 and < 256 && 6 + 16 * n <= b.Length)
            return new ImageInfo(b[2] == 1 ? "ico" : "cur", b[6] == 0 ? 256 : b[6], b[7] == 0 ? 256 : b[7], n, BitConverter.ToUInt16(b, 12) is var bpp and > 0 ? bpp : null);
        return null;
    }

    // WinForms ImageListStreamer data: optionally "MSFt" + (count, value) run-length pairs, then the ImageList_Write stream
    // (ILHEAD: 'IL', version, cCurImage, cMaxImage, cGrow, cx, cy, ...). The run-length data expands up to 127 times, so
    // a stream that would expand past MaxExpanded is not an image list dnSpy could show either.
    const int MaxExpanded = 64 * 1024 * 1024;

    static (byte[], ImageInfo)? ImageList(byte[] d)
    {
        if (d.Length >= 4 && d[0] == 'M' && d[1] == 'S' && d[2] == 'F' && d[3] == 't')
        {
            long total = 0;
            for (int i = 4; i + 1 < d.Length; i += 2) total += d[i];
            if (total > MaxExpanded) return null;
            var expanded = new byte[total];
            int o = 0;
            for (int i = 4; i + 1 < d.Length; i += 2)
            {
                expanded.AsSpan(o, d[i]).Fill(d[i + 1]);
                o += d[i];
            }
            d = expanded;
        }
        if (d.Length < 14 || d[0] != 'I' || d[1] != 'L') return null;
        return (d, new ImageInfo("imagelist", BitConverter.ToInt16(d, 10), BitConverter.ToInt16(d, 12), BitConverter.ToInt16(d, 4), null));
    }
}
