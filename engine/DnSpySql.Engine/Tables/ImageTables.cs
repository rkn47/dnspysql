// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.IO.Compression;
using DnSpySql.Functions;
using DnSpySql.Sql;
using dnlib.DotNet;
using dnlib.DotNet.Resources;

namespace DnSpySql.Tables;

/// <summary>
/// Images inside an assembly, as dnSpy previews them (dnSpy/Documents/TreeView/Resources: ImageResourceNode,
/// SerializedImageResourceElementNode, SerializedImageListStreamerResourceElementNode): image manifest resources,
/// images in .resources files, and serialized System.Drawing.Bitmap/Icon and WinForms ImageListStreamer objects.
/// Serialized objects are never deserialized (BinaryFormatter can run code): the image bytes are located in the NRBF
/// stream and checked against image signatures. image_pixels() decodes PNG/BMP/ICO pixels in managed code, for payloads
/// hidden in pixel data.
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
                "Bitmap/Icon/ImageListStreamer objects (read without deserializing). data is the image file; decode pixels with image_pixels()") { Domain = "resources" }
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
            .Blob("data", r => r.Data)
            .Estimate(50, 5));

        s.Fn("image_pixels", 1, 3, a =>
            {
                var data = Values.ToBytes(a[0]) ?? throw new SqlException("data is NULL");
                var channels = (Values.ToText(a.Arg(1)) ?? "rgba").ToLowerInvariant();
                if (channels.Length == 0 || channels.Any(ch => ch is not ('r' or 'g' or 'b' or 'a')))
                    throw new SqlException("channels is a combination of r, g, b, a (e.g. 'rgb', 'bgra')");
                var order = (Values.ToText(a.Arg(2)) ?? "rows").ToLowerInvariant();
                if (order is not ("rows" or "columns")) throw new SqlException("order is 'rows' (y outer) or 'columns' (x outer)");
                var (w, h, rgba) = Decode(data);
                var map = channels.Select(ch => ch switch { 'r' => 0, 'g' => 1, 'b' => 2, _ => 3 }).ToArray();
                var outp = new byte[(long)w * h * map.Length];
                bool rows = order == "rows";
                int o = 0;
                for (int i = 0; i < w * h; i++)
                {
                    int x = rows ? i % w : i / h, y = rows ? i / w : i % h;
                    int p = (y * w + x) * 4;
                    foreach (var k in map) outp[o++] = rgba[p + k];
                }
                return outp;
            }, "image_pixels(data [, channels [, order]])",
            "decode a PNG, BMP or ICO image to raw pixel bytes, top-down: channels picks and orders r/g/b/a (default 'rgba', e.g. 'bgr' " +
            "for GetPixel-style BGR loops), order is 'rows' (y outer, default) or 'columns' (x outer). For payloads hidden in pixels", "data");
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

    // ---- pixel decoding (RGBA8, top-down) --------------------------------------------------------------------------------
    // Every size and offset taken from the image is checked before it is used. What can still slip through on a hostile
    // image (a structure that ends early, a corrupt zlib stream) is reported as a malformed image, not an internal error.

    const long MaxPixels = 64L * 1024 * 1024;

    public static (int w, int h, byte[] rgba) Decode(byte[] b)
    {
        var info = Info(b) ?? throw new SqlException("not a PNG, BMP or ICO image");
        try
        {
            return info.Format switch
            {
                "png" => Png(b),
                "bmp" => Dib(b, 14, BitConverter.ToUInt32(b, 10), false),
                "ico" or "cur" => Icon(b),
                _ => throw new SqlException($"decoding {info.Format} is not supported; the image bytes are in data"),
            };
        }
        catch (Exception e) when (e is IndexOutOfRangeException or ArgumentException or InvalidDataException)
        {
            throw new SqlException($"malformed {info.Format} image ({e.Message})");
        }
    }

    static void Check(long w, long h)
    {
        if (w <= 0 || h <= 0 || w * h > MaxPixels) throw new SqlException($"unsupported size {w}x{h}");
    }

    static (int, int, byte[]) Png(byte[] b)
    {
        int w = 0, h = 0, depth = 0, color = 0, interlace = 0;
        bool header = false;
        byte[]? palette = null, trns = null;
        using var idat = new MemoryStream();
        for (int i = 8; i + 8 <= b.Length;)
        {
            int len = b[i] << 24 | b[i + 1] << 16 | b[i + 2] << 8 | b[i + 3];
            var type = System.Text.Encoding.ASCII.GetString(b, i + 4, 4);
            if (len < 0 || len > b.Length - i - 12) throw new SqlException("truncated PNG chunk " + type);
            var data = b.AsSpan(i + 8, len);
            switch (type)
            {
                case "IHDR" when len >= 13:
                    w = data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];
                    h = data[4] << 24 | data[5] << 16 | data[6] << 8 | data[7];
                    depth = data[8]; color = data[9]; interlace = data[12];
                    header = true;
                    break;
                case "PLTE": palette = data.ToArray(); break;
                case "tRNS": trns = data.ToArray(); break;
                case "IDAT": idat.Write(data); break;
            }
            if (type == "IEND") break;
            i += 12 + len;
        }
        if (!header) throw new SqlException("PNG without an IHDR chunk");
        Check(w, h);
        if (interlace != 0) throw new SqlException("interlaced PNG is not supported");
        int ch = color switch { 0 => 1, 2 => 3, 3 => 1, 4 => 2, 6 => 4, _ => throw new SqlException($"PNG color type {color}") };
        if (!(color switch { 0 => depth is 1 or 2 or 4 or 8 or 16, 3 => depth is 1 or 2 or 4 or 8, _ => depth is 8 or 16 }))
            throw new SqlException($"PNG bit depth {depth} for color type {color}");
        int bpp = Math.Max(1, ch * depth / 8);
        // At most 64M pixels of at most 8 bytes, plus a filter byte per row: fits an int.
        int stride = (int)(((long)w * ch * depth + 7) / 8);
        long needed = (stride + 1L) * h;
        // Deflate expands at most about 1032:1, so a few compressed bytes cannot hold a large image: refuse before
        // allocating for it.
        if (needed > idat.Length * 1032 + 1024) throw new SqlException("truncated PNG data");
        idat.Position = 0;
        using var z = new ZLibStream(idat, CompressionMode.Decompress);
        var raw = new byte[needed];
        int got = 0;
        while (got < raw.Length && z.Read(raw, got, raw.Length - got) is var n && n > 0) got += n;
        if (got < raw.Length) throw new SqlException("truncated PNG data");

        var cur = new byte[stride];
        var prev = new byte[stride];
        var rgba = new byte[(long)w * h * 4];
        for (int y = 0; y < h; y++)
        {
            int f = raw[y * (stride + 1)];
            Array.Copy(raw, y * (stride + 1) + 1, cur, 0, stride);
            for (int x = 0; x < stride; x++)
            {
                int a = x >= bpp ? cur[x - bpp] : 0, up = prev[x], c = x >= bpp ? prev[x - bpp] : 0;
                cur[x] = (byte)(cur[x] + f switch
                {
                    0 => 0, 1 => a, 2 => up, 3 => (a + up) / 2,
                    4 => Paeth(a, up, c),
                    _ => throw new SqlException($"bad PNG filter {f}"),
                });
            }
            for (int x = 0; x < w; x++)
            {
                int Sample(int k)
                {
                    if (depth == 8) return cur[x * ch + k];
                    if (depth == 16) return cur[(x * ch + k) * 2];
                    int bitPos = (x * ch + k) * depth, v = cur[bitPos / 8] >> (8 - depth - bitPos % 8) & ((1 << depth) - 1);
                    return color == 3 ? v : v * 255 / ((1 << depth) - 1);
                }
                int o = (y * w + x) * 4;
                switch (color)
                {
                    case 0: rgba[o] = rgba[o + 1] = rgba[o + 2] = (byte)Sample(0); rgba[o + 3] = 255; break;
                    case 2: rgba[o] = (byte)Sample(0); rgba[o + 1] = (byte)Sample(1); rgba[o + 2] = (byte)Sample(2); rgba[o + 3] = 255; break;
                    case 3:
                        int idx = Sample(0);
                        if (palette == null || idx * 3 + 2 >= palette.Length) throw new SqlException("PNG palette index out of range");
                        rgba[o] = palette[idx * 3]; rgba[o + 1] = palette[idx * 3 + 1]; rgba[o + 2] = palette[idx * 3 + 2];
                        rgba[o + 3] = trns != null && idx < trns.Length ? trns[idx] : (byte)255;
                        break;
                    case 4: rgba[o] = rgba[o + 1] = rgba[o + 2] = (byte)Sample(0); rgba[o + 3] = (byte)Sample(1); break;
                    default: rgba[o] = (byte)Sample(0); rgba[o + 1] = (byte)Sample(1); rgba[o + 2] = (byte)Sample(2); rgba[o + 3] = (byte)Sample(3); break;
                }
            }
            (prev, cur) = (cur, prev);
        }
        return (w, h, rgba);
    }

    static int Paeth(int a, int b, int c)
    {
        int p = a + b - c, pa = Math.Abs(p - a), pb = Math.Abs(p - b), pc = Math.Abs(p - c);
        return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
    }

    // A DIB (BITMAPINFOHEADER or BITMAPCOREHEADER) at `at`; `pixels` is the file offset of the pixel array (0 = right after
    // the palette). Icons store the height doubled (XOR + AND masks); only the XOR (color) image is decoded.
    static (int, int, byte[]) Dib(byte[] b, int at, uint pixels, bool icon)
    {
        if ((long)at + 12 > b.Length) throw new SqlException("truncated BMP header");
        uint hdr = BitConverter.ToUInt32(b, at);
        bool core = hdr == 12;
        if (!core && hdr < 40) throw new SqlException($"BMP header size {hdr}");
        if (!core && hdr > b.Length - at) throw new SqlException("truncated BMP header");
        int w = core ? BitConverter.ToUInt16(b, at + 4) : BitConverter.ToInt32(b, at + 4);
        long hRaw = core ? BitConverter.ToUInt16(b, at + 6) : BitConverter.ToInt32(b, at + 8);
        int bpp = BitConverter.ToUInt16(b, at + (core ? 10 : 14));
        uint compression = core ? 0 : BitConverter.ToUInt32(b, at + 16);
        bool topDown = hRaw < 0;
        long hl = Math.Abs(hRaw) / (icon ? 2 : 1);
        Check(w, hl);
        int h = (int)hl;
        if (compression is not (0 or 3)) throw new SqlException("compressed BMP (RLE/JPEG/PNG in BMP) is not supported");
        if (bpp is not (1 or 4 or 8 or 24 or 32)) throw new SqlException($"{bpp}-bit BMP is not supported");
        uint used = core ? 0 : BitConverter.ToUInt32(b, at + 32);
        int colors = bpp > 8 ? 0 : used > 0 && used < 1u << bpp ? (int)used : 1 << bpp;
        long palAt = at + (long)hdr + (compression == 3 && hdr == 40 ? 12 : 0);
        int entry = core ? 3 : 4;
        long palEnd = palAt + (long)colors * entry;
        long data = pixels != 0 ? pixels : palEnd;
        long stride = ((long)w * bpp + 31) / 32 * 4;
        if (palEnd > b.Length) throw new SqlException("truncated BMP palette");
        if (data + stride * h > b.Length) throw new SqlException("truncated BMP pixel data");
        var rgba = new byte[(long)w * h * 4];
        for (int y = 0; y < h; y++)
        {
            int row = (int)(data + (topDown ? y : h - 1 - y) * stride);
            for (int x = 0; x < w; x++)
            {
                int o = (y * w + x) * 4;
                switch (bpp)
                {
                    case 32: rgba[o] = b[row + x * 4 + 2]; rgba[o + 1] = b[row + x * 4 + 1]; rgba[o + 2] = b[row + x * 4]; rgba[o + 3] = b[row + x * 4 + 3]; break;
                    case 24: rgba[o] = b[row + x * 3 + 2]; rgba[o + 1] = b[row + x * 3 + 1]; rgba[o + 2] = b[row + x * 3]; rgba[o + 3] = 255; break;
                    default:
                        int bit = x * bpp, idx = b[row + bit / 8] >> (8 - bpp - bit % 8) & ((1 << bpp) - 1);
                        // an index past the palette reads as black
                        if (idx < colors) { int p = (int)palAt + idx * entry; rgba[o] = b[p + 2]; rgba[o + 1] = b[p + 1]; rgba[o + 2] = b[p]; }
                        rgba[o + 3] = 255;
                        break;
                }
            }
        }
        if (bpp == 32 && compression == 0 && !icon)
        {
            // BI_RGB 32-bit: the fourth byte is unused, so an image whose alpha is 0 everywhere is opaque
            bool alpha = false;
            for (int i = 3; i < rgba.Length && !alpha; i += 4) alpha = rgba[i] != 0;
            if (!alpha) for (int i = 3; i < rgba.Length; i += 4) rgba[i] = 255;
        }
        return (w, h, rgba);
    }

    // The first image of an icon: PNG-compressed or a DIB.
    static (int, int, byte[]) Icon(byte[] b)
    {
        int size = BitConverter.ToInt32(b, 14), off = BitConverter.ToInt32(b, 18);
        if (off < 0 || size <= 0 || size > b.Length - off) throw new SqlException("bad icon directory entry");
        var img = b.AsSpan(off, size).ToArray();
        if (img.Length >= 8 && img[0] == 0x89 && img[1] == 0x50) return Png(img);
        return Dib(img, 0, 0, true);
    }
}
