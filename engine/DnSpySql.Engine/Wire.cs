// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Buffers.Binary;
using System.Text;

namespace DnSpySql;

// Tagged-cell encoding shared with the native side (src/wire.hpp).
//   cell   := tag:u8 payload
//   tag 0  := NULL
//   tag 1  := i64 (8 bytes LE)
//   tag 2  := f64 (8 bytes LE)
//   tag 3  := text (u32 len LE + UTF-8)
//   tag 4  := blob (u32 len LE + bytes)
//   list   := count:u32 cell*
//   rowset := ncols:u32 nrows:u32 cell*   (ncols includes the leading key cell)
static class Wire
{
    public const byte Null = 0, Int = 1, Real = 2, Text = 3, Blob = 4;

    public sealed class Writer
    {
        readonly MemoryStream ms = new();
        readonly byte[] scratch = new byte[8];

        public void U32(uint v) { BinaryPrimitives.WriteUInt32LittleEndian(scratch, v); ms.Write(scratch, 0, 4); }
        public void Raw64(long v) { BinaryPrimitives.WriteInt64LittleEndian(scratch, v); ms.Write(scratch, 0, 8); }
        public int Position => (int)ms.Position;
        // a count written ahead of what it counts, once it is known
        public void PatchU32(int at, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(ms.GetBuffer().AsSpan(at, 4), v);

        public void Cell(object? v)
        {
            switch (v)
            {
                case null: ms.WriteByte(Null); break;
                case bool b: I64(b ? 1 : 0); break;
                case byte or sbyte or short or ushort or int or uint or long:
                    I64(Convert.ToInt64(v)); break;
                case ulong ul: I64(unchecked((long)ul)); break;
                case float or double:
                    ms.WriteByte(Real);
                    BinaryPrimitives.WriteDoubleLittleEndian(scratch, Convert.ToDouble(v));
                    ms.Write(scratch, 0, 8);
                    break;
                case byte[] bytes:
                    ms.WriteByte(Blob); U32((uint)bytes.Length); ms.Write(bytes); break;
                default:
                    var s = Encoding.UTF8.GetBytes(v.ToString() ?? "");
                    ms.WriteByte(Text); U32((uint)s.Length); ms.Write(s); break;
            }
        }

        void I64(long v)
        {
            ms.WriteByte(Int);
            BinaryPrimitives.WriteInt64LittleEndian(scratch, v);
            ms.Write(scratch, 0, 8);
        }

        public byte[] ToArray() => ms.ToArray();
        // the bytes written, in the stream's own buffer: the caller copies them to native memory once
        public ArraySegment<byte> Segment() => new(ms.GetBuffer(), 0, (int)ms.Length);
    }

    public static List<object?> ReadList(ReadOnlySpan<byte> buf)
    {
        var list = new List<object?>();
        if (buf.Length < 4) return list;
        uint n = BinaryPrimitives.ReadUInt32LittleEndian(buf);
        int pos = 4;
        for (uint i = 0; i < n; i++)
        {
            byte tag = buf[pos++];
            switch (tag)
            {
                case Null: list.Add(null); break;
                case Int: list.Add(BinaryPrimitives.ReadInt64LittleEndian(buf[pos..])); pos += 8; break;
                case Real: list.Add(BinaryPrimitives.ReadDoubleLittleEndian(buf[pos..])); pos += 8; break;
                case Text:
                case Blob:
                    int len = (int)BinaryPrimitives.ReadUInt32LittleEndian(buf[pos..]); pos += 4;
                    var slice = buf.Slice(pos, len); pos += len;
                    list.Add(tag == Text ? Encoding.UTF8.GetString(slice) : slice.ToArray());
                    break;
                default: throw new InvalidDataException($"bad cell tag {tag}");
            }
        }
        return list;
    }

    public static byte[] EncodeList(params object?[] cells)
    {
        var w = new Writer();
        w.U32((uint)cells.Length);
        foreach (var c in cells) w.Cell(c);
        return w.ToArray();
    }

    // cursor := id:i64 rowset   (scan_open: the cursor id and its first batch)
    public static ArraySegment<byte> EncodeCursor(long id, int ncols, IEnumerable<Row> rows) => EncodeRows(ncols, rows, id);

    // One buffer, the header first and its row count filled in at the end, handed over as it is: a batch of large blobs
    // (payload resources) is copied once on the way out (to native memory), not four times.
    public static ArraySegment<byte> EncodeRows(int ncols, IEnumerable<Row> rows, long? cursor = null)
    {
        var w = new Writer();
        if (cursor is long id) w.Raw64(id);
        w.U32((uint)(ncols + 1));
        int countAt = w.Position;
        w.U32(0);
        uint n = 0;
        foreach (var r in rows)
        {
            w.Cell(r.Key);
            for (int i = 0; i < ncols; i++) w.Cell(i < r.Values.Length ? r.Values[i] : null);
            n++;
        }
        w.PatchU32(countAt, n);
        return w.Segment();
    }
}

readonly record struct Row(long Key, object?[] Values);
