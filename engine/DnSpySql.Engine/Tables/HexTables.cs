// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Text;
using DnSpySql.Sql;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.MD;
using dnlib.IO;
using dnlib.PE;
using static DnSpySql.Tables.TableKit;

namespace DnSpySql.Tables;

/// <summary>
/// What dnSpy's hex view labels in a .NET file (dnSpy/Hex/Files/PE, dnSpy/Hex/Files/DotNet), read from the file's own
/// bytes rather than dnlib's parsed model, so that packed, encrypted or deliberately broken structures show as they are:
/// raw method bodies (ECMA-335 II.25.4), metadata heap entries (II.24.2) and a map of every byte range with the gaps
/// no structure accounts for.
/// </summary>
public static class HexTables
{
    public sealed class Body
    {
        public required LoadedModule M;
        public uint Rid;
        public uint Rva;
        public long FileOffset;
        public string? Section;
        public string Format = "invalid";
        public int HeaderSize;
        public int Flags;
        public int MaxStack;
        public long CodeSize;
        public uint LocalSigToken;
        public long? EhOffset;
        public string? EhFormat;
        public int EhSize;
        public int EhClauses;
        public int Padding;
        public long End;
        public string IlStatus = "ok";
        public long? IlErrorOffset;
        public uint SharedWith;
        public uint Overlaps;
        public string? Error;
        public HashSet<uint> UserStrings = new();
    }

    public sealed record HeapEntry(LoadedModule M, string Heap, long Offset, long FileOffset, long Length, string? Value, byte[] Data, bool? Referenced, string Kind);

    public sealed record Region(LoadedModule M, long Offset, long Size, string Kind, string Path, long? Handle);

    // The file's bytes do not change within a session (edits go to the model), so a module's bodies are parsed once.
    static readonly System.Runtime.CompilerServices.ConditionalWeakTable<LoadedModule, List<Body>> _bodies = new();
    static readonly System.Runtime.CompilerServices.ConditionalWeakTable<LoadedModule, Dictionary<uint, string>> _undecodable = new();

    /// <summary>Method tokens whose body does not decode as IL in the file, with the il_status (asked on every decompile).</summary>
    public static IReadOnlyDictionary<uint, string> Undecodable(LoadedModule m) =>
        _undecodable.GetValue(m, lm => Bodies(lm).Where(b => b.IlStatus != "ok").ToDictionary(b => 0x06000000u | b.Rid, b => b.IlStatus));
    // Likewise the file map and the heaps' column references: both read OriginalBytes and FileMetadata, which stay the
    // file's (raw patches and model edits do not change them).
    static readonly System.Runtime.CompilerServices.ConditionalWeakTable<LoadedModule, List<Region>> _maps = new();
    static readonly System.Runtime.CompilerServices.ConditionalWeakTable<LoadedModule, Refs> _refs = new();
    sealed record Refs(List<uint> Strings, HashSet<uint> Blobs, HashSet<uint> Guids);

    public static void Register(Session s)
    {
        var ws = s.Ws;
        var db = s.Db;

        db.Register(new Table<Body>("method_bodies",
                "Method bodies as they are in the file (dnSpy hex view): tiny/fat/invalid header, exception sections, whether the IL decodes, " +
                "and bodies that share or overlap another. Anti-tamper and packers show up here") { Domain = "pe" }
            .Source(c =>
            {
                var rows = ws.Modules(c).SelectMany(Bodies);
                if (c.Long("method") is long h) { h = ws.Normalize(h); rows = rows.Where(b => b.M.H(0x06000000 | b.Rid) == h); }
                return rows;
            })
            .Int("module", b => b.M.Id, pushdown: Pushdown.Eq)
            .Int("method", b => b.M.H(0x06000000 | b.Rid), pushdown: Pushdown.Eq, doc: "method handle")
            .Text("method_name", b => b.M.Module.ResolveToken(0x06000000 | b.Rid) is MethodDef md ? md.FullName : null)
            .Int("rva", b => b.Rva)
            .Int("file_offset", b => b.FileOffset)
            .Text("section", b => b.Section, doc: "PE section holding the body (NULL = outside every section)")
            .Text("format", b => b.Format, doc: "tiny | fat | invalid")
            .Int("header_size", b => b.HeaderSize)
            .Int("flags", b => b.Flags, doc: "fat header flags (0x08 MoreSects, 0x10 InitLocals)")
            .Int("max_stack", b => b.MaxStack)
            .Int("code_size", b => b.CodeSize)
            .Int("local_sig_token", b => b.LocalSigToken == 0 ? null : b.LocalSigToken)
            .Int("eh_offset", b => b.EhOffset, doc: "file offset of the exception-handling section")
            .Text("eh_format", b => b.EhFormat, doc: "small | fat")
            .Int("eh_size", b => b.EhSize)
            .Int("eh_clauses", b => b.EhClauses)
            .Int("padding", b => b.Padding, doc: "alignment bytes between the code and the exception section")
            .Int("size", b => b.End - b.FileOffset, doc: "header + code + padding + exception sections")
            .Text("il_status", b => b.IlStatus, doc: "ok | bad_opcode | bad_token | bad_branch | truncated | no_body (header invalid)")
            .Int("il_error_offset", b => b.IlErrorOffset, doc: "IL offset of the first problem")
            .Int("shared_with", b => b.SharedWith == 0 ? null : b.M.H(0x06000000 | b.SharedWith), doc: "another method with the same RVA")
            .Int("overlaps", b => b.Overlaps == 0 ? null : b.M.H(0x06000000 | b.Overlaps), doc: "another method whose body overlaps this one")
            .Text("error", b => b.Error)
            .Estimate(5000, 2));

        db.Register(new Table<HeapEntry>("heap_entries",
                "Entries of the #Strings, #US, #Blob and #GUID heaps (dnSpy hex view), whether any metadata or IL references them, and " +
                "slack (bytes after the last entry that parses). Unreferenced entries and slack are where data hides") { Domain = "pe" }
            .Source(c => ws.Modules(c).SelectMany(m => Heaps(m, c.Text("heap"))).Where(e => InRange(c, "offset", e.Offset)))
            .Int("module", e => e.M.Id, pushdown: Pushdown.Eq)
            .Text("heap", e => e.Heap, pushdown: Pushdown.Eq, doc: "#Strings | #US | #Blob | #GUID")
            .Int("offset", e => e.Offset, pushdown: Pushdown.Range, doc: "heap offset (#GUID: (index - 1) * 16); #US tokens are 0x70000000 | offset")
            .Int("file_offset", e => e.FileOffset)
            .Int("length", e => e.Length, doc: "bytes including the length prefix or terminator")
            .Text("value", e => e.Value, doc: "string, GUID, or hex preview of a blob")
            .Blob("data", e => e.Data)
            .Int("referenced", e => e.Referenced is bool b ? (b ? 1L : 0L) : null, doc: "any metadata column (or ldstr, for #US) points into it; NULL for slack")
            .Text("kind", e => e.Kind, doc: "entry | slack")
            .Estimate(20000, 2));

        db.Register(new Table<Region>("file_map",
                "Every byte range of the file and what it is (dnSpy hex view structure info): headers, sections, CLR and metadata " +
                "structures, tables, heaps, method bodies, resources, field data, overlay, and gaps that no structure accounts for") { Domain = "pe" }
            .Source(c => ws.Modules(c).SelectMany(m => Map(m))
                .Where(r => { var (lo, hi) = c.LongRange("offset"); var (plo, phi) = c.LongRange("contains"); return r.Offset >= lo && r.Offset <= hi && r.Offset <= phi && r.Offset + r.Size > plo; }))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Int("offset", r => r.Offset, pushdown: Pushdown.Range)
            .Int("size", r => r.Size)
            .Int("end", r => r.Offset + r.Size)
            .Text("kind", r => r.Kind, doc: "header | section | directory | clr | metadata | stream | table | method_body | resource | field_data | overlay | gap")
            .Text("path", r => r.Path)
            .Int("handle", r => r.Handle, doc: "the method, field or resource the range belongs to")
            .Real("entropy", r => Overlay.Entropy(Slice(r)), doc: "Shannon entropy (bits per byte)")
            .Bool("all_zero", r => !Slice(r).ContainsAnyExcept((byte)0))
            .Arg("contains", SqlType.Integer, _ => null, required: false, doc: "WHERE contains = <file offset>: the ranges that hold that byte")
            .Estimate(5000, 2));
    }

    static bool InRange(Constraints c, string col, long v) { var (lo, hi) = c.LongRange(col); return v >= lo && v <= hi; }

    static ReadOnlySpan<byte> Slice(Region r)
    {
        var bytes = r.M.OriginalBytes;
        long start = Math.Clamp(r.Offset, 0, bytes.Length), end = Math.Clamp(r.Offset + r.Size, start, bytes.Length);
        return bytes.AsSpan((int)start, (int)(end - start));
    }

    static string? SectionOf(IPEImage pe, uint rva) =>
        pe.ImageSectionHeaders.FirstOrDefault(h => rva >= (uint)h.VirtualAddress && rva < (long)(uint)h.VirtualAddress + Math.Max(h.VirtualSize, h.SizeOfRawData))?.DisplayName;

    // ---- method bodies -----------------------------------------------------------------------------------------------

    public static List<Body> Bodies(LoadedModule m)
    {
        if (_bodies.TryGetValue(m, out var hit)) return hit;
        var md = m.FileMetadata;
        var pe = md.PEImage;
        var tables = md.TablesStream;
        var list = new List<Body>();
        for (uint rid = 1; rid <= tables.MethodTable.Rows; rid++)
        {
            if (!tables.TryReadMethodRow(rid, out var row) || row.RVA == 0) continue;
            var b = new Body { M = m, Rid = rid, Rva = row.RVA };
            try { b.FileOffset = (long)pe.ToFileOffset((RVA)row.RVA); } catch (Exception) { b.FileOffset = -1; }
            b.Section = SectionOf(pe, row.RVA);
            if (b.Section == null || !PeTables.InFile(pe, row.RVA) || b.FileOffset < 0 || b.FileOffset >= m.OriginalBytes.Length)
            {
                b.Error = b.Section == null ? "RVA outside every section" : $"RVA in {b.Section} past its bytes in the file (zero-filled when loaded)";
                b.IlStatus = "no_body"; b.End = Math.Max(b.FileOffset, 0);
            }
            else ParseBody(m, b, md);
            list.Add(b);
        }
        // Bodies that share an RVA or overlap another one. A body is compared with the one reaching furthest so far, not
        // just its neighbour: a long body can hold several short ones.
        foreach (var g in list.Where(b => b.Format != "invalid").GroupBy(b => b.Rva).Select(g => g.ToList()).Where(g => g.Count > 1))
            foreach (var b in g) b.SharedWith = (b == g[0] ? g[1] : g[0]).Rid; // linear: protectors point thousands at one body
        Body? reach = null;
        foreach (var b in list.Where(b => b.Format != "invalid" && b.End > b.FileOffset).OrderBy(b => b.FileOffset))
        {
            if (reach != null && b.FileOffset < reach.End && b.Rva != reach.Rva)
            {
                b.Overlaps = reach.Rid;
                if (reach.Overlaps == 0) reach.Overlaps = b.Rid;
            }
            if (reach == null || b.End > reach.End) reach = b;
        }
        _bodies.AddOrUpdate(m, list);
        return list;
    }

    static void ParseBody(LoadedModule m, Body b, Metadata md)
    {
        var bytes = m.OriginalBytes;
        long p = b.FileOffset;
        byte h = bytes[p];
        if ((h & 3) == 2)
        {
            b.Format = "tiny"; b.HeaderSize = 1; b.MaxStack = 8; b.CodeSize = h >> 2;
        }
        else if ((h & 3) == 3 && p + 12 > bytes.Length) b.Error = "fat header runs past the end of the file";
        else if ((h & 3) == 3)
        {
            ushort fs = BitConverter.ToUInt16(bytes, (int)p);
            b.Flags = fs & 0xFFF;
            b.HeaderSize = (fs >> 12) * 4;
            b.MaxStack = BitConverter.ToUInt16(bytes, (int)p + 2);
            b.CodeSize = BitConverter.ToUInt32(bytes, (int)p + 4);
            b.LocalSigToken = BitConverter.ToUInt32(bytes, (int)p + 8);
            b.Format = b.HeaderSize >= 12 ? "fat" : "invalid";
            if (b.Format == "invalid") b.Error = $"fat header size {b.HeaderSize} (expected 12)";
        }
        else { b.Error = $"header byte 0x{h:X2} is neither tiny nor fat"; }

        long code = p + b.HeaderSize;
        if (b.Format == "invalid" || code + b.CodeSize > bytes.Length)
        {
            b.Format = "invalid"; b.IlStatus = "no_body"; b.Error ??= "code runs past the end of the file"; b.End = p + Math.Max(b.HeaderSize, 1);
            return;
        }
        b.End = code + b.CodeSize;
        CheckIl(md, bytes.AsSpan((int)code, (int)b.CodeSize), b);

        if ((b.Flags & 0x08) != 0)
        {
            long sec = (b.End + 3) & ~3L;
            b.Padding = (int)(sec - b.End);
            b.EhOffset = sec;
            bool more = true;
            while (more && sec < bytes.Length)
            {
                byte kind = bytes[sec];
                bool fat = (kind & 0x40) != 0;
                int size = fat ? (sec + 4 <= bytes.Length ? bytes[sec + 1] | bytes[sec + 2] << 8 | bytes[sec + 3] << 16 : 0) : (sec + 1 < bytes.Length ? bytes[sec + 1] : 0);
                if (size < 4 || sec + size > bytes.Length) { b.Error = "bad exception section"; break; }
                b.EhFormat ??= fat ? "fat" : "small";
                b.EhSize += size;
                if ((kind & 0x01) != 0) b.EhClauses += (size - 4) / (fat ? 24 : 12);
                sec += size;
                more = (kind & 0x80) != 0;
                if (more) sec = (sec + 3) & ~3L;
            }
            b.End = sec;
        }
    }

    // Decodes the IL like the runtime would: known opcodes, operands inside the body, tokens that name existing rows of
    // the right tables, branch targets inside the code. The first problem is recorded.
    static void CheckIl(Metadata md, ReadOnlySpan<byte> il, Body b)
    {
        var tables = md.TablesStream;
        bool Rid(uint tok, params Table[] allowed)
        {
            var t = (Table)(tok >> 24);
            if (Array.IndexOf(allowed, t) < 0) return false;
            var rows = (int)t < tables.MDTables.Length ? tables.MDTables[(int)t]?.Rows ?? 0 : 0;
            return (tok & 0xFFFFFF) is var rid && rid >= 1 && rid <= rows;
        }
        void Fail(string status, int at) { if (b.IlStatus == "ok") { b.IlStatus = status; b.IlErrorOffset = at; } }
        int i = 0;
        var targets = new List<(int at, long target)>();
        while (i < il.Length && b.IlStatus == "ok")
        {
            int at = i;
            OpCode op;
            if (il[i] == 0xFE)
            {
                if (i + 1 >= il.Length) { Fail("truncated", at); break; }
                op = OpCodes.TwoByteOpCodes[il[i + 1]];
                i += 2;
            }
            else { op = OpCodes.OneByteOpCodes[il[i]]; i += 1; }
            if (op.Code == Code.UNKNOWN1 || op.Code == Code.UNKNOWN2) { Fail("bad_opcode", at); break; }
            int size = op.OperandType switch
            {
                OperandType.InlineNone or OperandType.InlinePhi => 0,
                OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
                OperandType.InlineVar => 2,
                OperandType.InlineI8 or OperandType.InlineR => 8,
                OperandType.InlineSwitch => i + 4 <= il.Length ? 4 + 4 * (int)Math.Min(BitConverter.ToUInt32(il.Slice(i, 4)), int.MaxValue / 8) : int.MaxValue,
                _ => 4,
            };
            if (size == int.MaxValue || i + size > il.Length) { Fail("truncated", at); break; }
            var operand = il.Slice(i, size);
            switch (op.OperandType)
            {
                case OperandType.ShortInlineBrTarget: targets.Add((at, i + 1 + (sbyte)operand[0])); break;
                case OperandType.InlineBrTarget: targets.Add((at, i + 4 + BitConverter.ToInt32(operand))); break;
                case OperandType.InlineSwitch:
                    int n = (size - 4) / 4;
                    for (int k = 0; k < n; k++) targets.Add((at, i + size + BitConverter.ToInt32(operand.Slice(4 + 4 * k, 4))));
                    break;
                case OperandType.InlineString:
                    uint st = BitConverter.ToUInt32(operand);
                    if (st >> 24 != 0x70 || (st & 0xFFFFFF) >= (md.USStream?.StreamLength ?? 0)) Fail("bad_token", at);
                    else b.UserStrings.Add(st & 0xFFFFFF);
                    break;
                case OperandType.InlineMethod:
                    if (!Rid(BitConverter.ToUInt32(operand), Table.Method, Table.MemberRef, Table.MethodSpec)) Fail("bad_token", at); break;
                case OperandType.InlineField:
                    if (!Rid(BitConverter.ToUInt32(operand), Table.Field, Table.MemberRef)) Fail("bad_token", at); break;
                case OperandType.InlineType:
                    if (!Rid(BitConverter.ToUInt32(operand), Table.TypeDef, Table.TypeRef, Table.TypeSpec)) Fail("bad_token", at); break;
                case OperandType.InlineTok:
                    if (!Rid(BitConverter.ToUInt32(operand), Table.TypeDef, Table.TypeRef, Table.TypeSpec, Table.Method, Table.Field, Table.MemberRef, Table.MethodSpec)) Fail("bad_token", at); break;
                case OperandType.InlineSig:
                    if (!Rid(BitConverter.ToUInt32(operand), Table.StandAloneSig)) Fail("bad_token", at); break;
            }
            i += size;
        }
        foreach (var (at, target) in targets)
            if (target < 0 || target >= il.Length) { Fail("bad_branch", at); break; }
    }

    // ---- heaps -------------------------------------------------------------------------------------------------------

    static IEnumerable<HeapEntry> Heaps(LoadedModule m, string? which)
    {
        var md = m.FileMetadata;
        bool Want(string h) => which == null || string.Equals(which, h, StringComparison.OrdinalIgnoreCase);
        var refs = Want("#Strings") || Want("#Blob") || Want("#GUID") ? _refs.GetValue(m, _ => ColumnRefs(md)) : null;
        if (Want("#Strings") && md.StringsStream is { StreamLength: > 0 } ss) foreach (var e in Strings(m, ss, refs!.Strings)) yield return e;
        if (Want("#US") && md.USStream is { StreamLength: > 0 } us)
        {
            var used = Bodies(m).SelectMany(b => b.UserStrings).ToHashSet();
            foreach (var e in Prefixed(m, us, "#US", used)) yield return e;
        }
        if (Want("#Blob") && md.BlobStream is { StreamLength: > 0 } bs) foreach (var e in Prefixed(m, bs, "#Blob", refs!.Blobs)) yield return e;
        if (Want("#GUID") && md.GuidStream is { StreamLength: > 0 } gs)
        {
            var data = Bytes(m, gs);
            for (int i = 0; i + 16 <= data.Length; i += 16)
                yield return new HeapEntry(m, "#GUID", i, (long)gs.StartOffset + i, 16, new Guid(data.AsSpan(i, 16)).ToString(), data[i..(i + 16)],
                    refs!.Guids.Contains((uint)(i / 16 + 1)), "entry");
            if (data.Length % 16 != 0)
                yield return Slack(m, gs, "#GUID", data.Length / 16 * 16, data);
        }
    }

    static byte[] Bytes(LoadedModule m, DotNetStream s)
    {
        long start = (long)s.StartOffset, len = s.StreamLength;
        var bytes = m.OriginalBytes;
        if (start < 0 || start >= bytes.Length) return [];
        return bytes.AsSpan((int)start, (int)Math.Min(len, bytes.Length - start)).ToArray();
    }

    static HeapEntry Slack(LoadedModule m, DotNetStream s, string heap, int at, byte[] data) =>
        new(m, heap, at, (long)s.StartOffset + at, data.Length - at, Preview(data.AsSpan(at)), data[at..], null, "slack");

    static string Preview(ReadOnlySpan<byte> d) => Convert.ToHexString(d[..Math.Min(d.Length, 32)]).ToLowerInvariant() + (d.Length > 32 ? "…" : "");

    static IEnumerable<HeapEntry> Strings(LoadedModule m, DotNetStream s, List<uint> refs)
    {
        var data = Bytes(m, s);
        int i = 0;
        while (i < data.Length)
        {
            int end = Array.IndexOf(data, (byte)0, i);
            if (end < 0) { yield return Slack(m, s, "#Strings", i, data); yield break; }
            // a metadata string may point into the middle of an entry (suffix sharing)
            int k = refs.BinarySearch((uint)i);
            if (k < 0) k = ~k;
            bool referenced = k < refs.Count && refs[k] <= (uint)end && (refs[k] < end || i == end);
            yield return new HeapEntry(m, "#Strings", i, (long)s.StartOffset + i, end - i + 1, Encoding.UTF8.GetString(data, i, end - i), data[i..(end + 1)], referenced || i == 0, "entry");
            i = end + 1;
        }
    }

    // #US and #Blob: compressed length + bytes (II.24.2.4).
    static IEnumerable<HeapEntry> Prefixed(LoadedModule m, DotNetStream s, string heap, HashSet<uint> used)
    {
        var data = Bytes(m, s);
        int i = 0;
        while (i < data.Length)
        {
            int at = i;
            if (!ReadCompressed(data, ref i, out uint len) || i + len > data.Length) { yield return Slack(m, s, heap, at, data); yield break; }
            var body = data.AsSpan(i, (int)len);
            string? value = heap == "#US"
                ? Encoding.Unicode.GetString(body[..(int)(len & ~1u)])
                : len == 0 ? "" : Preview(body);
            i += (int)len;
            yield return new HeapEntry(m, heap, at, (long)s.StartOffset + at, i - at, value, data[at..i], used.Contains((uint)at) || at == 0, "entry");
        }
    }

    static bool ReadCompressed(byte[] d, ref int i, out uint v)
    {
        v = 0;
        if (i >= d.Length) return false;
        byte b = d[i];
        if ((b & 0x80) == 0) { v = b; i += 1; return true; }
        if ((b & 0xC0) == 0x80) { if (i + 2 > d.Length) return false; v = (uint)((b & 0x3F) << 8 | d[i + 1]); i += 2; return true; }
        if ((b & 0xE0) == 0xC0) { if (i + 4 > d.Length) return false; v = (uint)((b & 0x1F) << 24 | d[i + 1] << 16 | d[i + 2] << 8 | d[i + 3]); i += 4; return true; }
        return false;
    }

    // Every #Strings / #Blob / #GUID value any metadata table cell holds.
    static Refs ColumnRefs(Metadata md)
    {
        var strings = new List<uint>();
        var blobs = new HashSet<uint>();
        var guids = new HashSet<uint>();
        var ts = md.TablesStream;
        foreach (var t in ts.MDTables)
        {
            if (t == null || t.IsEmpty) continue;
            var cols = t.Columns.Where(c => c.ColumnSize is ColumnSize.Strings or ColumnSize.Blob or ColumnSize.GUID).ToList();
            if (cols.Count == 0) continue;
            for (uint rid = 1; rid <= t.Rows; rid++)
                foreach (var c in cols)
                    if (ts.TryReadColumn(t, rid, c, out var v))
                        switch (c.ColumnSize)
                        {
                            case ColumnSize.Strings: strings.Add(v); break;
                            case ColumnSize.Blob: blobs.Add(v); break;
                            default: guids.Add(v); break;
                        }
        }
        strings.Sort(); // Strings() binary-searches it
        return new Refs(strings, blobs, guids);
    }

    // ---- file map ----------------------------------------------------------------------------------------------------

    static List<Region> Map(LoadedModule m) => _maps.GetValue(m, BuildMap);

    static List<Region> BuildMap(LoadedModule m)
    {
        var bytes = m.OriginalBytes;
        var md = m.FileMetadata;
        var pe = md.PEImage;
        var regions = new List<Region>();
        void Add(long off, long size, string kind, string path, long? handle = null)
        {
            if (off < 0 || size <= 0 || off >= bytes.Length) return;
            regions.Add(new Region(m, off, Math.Min(size, bytes.Length - off), kind, path, handle));
        }
        long Off(RVA rva) { try { return rva == 0 ? -1 : (long)pe.ToFileOffset(rva); } catch (Exception) { return -1; } }

        var dos = pe.ImageDosHeader;
        Add((long)dos.StartOffset, dos.EndOffset - dos.StartOffset, "header", "DOS header");
        var nt = pe.ImageNTHeaders;
        Add((long)dos.EndOffset, (long)nt.StartOffset - (long)dos.EndOffset, "header", "DOS stub");
        Add((long)nt.StartOffset, nt.EndOffset - nt.StartOffset, "header", "PE headers");
        var secs = pe.ImageSectionHeaders;
        if (secs.Count > 0) Add((long)secs[0].StartOffset, (long)secs[^1].EndOffset - (long)secs[0].StartOffset, "header", "Section table");
        foreach (var h in secs) Add(h.PointerToRawData, h.SizeOfRawData, "section", $"Section {h.DisplayName}");

        string[] dirNames = ["Export", "Import", "Win32 resources", "Exception", "Certificate", "Relocations", "Debug", "Architecture",
                             "Global pointer", "TLS", "Load config", "Bound import", "IAT", "Delay import", "CLR header", "Reserved"];
        var dirs = nt.OptionalHeader.DataDirectories;
        for (int i = 0; i < dirs.Length && i < dirNames.Length; i++)
        {
            var d = dirs[i];
            if (d.VirtualAddress == 0 || d.Size == 0 || i == 14) continue;
            // the certificate directory holds a file offset, not an RVA
            Add(i == 4 ? (long)(uint)d.VirtualAddress : Off(d.VirtualAddress), d.Size, "directory", dirNames[i]);
        }
        // the native entry stub (jmp [_CorExeMain]) of x86 images
        var ep = nt.OptionalHeader.AddressOfEntryPoint;
        if (ep != 0 && Off(ep) is var epo and >= 2 && epo + 6 <= bytes.Length && bytes[epo] == 0xFF && bytes[epo + 1] == 0x25)
            Add(epo - 2, 8, "header", "Entry stub (jmp [_CorExeMain])");

        var cor = md.ImageCor20Header;
        Add((long)cor.StartOffset, cor.EndOffset - cor.StartOffset, "clr", "CLR header");
        if (cor.StrongNameSignature.Size > 0) Add(Off(cor.StrongNameSignature.VirtualAddress), cor.StrongNameSignature.Size, "clr", "Strong name signature");
        if (cor.VTableFixups.Size > 0) Add(Off(cor.VTableFixups.VirtualAddress), cor.VTableFixups.Size, "clr", "VTable fixups");
        if (cor.ManagedNativeHeader.Size > 0) Add(Off(cor.ManagedNativeHeader.VirtualAddress), cor.ManagedNativeHeader.Size, "clr", "Managed native header (ReadyToRun)");
        var mh = md.MetadataHeader;
        Add((long)mh.StartOffset, mh.EndOffset - mh.StartOffset, "metadata", "Metadata root and stream headers");
        foreach (var st in md.AllStreams)
            Add((long)st.StartOffset, st.StreamLength, "stream", $"Stream {st.Name}");
        foreach (var t in md.TablesStream.MDTables)
            if (t is { IsEmpty: false }) Add((long)t.StartOffset, t.EndOffset - t.StartOffset, "table", $"Table {t.Table}");

        // managed resources: 4-byte length + data each
        if (cor.Resources.Size > 0 && Off(cor.Resources.VirtualAddress) is var rbase and >= 0)
            for (uint rid = 1; rid <= md.TablesStream.ManifestResourceTable.Rows; rid++)
                if (md.TablesStream.TryReadManifestResourceRow(rid, out var rr) && rr.Implementation == 0 && rbase + rr.Offset + 4 <= bytes.Length)
                {
                    long at = rbase + rr.Offset;
                    // the row's own name: dnlib resolves no ManifestResource tokens, and the model's list may be edited
                    var name = md.StringsStream.ReadNoNull(rr.Name).String;
                    Add(at, 4L + BitConverter.ToUInt32(bytes, (int)at), "resource", $"Resource {name}", m.H(0x28000000 | rid));
                }

        foreach (var b in Bodies(m).Where(b => b.FileOffset >= 0 && b.End > b.FileOffset))
            Add(b.FileOffset, b.End - b.FileOffset, "method_body", $"Method body 0x{0x06000000 | b.Rid:X8}", m.H(0x06000000 | b.Rid));

        for (uint rid = 1; rid <= md.TablesStream.FieldRVATable.Rows; rid++)
            if (md.TablesStream.TryReadFieldRVARow(rid, out var fr) && fr.RVA != 0 && m.Module.ResolveToken(0x04000000 | fr.Field) is FieldDef f)
            {
                uint size = f.GetFieldSize(out var sz) ? sz : 0;
                // the name as the file has it (the map is cached, and the model may be renamed since)
                var name = md.TablesStream.TryReadFieldRow(fr.Field, out var row) ? md.StringsStream.ReadNoNull(row.Name).String : f.Name.String;
                Add(Off((RVA)fr.RVA), Math.Max(size, 1u), "field_data", $"Field data 0x{0x04000000 | fr.Field:X8} {name}", m.H(f));
            }

        if (m.Overlay is { Size: > 0 } ov) Add(ov.Offset, ov.Size, "overlay", $"Overlay ({ov.Kind})");

        // gaps: bytes no structure other than a section covers
        var covered = regions.Where(r => r.Kind != "section").OrderBy(r => r.Offset).ToList();
        long pos = 0;
        var gaps = new List<Region>();
        foreach (var r in covered)
        {
            if (r.Offset > pos) gaps.Add(new Region(m, pos, r.Offset - pos, "gap", GapPath(pe, pos), null));
            pos = Math.Max(pos, r.Offset + r.Size);
        }
        if (pos < bytes.Length) gaps.Add(new Region(m, pos, bytes.Length - pos, "gap", GapPath(pe, pos), null));
        return regions.Concat(gaps).OrderBy(r => r.Offset).ThenByDescending(r => r.Size).ToList();
    }

    static string GapPath(IPEImage pe, long off) =>
        pe.ImageSectionHeaders.FirstOrDefault(h => off >= h.PointerToRawData && off < (long)h.PointerToRawData + h.SizeOfRawData) is { } h
            ? $"Gap in {h.DisplayName}" : "Gap";
}
