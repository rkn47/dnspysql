// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Buffers.Binary;
using DnSpySql.Sql;
using dnlib.DotNet.MD;
using dnlib.PE;
using dnlib.W32Resources;
using static DnSpySql.Tables.TableKit;
using MdColumn = dnlib.DotNet.MD.ColumnInfo;

namespace DnSpySql.Tables;

public sealed record PeField(LoadedModule M, string Structure, string Field, long Offset, int Size, string? Note = null);

/// <summary>PE / CLI headers, sections, metadata streams/tables/rows and raw file bytes (dnSpy's hex + PE tree).</summary>
public static class PeTables
{
    public static void Register(Session s)
    {
        var ws = s.Ws;
        var db = s.Db;

        var fields = new Table<PeField>("pe_fields",
            "Every field of the DOS, file, optional, COR20 and metadata headers with its file offset. UPDATE value patches the raw file (save_raw)") { Domain = "pe" };
        fields.Source(c => ws.Modules(c).SelectMany(m => HeaderFields(m)).Where(f => c.Text("structure") is not string st || f.Structure == st))
            .Int("module", f => f.M.Id, pushdown: Pushdown.Eq)
            .Text("structure", f => f.Structure, pushdown: Pushdown.Eq, doc: "dos_header | file_header | optional_header | data_directory | section_header | cor20_header | metadata_header | stream_header | tables_header")
            .Text("field", f => f.Field)
            .Int("offset", f => f.Offset)
            .Int("size", f => f.Size)
            .Col("value", SqlType.Any, f => ReadField(ws, f), (f, v) => WriteField(s, f, v))
            .Text("hex", f => ReadField(ws, f) is long l ? $"0x{l:X}" : null)
            .Text("note", f => f.Note);
        fields.JournalUpdates = false;
        db.Register(fields);

        db.Register(new Table<Row<(int idx, ImageSectionHeader h)>>("pe_sections", "PE section headers") { Domain = "pe" }
            .Source(c => ws.Modules(c).SelectMany(m => m.FileMetadata.PEImage.ImageSectionHeaders.Select((h, i) => new Row<(int, ImageSectionHeader)>(m, (i, h)))))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Int("idx", r => r.Item.idx)
            .Text("name", r => r.Item.h.DisplayName)
            .Int("virtual_address", r => (long)r.Item.h.VirtualAddress)
            .Int("virtual_size", r => (long)r.Item.h.VirtualSize)
            .Int("raw_ptr", r => (long)r.Item.h.PointerToRawData)
            .Int("raw_size", r => (long)r.Item.h.SizeOfRawData)
            .Int("characteristics", r => (long)r.Item.h.Characteristics)
            .Text("characteristics_text", r => SectionFlags(r.Item.h.Characteristics))
            .Text("perm", r => ((r.Item.h.Characteristics & 0x40000000) != 0 ? "r" : "-") + ((r.Item.h.Characteristics & 0x80000000) != 0 ? "w" : "-") + ((r.Item.h.Characteristics & 0x20000000) != 0 ? "x" : "-"))
            .Text("entropy", r => Entropy(r.M, r.Item.h).ToString("F3")));

        string[] dirNames = { "export", "import", "resource", "exception", "security", "basereloc", "debug", "architecture", "globalptr", "tls",
            "load_config", "bound_import", "iat", "delay_import", "clr_runtime_header", "reserved" };
        db.Register(new Table<Row<(int idx, ImageDataDirectory d)>>("pe_data_directories", "The 16 optional-header data directories") { Domain = "pe" }
            .Source(c => ws.Modules(c).SelectMany(m => m.FileMetadata.PEImage.ImageNTHeaders.OptionalHeader.DataDirectories.Select((d, i) => new Row<(int, ImageDataDirectory)>(m, (i, d)))))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Int("idx", r => r.Item.idx)
            .Text("name", r => r.Item.idx < dirNames.Length ? dirNames[r.Item.idx] : $"dir{r.Item.idx}")
            .Int("rva", r => (long)(uint)r.Item.d.VirtualAddress)
            .Int("size", r => (long)r.Item.d.Size)
            .Int("file_offset", r => r.Item.d.VirtualAddress == 0 ? null : (long)r.M.FileMetadata.PEImage.ToFileOffset(r.Item.d.VirtualAddress)));

        db.Register(new Table<Row<(int idx, StreamHeader h)>>("md_streams", "Metadata stream headers (#~, #Strings, #US, #GUID, #Blob, #Pdb ...)") { Domain = "pe" }
            .Source(c => ws.Modules(c).SelectMany(m => m.FileMetadata.MetadataHeader.StreamHeaders.Select((h, i) => new Row<(int, StreamHeader)>(m, (i, h)))))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Int("idx", r => r.Item.idx)
            .Text("name", r => r.Item.h.Name)
            .Int("offset", r => (long)r.Item.h.Offset, doc: "relative to the metadata root")
            .Int("size", r => (long)r.Item.h.StreamSize)
            .Int("file_offset", r => (long)r.M.FileMetadata.MetadataHeader.StartOffset + r.Item.h.Offset));

        db.Register(new Table<Row<MDTable>>("md_tables", "Metadata tables present in #~ with row counts, row sizes and file offsets") { Domain = "pe" }
            .Source(c => ws.Modules(c).SelectMany(m => m.FileMetadata.TablesStream.MDTables.Where(t => t.Rows > 0).Select(t => new Row<MDTable>(m, t))))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Int("table_id", r => (long)r.Item.Table)
            .Text("name", r => r.Item.Table.ToString())
            .Int("rows", r => (long)r.Item.Rows)
            .Int("row_size", r => (long)r.Item.RowSize)
            .Int("file_offset", r => (long)r.Item.StartOffset)
            .Int("column_count", r => r.Item.Columns.Count)
            .Bool("is_sorted", r => (r.M.FileMetadata.TablesStream.SortedMask & (1UL << (int)r.Item.Table)) != 0));

        var cells = new Table<MdCell>("md_rows",
            "Raw metadata table cells (dnSpy metadata table view). Requires WHERE table_name = '...'. UPDATE value patches the raw file") { Domain = "pe" };
        cells.Source(c => MdCells(s, c))
            .Int("module", x => x.M.Id, pushdown: Pushdown.Eq)
            .Text("table_name", x => x.Table.Table.ToString(), pushdown: Pushdown.Eq, required: true)
            .Int("rid", x => (long)x.Rid, pushdown: Pushdown.Eq)
            .Int("token", x => ((long)x.Table.Table << 24) | x.Rid)
            .Text("column", x => x.Col.Name)
            .Int("column_idx", x => x.Col.Index)
            .Int("offset", x => x.Offset)
            .Int("size", x => x.Col.Size)
            .Int("value", x => ReadUInt(ws, x.M, x.Offset, x.Col.Size), (x, v) => PatchUInt(s, x.M, x.Offset, x.Col.Size, Lng(v, "value")))
            .Text("decoded", x => Decode(x));
        cells.JournalUpdates = false;
        db.Register(cells);

        // ================= raw file bytes =================
        var bytes = new Table<(LoadedModule m, long off)>("file_bytes",
            "Raw file bytes (current image incl. patches). Filter offset ranges; UPDATE value patches (hex editor, saved with save_raw)") { Domain = "pe" };
        bytes.Source(c => ws.Modules(c).SelectMany(m =>
            {
                var (lo, hi) = c.LongRange("offset", 0, m.DiskBytes.Length - 1);
                if (c.Long("rva") is long rva) { var o = RvaToOffset(m, rva); lo = hi = o ?? -1; }
                lo = Math.Max(0, lo); hi = Math.Min(m.DiskBytes.Length - 1, hi);
                return Range(lo, hi).Select(o => (m, o));
            }))
            .Int("module", r => r.m.Id, pushdown: Pushdown.Eq)
            .Int("offset", r => r.off, pushdown: Pushdown.Range)
            .Int("rva", r => OffsetToRva(r.m, r.off), pushdown: Pushdown.Eq)
            .Int("value", r => ws.RawByte(r.m, r.off), (r, v) => PatchBytes(s, r.m, r.off, new[] { (byte)Lng(v, "value") }))
            .Text("hex", r => ws.RawByte(r.m, r.off).ToString("x2"))
            .Text("ascii", r => ws.RawByte(r.m, r.off) is var b && b >= 0x20 && b < 0x7f ? ((char)b).ToString() : ".")
            .Bool("is_patched", r => r.m.RawPatches.ContainsKey(r.off))
            .Text("section", r => SectionOf(r.m, r.off));
        bytes.JournalUpdates = false;
        bytes.Estimate(1_000_000);
        db.Register(bytes);

        db.Register(new Table<(LoadedModule m, long off, int len)>("byte_search",
                "Byte pattern search over module files: WHERE pattern = '4D 5A ?? 00' [AND module = ..]. ?? / ? nibbles are wildcards") { Domain = "pe" }
            .Source(c =>
            {
                var pat = c.Text("pattern") ?? throw new SqlException("byte_search needs WHERE pattern = '...'");
                var (bytesPat, mask) = ParsePattern(pat);
                var max = c.Long("max_results") ?? 10_000;
                return ws.Modules(c).SelectMany(m => Search(ws, m, bytesPat, mask).Select(o => (m, o, bytesPat.Length))).Take((int)max);
            })
            .Arg("pattern", SqlType.Text, _ => null)
            .Arg("max_results", SqlType.Integer, _ => null, required: false)
            .Int("module", r => r.m.Id, pushdown: Pushdown.Eq)
            .Int("offset", r => r.off)
            .Int("rva", r => OffsetToRva(r.m, r.off))
            .Text("section", r => SectionOf(r.m, r.off))
            .Text("matched_hex", r => string.Join(" ", Range(r.off, r.off + r.len - 1).Select(o => ws.RawByte(r.m, o).ToString("x2")))));

        db.Register(new Table<Row<(int idx, ImageDebugDirectory d)>>("debug_directories", "Debug directory entries (CodeView/PDB path, embedded PDB, checksum, deterministic)") { Domain = "pe" }
            .Source(c => ws.Modules(c).SelectMany(m => m.FileMetadata.PEImage.ImageDebugDirectories.Select((d, i) => new Row<(int, ImageDebugDirectory)>(m, (i, d)))))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Int("idx", r => r.Item.idx)
            .Text("type", r => r.Item.d.Type.ToString())
            .Int("timestamp", r => (long)r.Item.d.TimeDateStamp)
            .Int("major_version", r => r.Item.d.MajorVersion)
            .Int("minor_version", r => r.Item.d.MinorVersion)
            .Int("size", r => (long)r.Item.d.SizeOfData)
            .Int("rva", r => (long)(uint)r.Item.d.AddressOfRawData)
            .Int("file_offset", r => (long)(uint)r.Item.d.PointerToRawData)
            .Text("pdb_guid", r => CodeView(r.M, r.Item.d)?.guid)
            .Int("pdb_age", r => CodeView(r.M, r.Item.d)?.age)
            .Text("pdb_path", r => CodeView(r.M, r.Item.d)?.path));

        db.Register(new Table<Row<(string type, string name, string lang, byte[] data)>>("win32_resources", "Native Win32 resources (version info, manifest, icons ...)") { Domain = "pe" }
            .Source(c => ws.Modules(c).SelectMany(m => Win32Res(m).Select(x => new Row<(string, string, string, byte[])>(m, x))))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Text("type", r => r.Item.type)
            .Text("name", r => r.Item.name)
            .Text("language", r => r.Item.lang)
            .Int("size", r => r.Item.data.Length)
            .Blob("data", r => r.Item.data)
            .Text("text", r => r.Item.type is "MANIFEST" or "24" ? System.Text.Encoding.UTF8.GetString(r.Item.data) : r.Item.type is "VERSION" or "16" ? VersionText(r.Item.data) : null));
    }

    static IEnumerable<long> Range(long lo, long hi) { for (long i = lo; i <= hi; i++) yield return i; }

    // ---------------- header field layouts ----------------
    static IEnumerable<PeField> HeaderFields(LoadedModule m)
    {
        var raw = m.DiskBytes;
        var list = new List<PeField>();
        void F(string st, string name, long off, int size, string? note = null) { if (off >= 0 && off + size <= raw.Length) list.Add(new PeField(m, st, name, off, size, note)); }
        // DOS header
        var dos = new (string, int)[] { ("e_magic", 2), ("e_cblp", 2), ("e_cp", 2), ("e_crlc", 2), ("e_cparhdr", 2), ("e_minalloc", 2), ("e_maxalloc", 2), ("e_ss", 2),
            ("e_sp", 2), ("e_csum", 2), ("e_ip", 2), ("e_cs", 2), ("e_lfarlc", 2), ("e_ovno", 2), ("e_res", 8), ("e_oemid", 2), ("e_oeminfo", 2), ("e_res2", 20), ("e_lfanew", 4) };
        long o = 0;
        foreach (var (n, sz) in dos) { F("dos_header", n, o, sz); o += sz; }
        long nt = BinaryPrimitives.ReadInt32LittleEndian(raw.AsSpan(0x3c));
        F("nt_headers", "Signature", nt, 4);
        long fh = nt + 4;
        var file = new (string, int)[] { ("Machine", 2), ("NumberOfSections", 2), ("TimeDateStamp", 4), ("PointerToSymbolTable", 4), ("NumberOfSymbols", 4), ("SizeOfOptionalHeader", 2), ("Characteristics", 2) };
        o = fh;
        foreach (var (n, sz) in file) { F("file_header", n, o, sz); o += sz; }
        long oh = fh + 20;
        bool pe64 = BinaryPrimitives.ReadUInt16LittleEndian(raw.AsSpan((int)oh)) == 0x20b;
        var opt = new List<(string, int)> { ("Magic", 2), ("MajorLinkerVersion", 1), ("MinorLinkerVersion", 1), ("SizeOfCode", 4), ("SizeOfInitializedData", 4),
            ("SizeOfUninitializedData", 4), ("AddressOfEntryPoint", 4), ("BaseOfCode", 4) };
        if (!pe64) opt.Add(("BaseOfData", 4));
        opt.Add(("ImageBase", pe64 ? 8 : 4));
        opt.AddRange(new[] { ("SectionAlignment", 4), ("FileAlignment", 4), ("MajorOperatingSystemVersion", 2), ("MinorOperatingSystemVersion", 2),
            ("MajorImageVersion", 2), ("MinorImageVersion", 2), ("MajorSubsystemVersion", 2), ("MinorSubsystemVersion", 2), ("Win32VersionValue", 4),
            ("SizeOfImage", 4), ("SizeOfHeaders", 4), ("CheckSum", 4), ("Subsystem", 2), ("DllCharacteristics", 2) });
        int p = pe64 ? 8 : 4;
        opt.AddRange(new[] { ("SizeOfStackReserve", p), ("SizeOfStackCommit", p), ("SizeOfHeapReserve", p), ("SizeOfHeapCommit", p), ("LoaderFlags", 4), ("NumberOfRvaAndSizes", 4) });
        o = oh;
        foreach (var (n, sz) in opt) { F("optional_header", n, o, sz); o += sz; }
        string[] dn = { "Export", "Import", "Resource", "Exception", "Security", "BaseReloc", "Debug", "Architecture", "GlobalPtr", "TLS", "LoadConfig", "BoundImport", "IAT", "DelayImport", "CLRRuntimeHeader", "Reserved" };
        for (int i = 0; i < 16; i++) { F("data_directory", dn[i] + ".VirtualAddress", o, 4); F("data_directory", dn[i] + ".Size", o + 4, 4); o += 8; }
        long sh = oh + BinaryPrimitives.ReadUInt16LittleEndian(raw.AsSpan((int)fh + 16));
        int nsec = BinaryPrimitives.ReadUInt16LittleEndian(raw.AsSpan((int)fh + 2));
        for (int i = 0; i < nsec; i++)
        {
            long b = sh + i * 40;
            var sname = System.Text.Encoding.ASCII.GetString(raw, (int)b, 8).TrimEnd('\0');
            var sec = new (string, int)[] { ("Name", 8), ("VirtualSize", 4), ("VirtualAddress", 4), ("SizeOfRawData", 4), ("PointerToRawData", 4),
                ("PointerToRelocations", 4), ("PointerToLinenumbers", 4), ("NumberOfRelocations", 2), ("NumberOfLinenumbers", 2), ("Characteristics", 4) };
            long so = b;
            foreach (var (n, sz) in sec) { F("section_header", $"{sname}.{n}", so, sz, $"section {i}"); so += sz; }
        }
        var md = m.FileMetadata;
        long cor = (long)(uint)md.ImageCor20Header.StartOffset;
        var corf = new (string, int)[] { ("cb", 4), ("MajorRuntimeVersion", 2), ("MinorRuntimeVersion", 2), ("MetaData.VirtualAddress", 4), ("MetaData.Size", 4),
            ("Flags", 4), ("EntryPointTokenOrRVA", 4), ("Resources.VirtualAddress", 4), ("Resources.Size", 4), ("StrongNameSignature.VirtualAddress", 4),
            ("StrongNameSignature.Size", 4), ("CodeManagerTable.VirtualAddress", 4), ("CodeManagerTable.Size", 4), ("VTableFixups.VirtualAddress", 4),
            ("VTableFixups.Size", 4), ("ExportAddressTableJumps.VirtualAddress", 4), ("ExportAddressTableJumps.Size", 4), ("ManagedNativeHeader.VirtualAddress", 4), ("ManagedNativeHeader.Size", 4) };
        o = cor;
        foreach (var (n, sz) in corf) { F("cor20_header", n, o, sz); o += sz; }
        long mh = (long)(uint)md.MetadataHeader.StartOffset;
        F("metadata_header", "Signature", mh, 4); F("metadata_header", "MajorVersion", mh + 4, 2); F("metadata_header", "MinorVersion", mh + 6, 2);
        F("metadata_header", "Reserved", mh + 8, 4); F("metadata_header", "VersionLength", mh + 12, 4);
        int vlen = BinaryPrimitives.ReadInt32LittleEndian(raw.AsSpan((int)mh + 12));
        F("metadata_header", "VersionString", mh + 16, vlen, md.MetadataHeader.VersionString);
        F("metadata_header", "Flags", mh + 16 + vlen, 2); F("metadata_header", "Streams", mh + 18 + vlen, 2);
        foreach (var h in md.MetadataHeader.StreamHeaders)
        {
            long hs = (long)(uint)h.StartOffset;
            F("stream_header", h.Name + ".Offset", hs, 4); F("stream_header", h.Name + ".Size", hs + 4, 4);
        }
        long ts = (long)(uint)md.TablesStream.StartOffset;
        F("tables_header", "Reserved", ts, 4); F("tables_header", "MajorVersion", ts + 4, 1); F("tables_header", "MinorVersion", ts + 5, 1);
        F("tables_header", "HeapSizes", ts + 6, 1); F("tables_header", "Reserved2", ts + 7, 1); F("tables_header", "Valid", ts + 8, 8); F("tables_header", "Sorted", ts + 16, 8);
        return list;
    }

    static object? ReadField(Workspace ws, PeField f)
    {
        if (f.Size is 1 or 2 or 4 or 8) return ReadUInt(ws, f.M, f.Offset, f.Size);
        var b = new byte[f.Size];
        for (int i = 0; i < f.Size; i++) b[i] = ws.RawByte(f.M, f.Offset + i);
        return f.Field.EndsWith("Name") || f.Field == "VersionString" ? System.Text.Encoding.ASCII.GetString(b).TrimEnd('\0') : b;
    }

    static void WriteField(Session s, PeField f, object? v)
    {
        if (f.Size is 1 or 2 or 4 or 8) { PatchUInt(s, f.M, f.Offset, f.Size, Lng(v, f.Field)); return; }
        var data = v is string str ? System.Text.Encoding.ASCII.GetBytes(str) : Values.ToBytes(v) ?? Array.Empty<byte>();
        var buf = new byte[f.Size];
        Array.Copy(data, buf, Math.Min(data.Length, f.Size));
        PatchBytes(s, f.M, f.Offset, buf);
    }

    public static long ReadUInt(Workspace ws, LoadedModule m, long off, int size)
    {
        ulong v = 0;
        for (int i = 0; i < size; i++) v |= (ulong)(m.RawPatches.TryGetValue(off + i, out var b) ? b : m.DiskBytes[off + i]) << (8 * i);
        return unchecked((long)v);
    }

    static void PatchUInt(Session s, LoadedModule m, long off, int size, long value)
    {
        var b = new byte[size];
        for (int i = 0; i < size; i++) b[i] = (byte)(value >> (8 * i));
        PatchBytes(s, m, off, b);
    }

    /// <summary>Raw patch with undo (hex editor). The dnlib model is not changed; save with save_raw().</summary>
    public static void PatchBytes(Session s, LoadedModule m, long off, byte[] data)
    {
        if (off < 0 || off + data.Length > m.DiskBytes.Length) throw new SqlException($"patch at 0x{off:X} (+{data.Length}) is outside the file (size 0x{m.DiskBytes.Length:X})");
        var before = new Dictionary<long, byte?>();
        for (int i = 0; i < data.Length; i++) before[off + i] = m.RawPatches.TryGetValue(off + i, out var b) ? b : null;
        void Apply() { for (int i = 0; i < data.Length; i++) { if (m.DiskBytes[off + i] == data[i]) m.RawPatches.Remove(off + i); else m.RawPatches[off + i] = data[i]; } m.Revision++; }
        void Revert() { foreach (var (k, b) in before) { if (b is byte x) m.RawPatches[k] = x; else m.RawPatches.Remove(k); } m.Revision++; }
        Apply();
        s.Ws.NoteEdit(m);
        s.Ws.Record("file_bytes", $"patch {data.Length} byte(s) at 0x{off:X}", Revert, Apply);
    }

    /// <summary>
    /// The RVA of a method's body in the file, from the method's row: the model's own RVA describes a serialized image
    /// after a whole-module edit is undone or redone (see LoadedModule.FileMetadata). 0 for a method the file lacks.
    /// </summary>
    public static uint FileRva(LoadedModule m, dnlib.DotNet.MethodDef md) =>
        md.Rid != 0 && m.FileMetadata.TablesStream.TryReadMethodRow(md.Rid, out var row) ? row.RVA : 0;

    // Section bounds are summed as long: the uint sums wrap on hostile headers.
    public static long? RvaToOffset(LoadedModule m, long rva)
    {
        foreach (var h in m.FileMetadata.PEImage.ImageSectionHeaders)
            if (rva >= (uint)h.VirtualAddress && rva < (long)(uint)h.VirtualAddress + Math.Max(h.VirtualSize, h.SizeOfRawData))
                // the part of a section past its raw data (VirtualSize > SizeOfRawData) is zero-filled memory, not file bytes
                return rva - (uint)h.VirtualAddress < h.SizeOfRawData ? rva - (uint)h.VirtualAddress + h.PointerToRawData : null;
        var hdr = m.FileMetadata.PEImage.ImageNTHeaders.OptionalHeader.SizeOfHeaders;
        return rva < hdr ? rva : null;
    }

    public static long? OffsetToRva(LoadedModule m, long off)
    {
        foreach (var h in m.FileMetadata.PEImage.ImageSectionHeaders)
            if (off >= h.PointerToRawData && off < (long)h.PointerToRawData + h.SizeOfRawData)
                return off - h.PointerToRawData + (uint)h.VirtualAddress;
        return off < m.FileMetadata.PEImage.ImageNTHeaders.OptionalHeader.SizeOfHeaders ? off : null;
    }

    static string? SectionOf(LoadedModule m, long off)
    {
        foreach (var h in m.FileMetadata.PEImage.ImageSectionHeaders)
            if (off >= h.PointerToRawData && off < (long)h.PointerToRawData + h.SizeOfRawData) return h.DisplayName;
        return off < m.FileMetadata.PEImage.ImageNTHeaders.OptionalHeader.SizeOfHeaders ? "(headers)" : "(overlay)";
    }

    static string SectionFlags(uint c)
    {
        var parts = new List<string>();
        if ((c & 0x20) != 0) parts.Add("CODE");
        if ((c & 0x40) != 0) parts.Add("INITIALIZED_DATA");
        if ((c & 0x80) != 0) parts.Add("UNINITIALIZED_DATA");
        if ((c & 0x02000000) != 0) parts.Add("DISCARDABLE");
        if ((c & 0x10000000) != 0) parts.Add("SHARED");
        if ((c & 0x20000000) != 0) parts.Add("EXECUTE");
        if ((c & 0x40000000) != 0) parts.Add("READ");
        if ((c & 0x80000000) != 0) parts.Add("WRITE");
        return string.Join("|", parts);
    }

    static readonly string[] StandardStreams = { "#~", "#-", "#Strings", "#US", "#GUID", "#Blob", "#Pdb", "#JTD" };

    /// <summary>
    /// Static hints that a protector or packer touched the module: things the CLR tolerates but compilers never emit.
    /// Each entry is one human-readable finding (binary.anomalies).
    /// </summary>
    /// <summary>The bytes the section headers need and the bytes the file has: more needed than had is a truncated file.</summary>
    public static (long Needed, long Have) Truncated(LoadedModule m) =>
        (m.FileMetadata.PEImage.ImageSectionHeaders.Select(h => (long)h.PointerToRawData + h.SizeOfRawData).DefaultIfEmpty(0).Max(),
         (m.FileBytes ?? m.OriginalBytes).Length);

    public static List<string> Anomalies(LoadedModule m)
    {
        var list = new List<string>();
        if (m.Repair != null) list.Add(m.Repair);
        var md = m.Module;
        var pe = m.FileMetadata.PEImage;
        if (Truncated(m) is var (needed, have) && needed > have)
            list.Add($"file truncated: its sections need {needed:N0} bytes, the file has {have:N0} (what lies past the end is missing, not hidden)");
        foreach (var h in pe.ImageSectionHeaders)
        {
            bool exec = (h.Characteristics & 0x20000020) != 0;
            if (exec && h.SizeOfRawData == 0 && h.VirtualSize > 0)
                list.Add($"section {h.DisplayName} is executable but has no file data (filled at runtime: packed)");
            // .rsrc is skipped: icons are compressed PNGs, so it is high-entropy in ordinary GUI apps too.
            else if (h.DisplayName != ".rsrc" && h.SizeOfRawData >= 4096 && Entropy(m, h) is var e && e > 7.2)
                list.Add($"section {h.DisplayName} has high entropy ({e:F2}): mostly compressed or encrypted data (embedded payloads/resources)");
        }
        int missing = md.GetTypes().SelectMany(t => t.Methods).Count(x => FileRva(m, x) is var rva && rva != 0 && !InFile(pe, rva));
        if (missing > 0) list.Add($"{missing} method bodies are not in the file (RVA outside section raw data: decrypted/unpacked at runtime)");
        var odd = m.FileMetadata.MetadataHeader.StreamHeaders.Select(x => x.Name).Where(n => !StandardStreams.Contains(n, StringComparer.Ordinal)).ToList();
        if (odd.Count > 0) list.Add($"nonstandard metadata stream names: {string.Join(", ", odd)} (anti-decompiler trick; the CLR ignores or case-folds them)");
        var names = md.GetTypes().SelectMany(t => new[] { t.Name.String }.Concat(t.Methods.Select(x => x.Name.String)).Concat(t.Fields.Select(x => x.Name.String)));
        int hidden = names.Count(n => Output.Visible(n) != n);
        if (hidden > 0) list.Add($"{hidden} type/method/field names contain invisible, bidi or private-use characters (name obfuscation)");
        if (md.GlobalType?.Methods.Any(x => x.ImplMap?.Name.String is "VirtualProtect") == true)
            list.Add(m.Origin == "untamper" ? $"<Module> P/Invokes VirtualProtect (anti-tamper code, already applied: this is the decrypted copy of module {m.DerivedFrom})"
                : HexTables.Undecodable(m).Count == 0 ? "<Module> P/Invokes VirtualProtect (anti-tamper code, but every method body decodes as IL: nothing is encrypted in the file)"
                : "<Module> P/Invokes VirtualProtect (anti-tamper: method bodies decrypted in place at startup)");
        if (Overlay.Analyze(m.DiskBytes)?.Anomaly is string ov) list.Add(ov);
        return list;
    }

    internal static bool InFile(IPEImage pe, uint rva)
    {
        foreach (var h in pe.ImageSectionHeaders)
            if (rva >= (uint)h.VirtualAddress && rva < (long)(uint)h.VirtualAddress + Math.Max(h.VirtualSize, h.SizeOfRawData))
                return rva - (uint)h.VirtualAddress < h.SizeOfRawData;
        return false;
    }

    static double Entropy(LoadedModule m, ImageSectionHeader h)
    {
        long start = h.PointerToRawData, len = Math.Min(h.SizeOfRawData, m.DiskBytes.Length - start);
        if (len <= 0) return 0;
        var counts = new long[256];
        for (long i = 0; i < len; i++) counts[m.DiskBytes[start + i]]++;
        double e = 0;
        foreach (var c in counts) if (c > 0) { var pr = (double)c / len; e -= pr * Math.Log2(pr); }
        return e;
    }

    public static (byte[] bytes, byte[] mask) ParsePattern(string pat)
    {
        var toks = pat.Replace(",", " ").Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (toks.Length == 1 && toks[0].Length > 2 && toks[0].Length % 2 == 0)
            toks = Enumerable.Range(0, toks[0].Length / 2).Select(i => toks[0].Substring(i * 2, 2)).ToArray();
        var b = new byte[toks.Length];
        var m = new byte[toks.Length];
        for (int i = 0; i < toks.Length; i++)
        {
            var t = toks[i].Length == 1 ? "?" + toks[i] : toks[i];
            if (t.Length != 2) throw new SqlException($"bad pattern byte '{toks[i]}'");
            byte val = 0, mask = 0;
            for (int k = 0; k < 2; k++)
            {
                var ch = t[k];
                val <<= 4; mask <<= 4;
                if (ch == '?') continue;
                val |= Convert.ToByte(ch.ToString(), 16);
                mask |= 0xF;
            }
            b[i] = val; m[i] = mask;
        }
        if (b.Length == 0) throw new SqlException("empty pattern");
        return (b, m);
    }

    static IEnumerable<long> Search(Workspace ws, LoadedModule lm, byte[] pat, byte[] mask)
    {
        var data = lm.DiskBytes;
        for (long i = 0; i + pat.Length <= data.Length; i++)
        {
            bool ok = true;
            for (int k = 0; k < pat.Length && ok; k++)
            {
                var b = lm.RawPatches.Count > 0 ? ws.RawByte(lm, i + k) : data[i + k];
                ok = (b & mask[k]) == pat[k];
            }
            if (ok) yield return i;
        }
    }

    static (string guid, long age, string path)? CodeView(LoadedModule m, ImageDebugDirectory d)
    {
        if (d.Type != ImageDebugType.CodeView || d.SizeOfData < 24) return null;
        var raw = m.DiskBytes;
        long o = (long)(uint)d.PointerToRawData;
        if (o + 24 > raw.Length || BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan((int)o)) != 0x53445352) return null; // RSDS
        var guid = new Guid(raw.AsSpan((int)o + 4, 16));
        var age = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan((int)o + 20));
        // the path is NUL-terminated within the entry; an unterminated one ends with the entry, not at the next zero byte
        int start = (int)o + 24, limit = (int)Math.Min(raw.Length, o + d.SizeOfData);
        var end = Array.IndexOf(raw, (byte)0, start, limit - start);
        var path = System.Text.Encoding.UTF8.GetString(raw, start, (end < 0 ? limit : end) - start);
        return (guid.ToString(), age, path);
    }

    static readonly Dictionary<int, string> ResTypes = new()
    {
        [1] = "CURSOR", [2] = "BITMAP", [3] = "ICON", [4] = "MENU", [5] = "DIALOG", [6] = "STRING", [7] = "FONTDIR", [8] = "FONT",
        [9] = "ACCELERATOR", [10] = "RCDATA", [11] = "MESSAGETABLE", [12] = "GROUP_CURSOR", [14] = "GROUP_ICON", [16] = "VERSION", [24] = "MANIFEST",
    };

    static IEnumerable<(string, string, string, byte[])> Win32Res(LoadedModule m)
    {
        var root = m.FileMetadata.PEImage.Win32Resources?.Root;
        if (root == null) yield break;
        static string N(ResourceName n, Dictionary<int, string>? map = null) =>
            n.HasId ? (map != null && map.TryGetValue(n.Id, out var s) ? s : n.Id.ToString()) : n.Name;
        foreach (var t in root.Directories)
            foreach (var n in t.Directories)
                foreach (var l in n.Data)
                {
                    var r = l.CreateReader();
                    yield return (N(t.Name, ResTypes), N(n.Name), N(l.Name), r.ReadBytes((int)r.Length));
                }
    }

    static string VersionText(byte[] data)
    {
        // Extract printable UTF-16 key/value strings from VS_VERSIONINFO.
        var s = System.Text.Encoding.Unicode.GetString(data);
        var parts = s.Split('\0', StringSplitOptions.RemoveEmptyEntries).Where(p => p.Length > 1 && p.All(ch => ch >= 0x20 && ch < 0xFFFE)).ToList();
        var keys = new[] { "CompanyName", "FileDescription", "FileVersion", "InternalName", "LegalCopyright", "OriginalFilename", "ProductName", "ProductVersion", "Comments", "Assembly Version" };
        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < parts.Count - 1; i++)
            if (keys.Contains(parts[i])) sb.Append(parts[i]).Append('=').Append(parts[i + 1]).Append("; ");
        return sb.ToString().TrimEnd(' ', ';');
    }

    // ---------------- raw metadata cells ----------------
    public sealed record MdCell(LoadedModule M, MDTable Table, uint Rid, MdColumn Col, long Offset);

    static IEnumerable<MdCell> MdCells(Session s, Constraints c)
    {
        var name = c.Text("table_name")!;
        if (!Enum.TryParse<Table>(name, true, out var tid)) throw new SqlException($"unknown metadata table '{name}' (see md_tables.name)");
        foreach (var m in s.Ws.Modules(c))
        {
            var t = m.FileMetadata.TablesStream.Get(tid);
            if (t == null || t.Rows == 0) continue;
            uint lo = 1, hi = t.Rows;
            if (c.Long("rid") is long r) { lo = hi = (uint)r; if (r < 1 || r > t.Rows) continue; }
            for (uint rid = lo; rid <= hi; rid++)
                foreach (var col in t.Columns)
                    yield return new MdCell(m, t, rid, col, (long)t.StartOffset + (rid - 1) * t.RowSize + col.Offset);
        }
    }

    static string? Decode(MdCell x)
    {
        var md = x.M.FileMetadata;
        uint v = (uint)ReadUInt(null!, x.M, x.Offset, x.Col.Size);
        try
        {
            var ct = x.Col.ColumnSize;
            if (ct == ColumnSize.Strings) return md.StringsStream.ReadNoNull(v).String;
            if (ct == ColumnSize.GUID) return md.GuidStream.Read(v)?.ToString();
            if (ct == ColumnSize.Blob) return $"blob@0x{v:X}";
            if (ct >= ColumnSize.Module && ct <= ColumnSize.CustomDebugInformation) return $"{(Table)(ct - ColumnSize.Module)}[{v}]";
            if (ct >= ColumnSize.TypeDefOrRef && ct <= ColumnSize.HasCustomDebugInformation)
            {
                var info = CodedTokenFor(ct);
                if (info != null && info.Decode(v, out uint token)) return (token & 0x00FFFFFF) == 0 ? null : $"0x{token:X8}";
            }
        }
        catch { }
        return null;
    }

    static CodedToken? CodedTokenFor(ColumnSize cs) => cs switch
    {
        ColumnSize.TypeDefOrRef => CodedToken.TypeDefOrRef,
        ColumnSize.HasConstant => CodedToken.HasConstant,
        ColumnSize.HasCustomAttribute => CodedToken.HasCustomAttribute,
        ColumnSize.HasFieldMarshal => CodedToken.HasFieldMarshal,
        ColumnSize.HasDeclSecurity => CodedToken.HasDeclSecurity,
        ColumnSize.MemberRefParent => CodedToken.MemberRefParent,
        ColumnSize.HasSemantic => CodedToken.HasSemantic,
        ColumnSize.MethodDefOrRef => CodedToken.MethodDefOrRef,
        ColumnSize.MemberForwarded => CodedToken.MemberForwarded,
        ColumnSize.Implementation => CodedToken.Implementation,
        ColumnSize.CustomAttributeType => CodedToken.CustomAttributeType,
        ColumnSize.ResolutionScope => CodedToken.ResolutionScope,
        ColumnSize.TypeOrMethodDef => CodedToken.TypeOrMethodDef,
        ColumnSize.HasCustomDebugInformation => CodedToken.HasCustomDebugInformation,
        _ => null,
    };
}
