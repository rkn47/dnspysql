// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.IO.Compression;
using System.Text.Json;
using System.Xml.Linq;

namespace DnSpySql.Tests;

/// <summary>The tables mapped from dnSpy's views and state: decompiler references, hex structures, images, API docs, dnSpy.xml.</summary>
public sealed class DnSpyTableTests : SampleTest
{
    const string IsValid = "resolve('Sample.MemberCard::IsValid')";

    static string Hex(byte[] b) => "x'" + Convert.ToHexString(b) + "'";

    [Fact]
    public void Pseudocode_refs_link_names_to_their_definitions()
    {
        var r = Run($"select text, kind, target, target_name, is_definition from pseudocode_refs where handle = {IsValid} and kind = 'method'",
                    $"select {IsValid}", "select resolve('Sample.MemberCard::Checksum')");
        var rows = r.Rows(0);
        long isValid = r.Long(1), checksum = r.Long(2);
        Assert.Contains(rows, x => x.GetProperty("text").GetString() == "IsValid" && x.GetProperty("is_definition").GetInt64() == 1
                                   && x.GetProperty("target").GetInt64() == isValid);
        Assert.Contains(rows, x => x.GetProperty("text").GetString() == "Checksum" && x.GetProperty("target").GetInt64() == checksum);
        // an external member: no handle, but its full name
        Assert.Contains(rows, x => x.GetProperty("text").GetString() == "StartsWith" && x.GetProperty("target").ValueKind == JsonValueKind.Null
                                   && x.GetProperty("target_name").GetString()!.Contains("System.String::StartsWith"));

        var locals = Run("select distinct text, kind from pseudocode_refs where handle = resolve('Sample.MemberCard::Checksum') and kind in ('local', 'parameter')").Rows();
        Assert.Contains(locals, x => x.GetProperty("kind").GetString() == "local"); // named by the decompiler: no PDB next to the copy
        Assert.Contains(locals, x => x.GetProperty("text").GetString() == "s" && x.GetProperty("kind").GetString() == "parameter");
    }

    [Fact]
    public void Method_bodies_are_read_from_the_file()
    {
        var r = Run("select count(*) from methods where rva <> 0", "select count(*), sum(il_status = 'ok'), sum(format in ('tiny', 'fat')) from method_bodies",
                    $"select file_offset, header_size from method_bodies where method = {IsValid}",
                    "select file_offset, header_size from method_bodies where method = resolve('Sample.MemberCard::Checksum')");
        var counts = r.Values(1);
        Assert.Equal(r.Long(0), counts[0].GetInt64());
        Assert.Equal(counts[0].GetInt64(), counts[1].GetInt64());
        Assert.Equal(counts[0].GetInt64(), counts[2].GetInt64());

        // break IsValid's header and Checksum's first opcode in a copy of the file
        var bytes = File.ReadAllBytes(Sample);
        bytes[r.Values(2)[0].GetInt64()] = 0x00;
        var cs = r.Values(3);
        bytes[cs[0].GetInt64() + cs[1].GetInt64()] = 0xA6; // an unused one-byte opcode
        var broken = PathIn("Broken.dll");
        File.WriteAllBytes(broken, bytes);
        var b = Cli.Run(broken, $"select format, il_status, error from method_bodies where method = {IsValid}",
            "select format, il_status, il_error_offset from method_bodies where method = resolve('Sample.MemberCard::Checksum')").Ok();
        Assert.Equal("invalid", b.Values(0)[0].GetString());
        Assert.Equal("no_body", b.Values(0)[1].GetString());
        Assert.Equal("bad_opcode", b.Values(1)[1].GetString());
        Assert.Equal(0, b.Values(1)[2].GetInt64());

        // decompile() would show such bodies as real (empty or garbage) code: it says they do not decode, after the code
        var d = Cli.Run(broken, "select decompile(resolve('Sample.MemberCard::Checksum'))", "select decompile(resolve('Sample.MemberCard'))").Ok();
        Assert.Contains("// dnspysql: this method's body does not decode as IL in the file (bad_opcode)", d.Text(0));
        Assert.Contains("// dnspysql: 2 of ", d.Text(1));
        Assert.EndsWith("\n", d.Text(1));
    }

    [Fact]
    public void Heap_entries_know_what_references_them()
    {
        var r = Run("select referenced from heap_entries where heap = '#US' and value = 'LIB-1234'",
                    "select referenced from heap_entries where heap = '#Strings' and value = 'IsValid'",
                    "select count(*) from heap_entries where kind = 'slack'",
                    "select count(*), sum(referenced) from heap_entries where heap = '#GUID'",
                    "select count(*) from heap_entries where heap = '#US' and offset >= 1 and offset < 3");
        Assert.Equal(1, r.Long(0));
        Assert.Equal(1, r.Long(1));
        Assert.Equal(0, r.Long(2));
        Assert.Equal(1, r.Values(3)[1].GetInt64());
        Assert.Equal(1, r.Long(4)); // offset range pushdown: the entry at offset 1 only
    }

    [Fact]
    public void File_map_accounts_for_every_byte()
    {
        var r = Run("select offset, \"end\" from file_map where kind <> 'section' order by offset",
                    $"select kind, handle from file_map where contains = (select file_offset + 1 from method_bodies where method = {IsValid}) and kind = 'method_body'",
                    $"select {IsValid}",
                    "select count(*) from file_map where kind = 'field_data'");
        long pos = 0, covered = 0;
        foreach (var row in r.Rows(0))
        {
            long a = row.GetProperty("offset").GetInt64(), b = row.GetProperty("end").GetInt64();
            if (b > pos) { covered += b - Math.Max(a, pos); pos = b; }
        }
        Assert.Equal(new FileInfo(Sample).Length, covered);
        Assert.Equal(r.Long(2), r.Values(1)[1].GetInt64());
        Assert.True(r.Long(3) >= 1); // MemberCard.Nested.Table's initial data
    }

    [Fact]
    public void Method_bodies_report_every_overlap()
    {
        // Two short bodies planted inside the code of a long one: both overlap it, though only the first is its neighbour.
        const string cell = "select offset from md_rows where table_name = 'Method' and column = 'RVA' and rid = ";
        var r = Run("select method, rva, file_offset, header_size from method_bodies where code_size >= 8 order by code_size desc limit 1",
                    $"{cell}(resolve('Sample.Shapes::Total') & 0xFFFFFF)", $"{cell}(resolve('Sample.Shapes::Name') & 0xFFFFFF)",
                    "select resolve('Sample.Shapes::Total'), resolve('Sample.Shapes::Name')");
        var a = r.Values(0);
        long host = a[0].GetInt64(), rva = a[1].GetInt64(), code = a[2].GetInt64() + a[3].GetInt64();
        var bytes = File.ReadAllBytes(Sample);
        foreach (var (rvaCell, at) in new[] { (r.Long(1), 2), (r.Long(2), 6) })
        {
            bytes[code + at] = 0x06;     // tiny header, 1 byte of code
            bytes[code + at + 1] = 0x2A; // ret
            BitConverter.GetBytes((uint)(rva + a[3].GetInt64() + at)).CopyTo(bytes, rvaCell);
        }
        var planted = PathIn("Planted.dll");
        File.WriteAllBytes(planted, bytes);
        var p = Cli.Run(planted, $"select overlaps from method_bodies where method in ({r.Values(3)[0].GetInt64()}, {r.Values(3)[1].GetInt64()})").Ok();
        Assert.Equal(new[] { host, host }, p.Rows().Select(x => x.GetProperty("overlaps").GetInt64()));
    }

    [Fact]
    public void Native_method_bodies_of_a_mixed_mode_image_are_recognised()
    {
        // what a C++/CLI image looks like: methods whose code type is Native, their RVA pointing at machine code
        var r = Run("select method & 0xFFFFFF as rid, file_offset from method_bodies order by code_size desc limit 6",
                    "select rid, offset from md_rows where table_name = 'Method' and column = 'ImplFlags'");
        var flags = r.Rows(1).ToDictionary(x => x.GetProperty("rid").GetInt64(), x => x.GetProperty("offset").GetInt64());
        var bytes = File.ReadAllBytes(Sample);
        foreach (var row in r.Rows(0))
        {
            long rid = row.GetProperty("rid").GetInt64(), at = row.GetProperty("file_offset").GetInt64();
            BitConverter.GetBytes((ushort)1).CopyTo(bytes, flags[rid]); // MethodImplAttributes.Native
            for (int i = 0; i < 4; i++) bytes[at + i] = 0xCC;
        }
        var mixed = PathIn("Mixed.dll");
        File.WriteAllBytes(mixed, bytes);
        var m = Cli.Run(mixed, "select count(*), sum(il_status = 'native') from method_bodies where format = 'native'").Ok();
        Assert.Equal(6, m.Values(0)[0].GetInt64());
        Assert.Equal(6, m.Values(0)[1].GetInt64());
    }

    [Fact]
    public void File_map_names_resources_from_the_file()
    {
        var target = PathIn("SampleTarget.dll");
        File.Copy(Path.Combine(AppContext.BaseDirectory, "sample", "SampleTarget.dll"), target);
        var r = Cli.Run(target, "select path from file_map where kind = 'resource'").Ok();
        Assert.Equal(new[] { "Resource SampleTarget.Strings.resources", "Resource SampleTarget.config.json" },
            r.Rows().Select(x => x.GetProperty("path").GetString()).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Raw_views_describe_the_file_after_a_whole_module_undo()
    {
        // add_type runs on a re-serialized copy of the module and undo swaps the old one back; the raw views must keep showing the file.
        const string cell = "select offset from md_rows where table_name = 'Method' and rid = 1 and column = 'RVA'";
        const string body = "select rva || ' ' || file_offset || ' ' || hex(method_bytes(handle)) from methods where name = 'IsValid'";
        var r = Run(cell, body, "select add_type('public class Zed { public int X() { return 1; } }')", "select undo(1)", cell, body,
                    "select count(*), sum(il_status = 'ok') from method_bodies", "select count(*) from methods where rva <> 0");
        Assert.Equal(r.Long(0), r.Long(4));
        Assert.Equal(r.Text(1), r.Text(5));
        Assert.Equal(r.Long(7), r.Values(6)[0].GetInt64());
        Assert.Equal(r.Long(7), r.Values(6)[1].GetInt64());
    }

    [Fact]
    public void Analyzer_finds_calls_through_base_and_interface_slots()
    {
        var r = Run("select name, detail from analyze where target = resolve('Sample.Square::Area') and relation = 'method.virtual_used_by'",
                    "select name from analyze where target = resolve('Sample.Square::Describe') and relation = 'method.virtual_used_by'",
                    "select name from analyze where target = (select handle from events where name = 'Changed' and type = resolve('Sample.Square')) and relation = 'event.overrides'");
        // the slot each caller goes through (C# emits callvirt to the original declaration even on a sealed class)
        var area = r.Rows(0).ToDictionary(x => x.GetProperty("name").GetString()!, x => x.GetProperty("detail").GetString()!);
        Assert.Contains("via IShape::Area", area.Single(kv => kv.Key.Contains("Shapes::Total")).Value);
        Assert.Contains("via Shape::Area", area.Single(kv => kv.Key.Contains("Shapes::Direct")).Value);
        Assert.Contains(r.Rows(1), x => x.GetProperty("name").GetString()!.Contains("Shapes::Name"));
        // Square.Describe calls base.Describe() with a plain call, which cannot dispatch back to it
        Assert.DoesNotContain(r.Rows(1), x => x.GetProperty("name").GetString()!.Contains("Square::Describe"));
        Assert.Contains(r.Rows(2), x => x.GetProperty("name").GetString()!.Contains("Sample.Shape::Changed"));
    }

    // ---- images --------------------------------------------------------------------------------------------------------

    // 2x2, 24-bit, bottom-up: top row red, green; bottom row blue, white.
    static byte[] Bmp()
    {
        var px = new byte[] { 0xFF, 0, 0, 0xFF, 0xFF, 0xFF, 0, 0, /* bottom: blue, white (BGR) + pad */ 0, 0, 0xFF, 0, 0xFF, 0, 0, 0 /* top: red, green */ };
        var b = new byte[54 + px.Length];
        b[0] = (byte)'B'; b[1] = (byte)'M';
        BitConverter.GetBytes(b.Length).CopyTo(b, 2);
        BitConverter.GetBytes(54).CopyTo(b, 10);
        BitConverter.GetBytes(40).CopyTo(b, 14);
        BitConverter.GetBytes(2).CopyTo(b, 18);
        BitConverter.GetBytes(2).CopyTo(b, 22);
        BitConverter.GetBytes((short)1).CopyTo(b, 26);
        BitConverter.GetBytes((short)24).CopyTo(b, 28);
        px.CopyTo(b, 54);
        return b;
    }

    // 3x1 RGBA PNG: red, green, blue (opaque).
    static byte[] Png()
    {
        static void Chunk(Stream s, string type, byte[] data)
        {
            var len = BitConverter.GetBytes(data.Length); Array.Reverse(len); s.Write(len);
            var td = System.Text.Encoding.ASCII.GetBytes(type).Concat(data).ToArray();
            s.Write(td);
            var crc = BitConverter.GetBytes(Crc32(td)); Array.Reverse(crc); s.Write(crc);
        }
        using var ms = new MemoryStream();
        ms.Write([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        Chunk(ms, "IHDR", [0, 0, 0, 3, 0, 0, 0, 1, 8, 6, 0, 0, 0]);
        using var z = new MemoryStream();
        using (var zs = new ZLibStream(z, CompressionLevel.Optimal, true)) zs.Write([0, 0xFF, 0, 0, 0xFF, 0, 0xFF, 0, 0xFF, 0, 0, 0xFF, 0xFF]);
        Chunk(ms, "IDAT", z.ToArray());
        Chunk(ms, "IEND", []);
        return ms.ToArray();
    }

    static uint Crc32(byte[] d)
    {
        uint c = 0xFFFFFFFF;
        foreach (var b in d) { c ^= b; for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1; }
        return ~c;
    }

    // A .resources file with a serialized System.Drawing.Bitmap: an NRBF stream whose byte[] (record 15, Byte) holds the PNG.
    static byte[] SerializedBitmap(byte[] png, byte[]? before = null)
    {
        var nrbf = new List<byte> { 0, 1, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 1, 0, 0, 0, 0, 0, 0, 0 }; // header record (not parsed)
        nrbf.AddRange(before ?? []);
        nrbf.Add(15);
        nrbf.AddRange(BitConverter.GetBytes(2));
        nrbf.AddRange(BitConverter.GetBytes(png.Length));
        nrbf.Add(2);
        nrbf.AddRange(png);
        nrbf.Add(11);
        using var ms = new MemoryStream();
        using (var w = new System.Resources.ResourceWriter(ms))
        {
            w.AddResourceData("Logo", "System.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a", nrbf.ToArray());
            w.Generate();
            return ms.ToArray();
        }
    }

    [Fact]
    public void Resource_images_hand_out_the_image_bytes()
    {
        var r = Run($"select add_resource('pic.bmp', {Hex(Bmp())}), add_resource('Img.resources', {Hex(SerializedBitmap(Png()))})",
            "select resource, element, source, format, width, height from resource_images order by resource",
            "select hex(data) from resource_images where format = 'bmp'",
            "select hex(data), type_name from resource_images where source = 'serialized'");
        var rows = r.Rows(1);
        Assert.Equal(2, rows.Count);
        var ser = rows.Single(x => x.GetProperty("source").GetString() == "serialized");
        Assert.Equal(("Logo", "png", 3L, 1L), (ser.GetProperty("element").GetString(), ser.GetProperty("format").GetString(), ser.GetProperty("width").GetInt64(), ser.GetProperty("height").GetInt64()));
        var bmp = rows.Single(x => x.GetProperty("source").GetString() == "resource");
        Assert.Equal(("bmp", 2L, 2L), (bmp.GetProperty("format").GetString(), bmp.GetProperty("width").GetInt64(), bmp.GetProperty("height").GetInt64()));

        // the image files as they are: decoding them is left to the caller
        Assert.Equal(Convert.ToHexString(Bmp()), r.Text(2));
        Assert.Equal(Convert.ToHexString(Png()), r.Values(3)[0].GetString());
        Assert.StartsWith("System.Drawing.Bitmap", r.Values(3)[1].GetString());
    }

    [Fact]
    public void Malformed_images_are_reported_not_crashed_on()
    {
        var tall = Bmp();
        BitConverter.GetBytes(int.MinValue).CopyTo(tall, 22); // Math.Abs(int.MinValue) throws
        // a byte[] record whose length overflows offset + length, before the real image
        byte[] bogus = [15, 1, 0, 0, 0, 0xF8, 0xFF, 0xFF, 0x7F, 2, 0, 0];
        using var live = new Live(Sample, "--no-project");
        live.Q($"select add_resource('tall.bmp', {Hex(tall)}), add_resource('Odd.resources', {Hex(SerializedBitmap(Png(), bogus))})");
        Assert.Equal(2L, live.Long("select count(*) from resource_images"));
        Assert.Equal(int.MaxValue, live.Long("select height from resource_images where resource = 'tall.bmp'"));
    }

    [Fact]
    public void Api_docs_read_the_documentation_next_to_the_assembly()
    {
        File.WriteAllText(Path.ChangeExtension(Sample, ".xml"), """
            <?xml version="1.0"?>
            <doc><assembly><name>Sample</name></assembly><members>
              <member name="M:Sample.MemberCard.IsValid"><summary>Checks a <see cref="T:Sample.MemberCard"/> against <see href="https://example.com">the spec</see>.</summary></member>
            </members></doc>
            """);
        Assert.Equal("Checks a Sample.MemberCard against the spec.", Run($"select api_doc({IsValid})").Text());
    }

    [Fact]
    public void Documentation_next_to_a_sample_cannot_redirect_or_declare_entities()
    {
        // dnSpy follows <doc redirect="..."> to any path, a network share included. A rooted local
        // file stands in for the share here (the test never touches the network): it must not be read.
        var elsewhere = PathIn("elsewhere.xml");
        File.WriteAllText(elsewhere, """
            <?xml version="1.0"?>
            <doc><members>
              <member name="M:Sample.MemberCard.IsValid"><summary>REDIRECTED</summary></member>
            </members></doc>
            """);
        var xml = Path.ChangeExtension(Sample, ".xml");
        File.WriteAllText(xml, $"""<?xml version="1.0"?><doc redirect="{elsewhere}" />""");
        var r = Run($"select api_doc({IsValid})", $"select decompile({IsValid})");
        Assert.Equal(JsonValueKind.Null, r.Scalar(0).ValueKind);
        Assert.DoesNotContain("REDIRECTED", r.Text(1));

        File.WriteAllText(xml, """
            <?xml version="1.0"?>
            <!DOCTYPE doc [<!ENTITY a "ENTITY">]>
            <doc><members>
              <member name="M:Sample.MemberCard.IsValid"><summary>&a;</summary></member>
            </members></doc>
            """);
        Assert.Equal(JsonValueKind.Null, Run($"select api_doc({IsValid})").Scalar().ValueKind);
    }

    [Fact]
    public void Api_docs_come_from_the_reference_pack()
    {
        var r = Run("select api_doc('M:System.Convert.FromBase64String(System.String)')",
            "select d.doc_id, d.summary, d.params from memberrefs m join api_docs d on d.member = m.handle where m.full_name like '%String::StartsWith(System.String)'",
            // a bare token (or its hex text) is a handle in the current module, as in every other handle filter
            "select d.doc_id from memberrefs m join api_docs d on d.member = (m.handle & 0xFFFFFFFF) where m.full_name like '%String::StartsWith(System.String)'",
            "select d.doc_id from memberrefs m join api_docs d on d.member = printf('0x%08X', m.handle & 0xFFFFFFFF) where m.full_name like '%String::StartsWith(System.String)'");
        Assert.Contains("base-64", r.Text(0));
        var doc = r.Rows(1).Single();
        Assert.Equal("M:System.String.StartsWith(System.String)", doc.GetProperty("doc_id").GetString());
        Assert.Contains("value:", doc.GetProperty("params").GetString());
        Assert.Equal("M:System.String.StartsWith(System.String)", r.Text(2));
        Assert.Equal("M:System.String.StartsWith(System.String)", r.Text(3));
        // an accessor has the documentation of its property (an indexer keeps its parameters), an event's of its event
        var acc = Run("select api_doc('M:System.Exception.get_Message')", "select api_doc('M:System.Collections.Generic.List`1.get_Item(System.Int32)')",
                      "select api_doc('M:Nope.Missing.get_Thing')");
        Assert.Contains("message", acc.Text(0));
        Assert.Contains("index", acc.Text(1));
        Assert.Equal(JsonValueKind.Null, acc.Scalar(2).ValueKind);
    }

    // ---- dnSpy.xml ---------------------------------------------------------------------------------------------------

    const string Fixture = """
        <?xml version="1.0" encoding="utf-8"?>
        <settings>
          <section _="53863c11-df95-43f2-8f86-5e9dfcce6893">
            <section _="FileLists" name="(Default)">
              <section _="FileList" name="(Default)">
                <section _="File" name="C:\work\Other.dll" />
              </section>
            </section>
            <section _="TabGroupWindow" name="Main" index="0" is-horizontal="False">
              <section _="TabGroup" index="0">
                <section _="Tab" index="0">
                  <section _="Content" _g_="2ef0a5c9-1ed9-48e2-90ec-ba5b2b2bf7b6" />
                  <section _="Path">
                    <section _="Name" id="9e88a9a6-7b81-4b54-8a3e-9be56dfc6c0f" name="Sample" />
                    <section _="Name" id="4c3e4f6b-1b8f-4d6f-9d6e-6c1f7c7f8c11" name="Sample.MemberCard" />
                    <section _="Name" id="1f0c4b0c-6a1d-4c0e-8a0f-2b1d0e0f0a01" name="System.Boolean Sample.MemberCard::IsValid()" />
                  </section>
                </section>
              </section>
            </section>
          </section>
        </settings>
        """;

    [Fact]
    public void DnSpy_state_tables_read_and_write_dnspy_xml()
    {
        var xml = PathIn("dnSpy.xml");
        File.WriteAllText(xml, Fixture);
        using var live = new Live(Sample, "--no-project", "--dnspy-xml", xml);
        XElement Section(string guid) => XDocument.Load(xml).Root!.Elements("section").Single(e => (string?)e.Attribute("_") == guid);

        // debugger settings: set, then back to dnSpy's own value
        Assert.Equal(0L, live.Scalar("select value from dnspy_debugger_settings where name = 'UseMemoryModules'"));
        live.Q("update dnspy_debugger_settings set value = 1 where name = 'UseMemoryModules'");
        Assert.Equal("True", (string?)Section("91f1ed94-1bea-4853-9240-b542a7d022ca").Attribute("UseMemoryModules"));
        Assert.Equal(1L, live.Long("select count(*) from transactions where kind = 'undo'")); // journaled once
        live.Q("update dnspy_debugger_settings set value = null where name = 'UseMemoryModules'");
        Assert.Null(Section("91f1ed94-1bea-4853-9240-b542a7d022ca").Attribute("UseMemoryModules"));

        // dnSpy rewriting its file (it does on exit) shows at once
        Assert.Null(live.Scalar("select dnspy_value from dnspy_debugger_settings where name = 'UseHexadecimal'"));
        var edited = XDocument.Load(xml);
        edited.Root!.Elements("section").Single(e => (string?)e.Attribute("_") == "91f1ed94-1bea-4853-9240-b542a7d022ca").SetAttributeValue("UseHexadecimal", "False");
        edited.Save(xml);
        Assert.Equal(0L, live.Long("select dnspy_value from dnspy_debugger_settings where name = 'UseHexadecimal'"));

        // watch: added, then taken back
        live.Q("insert into dnspy_watch (window, expression) values (1, 'Number.Length')");
        Assert.Contains(Section("4052ef89-2381-4cd0-b296-a5497c204b98").Descendants("section"), e => (string?)e.Attribute("Value") == "Number.Length");
        live.Q("delete from dnspy_watch where expression = 'Number.Length'");
        Assert.DoesNotContain(Section("4052ef89-2381-4cd0-b296-a5497c204b98").Descendants("section"), e => (string?)e.Attribute("Value") == "Number.Length");
        Assert.Contains("window must be 0-3", live.Error("insert into dnspy_watch (window, expression) values (7, 'x')"));

        // documents: dnSpy's own entry is listed and kept; ours is appended to the current list
        live.Q($"insert into dnspy_documents (path) values ('{Sample}')");
        var files = Section("53863c11-df95-43f2-8f86-5e9dfcce6893").Descendants("section").Where(e => (string?)e.Attribute("_") == "File").Select(e => (string?)e.Attribute("name")).ToList();
        Assert.Equal(new[] { @"C:\work\Other.dll", Sample }, files);
        var docs = live.Rows("select path, dnspysql, module from dnspy_documents order by dnspysql");
        Assert.Equal((@"C:\work\Other.dll", 0L), ((string)docs[0][0]!, (long)docs[0][1]!));
        Assert.Equal(1L, docs[1][2]);
        Assert.Contains("dnSpy's own list", live.Error("delete from dnspy_documents where path like '%Other.dll'"));

        // tabs: the node the tab showed, resolved to a handle
        var tab = live.Rows("select node, target, content from dnspy_tabs").Single();
        Assert.Equal("System.Boolean Sample.MemberCard::IsValid()", tab[0]);
        Assert.Equal(live.Long($"select {IsValid}"), tab[1]);
    }

    [Fact]
    public void DnSpy_imports_do_not_duplicate_and_export_again()
    {
        var xml = PathIn("dnSpy.xml");
        File.WriteAllText(xml, """
            <?xml version="1.0" encoding="utf-8"?>
            <settings>
              <section _="a7c5956e-593b-4b04-a237-f837cf17e44e">
                <section _="Breakpoint" IsEnabled="True" IsLoaded="True" ModuleName="plugin*.dll" />
              </section>
              <section _="102dcd2e-be0a-477c-b4d0-600c5ca28a6a">
                <section _="Category" Name="DotNet">
                  <section _="Exception" DiffType="Update" Flags="StopFirstChance" IdKind="Name" Name="System.Exception">
                    <section _="Conditions" Condition="a;b" Type="ModuleNameEquals" />
                  </section>
                </section>
              </section>
            </settings>
            """);
        var copy = PathIn("export.xml");
        var r = Run($"select bp_import({Cli.Sql(xml)})", $"select bp_import({Cli.Sql(xml)})", "select count(*) from module_breakpoints",
                    $"select bp_export({Cli.Sql(copy)})");
        Assert.Equal(1, r.Long(2));
        Assert.Contains(XDocument.Load(copy).Descendants("section"), e => (string?)e.Attribute("Name") == "System.Exception");
    }

    [Fact]
    public void Modules_name_the_file_dnspy_binds_to()
    {
        using var live = new Live(Sample, "--no-project", "--dnspy-xml", "off");
        Assert.Equal(Sample, live.Scalar("select dnspy_target from modules"));
        var saved = PathIn("Sample.annotated.dll");
        live.Q($"select save({Cli.Sql(saved)})");
        Assert.Equal(saved, live.Scalar("select dnspy_target from modules"));
        Assert.Equal(1L, live.Scalar($"select count(*) from dnspy_documents where path = {Cli.Sql(saved)}"));
    }
}
