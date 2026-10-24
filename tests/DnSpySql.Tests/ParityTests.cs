// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Reflection;
using System.Runtime.Loader;

namespace DnSpySql.Tests;

/// <summary>
/// The parity suite: fixed SQL against SampleTarget with known expected values, through a live DnSpySql session. Where an expectation depends on
/// the decompiler's exact output, dnSpy's engine is what DnSpySql runs, so the expected text is dnSpy's (noted).
/// </summary>
public sealed class ParityTests : IDisposable
{
    readonly string _dir;
    readonly string _dll;
    readonly Live _s;

    public ParityTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "dnspysql-parity-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        foreach (var f in new[] { "SampleTarget.dll", "SampleTarget.pdb" })
            File.Copy(Path.Combine(AppContext.BaseDirectory, "sample", f), Path.Combine(_dir, f));
        _dll = Path.Combine(_dir, "SampleTarget.dll");
        _s = new Live(_dll, "--project", Path.Combine(_dir, "project.json"));
    }

    public void Dispose()
    {
        _s.Dispose();
        try { Directory.Delete(_dir, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    object? Scalar(string sql) => _s.Scalar(sql);
    long Long(string sql) => _s.Long(sql);
    void Q(string sql) => _s.Q(sql);
    static string Sql(string s) => Cli.Sql(s);

    Live Other(string path, params string[] options) => new(path, options.Length == 0 ? ["--no-project"] : options);

    /// <summary>Loads a saved assembly in an isolated, collectible context and invokes a method (the benign SampleTarget).</summary>
    static object? Run(string path, string type, string method, params object?[] args)
    {
        var alc = new AssemblyLoadContext("t" + Guid.NewGuid(), isCollectible: true);
        try
        {
            using var fs = File.OpenRead(path);
            var asm = alc.LoadFromStream(fs);
            var t = asm.GetType(type, true)!;
            var m = t.GetMethod(method, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance)!;
            var target = m.IsStatic ? null : Activator.CreateInstance(t);
            return m.Invoke(target, args);
        }
        finally { alc.Unload(); }
    }

    [Fact]
    public void Metadata_tables()
    {
        Assert.Equal(1, Long("SELECT count(*) FROM modules"));
        Assert.True(Long("SELECT count(*) FROM types WHERE full_name LIKE 'Sample.%'") >= 10);
        Assert.Equal("Boolean Validate(String code)", Scalar("SELECT signature FROM methods WHERE handle = resolve('Sample.MemberCard::Validate')"));
        Assert.Equal("code", Scalar("SELECT name FROM params WHERE method = resolve('Sample.MemberCard::Validate') AND seq = 1"));
        Assert.Equal("CITY-LIBRARY", Scalar("SELECT constant FROM fields WHERE name = 'Library'"));
        Assert.Equal(2, Long("SELECT count(*) FROM pinvokes"));
        Assert.Equal("Sample.IValidator", Scalar("SELECT interface_name FROM interfaces WHERE type = resolve('Sample.MemberCard')"));
        Assert.Equal(1L, Long("SELECT has_pdb FROM modules"));
        Assert.True(Long("SELECT count(*) FROM dnspysql_tables") > 70);
    }

    [Fact]
    public void Required_filter_is_explained()
    {
        Assert.Contains("needs a filter", _s.Error("SELECT * FROM pseudocode"));
    }

    [Fact]
    public void Il_is_scannable_without_a_method_filter()
    {
        // il stays full-scannable; a method filter is optional.
        Assert.True(Long("SELECT count(*) FROM il WHERE opcode = 'callvirt'") > 0);
    }

    [Fact]
    public void Xrefs_and_analyzer()
    {
        Assert.Equal("System.Boolean Sample.MemberCard::Validate(System.String)", Scalar("SELECT caller_name FROM callers WHERE method = resolve('Sample.MemberCard::IsValid')"));
        Assert.Equal("System.Boolean Sample.GuestCard::IsValid(System.String)",
            Scalar("SELECT name FROM analyze WHERE target = resolve('Sample.MemberCard::IsValid') AND relation = 'method.overridden_by'"));
        Assert.Equal(3, Long("SELECT count(*) FROM analyze WHERE target = resolve('Sample.MemberCard::checks')")); // read_by x2, assigned_by x1
        Assert.Equal(1, Long("SELECT count(*) FROM analyze WHERE target = resolve('Sample.IValidator::Validate') AND relation = 'method.implemented_by'"));
        Assert.Equal("LIB-", Scalar("SELECT value FROM string_refs WHERE referrer = resolve('Sample.MemberCard::IsValid')"));
        Assert.Equal(1, Long("SELECT count(*) FROM call_edges WHERE src = resolve('Sample.Program::Main') AND dst_name LIKE '%Console::WriteLine%' AND is_external"));
    }

    [Fact]
    public void Decompiler_and_search()
    {
        Assert.Contains("StartsWith(\"LIB-\")", (string)Scalar("SELECT text FROM pseudocode WHERE handle = resolve('Sample.MemberCard::IsValid')")!);
        // dnSpy's IL view pads the operand column: `ldstr     "LIB-"`.
        Assert.Matches("ldstr +\"LIB-\"", (string)Scalar("SELECT il_text(resolve('Sample.MemberCard::IsValid'))")!);
        Assert.True(Long("SELECT count(*) FROM pseudocode_lines WHERE handle = resolve('Sample.MemberCard::Validate') AND il_offset IS NOT NULL") >= 3);
        Assert.Equal(1, Long("SELECT count(*) FROM search WHERE query = 'LIB-' AND kind = 'string'"));
        // kind is a category: 'any' is everything, 'member' the methods, fields, properties and events
        Assert.Equal(Long("SELECT count(*) FROM search WHERE query = 'Card'"), Long("SELECT count(*) FROM search WHERE query = 'Card' AND kind = 'any'"));
        Assert.True(Long("SELECT count(*) FROM search WHERE query = 'Card' AND kind = 'member'") > 0);
        Assert.Equal(0, Long("SELECT count(*) FROM search WHERE query = '0xZZ'")); // not a number: searched as text
        Assert.Equal("Your card has expired", Scalar("SELECT value FROM resource_elements WHERE name = 'CardExpired'"));
    }

    [Fact]
    public void Stub_body_save_and_execute()
    {
        Assert.Equal(false, Run(_dll, "Sample.MemberCard", "IsValid", "nope"));
        Q("SELECT set_body_stub(resolve('Sample.MemberCard::IsValid'), 1)");
        var outPath = Path.Combine(_dir, "stub.dll");
        Q($"SELECT save({Sql(outPath)})");
        Assert.Equal(true, Run(outPath, "Sample.MemberCard", "IsValid", "nope"));
    }

    [Fact]
    public void Il_table_edit_and_execute()
    {
        // Checksum: sum = sum * 31 + ... ; change 31 -> 1 through the il table
        var idx = Long("SELECT idx FROM il WHERE method = resolve('Sample.MemberCard::Checksum') AND opcode = 'ldc.i4.s' AND operand = 31");
        Q($"UPDATE il SET operand = 1 WHERE method = resolve('Sample.MemberCard::Checksum') AND idx = {idx}");
        var outPath = Path.Combine(_dir, "il.dll");
        Q($"SELECT save({Sql(outPath)})");
        // with multiplier 1: checksum("ab") = ('a' + Table[97 % 8]) + ('b' + Table[98 % 8]) = (97 + 2) + (98 + 3)
        Assert.Equal(200, Run(outPath, "Sample.MemberCard", "Checksum", "ab"));
    }

    [Fact]
    public void Compile_method_with_lambda_and_execute()
    {
        Q("SELECT compile_method(resolve('Sample.MemberCard::DaysLeft'), 'public int DaysLeft(System.DateTime now) { var l = new System.Collections.Generic.List<int> { 1, 2, 3 }; return l.FindAll(x => x > 1).Count + checks * 10; }')");
        var outPath = Path.Combine(_dir, "compiled.dll");
        Q($"SELECT save({Sql(outPath)})");
        Assert.Equal(2, Run(outPath, "Sample.MemberCard", "DaysLeft", DateTime.Now));
    }

    [Fact]
    public void Add_type_and_members_execute()
    {
        Q("SELECT add_type('namespace Sample.Patches { public static class Hook { public static int Twice(int x) => x * 2 + new Sample.MemberCard().Checks; } }')");
        Q("SELECT add_members(resolve('Sample.MemberCard'), 'public string Describe() => Library + \":\" + checks;')");
        var outPath = Path.Combine(_dir, "added.dll");
        Q($"SELECT save({Sql(outPath)})");
        Assert.Equal(42, Run(outPath, "Sample.Patches.Hook", "Twice", 21));
        Assert.Equal("CITY-LIBRARY:0", Run(outPath, "Sample.MemberCard", "Describe"));
    }

    [Fact]
    public void Renaming_an_override_keeps_base_member_references()
    {
        Q("UPDATE methods SET name = 'ToString2' WHERE handle = resolve('Sample.GuestCard::ToString')");
        // base.ToString() is a MemberRef to System.Object::ToString and must not be renamed with the override.
        Assert.Equal(1, Long("SELECT count(*) FROM memberrefs WHERE full_name = 'System.String System.Object::ToString()'"));
        Assert.Equal(0, Long("SELECT count(*) FROM memberrefs WHERE name = 'ToString2'"));
        var outPath = Path.Combine(_dir, "renamed.dll");
        Q($"SELECT save({Sql(outPath)})");
        Assert.Equal("Guest:Sample.GuestCard7", Run(outPath, "Sample.GuestCard", "ToString2"));
    }

    [Fact]
    public void Undo_redo_restore_model()
    {
        Q("UPDATE methods SET name = 'Renamed' WHERE handle = resolve('Sample.MemberCard::Validate')");
        Q("SELECT set_body_stub(resolve('Sample.MemberCard::IsValid'), 1)");
        Assert.Equal(2, Long("SELECT count(*) FROM transactions WHERE kind = 'undo'"));
        Assert.Equal(2, Long("SELECT undo(2)"));
        Assert.NotNull(Scalar("SELECT resolve('Sample.MemberCard::Validate')"));
        Assert.Contains("StartsWith", (string)Scalar("SELECT decompile(resolve('Sample.MemberCard::IsValid'))")!);
        Assert.Equal(1, Long("SELECT redo(1)"));
        Assert.NotNull(Scalar("SELECT resolve('Sample.MemberCard::Renamed')"));
    }

    [Fact]
    public void Resources_round_trip()
    {
        Q("UPDATE resource_elements SET value = 'changed' WHERE name = 'CardExpired'");
        Q("INSERT INTO resources(name, data) VALUES ('extra.txt', 'hello')");
        var outPath = Path.Combine(_dir, "res.dll");
        Q($"SELECT save({Sql(outPath)})");
        using var s2 = Other(outPath);
        Assert.Equal("changed", s2.Scalar("SELECT value FROM resource_elements WHERE name = 'CardExpired'"));
        Assert.Equal("hello", s2.Scalar("SELECT text FROM resources WHERE name = 'extra.txt'"));
    }

    [Fact]
    public void Raw_patch_and_save_raw()
    {
        Q("SELECT patch_bytes(0x40, 'DE AD')");
        Assert.Equal(1, Long("SELECT is_dirty()"));
        var outPath = Path.Combine(_dir, "raw.dll");
        Q($"SELECT save_raw({Sql(outPath)})");
        var b = File.ReadAllBytes(outPath);
        Assert.Equal(0xDE, b[0x40]);
        Assert.Equal(0xAD, b[0x41]);
        Assert.Equal(0, Long("SELECT count(*) FROM byte_search WHERE pattern = 'DE AD BE EF'"));
        Assert.Equal(1, Long("SELECT count(*) FROM byte_search WHERE pattern = 'DE AD'"));
        // saved: the patches stay what the file is, but nothing is left to save, so close() does not refuse
        Assert.Equal(0, Long("SELECT is_dirty()"));
        Assert.Equal(2, Long("SELECT raw_patch_count FROM modules"));
        Q("SELECT patch_bytes(0x40, 'DE')");
        Assert.Equal(1, Long("SELECT is_dirty()"));
    }

    [Fact]
    public void Comments_and_tags_from_functions_undo()
    {
        Q("SELECT set_comment(resolve('Sample.MemberCard::Validate'), 'first')");
        Q("SELECT set_comment(resolve('Sample.MemberCard::Validate'), 'second'), tag(resolve('Sample.MemberCard'), 'seen')");
        Assert.Equal("second", Scalar("SELECT comment FROM comments"));
        Assert.Equal(1, Long("SELECT undo()"));
        Assert.Equal("first", Scalar("SELECT comment FROM comments"));
        Assert.Equal(0, Long("SELECT count(*) FROM tags"));
        Assert.Equal(1, Long("SELECT undo()"));
        Assert.Equal(0, Long("SELECT count(*) FROM comments"));
        Assert.Equal(2, Long("SELECT redo(2)"));
        Assert.Equal("second", Scalar("SELECT comment FROM comments"));
        Assert.Equal("seen", Scalar("SELECT tag FROM tags"));
        // removing a comment (NULL text) undoes too
        Q("SELECT set_comment(resolve('Sample.MemberCard::Validate'), NULL)");
        Assert.Equal(0, Long("SELECT count(*) FROM comments"));
        Assert.Equal(1, Long("SELECT undo()"));
        Assert.Equal("second", Scalar("SELECT comment FROM comments"));
    }

    [Fact]
    public void The_max_rows_setting_caps_every_front_end()
    {
        Assert.Equal(0, Long("SELECT value FROM runtime_settings WHERE key = 'max_rows'")); // no --max-rows: no cap of its own
        Q("SELECT set_setting('max_rows', 3)");
        var e = _s.Envelope("SELECT name FROM methods");
        var result = e.GetProperty("results")[0];
        Assert.Equal(3, result.GetProperty("rows").GetArrayLength());
        Assert.True(result.GetProperty("truncated").GetBoolean());
        Q("SELECT set_setting('max_rows', 0)");
        Assert.True(_s.Envelope("SELECT name FROM methods").GetProperty("results")[0].GetProperty("rows").GetArrayLength() > 3);
    }

    [Fact]
    public void Annotations_persist()
    {
        Q("INSERT INTO comments(handle, offset, comment) VALUES (resolve('Sample.MemberCard::Validate'), 31, 'calls IsValid')");
        Q("INSERT INTO tags(handle, tag) VALUES (resolve('Sample.MemberCard'), 'progress:reviewed')");
        Q("INSERT INTO kv(key, value) VALUES ('note', 'x')");
        using var s2 = Other(_dll, "--project", Path.Combine(_dir, "project.json"));
        Assert.Equal("calls IsValid", s2.Scalar("SELECT comment FROM comments"));
        Assert.Equal("progress:reviewed", s2.Scalar("SELECT tag FROM tags WHERE handle = resolve('Sample.MemberCard')"));
        Assert.Equal("x", s2.Scalar("SELECT value FROM kv WHERE key = 'note'"));
    }

    [Fact]
    public void Breakpoints_by_offset_source_line_and_decompiled_line()
    {
        var id = Long("SELECT bp_set(resolve('Sample.MemberCard::Validate'))");
        Assert.Equal(id, Long("SELECT bp_set(resolve('Sample.MemberCard::Validate'), 0)")); // same location -> same breakpoint
        Assert.Equal("ok", Scalar($"SELECT status FROM breakpoints WHERE id = {id}"));
        // The PDB line of the first instruction: the method's opening brace in a Debug build, `checks++;` in Release.
        Assert.Contains(Long($"SELECT line FROM breakpoints WHERE id = {id}"), new long[] { 38, 39 });

        // source line 41 of Sample.cs = `if (string.IsNullOrEmpty(code)) return false;` in Validate
        var bySource = Long("SELECT bp_set_line('Sample.cs', 41, 'code == null')");
        Assert.Equal("System.Boolean Sample.MemberCard::Validate(System.String)", Scalar($"SELECT method_name FROM breakpoints WHERE id = {bySource}"));
        Assert.Equal("code == null", Scalar($"SELECT condition FROM breakpoints WHERE id = {bySource}"));

        // The return statement of Validate, on whatever line dnSpy prints it: a breakpoint there lands on the IL
        // of that statement, as clicking dnSpy's margin would.
        var ret = Rows("SELECT line_num, il_offset FROM pseudocode_lines WHERE handle = resolve('Sample.MemberCard::Validate') AND line LIKE '%return %IsValid(code)%'").Single();
        var byDecompiled = Long($"SELECT bp_set_decompiled(resolve('Sample.MemberCard::Validate'), {ret[0]})");
        Assert.Equal(ret[1], Scalar($"SELECT offset FROM breakpoints WHERE id = {byDecompiled}"));

        Q("INSERT INTO breakpoints(method, offset, message, labels) VALUES (resolve('Sample.MemberCard::IsValid'), 0, 'IsValid({code})', 'trace, cards')");
        Assert.Equal(1, Long("SELECT count(*) FROM breakpoints WHERE is_tracepoint AND labels = 'trace, cards'"));
        Q("UPDATE breakpoints SET hit_count = 3, hit_count_kind = 'MultipleOf' WHERE id = " + id);
        Assert.Equal("MultipleOf", Scalar($"SELECT hit_count_kind FROM breakpoints WHERE id = {id}"));

        Assert.Equal(0, Long("SELECT bp_toggle(resolve('Sample.MemberCard::Validate'), 0)"));
        Assert.Equal(3, Long("SELECT count(*) FROM breakpoints"));
        Assert.Equal(1, Long("SELECT bp_clear('trace')"));
        Assert.Equal(1, Long("SELECT undo(1)"));
        Assert.Equal(3, Long("SELECT count(*) FROM breakpoints"));

        Assert.Contains("not an instruction boundary", _s.Error("SELECT bp_set(resolve('Sample.MemberCard::Validate'), 4)"));
    }

    List<object?[]> Rows(string sql) => _s.Rows(sql);

    [Fact]
    public void Module_breakpoints_exceptions_and_throw_sites()
    {
        Q("INSERT INTO module_breakpoints(module_name) VALUES ('Sample*.dll')");
        Assert.Equal("1", Scalar("SELECT matches_loaded FROM module_breakpoints"));
        Assert.Equal(1L, Long("SELECT on_load FROM module_breakpoints"));
        Q("SELECT break_on_exception('System.ArgumentException')");
        Q("INSERT INTO exception_settings(name, stop_first_chance, conditions) VALUES ('System.InvalidOperationException', 1, 'module:Sample*')");
        Assert.Equal("ModuleNameEquals:Sample*", Scalar("SELECT conditions FROM exception_settings WHERE name = 'System.InvalidOperationException'"));
        Assert.Equal(0L, Long("SELECT is_custom FROM exception_settings WHERE name = 'System.ArgumentException'"));
        Assert.True(Long("SELECT count(*) FROM throw_sites") >= 1);
    }

    [Fact]
    public void Dnspy_settings_export_and_import()
    {
        Q("SELECT bp_set(resolve('Sample.MemberCard::Validate'), 0, 'code.Length > 3')");
        Q("SELECT bp_trace(resolve('Sample.MemberCard::IsValid'), 0, 'checking {code}', 0)");
        Q("INSERT INTO module_breakpoints(module_name, on_load) VALUES ('plugin*.dll', 1)");
        Q("SELECT break_on_exception('System.ArgumentException')");
        var xml = Path.Combine(_dir, "dnSpy.xml");
        File.WriteAllText(xml, "<settings><section _=\"11111111-2222-3333-4444-555555555555\" keep=\"yes\" /></settings>");
        Assert.Equal(4, Long($"SELECT export_dnspy_breakpoints({Sql(xml)}, 'C:\\samples')"));

        var doc = System.Xml.Linq.XDocument.Load(xml);
        Assert.Contains(doc.Root!.Elements("section"), e => (string?)e.Attribute("keep") == "yes"); // other dnSpy settings untouched
        var bpl = doc.Descendants("section").First(e => (string?)e.Attribute("_") == "BPL");
        Assert.Equal("DotNet", (string?)bpl.Attribute("__BPT"));
        Assert.Equal("C:\\samples\\SampleTarget.dll", (string?)bpl.Attribute("ModuleName"));
        Assert.Equal("System.Boolean Sample.MemberCard::Validate(System.String)", (string?)bpl.Attribute("Method"));
        Assert.Contains(doc.Descendants("section"), e => (string?)e.Attribute("_") == "Trace" && (string?)e.Attribute("Continue") == "False");
        Assert.Contains(doc.Descendants("section"), e => (string?)e.Attribute("_") == "Exception" && (string?)e.Attribute("DiffType") == "Update"
                                                         && (string?)e.Attribute("Flags") == "StopFirstChance, StopSecondChance");

        using var s2 = Other(_dll);
        Assert.Equal(4L, s2.Long($"SELECT import_dnspy_breakpoints({Sql(xml)})"));
        Assert.Equal("code.Length > 3", s2.Scalar("SELECT condition FROM breakpoints WHERE method = resolve('Sample.MemberCard::Validate')"));
        Assert.Equal(0L, s2.Scalar("SELECT continue FROM breakpoints WHERE is_tracepoint"));
        Assert.Equal("plugin*.dll", s2.Scalar("SELECT module_name FROM module_breakpoints"));
    }

    [Fact]
    public void Readonly_session_refuses_writes()
    {
        using var ro = Other(_dll, "--readonly", "--no-project");
        Assert.NotNull(ro.Error("UPDATE methods SET name = 'x' WHERE handle = resolve('Sample.MemberCard::Validate')"));
        Assert.NotNull(ro.Error("SELECT set_body_stub(resolve('Sample.MemberCard::IsValid'), 1)"));
    }

    [Fact]
    public void Pe_and_metadata_tables()
    {
        Assert.Equal(0x5A4DL, Long("SELECT value FROM pe_fields WHERE structure = 'dos_header' AND field = 'e_magic'"));
        Assert.Equal(".text", Scalar("SELECT name FROM pe_sections WHERE idx = 0"));
        Assert.Equal("IValidator", Scalar("SELECT decoded FROM md_rows WHERE table_name = 'TypeDef' AND rid = 2 AND column = 'Name'"));
        Assert.True(Long("SELECT count(*) FROM md_streams") >= 4);
        Assert.Equal(0x4DL, Long("SELECT value FROM file_bytes WHERE offset = 0"));
    }

    [Fact]
    public void Flag_name_columns_do_not_use_enum_aliases()
    {
        Assert.Equal("AnsiClass", Scalar("SELECT charset FROM types WHERE handle = resolve('Sample.MemberCard')"));
        Assert.Equal("CharSetUnicode", Scalar("SELECT charset FROM pinvokes WHERE entry = 'MessageBoxW'"));
        Assert.Equal("CharSetNotSpec", Scalar("SELECT charset FROM pinvokes WHERE entry = 'GetTickCount'"));
        Assert.Equal("CallConvWinapi", Scalar("SELECT calling_convention FROM pinvokes WHERE entry = 'GetTickCount'"));
    }

    [Fact]
    public void Sniff_rejects_high_entropy_bytes_as_text()
    {
        var rnd = new Random(1);
        var noise = new byte[4096];
        rnd.NextBytes(noise);
        for (int i = 0; i < noise.Length; i++) noise[i] |= 0x80; // no control bytes: a naive check calls this "text"
        Q($"INSERT INTO resources(name, data) VALUES ('cfg', x'{Convert.ToHexString(noise)}')");
        Assert.Equal("binary", Scalar("SELECT sniffed_type FROM resources WHERE name = 'cfg'"));
        Assert.Equal("binary", Scalar("SELECT content_type FROM resources WHERE name = 'cfg'"));
        rnd.NextBytes(noise); // full-range random bytes, named like an executable: ciphertext, not a PE
        Q($"INSERT INTO resources(name, data) VALUES ('blob.exe', x'{Convert.ToHexString(noise)}')");
        Assert.Equal("binary.exe", Scalar("SELECT sniffed_type FROM resources WHERE name = 'blob.exe'"));
        Assert.Equal("high entropy", Scalar("SELECT content_type FROM resources WHERE name = 'blob.exe'"));
        Q($"INSERT INTO resources(name, data) VALUES ('a.txt', {Sql("héllo wörld ✓")})");
        Assert.Equal("text", Scalar("SELECT sniffed_type FROM resources WHERE name = 'a.txt'"));
    }

    [Fact]
    public void Decompiles_modules_with_mangled_stream_names()
    {
        // Renamed streams: "#~" -> "#-" and "#Strings" -> "#strIngs". With "#-" metadata the CLR and dnlib match heap
        // names case-insensitively.
        var bytes = File.ReadAllBytes(_dll);
        void Rename(string from, string to)
        {
            var at = bytes.AsSpan().IndexOf(System.Text.Encoding.ASCII.GetBytes(from + "\0"));
            Assert.True(at > 0, from);
            System.Text.Encoding.ASCII.GetBytes(to).CopyTo(bytes, at);
        }
        Rename("#~", "#-");
        Rename("#Strings", "#strIngs");
        var path = Path.Combine(_dir, "Mangled.dll");
        File.WriteAllBytes(path, bytes);
        using var s2 = Other(path);
        var r = s2.Rows("SELECT completed, error, text FROM pseudocode WHERE handle = resolve('Sample.MemberCard::Validate')").Single();
        Assert.Equal(1L, r[0]);
        Assert.Contains("Validate", (string)r[2]!);
    }

    [Fact]
    public void Handle_filters_accept_bare_tokens_and_hex_text()
    {
        var h = Long("SELECT resolve('Sample.MemberCard::Validate')");
        var bare = h & 0xFFFFFFFF;
        foreach (var arg in new[] { h.ToString(), bare.ToString(), $"'0x{h:X}'", $"'0x{bare:X}'" })
        {
            Assert.Equal(1L, Long($"SELECT count(*) FROM methods WHERE handle = {arg}"));
            Assert.Equal(1L, Long($"SELECT count(*) FROM pseudocode WHERE handle = {arg}"));
            Assert.True(Long($"SELECT count(*) FROM il WHERE method = {arg}") > 0, arg);
            Assert.Equal(h, Long($"SELECT method FROM callers WHERE method = {arg} LIMIT 1"));
        }
        Assert.Equal(0L, Long("SELECT count(*) FROM methods WHERE handle = 'nope'"));
        Assert.Equal(0L, Long("SELECT count(*) FROM methods WHERE handle = NULL"));
        Assert.True(Long("SELECT count(*) FROM types WHERE declaring_type IS NULL") > 0);
        // 0 keeps meaning "external" instead of becoming a module-qualified handle.
        Assert.Equal(Long("SELECT count(*) FROM call_edges WHERE is_external"), Long("SELECT count(*) FROM call_edges WHERE dst = 0"));
    }

    [Fact]
    public void Catalog_lists_views()
    {
        Assert.Equal("view", Scalar("SELECT kind FROM dnspysql_tables WHERE table_name = 'entry_points'"));
        Assert.Equal("table", Scalar("SELECT kind FROM dnspysql_tables WHERE table_name = 'methods'"));
        Assert.Equal("method", Scalar("SELECT column_name FROM dnspysql_columns WHERE table_name = 'callers' AND ordinal = 0"));
        Assert.Equal(Long("SELECT count(*) FROM dnspysql_tables WHERE kind = 'view'"),
            Long("SELECT count(DISTINCT table_name) FROM dnspysql_columns WHERE table_name IN (SELECT table_name FROM dnspysql_tables WHERE kind = 'view')"));
    }

    [Fact]
    public void Table_output_escapes_invisible_characters()
    {
        var table = Cli.RunText(_dll, "table", "SELECT char(0x202E) || 'exe.txt' AS n, char(0x2009) || char(0xE037) AS m, 'héllo 名前 ✓' AS ok");
        Assert.Contains("\\u202eexe.txt", table);
        Assert.Contains("\\u2009\\ue037", table);
        Assert.Contains("héllo 名前 ✓", table);
        Assert.Contains("\u202eexe.txt", Cli.RunText(_dll, "csv", "SELECT char(0x202E) || 'exe.txt' AS n")); // machine formats stay raw
    }

    [Fact]
    public void Non_dotnet_files_are_explained()
    {
        var text = Path.Combine(_dir, "notes.dll");
        File.WriteAllText(text, new string('x', 100));
        Assert.Contains("not a PE file", Cli.Run(text, "SELECT 1").Error);
        var bytes = File.ReadAllBytes(_dll);
        int pe = BitConverter.ToInt32(bytes, 0x3C), opt = pe + 0x18;
        int clr = opt + (BitConverter.ToUInt16(bytes, opt) == 0x20B ? 0x70 : 0x60) + 14 * 8;
        Array.Clear(bytes, clr, 8);
        var path = Path.Combine(_dir, "native.exe");
        File.WriteAllBytes(path, bytes);
        var r = Cli.Run(path, "SELECT 1");
        Assert.NotEqual(0, r.Exit);
        Assert.Contains("not a .NET assembly", r.Error);
        Assert.Contains("native PE32", r.Error);
    }

    [Fact]
    public void Data_functions()
    {
        // the SQL utilities for reading what the tables return (decode and crypto are the agent's own, not dnSpy)
        Assert.Equal(1L, Long("SELECT 'abc123' REGEXP '[0-9]+$'"));
        Assert.Equal("443", Scalar("SELECT regexp_extract('example.org:443', ':(\\d+)', 1)"));
        Assert.Equal("example[.]org", Scalar("SELECT regexp_replace('example.org', '\\.', '[.]')"));
        Assert.Equal("hé", Scalar("SELECT text_decode(text_encode('hé', 'utf-16le'), 'utf-16le')"));
        // a NUL inside text survives the native boundary both ways (as a blob on the way out)
        Assert.Equal("410042", Scalar("SELECT hex(text_decode(x'410042'))"));
        Assert.Equal(3L, Long("SELECT length(text_decode(x'410042'))"));
        Assert.Equal("410042", Scalar("SELECT hex(text_encode(text_decode(x'410042')))"));
        Assert.Equal(0x04030201L, Long("SELECT int_at(x'01020304', 0, 4)"));
        Assert.Equal(0x01020304L, Long("SELECT int_at(x'01020304', 0, 4, 'be')"));
        Assert.Equal(0x0302L, Long("SELECT int_at(x'01020304', 1, 2)"));
        Assert.Null(Scalar("SELECT int_at(x'01', 0, 4)")); // past the end
        // decode and crypto helpers are gone from the SQL surface
        Assert.Equal(0L, Long("SELECT count(*) FROM dnspysql_functions WHERE name IN ('base64_decode', 'xor', 'decrypt', 'decompress', 'pbkdf2', 'md5', 'entropy')"));
    }

    [Fact]
    public void Binary_reports_anomalies()
    {
        Assert.Equal("0", Scalar("SELECT value FROM binary WHERE key = 'anomaly_count'"));
        var bytes = File.ReadAllBytes(_dll);
        var at = bytes.AsSpan().IndexOf(System.Text.Encoding.ASCII.GetBytes("#GUID\0"));
        System.Text.Encoding.ASCII.GetBytes("#GuID").CopyTo(bytes, at);
        var path = Path.Combine(_dir, "Odd.dll");
        File.WriteAllBytes(path, bytes);
        using var s2 = Other(path);
        Assert.Contains("#GuID", (string)s2.Scalar("SELECT value FROM binary WHERE key = 'anomalies'")!);
    }

    [Fact]
    public void Rebuilds_a_destroyed_cli_header()
    {
        var bytes = File.ReadAllBytes(_dll);
        using (var pe = new System.Reflection.PortableExecutable.PEReader(new MemoryStream(bytes)))
        {
            var dir = pe.PEHeaders.PEHeader!.CorHeaderTableDirectory;
            pe.PEHeaders.TryGetDirectoryOffset(dir, out var at);
            for (int i = 0; i < 72; i++) bytes[at + i] = (byte)(0xA5 ^ i);
        }
        var path = Path.Combine(_dir, "NoHeader.dll");
        File.WriteAllBytes(path, bytes);
        using var s2 = Other(path);
        Assert.Equal(Long("SELECT count(*) FROM types"), s2.Long("SELECT count(*) FROM types"));
        Assert.Contains("CLI header", (string)s2.Scalar("SELECT value FROM binary WHERE key = 'anomalies'")!);
        var sha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();
        Assert.Equal(sha, s2.Scalar("SELECT value FROM binary WHERE key = 'sha256'"));
        Assert.Contains("Validate", (string)s2.Scalar("SELECT decompile(resolve('Sample.MemberCard'))")!);
    }

    [Fact]
    public void Reports_data_appended_after_the_image()
    {
        Assert.Equal(0L, Long("SELECT value FROM binary WHERE key = 'overlay_size'"));
        Assert.DoesNotContain("overlay", (string)Scalar("SELECT value FROM binary WHERE key = 'anomalies'")!);

        // Data after the last section: random bytes, then a copy of the file.
        var bytes = File.ReadAllBytes(_dll);
        var junk = new byte[1000];
        new Random(1).NextBytes(junk);
        var path = Path.Combine(_dir, "Appended.dll");
        File.WriteAllBytes(path, [.. bytes, .. junk, .. bytes]);
        using var s2 = Other(path);
        object? Key(string k) => s2.Scalar($"SELECT value FROM binary WHERE key = '{k}'");
        Assert.Equal($"0x{bytes.Length:X}", Key("overlay_offset"));
        Assert.Equal((long)(bytes.Length + junk.Length), Convert.ToInt64(Key("overlay_size")));
        Assert.Equal($"0x{bytes.Length + junk.Length:X}", Key("overlay_pe_offset"));
        Assert.Contains("embedded PE", (string)Key("anomalies")!);
        Assert.Equal("4D5A", s2.Scalar($"SELECT hex(read_bytes({bytes.Length + junk.Length}, 2))"));
    }

    [Fact]
    public void Rebuilds_a_wiped_metadata_root()
    {
        // The CLI header, the "BSJB" signature and every stream name zeroed in the file.
        var bytes = File.ReadAllBytes(_dll);
        using (var pe = new System.Reflection.PortableExecutable.PEReader(new MemoryStream(bytes)))
        {
            var dir = pe.PEHeaders.PEHeader!.CorHeaderTableDirectory;
            pe.PEHeaders.TryGetDirectoryOffset(dir, out var at);
            Array.Clear(bytes, at, 72);
            int m = pe.PEHeaders.MetadataStartOffset;
            Array.Clear(bytes, m, 4);
            int p = m + 16 + BitConverter.ToInt32(bytes, m + 12), count = BitConverter.ToUInt16(bytes, p + 2);
            p += 4;
            for (int i = 0; i < count; i++)
            {
                int name = p += 8;
                while (bytes[p] != 0) p++;
                p = name + ((p - name + 4) & ~3);
                Array.Clear(bytes, name, p - name);
            }
        }
        var path = Path.Combine(_dir, "NoRoot.dll");
        File.WriteAllBytes(path, bytes);
        using var s2 = Other(path);
        Assert.Equal(Long("SELECT count(*) FROM types"), s2.Long("SELECT count(*) FROM types"));
        Assert.Equal(Long("SELECT count(*) FROM user_strings"), s2.Long("SELECT count(*) FROM user_strings"));
        Assert.Contains("unnamed stream(s) identified by content", (string)s2.Scalar("SELECT value FROM binary WHERE key = 'anomalies'")!);
        Assert.Contains("Validate", (string)s2.Scalar("SELECT decompile(resolve('Sample.MemberCard'))")!);
    }

    [Fact]
    public void Type_with_an_unreadable_method_body_still_decompiles()
    {
        // One unreadable method body must not sink its type.
        var bytes = File.ReadAllBytes(_dll);
        using (var pe = new System.Reflection.PortableExecutable.PEReader(new MemoryStream(bytes)))
        {
            var md = System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe);
            var getter = md.MethodDefinitions.Select(md.GetMethodDefinition)
                .Single(m => md.GetString(m.Name) == "get_Membership" && md.GetString(md.GetTypeDefinition(m.GetDeclaringType()).Name) == "MemberCard");
            var rva = getter.RelativeVirtualAddress;
            var sec = pe.PEHeaders.SectionHeaders.Single(s => rva >= s.VirtualAddress && rva < s.VirtualAddress + s.VirtualSize);
            bytes[rva - sec.VirtualAddress + sec.PointerToRawData] = 0x00; // neither a tiny nor a fat header
        }
        var path = Path.Combine(_dir, "Unreadable.dll");
        File.WriteAllBytes(path, bytes);
        using var s2 = Other(path);
        var text = (string)s2.Rows("SELECT completed, error, text FROM pseudocode WHERE handle = resolve('Sample.MemberCard')").Single()[2]!;
        Assert.Contains("class MemberCard", text);
        Assert.Contains("this.IsValid(code) && MemberCard.Checksum(code) % 7 == 3;", text); // dnSpy qualifies members
        Assert.Contains("DaysLeft", text);
    }
}
