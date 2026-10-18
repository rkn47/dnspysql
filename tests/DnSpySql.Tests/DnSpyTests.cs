// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Xml.Linq;

namespace DnSpySql.Tests;

public sealed class DnSpyTests : SampleTest
{
    const string IsValid = "(select token from methods where name = 'IsValid')";

    // A dnSpy.xml with dnSpy's own state: an unrelated settings section and a breakpoint in another module.
    const string DnSpyXml = """
        <?xml version="1.0" encoding="utf-8"?>
        <settings>
          <section _="3c1e3a3b-4f00-4b4e-9b49-2a6a0a1d5c11" Theme="Dark" />
          <section _="fbc6039c-8a7a-49dc-9c32-52c1b73de0a3">
            <section _="Breakpoint" IsEnabled="True">
              <section _="BPL" __BPT="DotNet" AssemblyFullName="Other, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" Method="System.Void Other::Run()" ModuleName="C:\work\Other.exe" Offset="0" Token="100663297" />
            </section>
          </section>
        </settings>
        """;

    [Fact]
    public void Undo_reverts_changes_to_existing_breakpoints_and_exception_settings()
    {
        var r = Run($"select bp_set({IsValid})", "select bp_enable(0)", "select undo(1)", "select enabled from breakpoints",
            $"select bp_trace({IsValid}, 0, 'hit')", $"select bp_trace({IsValid}, 0, 'again')", "select undo(1)", "select message from breakpoints",
            "select break_on_exception('System.InvalidOperationException', 1, 0)", "select break_on_exception('System.InvalidOperationException', 0, 1)",
            "select undo(1)", "select stop_first_chance, stop_second_chance from exception_settings where name = 'System.InvalidOperationException'");
        Assert.Equal(1, r.Long(3));
        Assert.Equal("hit", r.Text(7));
        Assert.Equal(new[] { 1L, 0L }, r.Values(11).Select(v => v.GetInt64()));
    }

    [Fact]
    public void Breakpoints_merge_into_dnspy_xml()
    {
        var xml = PathIn("dnSpy.xml");
        File.WriteAllText(xml, DnSpyXml);
        var export = $"select bp_export({Cli.Sql(xml)}, NULL, 'C:\\samples')";
        Run($"select bp_set({IsValid})",
            "update breakpoints set condition = 'Number == null', labels = 'a,b'",
            "select bp_module('plugin*.dll'), break_on_exception('System.InvalidOperationException', 1, 1)",
            export, export); // twice: no duplicates

        var root = XDocument.Load(xml).Root!;
        Assert.Contains(root.Elements("section"), e => (string?)e.Attribute("Theme") == "Dark");
        var bpls = root.Descendants("section").Where(e => (string?)e.Attribute("_") == "BPL").ToList();
        Assert.Equal(2, bpls.Count);
        var ours = bpls.Single(e => ((string)e.Attribute("ModuleName")!).EndsWith("Sample.dll"));
        Assert.Equal(@"C:\samples\Sample.dll", (string)ours.Attribute("ModuleName")!);
        Assert.Equal("System.Boolean Sample.MemberCard::IsValid()", (string)ours.Attribute("Method")!);
        Assert.Equal("__BPT", ours.Attributes().Skip(1).First().Name.LocalName); // dnSpy's attribute order
        Assert.Equal("Number == null", (string)ours.Parent!.Elements().Single(e => (string?)e.Attribute("_") == "Condition").Attribute("Condition")!);
        Assert.Single(root.Descendants("section"), e => (string?)e.Attribute("ModuleName") == "plugin*.dll");
        Assert.Single(root.Descendants("section"), e => (string?)e.Attribute("Name") == "System.InvalidOperationException"
                                                        && (string?)e.Attribute("Flags") == "StopFirstChance, StopSecondChance");

        var r = Cli.Run(Sample, $"select bp_import({Cli.Sql(xml)})",
            "select method, condition, labels, dnspy_module from breakpoints",
            "select module_name, on_load from module_breakpoints",
            "select name, stop_first_chance, stop_second_chance from exception_settings").Ok();
        Assert.Equal(3, r.Long(0)); // Other.exe is not loaded, so its breakpoint is skipped
        var bp = r.Rows(1).Single();
        Assert.Equal("Number == null", bp.GetProperty("condition").GetString());
        Assert.Equal(@"C:\samples\Sample.dll", bp.GetProperty("dnspy_module").GetString());
        Assert.Equal("plugin*.dll", r.Rows(2).Single().GetProperty("module_name").GetString());
        Assert.Equal(1, r.Rows(3).Single().GetProperty("stop_second_chance").GetInt64());
    }

    [Fact]
    public void Undo_reverts_a_whole_bp_import()
    {
        var xml = PathIn("dnSpy.xml");
        File.WriteAllText(xml, DnSpyXml);
        Run($"select bp_set({IsValid})", "update breakpoints set condition = 'Number == null'",
            "select bp_module('plugin*.dll'), break_on_exception('System.InvalidOperationException', 1, 1)", $"select bp_export({Cli.Sql(xml)})");

        // the import both changes a breakpoint this session already has and adds new entries; one undo reverts all of it
        const string counts = "select (select count(*) from breakpoints), (select count(*) from module_breakpoints), (select count(*) from exception_settings)";
        const string cond = "select condition from breakpoints"; // the one breakpoint, on IsValid
        var r = Cli.Run(Sample, $"select bp_set({IsValid})", "update breakpoints set condition = 'local'", counts,
            $"select bp_import({Cli.Sql(xml)})", cond, counts,
            "select undo(1)", cond, counts,
            "select redo(1)", cond, counts).Ok();
        long[] Counts(int i) => r.Values(i).Select(v => v.GetInt64()).ToArray(); // result sets: the UPDATE returns none
        Assert.Equal("Number == null", r.Text(3));
        Assert.NotEqual(Counts(1), Counts(4));
        Assert.Equal("local", r.Text(6));
        Assert.Equal(Counts(1), Counts(7));
        Assert.Equal("Number == null", r.Text(9));
        Assert.Equal(Counts(4), Counts(10));
    }

    [Fact]
    public void Bookmarks_merge_into_dnspy_xml()
    {
        var xml = PathIn("dnSpy.xml");
        File.WriteAllText(xml, """
            <?xml version="1.0" encoding="utf-8"?>
            <settings>
              <section _="eaa1be38-7a55-44af-ad93-5b7ee2327edd">
                <section _="Bookmark" IsEnabled="True" Name="theirs">
                  <section _="BML" __BMT="DotNetToken" AssemblyFullName="Other, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" ModuleName="C:\work\Other.exe" Token="33554434" />
                </section>
              </section>
            </settings>
            """);
        var export = $"select bp_export({Cli.Sql(xml)})";
        Run($"insert into bookmarks (handle, offset, name, category, comment) values ({IsValid}, 0, 'check', 'cards, todo', 'returns the flag'), "
            + "(resolve('Sample.MemberCard'), NULL, 'card type', '', '')",
            export, export); // twice: no duplicates

        var marks = XDocument.Load(xml).Descendants("section").Where(e => (string?)e.Attribute("_") == "Bookmark").ToList();
        Assert.Equal(3, marks.Count);
        Assert.Single(marks, e => (string?)e.Attribute("Name") == "theirs");
        var body = marks.Single(e => (string?)e.Attribute("Name") == "check — returns the flag");
        Assert.Equal("cards, todo", (string)body.Attribute("Labels")!);
        var bml = body.Elements().Single();
        Assert.Equal("DotNetBody", (string)bml.Attribute("__BMT")!);
        Assert.Equal("0", (string)bml.Attribute("Offset")!);
        Assert.Equal("System.Boolean Sample.MemberCard::IsValid()", (string)bml.Attribute("TokenString")!);
        Assert.Equal(Sample, (string)bml.Attribute("ModuleName")!);
        var type = marks.Single(e => (string?)e.Attribute("Name") == "card type").Elements().Single();
        Assert.Equal("DotNetToken", (string)type.Attribute("__BMT")!);
        Assert.Null(type.Attribute("Offset"));
        Assert.Equal("Sample.MemberCard", (string)type.Attribute("TokenString")!);

        var r = Cli.Run(Sample, $"select bp_import({Cli.Sql(xml)})", "select name_of(handle) n, offset, name, category, comment from bookmarks order by offset").Ok();
        Assert.Equal(2, r.Long(0)); // Other.exe is not loaded
        var rows = r.Rows(1);
        Assert.Equal(-1, rows[0].GetProperty("offset").GetInt64());
        Assert.Equal("check", rows[1].GetProperty("name").GetString());
        Assert.Equal("returns the flag", rows[1].GetProperty("comment").GetString());
        Assert.Equal("cards, todo", rows[1].GetProperty("category").GetString());
    }

    [Fact]
    public void Bookmarks_of_an_edited_module_leave_out_the_token_check()
    {
        // dnSpy drops a bookmark whose TokenString differs from the file it opens, which an unsaved rename would cause.
        var file = PathIn("marks.xml");
        Run($"insert into bookmarks (handle, name) values ({IsValid}, 'x')", $"update methods set name = 'Renamed' where token = {IsValid}",
            $"select bp_export({Cli.Sql(file)})");
        var bml = XDocument.Load(file).Descendants("section").Single(e => (string?)e.Attribute("_") == "BML");
        Assert.Null(bml.Attribute("TokenString"));
    }

    static List<XElement> Sections(string xml, string name) =>
        XDocument.Load(xml).Descendants("section").Where(e => (string?)e.Attribute("_") == name).ToList();

    static string Notice(System.Text.Json.JsonElement envelope) =>
        string.Join("\n", envelope.GetProperty("results").EnumerateArray()
            .Select(r => r.TryGetProperty("notice", out var n) ? n.GetString() : null).Where(n => n != null));

    [Fact]
    public void Auto_sync_keeps_dnspy_xml_in_step()
    {
        var xml = PathIn("dnSpy.xml");
        File.WriteAllText(xml, DnSpyXml);
        using var live = new Live(Sample, "--no-project", "--dnspy-xml", xml);

        Assert.Contains("dnSpy.xml updated", Notice(live.Q($"select bp_set({IsValid})")));
        Assert.Equal(2, Sections(xml, "BPL").Count);
        var stamp = File.GetLastWriteTimeUtc(xml);
        Assert.Equal("", Notice(live.Q("select count(*) from methods"))); // nothing changed: not written
        Assert.Equal(stamp, File.GetLastWriteTimeUtc(xml));

        // an unsaved edit takes Method out (dnSpy drops a breakpoint whose Method does not match the file it opens)
        Assert.NotNull(Sections(xml, "BPL").Single(e => (string?)e.Attribute("ModuleName") == Sample).Attribute("Method"));
        live.Q("update methods set name = 'Renamed' where name = 'Checksum'");
        Assert.Null(Sections(xml, "BPL").Single(e => (string?)e.Attribute("ModuleName") == Sample).Attribute("Method"));

        live.Q("delete from breakpoints");
        Assert.Equal("C:\\work\\Other.exe", (string)Sections(xml, "BPL").Single().Attribute("ModuleName")!); // dnSpy's own stays

        live.Q($"insert into bookmarks (handle, name) values ({IsValid}, 'here')");
        Assert.Equal("here", (string)Sections(xml, "Bookmark").Single().Attribute("Name")!);
    }

    [Fact]
    public void Save_writes_xml_documentation_and_retargets_dnspy()
    {
        var xml = PathIn("dnSpy.xml");
        var saved = PathIn("Sample.annotated.dll");
        using var live = new Live(Sample, "--no-project", "--dnspy-xml", xml);
        live.Q($"select set_comment({IsValid}, 'checks the number'), set_comment({IsValid}, 0, 'first instruction'), tag({IsValid}, 'cards')");
        live.Q($"select bp_set({IsValid})");
        Assert.Equal(Sample, (string)Sections(xml, "BPL").Single().Attribute("ModuleName")!);

        var notice = Notice(live.Q($"select save({Cli.Sql(saved)})"));
        Assert.Contains("Sample.annotated.xml", notice);
        Assert.Contains("dnSpy.xml updated", notice);

        // dnSpyEx loads <assembly>.xml from next to the file and shows it as /// comments
        var member = XDocument.Load(PathIn("Sample.annotated.xml")).Descendants("member")
            .Single(m => (string?)m.Attribute("name") == "M:Sample.MemberCard.IsValid");
        Assert.Contains("checks the number", member.Element("summary")!.Value);
        var remarks = member.Element("remarks")!.Value;
        Assert.Contains("IL_0000 (", remarks); // the decompiled statement at that offset
        Assert.Contains("first instruction", remarks);
        Assert.Contains("Tags: cards", remarks);
        Assert.Contains("checks the number", File.ReadAllText(saved + ".dnspysql.json"));

        // the breakpoint now names the saved file (the one dnSpy opens); the entry at the original path is gone
        var bpl = Sections(xml, "BPL").Single();
        Assert.Equal(saved, (string)bpl.Attribute("ModuleName")!);
        Assert.Equal("System.Boolean Sample.MemberCard::IsValid()", (string)bpl.Attribute("Method")!);

        // with nothing annotated, a later save removes the sidecar it wrote, but never someone else's documentation file
        live.Q("delete from comments");
        live.Q("delete from tags");
        Assert.Contains("removed", Notice(live.Q($"select save({Cli.Sql(saved)})")));
        Assert.False(File.Exists(PathIn("Sample.annotated.xml")));
        File.WriteAllText(PathIn("Other.xml"), "<doc><members /></doc>");
        live.Q($"select save({Cli.Sql(PathIn("Other.dll"))})");
        Assert.True(File.Exists(PathIn("Other.xml")));
    }

    [Fact]
    public void A_new_breakpoint_file_is_standalone()
    {
        var file = PathIn("bps.xml");
        var r = Run($"select bp_set({IsValid}), bp_set({IsValid}, 0)", $"select bp_export({Cli.Sql(file)})");
        Assert.Equal(1, r.Long(-1));
        var bpl = XDocument.Load(file).Descendants("section").Single(e => (string?)e.Attribute("_") == "BPL");
        Assert.Equal(Sample, (string)bpl.Attribute("ModuleName")!);
    }

    [Fact]
    public void Bp_patch_writes_a_guarded_debugger_break()
    {
        var saved = PathIn("bp.dll");
        Run($"select bp_set({IsValid})", "select bp_patch()", $"select save({Cli.Sql(saved)})");
        var text = Cli.Run(saved, "select decompile(token) from methods where name = 'IsValid'").Ok().Text();
        Assert.Contains("Debugger.IsAttached", text);
        Assert.Contains("Debugger.Break()", text);
        var r = Cli.Run(Sample, $"select bp_set({IsValid})", "update breakpoints set hit_count = 3", "select bp_patch()");
        Assert.NotEqual(0, r.Exit); // a hit count needs a debugger; refused rather than weakened
    }

    [Fact]
    public void Export_project_writes_a_solution_dnspy_and_visual_studio_open()
    {
        var dir = PathIn("export");
        var sln = Run("select add_resource('we?ird*na<me>.bin', 'x')", $"select export_project({Cli.Sql(dir)})").Text();
        Assert.Equal(Path.Combine(dir, "Sample.sln"), sln);
        var proj = Path.Combine(dir, "Sample");
        var csproj = File.ReadAllText(Path.Combine(proj, "Sample.csproj"));
        Assert.Contains("<Compile Include=\"MemberCard.cs\" />", csproj);
        Assert.Contains("ToolsVersion=\"4.0\"", csproj); // dnSpy's default: a VS2010 project
        var card = File.ReadAllText(Path.Combine(proj, "MemberCard.cs"));
        Assert.Contains("public sealed class MemberCard", card);
        Assert.Contains("await Task.Delay(1);", File.ReadAllText(Path.Combine(proj, "Async.cs")));
        Assert.Equal("Welcome to the City Library.", File.ReadAllText(Path.Combine(proj, "readme.txt")).Trim());
        // Every file name must be valid on Windows, where the export is opened.
        var bad = "<>:\"\\|?*".ToCharArray();
        Assert.All(Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories), f => Assert.True(Path.GetFileName(f).IndexOfAny(bad) < 0, f));
        Assert.Contains(Directory.EnumerateFiles(proj), f => Path.GetFileName(f).StartsWith("we-ird-na-me-"));

        var sdk = Run($"select export_project({Cli.Sql(PathIn("sdk"))}, NULL, 1)").Text();
        Assert.StartsWith("<Project Sdk=\"Microsoft.NET.Sdk\">", File.ReadAllText(Path.Combine(Path.GetDirectoryName(sdk)!, "Sample", "Sample.csproj")).TrimStart('\uFEFF'));
    }
}
