// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Text.Json;

namespace DnSpySql.Tests;

/// <summary>
/// Working across modules: a payload opened from a resource as a module of its own, close() taking a sample and its
/// stages out, names several modules share, and whole-module decompilation under a timeout.
/// </summary>
public sealed class WorkflowTests : SampleTest
{
    static readonly string TargetDll = Path.Combine(AppContext.BaseDirectory, "sample", "SampleTarget.dll");

    static string? Notice(JsonElement envelope) =>
        envelope.GetProperty("results").EnumerateArray().Last().TryGetProperty("notice", out var n) ? n.GetString() : null;

    // a copy of the sample carrying SampleTarget in a resource, saved so the stage is in its file
    string Carrier()
    {
        var carrier = PathIn("Carrier.dll");
        Run($"INSERT INTO resources(name, data) VALUES ('stage.dll', x'{Convert.ToHexString(File.ReadAllBytes(TargetDll))}')", $"select save({Cli.Sql(carrier)})");
        return carrier;
    }

    const string OpenStage = "select open_bytes(data) from resources where name = 'stage.dll'";

    [Fact]
    public void A_payload_from_a_resource_opens_as_a_module_of_its_own()
    {
        using var live = new Live(Carrier(), "--no-project");
        Assert.Equal(2, live.Long(OpenStage));
        Assert.Equal(2, live.Long(OpenStage)); // the same bytes again: the same module, no copy
        Assert.Equal(2, live.Long("select count(*) from modules"));
        Assert.Equal(new object?[] { "bytes", 1L }, live.Rows("select origin, derived_from from modules where id = 2").Single());
        Assert.Equal(new object?[] { "file", null }, live.Rows("select origin, derived_from from modules where id = 1").Single());
    }

    [Fact]
    public void Close_takes_a_sample_and_its_stages_out_and_never_reuses_their_ids()
    {
        using var live = new Live(Carrier(), "--no-project");
        Assert.Equal(2, live.Long(OpenStage));
        Assert.Equal("[2]", live.Scalar("select close(2, 0)"));
        Assert.Equal(1, live.Long("select count(*) from modules"));
        Assert.Contains("module 2 was closed", live.Error("select resolve('SampleTarget.Program', NULL, 2)"));
        Assert.Contains("module 2 was closed", live.Error("select decompile(handle(2, 0x02000002))"));
        Assert.Equal(3, live.Long(OpenStage)); // a new id: a handle kept from module 2 must not reach this one
        var closed = live.Envelope("select close(1)"); // the sample and the stage that came out of it
        Assert.Equal("[1,3]", closed.GetProperty("results")[0].GetProperty("rows")[0][0].GetString());
        Assert.Contains("close: closed modules 1, 3", Notice(closed));
        Assert.Equal(0, live.Long("select count(*) from modules"));
        Assert.Equal(4, live.Long($"select open({Cli.Sql(PathIn("Carrier.dll"))})"));
    }

    [Fact]
    public void Close_keeps_unsaved_work_annotations_and_the_undo_history_safe()
    {
        using (var project = new Live(Sample))
            Assert.Contains("holds the session's project file", project.Error("select close(1)"));

        var carrier = Carrier();
        var xml = PathIn("dnSpy.xml");
        using var live = new Live(carrier, "--no-project", "--dnspy-xml", xml);
        live.Q(OpenStage);
        live.Q("update methods set name = 'Total' where module = 2 and name = 'Sum'");
        Assert.Contains("unsaved edits", live.Error("select close(1)")); // its stage's
        Assert.Contains("unsaved edits", live.Error("select close(2)"));
        live.Q($"select save(2, {Cli.Sql(PathIn("Stage.saved.dll"))})");
        live.Q("select bp_set(resolve('Sample.MemberCard::Checksum', NULL, 2))");
        Assert.Contains("STAGE.SAVED.DLL", File.ReadAllText(xml).ToUpperInvariant());
        live.Q("select close(2)");
        // its breakpoint stays in dnSpy: a closed module cannot be named, but what was written for it is not taken back
        live.Q("select bp_set(resolve('Sample.MemberCard::IsValid', NULL, 1))");
        Assert.Contains("STAGE.SAVED.DLL", File.ReadAllText(xml).ToUpperInvariant());
        Assert.Equal(2, live.Long("select count(*) from breakpoints"));
        // undo: the breakpoints are annotations and go back; the rename was module 2's, which is gone, so undo says so
        Assert.Equal(1, live.Long("select undo()"));
        Assert.Equal(1, live.Long("select undo()"));
        Assert.Contains("module 2, which close() removed", live.Error("select undo()"));
        Assert.Equal(0, live.Long("select undo()"));

        // an edit later in the same statement keeps the module open; close_all closes what it can and names the rest
        var copy = PathIn("Copy.dll");
        File.Copy(carrier, copy);
        Assert.Equal(3, live.Long($"select open({Cli.Sql(copy)})"));
        var same = live.Envelope("select close(3), set_body_stub(resolve('Sample.MemberCard::Checksum', NULL, 3), 0)");
        Assert.Contains("module 3 not closed: edited in the same statement", Notice(same));
        Assert.Equal(new object?[] { 1L, 3L }, live.Rows("select id from modules order by id").Select(r => r[0]).ToArray());
        var all = live.Envelope("select close_all()");
        Assert.Contains("module 3 left open: unsaved edits", Notice(all));
        Assert.Equal(new object?[] { 3L }, live.Rows("select id from modules").Select(r => r[0]).ToArray());

        live.Q("select set_setting('max_modules', 1)");
        Assert.Contains("close() the ones you are done with", live.Error($"select open({Cli.Sql(PathIn("Stage.saved.dll"))})"));
    }

    [Fact]
    public void Resolve_prefers_the_current_module_and_says_when_a_name_is_in_several()
    {
        var copy = PathIn("Copy.dll");
        File.Copy(Sample, copy);
        using var live = new Live(Sample, "--no-project");
        live.Q($"select open({Cli.Sql(copy)})");
        var first = live.Envelope("select module_of(resolve('Sample.Defaults'))");
        Assert.Contains("is in modules 1 and 2", Notice(first));
        Assert.Equal(1, live.Long("select module_of(resolve('Sample.Defaults'))"));
        live.Q("select use_module(2)");
        Assert.Equal(2, live.Long("select module_of(resolve('Sample.Defaults'))"));
        Assert.Equal(1, live.Long("select module_of(resolve('Sample.Defaults', NULL, 1))"));
    }

    [Fact]
    public void Decompile_module_stops_between_types_within_the_timeout()
    {
        // a 2 s timeout leaves nothing past the 2 s safety margin: each call decompiles one more type, says what to do, and
        // the next goes on (the decompiler is warmed up first, without a timeout)
        using var live = new Live(Sample, "--no-project");
        live.Q("select length(decompile(handle)) from types where name = 'Program'");
        live.Q("select set_setting('query_timeout_ms', 2000)");
        int Done(string text)
        {
            var m = System.Text.RegularExpressions.Regex.Match(text, @"stopped after (\d+) of (\d+) types");
            Assert.True(m.Success, text[^Math.Min(text.Length, 400)..]);
            Assert.Contains("run it again to go on", text);
            return int.Parse(m.Groups[1].Value);
        }
        int first = Done((string)live.Scalar("select decompile_module()")!);
        Assert.True(first >= 1);
        Assert.True(Done((string)live.Scalar("select decompile_module()")!) > first);
        using var plain = new Live(Sample, "--no-project");
        Assert.DoesNotContain("stopped after", (string)plain.Scalar("select decompile_module()")!);
    }

    [Fact]
    public void A_wrong_column_name_gets_the_near_ones()
    {
        Assert.Contains("modules has file_name", Cli.Run(Sample, "select file from modules").Error);
        Assert.Contains("types has full_name", Cli.Run(Sample, "select t.fullname from types t").Error);
    }
}
