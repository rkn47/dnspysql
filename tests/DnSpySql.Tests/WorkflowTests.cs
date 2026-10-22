// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Text.Json;

namespace DnSpySql.Tests;

/// <summary>
/// Following the guided workflow across modules: triage's next queries, stages opened from embedded PEs, names that
/// several modules share, decrypted strings put back into the code.
/// </summary>
public sealed class WorkflowTests : SampleTest
{
    static readonly string TargetDll = Path.Combine(AppContext.BaseDirectory, "sample", "SampleTarget.dll");

    static string? Notice(JsonElement envelope) =>
        envelope.GetProperty("results").EnumerateArray().Last().TryGetProperty("notice", out var n) ? n.GetString() : null;

    [Fact]
    public void Each_stage_triage_suggests_opens_once_and_names_its_origin()
    {
        // a sample carrying a .NET stage in a resource, saved so the stage is in its file
        var carrier = PathIn("Carrier.dll");
        Run($"INSERT INTO resources(name, data) VALUES ('stage.dll', x'{Convert.ToHexString(File.ReadAllBytes(TargetDll))}')", $"select save({Cli.Sql(carrier)})");
        using var live = new Live(carrier, "--no-project");
        var next = JsonDocument.Parse((string)live.Scalar("select triage()")!).RootElement.GetProperty("next").EnumerateArray().Select(x => x.GetString()!).ToList();
        var open = next.Single(n => n.Contains("open_bytes"));
        Assert.DoesNotContain("stage2.dll", open); // a fixed name fails on a sample's second stage
        var sql = open[..open.IndexOf("  --", StringComparison.Ordinal)];
        var id = live.Long(sql);
        Assert.Equal(2, id);
        Assert.Equal(id, live.Long(sql)); // the same suggestion again: the same module, no copy
        var again = live.Envelope("select open_bytes(data, 'other.dll') from embedded_pes where module = 1 and is_dotnet");
        Assert.Contains("same bytes are open as module 2", Notice(again));
        Assert.Equal(2, live.Long("select count(*) from modules"));
        Assert.Equal(new object?[] { "bytes", 1L }, live.Rows("select origin, derived_from from modules where id = 2").Single());
        Assert.Equal(new object?[] { "file", null }, live.Rows("select origin, derived_from from modules where id = 1").Single());
    }

    [Fact]
    public void Opening_every_stage_of_a_scan_survives_its_later_batches()
    {
        // 80 different .NET stages (one DOS-stub byte apart): the host reads a scan in batches of 64, then more, and each
        // open_bytes() adds a module while the scan over the module list is still going
        var carrier = PathIn("Carrier.dll");
        Run($"INSERT INTO resources(name, data) VALUES ('stage0.dll', x'{Convert.ToHexString(File.ReadAllBytes(TargetDll))}')",
            "CREATE TEMP TABLE src AS SELECT data FROM resources WHERE name = 'stage0.dll'",
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 79) INSERT INTO resources(name, data) " +
            "SELECT 'stage' || i || '.dll', concat_bytes(substr(data, 1, 78), unhex(printf('%02X', i)), substr(data, 80)) FROM n, src",
            $"select save({Cli.Sql(carrier)})");
        using (var live = new Live(carrier, "--no-project"))
        {
            Assert.Equal(80, live.Long("select count(open_bytes(data)) from embedded_pes where module = 1 and is_dotnet"));
            Assert.Equal(81, live.Long("select count(*) from modules"));
        }
        // no module filter: the scan walks the module list itself
        var copy = PathIn("Copy.dll");
        File.Copy(carrier, copy);
        using var both = new Live(carrier, "--no-project");
        both.Q($"select open({Cli.Sql(copy)})");
        Assert.Equal(160, both.Long("select count(open_bytes(data)) from embedded_pes where is_dotnet"));
        Assert.Equal(82, both.Long("select count(*) from modules"));
    }

    [Fact]
    public void A_stage_names_the_module_it_came_out_of_also_compressed_or_decoded_by_hand()
    {
        var stage = File.ReadAllBytes(TargetDll);
        using var gz = new MemoryStream();
        using (var z = new System.IO.Compression.GZipStream(gz, System.IO.Compression.CompressionLevel.SmallestSize)) z.Write(stage);
        var half = PathIn("Half.dll");
        var carrier = PathIn("Carrier.dll");
        Run($"INSERT INTO resources(name, data) VALUES ('stage.gz', x'{Convert.ToHexString(gz.ToArray())}')", $"select save({Cli.Sql(half)})");
        var other = (byte[])stage.Clone();
        other[78] ^= 1; // another stage (a DOS-stub byte apart), so it is not the gzip one
        Cli.Run(half, $"INSERT INTO resources(name, data) VALUES ('stage.bin', xor(x'{Convert.ToHexString(other)}', 90))", $"select save({Cli.Sql(carrier)})").Ok();
        using var live = new Live(carrier, "--no-project");
        // gzip: embedded_pes inflates it, so the stage's bytes are nowhere in the file as they are
        Assert.Equal(2, live.Long("select open_bytes(data) from embedded_pes where module = 1 and is_dotnet"));
        Assert.Equal(1, live.Long("select derived_from from modules where id = 2"));
        live.Q("select close(2)");
        // xor-encoded: decoded by hand, so only the caller knows where it came from
        Assert.Null(live.Scalar("select derived_from from modules where id = (select open_bytes(xor(data, 90), 'by-hand.dll') from resources where name = 'stage.bin')"));
        live.Q("select close(3)");
        Assert.Equal(1, live.Long("select derived_from from modules where id = (select open_bytes(xor(data, 90), 'by-hand.dll', 0, 1) from resources where name = 'stage.bin')"));
    }

    [Fact]
    public void Close_takes_a_sample_and_its_stages_out_and_never_reuses_their_ids()
    {
        var carrier = PathIn("Carrier.dll");
        Run($"INSERT INTO resources(name, data) VALUES ('stage.dll', x'{Convert.ToHexString(File.ReadAllBytes(TargetDll))}')", $"select save({Cli.Sql(carrier)})");
        using var live = new Live(carrier, "--no-project");
        const string openStage = "select open_bytes(data) from embedded_pes where module = 1 and is_dotnet";
        Assert.Equal(2, live.Long(openStage));
        Assert.Equal("[2]", live.Scalar("select close(2, 0)"));
        Assert.Equal(1, live.Long("select count(*) from modules"));
        Assert.Contains("module 2 was closed", live.Error("select resolve('SampleTarget.Program', NULL, 2)"));
        Assert.Contains("module 2 was closed", live.Error("select decompile(handle(2, 0x02000002))"));
        Assert.Equal(3, live.Long(openStage)); // a new id: a handle kept from module 2 must not reach this one
        var closed = live.Envelope("select close(1)"); // the sample and the stage that came out of it
        Assert.Equal("[1,3]", closed.GetProperty("results")[0].GetProperty("rows")[0][0].GetString());
        Assert.Contains("close: closed modules 1, 3", Notice(closed));
        Assert.Equal(0, live.Long("select count(*) from modules"));
        Assert.Equal(4, live.Long($"select open({Cli.Sql(carrier)})"));
    }

    [Fact]
    public void Close_keeps_unsaved_work_annotations_and_the_undo_history_safe()
    {
        using (var project = new Live(Sample))
            Assert.Contains("holds the session's project file", project.Error("select close(1)"));

        var carrier = PathIn("Carrier.dll");
        Run($"INSERT INTO resources(name, data) VALUES ('stage.dll', x'{Convert.ToHexString(File.ReadAllBytes(TargetDll))}')", $"select save({Cli.Sql(carrier)})");
        var xml = PathIn("dnSpy.xml");
        using var live = new Live(carrier, "--no-project", "--dnspy-xml", xml);
        live.Q("select open_bytes(data) from embedded_pes where module = 1 and is_dotnet");
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

        live.Q("select set_setting('max_modules', 1)");
        Assert.Contains("close() the ones you are done with", live.Error($"select open({Cli.Sql(PathIn("Stage.saved.dll"))})"));
    }

    static List<string> Next(Live live, long module) =>
        JsonDocument.Parse((string)live.Scalar($"select triage({module})")!).RootElement.GetProperty("next").EnumerateArray().Select(x => x.GetString()!).ToList();

    static string Statement(string next) => next.IndexOf("  --", StringComparison.Ordinal) is var i and >= 0 ? next[..i] : next;

    [Fact]
    public void Every_triage_suggestion_runs_as_written()
    {
        // a stage, an encrypted-looking resource, and a generic settings class (its field stores name a TypeSpec)
        var carrier = PathIn("Carrier.dll");
        Run($"INSERT INTO resources(name, data) VALUES ('stage.dll', x'{Convert.ToHexString(File.ReadAllBytes(TargetDll))}')",
            "INSERT INTO resources(name, data) SELECT 'blob.bin', unhex(group_concat(x, '')) FROM " +
            "(WITH RECURSIVE h(i, x) AS (SELECT 0, sha256('seed') UNION ALL SELECT i + 1, sha256(x) FROM h WHERE i < 255) SELECT x FROM h)",
            "select add_type('namespace Sample { public static class Gen<T> { public static string A = \"a1\", B = \"b1\", C = \"c1\", D = \"d1\", " +
            "E = \"e1\", F = \"f1\", G = \"g1\", H = \"h1\"; } }')",
            $"select save({Cli.Sql(carrier)})");
        using var live = new Live(carrier, "--no-project");
        var first = Next(live, 1);
        Assert.Contains(first, n => n.StartsWith("SELECT text FROM dnspysql_guides WHERE topic = 'unpack'  -- resource 'blob.bin' is high entropy"));
        var decompile = first.Single(n => n.Contains("the type with the most stored constants"));
        Assert.Contains("-- Sample.Gen`1:", decompile);
        Assert.Contains("class Gen<T>", (string)live.Scalar(Statement(decompile))!);
        Assert.DoesNotContain(first, n => n.Contains("close(")); // its stage is not open yet
        foreach (var module in new long[] { 1, 2 }) // the stage the open_bytes() suggestion opens, too
            foreach (var n in module == 1 ? first : Next(live, module))
                Assert.True(live.Error(Statement(n)) is null, $"{n}\n=> {live.Error(Statement(n))}");
        // the stage's last suggestion closed it: nothing was left to open or decrypt
        Assert.Equal(new object?[] { 1L }, live.Rows("select id from modules").Select(r => r[0]).ToArray());
    }

    [Fact]
    public void Triage_points_at_types_by_handle()
    {
        var next = JsonDocument.Parse(Run("select triage()").Text()).RootElement.GetProperty("next").EnumerateArray().Select(x => x.GetString()!).ToList();
        var decompile = next.Single(n => n.Contains("the type with the most stored constants"));
        Assert.Contains("-- Sample.Defaults:", decompile);
        Assert.DoesNotContain("resolve(", decompile); // a name can be in several modules
        Assert.Contains("class Defaults", Run(decompile[..decompile.IndexOf("  --", StringComparison.Ordinal)]).Text());
        Assert.DoesNotContain(next, n => n.Contains("untamper")); // nothing is encrypted
    }

    [Fact]
    public void A_name_in_a_suggested_query_stays_on_its_comment_line()
    {
        // a sample's type name with a line break would end the -- comment and run what follows as a statement
        var r = Run("update types set name = 'Defaults' || char(10) || 'select save(''x.dll'') --' where full_name = 'Sample.Defaults'", "select triage()");
        var decompile = JsonDocument.Parse(r.Text()).RootElement.GetProperty("next").EnumerateArray().Select(x => x.GetString()!)
            .Single(n => n.Contains("the type with the most stored constants"));
        Assert.DoesNotContain("\n", decompile);
        Assert.Contains("\\u000A", decompile);
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
    public void A_pe_inside_another_carve_names_its_container()
    {
        // outer: a module holding another in a resource, appended to the sample as an overlay
        var outer = PathIn("Outer.dll");
        Run($"INSERT INTO resources(name, data) VALUES ('inner.dll', x'{Convert.ToHexString(File.ReadAllBytes(TargetDll))}')", $"select save({Cli.Sql(outer)})");
        var dropper = PathIn("Dropper.dll");
        File.WriteAllBytes(dropper, [.. File.ReadAllBytes(Sample), .. File.ReadAllBytes(outer)]);
        long at = new FileInfo(Sample).Length;
        var rows = Cli.Run(dropper, "select offset, parent_offset from embedded_pes where module = 1 and location = 'overlay' order by offset").Ok().Rows();
        Assert.Equal(2, rows.Count);
        Assert.Equal(at, rows[0].GetProperty("offset").GetInt64());
        Assert.Equal(JsonValueKind.Null, rows[0].GetProperty("parent_offset").ValueKind);
        Assert.Equal(at, rows[1].GetProperty("parent_offset").GetInt64());
    }

    [Fact]
    public void Inline_strings_puts_the_plaintexts_into_the_code_as_one_undoable_step()
    {
        // F: both arms of the conditional reach one call, so its argument is not one literal: left as it is.
        // G: a method group (ldnull; ldftn D) passes no arguments, so it is no call site.
        var r = Run("select add_type('public static class Enc { public static string D(int k) => new string((char)(97 + k), 3); } " +
                    "public static class Use { public static string A() => Enc.D(1); public static string B() => Enc.D(2); " +
                    "public static string C() => Enc.D(3) + Enc.D(4); public static string E() => Enc.D(5); " +
                    "public static string F(bool c) => Enc.D(c ? 6 : 7); public static System.Func<int, string> G() => Enc.D; }')",
            "select count(*) from decryptor_calls where emulation = 'ok'",
            "select inline_strings()",
            "select decompile(resolve('Use::C'))",
            "select count(*) from decryptor_calls where decryptor = resolve('Enc::D')", // (too few sites left to rank as a decryptor)
            "select decompile(resolve('Use::F')) || decompile(resolve('Use::G'))",
            "select undo()",
            "select decompile(resolve('Use::C'))");
        Assert.Equal(6, r.Long(1)); // A..E, and F's arm that ends at the call
        Assert.Equal(5, r.Long(2));
        Assert.Contains("\"ddd\"", r.Text(3));
        Assert.Contains("\"eee\"", r.Text(3));
        Assert.DoesNotContain("Enc.D", r.Text(3));
        Assert.Equal(1, r.Long(4)); // F's
        Assert.Contains("Enc.D(A_0 ? 6 : 7)", r.Text(5));
        Assert.Contains("Enc.D", r.Text(5).Split("G(")[1]);
        Assert.Contains("Enc.D(3)", r.Text(7));
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
