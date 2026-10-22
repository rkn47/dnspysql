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
