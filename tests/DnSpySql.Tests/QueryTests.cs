// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

namespace DnSpySql.Tests;

public sealed class QueryTests : SampleTest
{
    // System.Reflection.Metadata reads the same file independently of dnlib, as an oracle for row counts.
    (int types, int methods, int fields, int strings) Oracle()
    {
        using var pe = new PEReader(File.OpenRead(Sample));
        var md = pe.GetMetadataReader();
        // the heap ends with padding that reads as empty entries; an empty string ("") before that is a real one
        var lengths = new List<int>();
        for (var h = MetadataTokens.UserStringHandle(1); !h.IsNil; h = md.GetNextHandle(h)) lengths.Add(md.GetUserString(h).Length);
        while (lengths.Count > 0 && lengths[^1] == 0) lengths.RemoveAt(lengths.Count - 1);
        int strings = lengths.Count;
        return (md.TypeDefinitions.Count - 1, md.MethodDefinitions.Count, md.FieldDefinitions.Count, strings); // minus <Module>
    }

    [Fact]
    public void Il_idx_lookups_answer_neighbours()
    {
        // idx = n and ranges are answered by the table: a self-join on the next instruction is one lookup per row
        var r = Run("select count(*) from il where method = resolve('Sample.MemberCard::Checksum')",
                    "select count(*) from il a join il b on b.method = a.method and b.idx = a.idx + 1 where a.method = resolve('Sample.MemberCard::Checksum')",
                    "select count(*) from il where method = resolve('Sample.MemberCard::Checksum') and idx between 2 and 4");
        Assert.Equal(r.Long(0) - 1, r.Long(1));
        Assert.Equal(3, r.Long(2));
    }

    [Fact]
    public void Row_counts_match_the_metadata()
    {
        var (types, methods, fields, strings) = Oracle();
        var r = Run("select (select count(*) from types where name <> '<Module>'), (select count(*) from methods), "
                    + "(select count(*) from fields), (select count(*) from user_strings)");
        var row = r.Values().Select(v => v.GetInt64()).ToArray();
        Assert.Equal(new long[] { types, methods, fields, strings }, row);
    }

    [Fact]
    public void Count_star_agrees_with_a_full_scan_and_with_limit()
    {
        var r = Run("select count(*) from methods", "select token from methods", "select token from methods limit 3",
                    "select token from methods limit 2 offset 4");
        Assert.Equal(r.Long(0), r.Rows(1).Count);
        Assert.Equal(r.Rows(1).Take(3).Select(x => x.GetProperty("token").GetInt64()), r.Rows(2).Select(x => x.GetProperty("token").GetInt64()));
        Assert.Equal(r.Rows(1).Skip(4).Take(2).Select(x => x.GetProperty("token").GetInt64()), r.Rows(3).Select(x => x.GetProperty("token").GetInt64()));
    }

    [Fact]
    public void Equality_lookups_and_joins_agree_with_scans()
    {
        var r = Run(
            "select token from methods where full_name = 'System.Boolean Sample.MemberCard::IsValid()'",
            "select t.name, count(*) n from types t join methods m on m.type_token = t.token group by t.name order by t.name",
            "select t.name, count(*) n from types t, methods m where m.type_token + 0 = t.token + 0 group by t.name order by t.name",
            "select count(*) from methods where token in (select token from methods where name like 'get_%')",
            "select count(*) from methods where name like 'get_%'");
        long isValid = r.Long(0);
        Assert.Equal(0x06000000, isValid & 0x7F000000);
        var byToken = Run($"select name from methods where token = {isValid}");
        Assert.Equal("IsValid", byToken.Text());
        Assert.Equal(r.Sets[2].GetRawText(), r.Sets[1].GetRawText()); // pushed-down join == unindexed join
        Assert.Equal(r.Long(4), r.Long(3));
    }

    [Fact]
    public void Lists_pinvokes_resources_strings_and_attributes()
    {
        var r = Run(
            "select dll, entry from pinvokes order by entry",
            "select name, size from resources",
            "select count(*) from user_strings where value = 'LIB-1234'",
            "select count(*) from attributes where attribute like '%ObsoleteAttribute' and args like '%demo attribute%'",
            "select count(*) from refs where kind = 'string' and target like '%accepted%'");
        Assert.Equal(new[] { "GetTickCount", "MessageBoxW" }, r.Rows(0).Select(x => x.GetProperty("entry").GetString()));
        var res = r.Rows(1).Single(x => x.GetProperty("name").GetString() == "Sample.readme.txt");
        Assert.Equal("Sample.readme.txt", res.GetProperty("name").GetString());
        Assert.Equal(new FileInfo(Path.Combine(AppContext.BaseDirectory, "../../../../corpus/Sample/readme.txt")).Length, res.GetProperty("size").GetInt64());
        Assert.Equal(1, r.Long(2));
        Assert.Equal(1, r.Long(3));
        Assert.Equal(2, r.Long(4)); // "accepted" and "not accepted"
    }

    [Fact]
    public void Il_rows_cover_each_body()
    {
        var r = Run("select instructions, il_size from methods where name = 'Checksum'",
                    "select count(*), max(offset + size) from il where method_token = (select token from methods where name = 'Checksum')");
        var m = r.Rows(0)[0];
        var il = r.Values(1).Select(v => v.GetInt64()).ToArray();
        Assert.Equal(m.GetProperty("instructions").GetInt64(), il[0]);
        Assert.Equal(m.GetProperty("il_size").GetInt64(), il[1]);
    }

    [Fact]
    public void Sql_errors_are_reported_with_a_nonzero_exit()
    {
        var r = Cli.Run(Sample, "select * from no_such_table");
        Assert.NotEqual(0, r.Exit);
        Assert.Contains("no_such_table", r.Error);
        r = Cli.Run(Sample, "select decompile(0x7F000001)");
        Assert.NotEqual(0, r.Exit);
    }

    [Fact]
    public void Mcp_server_answers_tool_calls()
    {
        var psi = new System.Diagnostics.ProcessStartInfo(Cli.Exe) { RedirectStandardInput = true, RedirectStandardOutput = true, UseShellExecute = false };
        psi.ArgumentList.Add("--mcp");
        psi.ArgumentList.Add(Sample);
        using var p = System.Diagnostics.Process.Start(psi)!;
        string Call(string json)
        {
            p.StandardInput.WriteLine(json);
            p.StandardInput.Flush();
            return p.StandardOutput.ReadLine()!;
        }
        Assert.Contains("dnspysql", Call("""{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"""));
        p.StandardInput.WriteLine("""{"jsonrpc":"2.0","method":"notifications/initialized"}""");
        var tools = Call("""{"jsonrpc":"2.0","id":2,"method":"tools/list"}""");
        Assert.Contains("\"sql\"", tools);
        var call = Call("""{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sql","arguments":{"query":"select name from methods where name = 'IsValid'"}}}""");
        Assert.Contains("IsValid", call);
        p.StandardInput.Close();
        Assert.True(p.WaitForExit(30_000));
    }
}
