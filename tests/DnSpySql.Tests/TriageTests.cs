// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Text.Json;

namespace DnSpySql.Tests;

/// <summary>field_inits, split_text, open_bytes, embedded_pes and the async call-graph link, on the sample's plain classes.</summary>
public sealed class TriageTests : SampleTest
{
    [Fact]
    public void Field_inits_read_what_a_static_constructor_stores()
    {
        var rows = Run("select field_name, kind, value, is_default from field_inits where type_name = 'Sample.Defaults'").Rows()
            .ToDictionary(x => x.GetProperty("field_name").GetString()!.Split("::")[1], x => x);
        Assert.Equal("City Library", rows["Title"].GetProperty("value").GetString());
        Assert.Equal(5, rows["MaxLoans"].GetProperty("value").GetInt64());
        Assert.Equal("bool", rows["Reminders"].GetProperty("kind").GetString());
        Assert.Equal(1, rows["Reminders"].GetProperty("value").GetInt64());
        Assert.Equal("string[]", rows["Branches"].GetProperty("kind").GetString());
        Assert.Equal(["North", "South"], JsonSerializer.Deserialize<string[]>(rows["Branches"].GetProperty("value").GetString()!));
        Assert.Equal("bytes", rows["Pattern"].GetProperty("kind").GetString());
        Assert.Equal(1, rows["Motto"].GetProperty("is_default").GetInt64()); // static string Motto = "": the compiler's store of the default
    }

    [Fact]
    public void Triage_summarizes_a_module_in_one_json_object()
    {
        var r = Run("select triage()", "select value from binary where key = 'sha256'", "select triage(1) = triage()");
        var t = JsonDocument.Parse(r.Text(0)).RootElement;
        Assert.Equal(r.Text(1), t.GetProperty("module").GetProperty("sha256").GetString());
        Assert.Contains(t.GetProperty("entry_points").EnumerateArray(), e => e.GetProperty("name").GetString()!.Contains("Program::Main"));
        foreach (var key in new[] { "protections", "embedded_pes", "capabilities", "next" })
            Assert.Equal(JsonValueKind.Array, t.GetProperty(key).ValueKind);
        // the settings class of the sample is the first config candidate, with its values
        var config = t.GetProperty("config_candidates");
        Assert.True(config.GetProperty("total").GetInt32() >= config.GetProperty("shown").GetInt32());
        Assert.Contains(config.GetProperty("items").EnumerateArray(),
            c => c.GetProperty("type").GetString() == "Sample.Defaults" && c.GetProperty("field").GetString() == "Title"
                 && c.GetProperty("value").GetString() == "City Library");
        Assert.DoesNotContain(config.GetProperty("items").EnumerateArray(), c => c.GetProperty("field").GetString() == "Motto"); // a default store
        Assert.Contains(t.GetProperty("next").EnumerateArray(), n => n.GetString()!.Contains("decompile(resolve('Sample.Defaults'))"));
        Assert.Equal(0, t.GetProperty("decrypted").GetProperty("call_sites").GetInt32());
        Assert.Equal(1, r.Long(2));
    }

    [Fact]
    public void Embedded_pes_reassemble_a_payload_split_across_resources()
    {
        // the sample's own bytes as the "payload": three binary pieces in order, and base64 text in three pieces numbered backwards
        var pe = File.ReadAllBytes(Sample);
        int third = pe.Length / 3;
        byte[][] bin = [pe[..third], pe[third..(2 * third)], pe[(2 * third)..]];
        var b64 = Convert.ToBase64String(pe);
        int t3 = b64.Length / 3;
        string[] text = [b64[(2 * t3)..], b64[t3..(2 * t3)], b64[..t3]]; // chunk_0 holds the end
        var sha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(pe)).ToLowerInvariant();
        // (two runs: the pieces travel on the command line, which Windows caps at 32K characters)
        var sql = Enumerable.Range(0, 3).Select(i => $"select add_resource('part{i + 1}', base64_decode('{Convert.ToBase64String(bin[i])}'))").ToList();
        sql.Add("select location, is_dotnet, sha256 from embedded_pes order by location");
        sql.Add("select open_bytes(data, 'joined.dll') is not null from embedded_pes where location like 'resources ''part1''%'");
        var r = Run(sql.ToArray());
        Assert.Contains(r.Rows(-2), x => x.GetProperty("location").GetString() == "resources 'part1'..'part3' (joined)"
                                         && x.GetProperty("is_dotnet").GetInt64() == 1 && x.GetProperty("sha256").GetString() == sha);
        Assert.Equal(1, r.Long(-1));

        sql = Enumerable.Range(0, 3).Select(i => $"select add_resource('chunk_{i}.txt', '{text[i]}')").ToList();
        sql.Add("select location, sha256 from embedded_pes");
        Assert.Contains(Run(sql.ToArray()).Rows(), x => x.GetProperty("location").GetString() == "resources 'chunk_0.txt'..'chunk_2.txt' (joined in reverse order, base64)"
                                                       && x.GetProperty("sha256").GetString() == sha);

        // a gap in the numbering is not one payload
        var gap = Run($"select add_resource('p1', base64_decode('{Convert.ToBase64String(bin[0])}'))",
                      $"select add_resource('p3', base64_decode('{Convert.ToBase64String(bin[2])}'))",
                      "select count(*) from embedded_pes where location like '%''p1''..%'"); // (p1 alone still shows: it starts with the PE headers)
        Assert.Equal(0, gap.Long());
    }

    [Fact]
    public void Guides_are_readable_with_sql()
    {
        var r = Run("select topic, title, length(text) as n from dnspysql_guides", "select text from dnspysql_guides where topic = 'basics'",
                    "select count(*) from dnspysql_guides where topic = 'nope'");
        Assert.Equal(["basics", "explore", "triage", "unpack", "dnspy"], r.Rows(0).Select(x => x.GetProperty("topic").GetString()));
        Assert.All(r.Rows(0), x => Assert.True(x.GetProperty("n").GetInt64() > 500));
        Assert.StartsWith("# dnspysql basics", r.Text(1));
        Assert.Equal(0, r.Long(2));
    }

    [Fact]
    public void Field_init_bytes_come_from_the_field_data()
    {
        Assert.Equal("0102030405060708090A0B0C0D0E0F10",
            Run("select hex(value) from field_inits where field_name like '%Sample.Defaults::Pattern'").Text());
    }

    [Fact]
    public void Split_text_cuts_at_the_separator()
    {
        Assert.Equal("a+b+c", Run("select group_concat(value, '+') from split_text where text = 'a|b|c' and separator = '|'").Text());
    }

    [Fact]
    public void Async_methods_link_to_their_state_machine()
    {
        var r = Run("select count(*) from xrefs where from_method = resolve('Sample.Async::Compute') and kind = 'async'",
                    "select count(*) from callers where method = resolve('Sample.Async::Twice') and caller_name like '%Compute%'");
        Assert.Equal(1, r.Long(0));
        Assert.True(r.Long(1) >= 1); // Twice is called from MoveNext, which Compute starts
    }

    [Fact]
    public void Open_bytes_of_a_native_pe_is_null_with_a_note()
    {
        // MZ, a PE header (AMD64, PE32+), 16 data directories, no CLR directory
        var pe = new byte[0x200];
        pe[0] = (byte)'M'; pe[1] = (byte)'Z';
        BitConverter.GetBytes(0x40).CopyTo(pe, 0x3C);
        pe[0x40] = (byte)'P'; pe[0x41] = (byte)'E';
        BitConverter.GetBytes((ushort)0x8664).CopyTo(pe, 0x44);
        BitConverter.GetBytes((ushort)0x20B).CopyTo(pe, 0x58);
        BitConverter.GetBytes(16).CopyTo(pe, 0x58 + 0x70 - 4);
        var r = Cli.Run(Sample, $"select open_bytes(x'{Convert.ToHexString(pe)}', 'native.dll') is null");
        Assert.True(r.Exit == 0, r.Error);
        Assert.Equal(1, r.Values()[0].GetInt64());
        Assert.Contains("native", r.Error); // the note
    }

    [Fact]
    public void Embedded_pes_are_carved_with_their_size()
    {
        // a resource holding a .NET module (the sample's own bytes): one row, its size from the headers, opened as is
        var bytes = File.ReadAllBytes(Sample);
        using var live = new Live(Sample, "--no-project");
        live.Q($"INSERT INTO resources(name, data) VALUES ('copy.dll', x'{Convert.ToHexString(bytes)}')");
        var row = live.Rows("select location, size, is_dotnet, kind from embedded_pes where location like '%copy.dll%'").Single();
        Assert.Equal(bytes.Length, Convert.ToInt64(row[1]));
        Assert.Equal(1L, Convert.ToInt64(row[2]));
        Assert.True(Convert.ToInt64(live.Scalar("select open_bytes(data, 'carved.dll') from embedded_pes where location like '%copy.dll%'")) >= 2);
    }

    [Fact]
    public void A_huge_literal_does_not_stall_iocs()
    {
        // "a.a.a...": every position a word boundary, the shape that made the e-mail pattern quadratic
        var huge = string.Concat(Enumerable.Repeat("a.", 150_000));
        using var live = new Live(Sample, "--no-project");
        live.Q($"select add_type('public static class Huge {{ public static string S = \"{huge}\"; }}')");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        live.Q("select count(*) from iocs");
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"iocs took {sw.Elapsed}");
    }
}
