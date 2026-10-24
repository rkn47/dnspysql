// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
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
        Assert.Equal(["North", "South"], JsonSerializer.Deserialize<string[]>(rows["Branches"].GetProperty("value").GetString()!)!);
        Assert.Equal("bytes", rows["Pattern"].GetProperty("kind").GetString());
        Assert.Equal(1, rows["Motto"].GetProperty("is_default").GetInt64()); // static string Motto = "": the compiler's store of the default
    }

    static readonly string TargetDll = Path.Combine(AppContext.BaseDirectory, "sample", "SampleTarget.dll");

    [Fact]
    public void Methods_virtualized_into_one_dispatcher_are_named()
    {
        // a dispatcher with a 60-way switch in a loop (the handlers), and twelve methods that only hand it an id and their arguments
        var cases = string.Join(" ", Enumerable.Range(0, 60).Select(k => $"case {k}: acc += {k + 1}; break;"));
        var stubs = string.Join(" ", Enumerable.Range(0, 12).Select(i => $"public static int Fn{i}(int a, int b) => (int)Shield.Vm.Run({i}, new object[] {{ a, b }});"));
        var r = Run($"select add_type('namespace Shield {{ public static class Vm {{ public static object Run(int id, object[] args) {{ int acc = 0; " +
                    $"for (int i = 0; i < 3; i++) {{ switch (id + i) {{ {cases} }} }} return acc + (int)args[0]; }} }} }} " +
                    $"public static class Virt {{ {stubs} }}')",
            "select name, confidence, evidence, handle = resolve('Shield.Vm::Run') from protections where kind = 'virtualization'",
            "select decompile(resolve('Virt::Fn3'))", "select triage()");
        var v = r.Values(1);
        Assert.Equal("Shield", v[0].GetString());
        Assert.Equal("high", v[1].GetString());
        Assert.StartsWith("12 of ", v[2].GetString());
        Assert.Equal(1, v[3].GetInt64());
        Assert.Contains("// dnspysql: virtualized: this body only calls System.Object Shield.Vm::Run(System.Int32,System.Object[]) with id 3", r.Text(2));
        var list = JsonDocument.Parse(r.Text(3)).RootElement.GetProperty("next").EnumerateArray().Select(x => x.GetString()!).Single(n => n.Contains("virtualized into"));
        Assert.StartsWith("SELECT caller_name FROM callers WHERE method = ", list);
    }

    [Fact]
    public void An_assembly_without_code_points_at_the_code_it_carries()
    {
        var carrier = PathIn("Carrier.dll");
        var shell = PathIn("Shell.dll");
        Run($"INSERT INTO resources(name, data) VALUES ('stage.dll', x'{Convert.ToHexString(File.ReadAllBytes(TargetDll))}')", $"select save({Cli.Sql(carrier)})");
        // every method row's RVA set to 0: types and resources, but no method body
        Cli.Run(carrier, "update md_rows set value = 0 where table_name = 'Method' and column = 'RVA'", $"select save_raw({Cli.Sql(shell)})").Ok();
        var r = Cli.Run(shell, "select evidence from protections where kind = 'stub assembly'", "select triage()").Ok();
        Assert.StartsWith("no code in this assembly (", r.Text(0));
        Assert.Contains("the largest .NET PE it carries is in resource 'stage.dll'", r.Text(0));
        var first = JsonDocument.Parse(r.Text(1)).RootElement.GetProperty("next")[0].GetString()!;
        Assert.StartsWith("SELECT open_bytes(data) FROM embedded_pes WHERE module = 1 AND is_dotnet ORDER BY size DESC LIMIT 1", first);
        Assert.Equal(2, Cli.Run(shell, first[..first.IndexOf("  --", StringComparison.Ordinal)]).Ok().Long());
    }

    [Fact]
    public void A_native_file_can_be_searched_for_the_pes_it_carries()
    {
        // a native-looking PE (the stage's headers without the CLR directory) with the .NET stage right after it
        var stage = File.ReadAllBytes(TargetDll);
        var stub = stage[..0x200];
        int pe = BitConverter.ToInt32(stub, 0x3C), opt = pe + 0x18;
        int clr = opt + (BitConverter.ToUInt16(stub, opt) == 0x20B ? 0x70 : 0x60) + 14 * 8;
        Array.Clear(stub, clr, 8);
        var dropper = PathIn("dropper.bin");
        File.WriteAllBytes(dropper, [.. stub, .. stage]);
        Assert.Contains("FROM carve_file WHERE path = ", Cli.Run(Sample, $"select open({Cli.Sql(dropper)})").Error);
        var r = Run($"select offset, is_dotnet from carve_file where path = {Cli.Sql(dropper)} order by offset",
            $"select open_bytes(data) from carve_file where path = {Cli.Sql(dropper)} and is_dotnet");
        Assert.Equal(new[] { "0 0", "512 1" }, r.Rows(0).Select(x => $"{x.GetProperty("offset").GetInt64()} {x.GetProperty("is_dotnet").GetInt64()}"));
        Assert.Equal(2, r.Long(1));
    }

    [Fact]
    public void Triage_writes_values_json_cannot_hold_as_text()
    {
        var r = Run("select add_type('public static class Limits { public static double Top = double.PositiveInfinity, Gap = double.NaN, " +
                    "Low = double.NegativeInfinity, One = 1.5; }')", "select triage()");
        var items = JsonDocument.Parse(r.Text(1)).RootElement.GetProperty("config_candidates").GetProperty("items").EnumerateArray()
            .Where(c => c.GetProperty("type").GetString() == "Limits").ToDictionary(c => c.GetProperty("field").GetString()!, c => c.GetProperty("value"));
        Assert.Equal("Infinity", items["Top"].GetString());
        Assert.Equal(1.5, items["One"].GetDouble());
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
        Assert.Contains(t.GetProperty("next").EnumerateArray(), n => n.GetString()!.Contains("-- Sample.Defaults: the type with the most stored constants"));
        // static: no interpreted section, and nothing for the interpreting queries to do in this sample
        Assert.False(t.TryGetProperty("decrypted", out _));
        Assert.False(t.TryGetProperty("iocs", out _));
        Assert.Equal(0, t.GetProperty("settings_decoders").GetProperty("total").GetInt32());
        Assert.DoesNotContain(t.GetProperty("next").EnumerateArray(), n => n.GetString()!.Contains("decryptor_calls"));
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
        Assert.StartsWith("# DnSpySql basics", r.Text(1));
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
        // the sample's own bytes: module 1 was edited (the resource added), so they open as a pristine copy of it; once
        // open, the same bytes again are that module
        Assert.Equal(2L, Convert.ToInt64(live.Scalar("select open_bytes(data, 'carved.dll') from embedded_pes where location like '%copy.dll%'")));
        Assert.Equal(2L, Convert.ToInt64(live.Scalar("select open_bytes(data, 'again.dll') from embedded_pes where module = 1 and location like '%copy.dll%'")));
    }

    [Fact]
    public void A_huge_literal_does_not_stall_triage()
    {
        // a 300 KB literal: capabilities, field_inits and string_args read every literal
        var huge = string.Concat(Enumerable.Repeat("a.", 150_000));
        using var live = new Live(Sample, "--no-project");
        live.Q($"select add_type('public static class Huge {{ public static string S = \"{huge}\"; }}')");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        live.Q("select triage()");
        live.Q("select count(string_args) from call_edges");
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"triage took {sw.Elapsed}");
    }

    [Fact]
    public void With_emulation_off_nothing_is_interpreted()
    {
        using var live = new Live(Sample, "--no-project", "--no-emulation");
        Assert.Equal("0", live.Scalar("select value from runtime_settings where key = 'emulation'"));
        Assert.Contains("emulation is off", live.Error("select emulate(resolve('Sample.MemberCard::Checksum'), 'ab')"));
        Assert.Contains("needs 1 or 0", live.Error("select set_setting('emulation', 'maybe')"));
        live.Q("select set_setting('emulation', 'on')");
        Assert.Equal("1", live.Scalar("select value from runtime_settings where key = 'emulation'"));
        Assert.Equal(33L, live.Long("select emulate(resolve('Sample.MemberCard::Checksum'), 'ab')"));
    }
}
