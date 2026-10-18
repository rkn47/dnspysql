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
