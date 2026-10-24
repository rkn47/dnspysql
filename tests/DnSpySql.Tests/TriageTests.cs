// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
namespace DnSpySql.Tests;

/// <summary>The workflow guides, the async call-graph link, and opening a decoded blob as a module.</summary>
public sealed class TriageTests : SampleTest
{
    [Fact]
    public void Guides_are_readable_with_sql()
    {
        var r = Run("select topic, title, length(text) as n from dnspysql_guides", "select text from dnspysql_guides where topic = 'basics'",
                    "select count(*) from dnspysql_guides where topic = 'nope'");
        Assert.Equal(["basics", "explore", "dnspy"], r.Rows(0).Select(x => x.GetProperty("topic").GetString()));
        Assert.All(r.Rows(0), x => Assert.True(x.GetProperty("n").GetInt64() > 500));
        Assert.StartsWith("# DnSpySql basics", r.Text(1));
        Assert.Equal(0, r.Long(2));
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
}
