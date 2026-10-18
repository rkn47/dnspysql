// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

namespace DnSpySql.Tests;

public sealed class DecompileTests : SampleTest
{
    string Type(string name) => Run($"select decompile(token) from types where name = '{name}'").Text();

    [Fact]
    public void Decompiles_types_like_dnspy()
    {
        var card = Type("MemberCard");
        Assert.Contains("public sealed class MemberCard", card);
        Assert.Contains("// Token: 0x", card); // dnSpy's token comments
        Assert.Contains("Checksum(", card);
        Assert.Contains("\"LIB-\"", card);
        Assert.Contains("public enum Color", Type("Color"));
    }

    [Fact]
    public void Reconstructs_async_methods()
    {
        // Needs Task<T> and the method builder to resolve, i.e. the .NET shared framework on the search path.
        var text = Type("Async");
        Assert.Contains("public static async Task<int> Compute(int x)", text);
        Assert.Contains("await Task.Delay(1);", text);
        Assert.DoesNotContain("t__builder", text);
    }

    [Fact]
    public void Decompiles_members_il_and_the_whole_module()
    {
        var r = Run("select decompile(token) from methods where name = 'IsValid'",
                    "select decompile(token, NULL, 'il') from methods where name = 'IsValid'",
                    "select il_text(token) from methods where name = 'IsValid'",
                    "select decompile_module()");
        Assert.Contains("public bool IsValid()", r.Text(0));
        Assert.Contains("ldstr", r.Text(1));
        Assert.Equal(r.Text(1), r.Text(2));
        Assert.Contains("class MemberCard", r.Text(3));
        Assert.Contains("enum Color", r.Text(3));
    }

    [Fact]
    public void Edits_show_up_in_later_decompiles()
    {
        var r = Run("select decompile(token) from methods where name = 'IsValid'",
                    "update methods set name = 'ComputeChecksum' where name = 'Checksum'",
                    "select decompile(token) from methods where name = 'IsValid'");
        Assert.Contains("Checksum(", r.Text(0));
        Assert.DoesNotContain("ComputeChecksum", r.Text(0));
        Assert.Contains("ComputeChecksum(", r.Text(1)); // the cached text of IsValid was dropped by the edit
    }

    [Fact]
    public void A_broken_method_body_costs_only_that_method()
    {
        // A method body that cannot be read; the type still decompiles.
        var bytes = File.ReadAllBytes(Sample);
        using (var pe = new PEReader(new MemoryStream(bytes)))
        {
            var md = pe.GetMetadataReader();
            var getKey = md.MethodDefinitions.Select(md.GetMethodDefinition).Single(m => md.GetString(m.Name) == "get_Number");
            var rva = getKey.RelativeVirtualAddress;
            var sec = pe.PEHeaders.SectionHeaders.Single(s => rva >= s.VirtualAddress && rva < s.VirtualAddress + s.VirtualSize);
            bytes[rva - sec.VirtualAddress + sec.PointerToRawData] = 0x00; // neither a tiny nor a fat header
        }
        File.WriteAllBytes(Sample, bytes);
        var text = Type("MemberCard");
        Assert.Contains("class MemberCard", text);
        Assert.Contains("public bool IsValid()", text);
        Assert.Contains("Checksum(", text);
    }
}
