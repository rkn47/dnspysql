// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
namespace DnSpySql.Tests;

/// <summary>emulate(): a static method's result computed by interpreting its IL, never by running it.</summary>
public sealed class EmulatorTests : SampleTest
{
    [Fact]
    public void A_static_method_is_computed_from_its_il()
    {
        // ('a' & 0xFF) = 97, then (97 * 31 + 'b') & 0xFF = 33
        Assert.Equal(33, Run("select emulate(resolve('Sample.MemberCard::Checksum'), 'ab')").Long(0));
    }

    [Fact]
    public void A_random_value_is_refused()
    {
        Assert.Contains("differs on every run", Cli.Run(Sample, "select emulate(resolve('Sample.Dice::Roll'))").Error);
    }

    [Fact]
    public void What_would_touch_the_system_is_refused_not_run()
    {
        Assert.Contains("not on the allowlist", Cli.Run(Sample, "select emulate(resolve('Sample.Greeter::Say'), 'you')").Error);
        Assert.Contains("no IL body", Cli.Run(Sample, "select emulate(resolve('Sample.Native::GetTickCount'))").Error);
    }

    [Fact]
    public void Framework_work_is_bounded_before_it_runs()
    {
        // a key derivation of two billion iterations is one framework call: refused up front, not left to hang the query
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var r = Cli.Run(Sample, "select add_type('public static class Slow { public static byte[] K(string pw) { " +
            "var d = new System.Security.Cryptography.Rfc2898DeriveBytes(pw, new byte[8], 2000000000, System.Security.Cryptography.HashAlgorithmName.SHA256); " +
            "return d.GetBytes(16); } }')", "select emulate(resolve('Slow::K'), 'pw')");
        Assert.Contains("iterations", r.Error);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(30), $"took {sw.Elapsed}");
    }

    [Fact]
    public void Stack_memory_and_block_copies_are_interpreted()
    {
        // stackalloc (localloc) filled in a loop; then two placeholder calls become cpblk and initblk, which C# never emits
        const string blocks = "select idx from il where method = resolve('Scratch::Blocks') and opcode = 'call' and operand_text like ";
        var r = Run("select add_type('public static unsafe class Scratch { " +
                    "public static int Sum(int n) { byte* p = stackalloc byte[32]; for (int i = 0; i < 32; i++) p[i] = (byte)(i * 7 + n); " +
                    "int s = 0; for (int i = 0; i < 32; i++) s = s * 31 + p[i]; return s; } " +
                    "public static int Blocks() { byte* a = stackalloc byte[16]; byte* b = stackalloc byte[16]; for (int i = 0; i < 16; i++) a[i] = (byte)(i + 1); " +
                    "Copy(b, a, 16); Fill(a, 90, 4); int s = 0; for (int i = 0; i < 16; i++) s = s * 31 + a[i] * 3 + b[i]; return s; } " +
                    "static void Copy(byte* d, byte* s, int n) { } static void Fill(byte* d, int v, int n) { } }')",
            $"select il_set(resolve('Scratch::Blocks'), ({blocks}'%Copy%'), 'cpblk')",
            $"select il_set(resolve('Scratch::Blocks'), ({blocks}'%Fill%'), 'initblk')",
            "select emulate(resolve('Scratch::Sum'), 5)", "select emulate(resolve('Scratch::Blocks'))");
        int sum = 0;
        for (int i = 0; i < 32; i++) sum = sum * 31 + (byte)(i * 7 + 5);
        Assert.Equal(sum, r.Long(3));
        var a = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();
        var b = (byte[])a.Clone();
        for (int i = 0; i < 4; i++) a[i] = 90;
        int s = 0;
        for (int i = 0; i < 16; i++) s = s * 31 + a[i] * 3 + b[i];
        Assert.Equal(s, r.Long(4));
        Assert.Contains("localloc of", Cli.Run(Sample, "select add_type('public static unsafe class Huge { public static int M() { byte* p = stackalloc byte[64 << 20]; return p[0]; } }')",
            "select emulate(resolve('Huge::M'))").Error);
    }

    [Fact]
    public void A_type_that_is_its_own_base_is_seen_once()
    {
        var cyc = Cli.Run(Sample,
            "select add_type('namespace Rv { public class Cyc { public int Foo() => 1; public static int Run(Cyc c) => c.Foo(); public static int Go() { var c = new Cyc(); return Run(c); } } }')",
            "update types set base_type_name = 'Rv.Cyc' where full_name = 'Rv.Cyc'",
            "select emulate(resolve('Rv.Cyc::Go'))");
        Assert.True(cyc.Exit == 0, cyc.Error);
        Assert.Equal(1, cyc.Values()[0].GetInt64());
    }
}
