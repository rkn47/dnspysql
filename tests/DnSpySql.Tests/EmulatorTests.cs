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
    public void Float_branches_treat_nan_as_unordered()
    {
        // `if (a < b)` skips its block with bge.un (taken for NaN), `if (!(a >= b))` with bge (not taken for NaN): every
        // comparison with NaN is false, whichever branch the compiler picked
        var methods = new (string Name, string Cond, int Nan)[]
        {
            ("Lt", "a < b", 20), ("Gt", "a > b", 20), ("Le", "a <= b", 20), ("Ge", "a >= b", 20),
            ("NotLt", "!(a < b)", 10), ("NotGt", "!(a > b)", 10), ("NotLe", "!(a <= b)", 10), ("NotGe", "!(a >= b)", 10),
        };
        var body = string.Join(" ", methods.Select(m =>
            $"public static int {m.Name}(double a, double b) {{ if ({m.Cond}) return 10; return 20; }} " +
            $"public static int {m.Name}Nan() => {m.Name}(double.NaN, 1.0); public static int {m.Name}One() => {m.Name}(1.0, 2.0);"));
        var r = Run(new[] { $"select add_type('public static class Fp {{ {body} }}')" }
            .Concat(methods.SelectMany(m => new[] { $"select emulate(resolve('Fp::{m.Name}Nan'))", $"select emulate(resolve('Fp::{m.Name}One'))" }))
            .Append("select group_concat(opcode, ' ') from il where method in (resolve('Fp::Lt'), resolve('Fp::NotGe'))")
            .ToArray());
        // the branches under test are the ones the compiler emitted
        Assert.Matches(@"\bbge\.un", r.Text());
        Assert.Matches(@"\bbge(\.s)?\b(?!\.un)", r.Text());
        for (int i = 0; i < methods.Length; i++)
        {
            var (name, cond, nan) = methods[i];
            // result set 0 is add_type's
            Assert.True(nan == r.Long(1 + 2 * i), $"{name} ({cond}) with NaN");
            bool lt = name.EndsWith("Lt") || name.EndsWith("Le"), one = name.StartsWith("Not") ? !lt : lt; // 1.0 against 2.0
            Assert.True((one ? 10 : 20) == r.Long(2 + 2 * i), $"{name} ({cond}) with 1, 2");
        }
    }

    [Fact]
    public void A_method_that_spins_on_every_call_is_tried_a_few_times_only()
    {
        // each call loops until the step budget: after three in a row, the other call sites are not interpreted
        var calls = string.Join(" + ", Enumerable.Range(0, 8).Select(i => $"Spin.D({i})"));
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var r = Run($"select add_type('public static class Spin {{ public static string D(int n) {{ long x = n; while (x >= 0) x++; return null; }} " +
                    $"public static string Go() => {calls}; }}')",
                    "select emulation from decryptor_calls where decryptor = resolve('Spin::D') order by offset");
        var status = r.Rows(1).Select(x => x.GetProperty("emulation").GetString()!).ToList();
        Assert.Equal(8, status.Count);
        Assert.All(status.Take(3), s => Assert.StartsWith("stopped after", s));
        Assert.All(status.Skip(3), s => Assert.StartsWith("not interpreted: the last 3 calls of this method each used the whole step budget", s));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(60), $"took {sw.Elapsed}");
    }

    [Fact]
    public void Sizeof_a_type_parameter_is_the_size_of_its_argument()
    {
        // sizeof(T) in generic code (a constant decoder's Get<T> copies sizeof(T) bytes), for primitives and an enum
        var r = Run("select add_type('public enum Small : short { A } public static unsafe class Sz { public static int Size<T>() where T : unmanaged => sizeof(T); " +
                    "public static int Go() => Size<int>() + Size<long>() * 10 + Size<byte>() * 100 + Size<Small>() * 1000; }')",
                    "select emulate(resolve('Sz::Go'))");
        Assert.Equal(4 + 80 + 100 + 2000, r.Long(1));
        // new T[1] is a T[] (Buffer.BlockCopy refuses an object[]): a constant table's Get<T>
        var get = Run("select add_type('public static unsafe class Tbl { public static T Get<T>(byte[] d) where T : unmanaged { var a = new T[1]; " +
                      "System.Buffer.BlockCopy(d, 0, a, 0, sizeof(T)); return a[0]; } " +
                      "public static long Go() => Get<int>(new byte[] { 1, 0, 0, 0 }) + Get<long>(new byte[] { 2, 0, 0, 0, 0, 0, 0, 0 }) * 10; }')",
                      "select emulate(resolve('Tbl::Go'))");
        Assert.Equal(21, get.Long(1));
    }

    [Fact]
    public void The_samples_own_assembly_name_comes_from_its_manifest()
    {
        var r = Run("select add_type('public static class AsmName { public static string Go() { var n = typeof(AsmName).Assembly.GetName(); " +
                    "var full = typeof(AsmName).Assembly.FullName; return n.Name + \" \" + n.Version + \" \" + full.Substring(0, full.IndexOf(System.Convert.ToChar(44))); } " +
                    "public static string Probe() => System.Reflection.AssemblyName.GetAssemblyName(\"x.dll\").Name; }')",
                    "select emulate(resolve('AsmName::Go'))", "select assembly || ' ' || version from modules");
        Assert.Equal(r.Text(2) + " Sample", r.Text(1));
        // reading another file's identity is refused, not done
        Assert.Contains("blocked", Cli.Run(Sample, "select add_type('public static class AsmName { public static string Probe() => " +
                                                   "System.Reflection.AssemblyName.GetAssemblyName(\"x.dll\").Name; }')",
                                           "select emulate(resolve('AsmName::Probe'))").Error);
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
