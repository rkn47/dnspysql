// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
namespace DnSpySql.Tests;

/// <summary>
/// The shared mechanisms behind several tables: the interpreter's environment model, one reader of call arguments
/// (constant arithmetic folded), calls through proxies, and the one test for library code.
/// </summary>
public sealed class GeneralizationTests : SampleTest
{
    [Fact]
    public void The_environment_model_is_one_list_and_a_table()
    {
        var r = Run(Fixture.AddType("""
            public static class Env
            {
                public static string Go()
                {
                    System.Threading.Thread.Sleep(5000);   // time only: returns at once
                    return System.Environment.UserName + "|" + typeof(Env).Assembly.Location;
                }
            }
            """),
            "select emulate(resolve('Env::Go'))",
            "select count(*) from emulator_model where area = 'environment' and name like '%Thread::Sleep(%'",
            "select kind, answer from emulator_model where name = 'P/Invoke IsDebuggerPresent'",
            "select count(*) from emulator_model where area = 'allowlist' and name = 'System.Text.StringBuilder'",
            "select count(*) from emulator_model where area = 'nondeterministic'");
        Assert.Equal(@"%USERNAME%|%APPDIR%\Sample.dll", r.Text(1));
        Assert.Equal(2, r.Long(2));
        Assert.Equal(["no debugger", "0"], r.Values(3).Select(v => v.GetString()!).ToArray());
        Assert.Equal(1, r.Long(4));
        Assert.True(r.Long(5) >= 5);
        // what would end the process is still refused, with the reason
        Assert.Contains("would end the process", Cli.Run(Sample, Fixture.AddType("public static class Bye { public static int Go() { System.Environment.Exit(1); return 0; } }"),
                                                       "select emulate(resolve('Bye::Go'))").Error);
    }

    [Fact]
    public void Arithmetic_on_constants_is_an_argument_like_a_literal()
    {
        // D(1)..D(6), then the first argument rewritten the way obfuscators write a literal: ldc 0x1234; ldc 0x1235; xor (= 1).
        // (C# folds such arithmetic itself, so the fixture is edited in IL.)
        // D(1)'s argument: the instruction before the first call of D (Go builds a string[] for Concat, so the first ldc is its length)
        const string first = "(select idx - 1 from il where method = resolve('Fold::Go') and opcode = 'call' and operand_text like '%Fold::D(%' order by idx limit 1)";
        // the inserts go after the rewritten ldc (an index computed from the call again would move with each insert)
        const string anchor = "(select idx from il where method = resolve('Fold::Go') and opcode = 'ldc.i4' and operand_text = '4660')";
        const string cctor = "(select handle from methods where full_name like '%Fold::.cctor%')";
        const string four = $"(select idx from il where method = {cctor} and opcode = 'ldc.i4' and operand_text = '4')";
        var r = Run(Fixture.AddType("""
            public static class Fold
            {
                public static int K = 5;
                public static string D(int n) => "s" + n;
                public static string Go() => D(1) + D(2) + D(3) + D(4) + D(5) + D(6);
            }
            """),
            $"select il_set(resolve('Fold::Go'), {first}, 'ldc.i4', 4660)",
            $"select il_insert(resolve('Fold::Go'), {anchor} + 1, 'ldc.i4', 4661)",
            $"select il_insert(resolve('Fold::Go'), {anchor} + 2, 'xor')",
            "select args, arg0, plaintext from decryptor_calls where decryptor = resolve('Fold::D') order by offset limit 1",
            "select constant_sites from string_decryptors where method = resolve('Fold::D')",
            // a field stored from arithmetic: K = 4 + 1
            $"select il_set({cctor}, (select idx from il where method = {cctor} and opcode = 'ldc.i4.5'), 'ldc.i4', 4)",
            $"select il_insert({cctor}, {four} + 1, 'ldc.i4', 1)",
            $"select il_insert({cctor}, {four} + 2, 'add')",
            "select value, source from field_inits where field_name like '%Fold::K'",
            // inline_strings puts the plaintext where the whole expression was
            "select inline_strings(1, resolve('Fold::D'))",
            "select count(*) from il where method = resolve('Fold::Go') and opcode = 'xor'");
        var call = r.Values(4);
        Assert.Equal("1", call[0].GetString());
        Assert.Equal(1, call[1].GetInt64());
        Assert.Equal("s1", call[2].GetString());
        Assert.Equal(6, r.Long(5)); // every site constant, the folded one too
        Assert.Equal([5L], r.Values(9).Take(1).Select(v => v.GetInt64()).ToArray());
        Assert.Equal("folded", r.Values(9)[1].GetString());
        Assert.Equal(6, r.Long(10));
        Assert.Equal(0, r.Long(11));
    }

    [Fact]
    public void Calls_through_proxies_name_the_method_behind_them()
    {
        var r = Run(Fixture.AddType("""
            public static class Px
            {
                static string P(int a) => D(a);                 // a proxy: only passes its argument on
                public static string D(int n) => "v" + n;
                public static string Go() => P(1) + P(2);
                public static void Run() => Q(new byte[0]);
                static System.Reflection.Assembly Q(byte[] b) => System.Reflection.Assembly.Load(b);
            }
            """),
            "select dst_name, target_name, proxies from call_edges where src = resolve('Px::Go') and dst_name like '%Px::P(%'",
            "select via, count(*) from callers where method = resolve('Px::D') group by via order by via",
            "select method_name, evidence from capabilities where kind = 'in-memory loading' and method_name like '%Px::%'",
            "select count(*) from call_edges where target = resolve('Px::D')");
        Assert.All(r.Rows(1), x =>
        {
            Assert.Contains("Px::D(", x.GetProperty("target_name").GetString());
            Assert.Equal(1, x.GetProperty("proxies").GetInt64());
        });
        var via = r.Rows(2).ToDictionary(x => x.GetProperty("via").GetString()!, x => x.GetProperty("count(*)").GetInt64());
        Assert.Equal(1, via["direct"]); // P itself
        Assert.Equal(2, via["proxy"]);  // Go, through P
        var cap = r.Rows(3).Single();
        Assert.Contains("Px::Run", cap.GetProperty("method_name").GetString());
        Assert.EndsWith("(through proxy Q)", cap.GetProperty("evidence").GetString());
        Assert.Equal(3, r.Long(4)); // P's call and Go's two
    }

    [Fact]
    public void Library_code_is_one_test_and_capabilities_say_their_basis()
    {
        var r = Run(Fixture.AddType("""
            namespace Newtonsoft.Json.Fake { public static class Lib { public static void Go() => System.Diagnostics.Process.Start("x"); } }
            public static class Own { public static void Go() => System.Diagnostics.Process.Start("schtasks /create"); }
            """),
            "select method_name, is_library, basis from capabilities where method_name like '%::Go()%' order by method_name, basis");
        var rows = r.Rows().Select(x => $"{x.GetProperty("method_name").GetString()!.Split(' ')[1]} {x.GetProperty("is_library").GetInt64()} {x.GetProperty("basis").GetString()}").ToList();
        Assert.Contains("Newtonsoft.Json.Fake.Lib::Go() 1 api", rows);
        Assert.Contains("Own::Go() 0 api", rows);
        Assert.Contains("Own::Go() 0 string", rows); // "schtasks": a judgment from a literal, not a call
    }

    [Fact]
    public void Bool_settings_take_their_words_and_keep_1_or_0()
    {
        var r = Run("select set_setting('decompiler_show_tokens', 'yes')", "select value from runtime_settings where key = 'decompiler_show_tokens'",
                    "select set_setting('max_modules', '0x10')", "select value from runtime_settings where key = 'max_modules'");
        Assert.Equal("1", r.Text(1));
        Assert.Equal("16", r.Text(3));
        Assert.Contains("needs 1 or 0", Cli.Run(Sample, "select set_setting('save_sidecars', 'maybe')").Error);
    }
}
