// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
namespace DnSpySql.Tests;

public sealed class EditTests : SampleTest
{
    [Fact]
    public void Saved_edits_survive_a_reload()
    {
        var saved = PathIn("Sample.patched.dll");
        Run("update methods set name = 'ComputeChecksum' where name = 'Checksum'",
            "select stub_return(token, 1) from methods where name = 'IsValid'",
            "select replace_string('LIB-1234', 'LIB-0000')",
            "select add_resource('extra.bin', x'DEADBEEF')",
            "select set_assembly('Patched', '2.0.0.0')",
            $"select save({Cli.Sql(saved)})");
        var r = Cli.Run(saved,
            "select count(*) from methods where name = 'ComputeChecksum'",
            "select decompile(token) from methods where name = 'IsValid'",
            "select count(*) from user_strings where value = 'LIB-0000'",
            "select hex(data) from resources where name = 'extra.bin'",
            "select assembly || ' ' || version from modules").Ok();
        Assert.Equal(1, r.Long(0));
        Assert.Contains("return true;", r.Text(1));
        Assert.Equal(1, r.Long(2));
        Assert.Equal("DEADBEEF", r.Text(3));
        Assert.Equal("Patched 2.0.0.0", r.Text(4));
    }

    [Fact]
    public void A_session_can_be_locked_read_only_but_not_unlocked()
    {
        using var live = new Live(Sample, "--no-project");
        live.Q("update methods set name = 'Before' where name = 'Roll'");
        Assert.Equal(1, live.Long("select set_setting('read_only', 0)")); // already writable: nothing to do
        live.Q("select set_setting('read_only', 1)");
        Assert.Equal("1", live.Scalar("select value from runtime_settings where key = 'read_only'"));
        Assert.Contains("read-only", live.Error("update methods set name = 'After' where name = 'Before'"));
        Assert.Contains("read-only", live.Error("select stub_return(resolve('Sample.Dice::Before'), 1)"));
        Assert.Contains("can only be switched on", live.Error("select set_setting('read_only', 0)"));
        Assert.Equal(1, live.Long("select count(*) from methods where name = 'Before'"));
    }

    [Fact]
    public void Undo_reverts_renames_of_locals_and_resources()
    {
        const string local = "select name from locals where method = resolve('Sample.MemberCard::Checksum') and idx = 1";
        var r = Run("update locals set name = 'before' where method = resolve('Sample.MemberCard::Checksum') and idx = 1",
            "update locals set name = 'after' where method = resolve('Sample.MemberCard::Checksum') and idx = 1", "select undo(1)", local,
            "select add_resource('a.bin', x'00')", "update resources set name = 'b.bin', visibility = 'private' where name = 'a.bin'",
            "select undo(1)", "select name, visibility from resources where name like '_.bin'");
        Assert.Equal("before", r.Text(1));
        Assert.Equal(new[] { "a.bin", "public" }, r.Values(4).Select(v => v.GetString()));
    }

    [Fact]
    public void Il_edits_keep_offsets_and_branches_consistent()
    {
        var r = Run(
            "select count(*) from il where method_token = (select token from methods where name = 'Checksum')",
            "select il_insert((select token from methods where name = 'Checksum'), 0, 'nop')",
            "select il_set((select token from methods where name = 'Checksum'), 0, 'nop')",
            "select count(*), min(offset), sum(opcode = 'nop') from il where method_token = (select token from methods where name = 'Checksum')",
            "select il_remove((select token from methods where name = 'Checksum'), 0)",
            "select count(*) from il where method_token = (select token from methods where name = 'Checksum')",
            "select decompile(token) from methods where name = 'Checksum'");
        long before = r.Long(0);
        var after = r.Values(3).Select(v => v.GetInt64()).ToArray();
        Assert.Equal(before + 1, after[0]);
        Assert.Equal(0, after[1]);
        Assert.True(after[2] >= 1);
        Assert.Equal(before, r.Long(5));
        Assert.Contains("& 255", r.Text(6));
    }

    [Fact]
    public void Edit_type_recompiles_a_class()
    {
        var r = Run(
            "select edit_type((select token from types where name = 'MemberCard'), "
            + Cli.Sql("""
                using System;
                namespace Sample {
                    public sealed class MemberCard {
                        const string Prefix = "LIB-";
                        public MemberCard(string number) { Number = number; }
                        public string Number { get; }
                        public bool IsValid() => true;
                        static int Checksum(string s) => 42;
                        public event EventHandler? Expired;
                        internal void Expire() => Expired?.Invoke(this, EventArgs.Empty);
                        public sealed class Nested { public static readonly int[] Table = new int[] { 1 }; }
                    }
                }
                """) + ")",
            "select decompile(token) from methods where name = 'Checksum'");
        Assert.Contains("return 42;", r.Text(-1));
    }

    [Fact]
    public void Edit_type_round_trips_decompiled_text()
    {
        // dnSpy prints a type without its namespace block; edit_type puts it back in the original namespace.
        var r = Run("SELECT edit_type(handle, replace(decompile(handle), '\"not accepted\"', '\"NOT ACCEPTED\"')) FROM types WHERE name = 'Program'",
                    "SELECT decompile(handle) FROM methods WHERE name = 'Main'");
        Assert.Contains("NOT ACCEPTED", r.Text(-1));
    }

    [Fact]
    public void Add_type_references_the_sdk_reference_pack()
    {
        // Compiled against the reference pack like a normal build: System.Runtime, never System.Private.CoreLib.
        var saved = PathIn("added.dll");
        Run("SELECT add_type('namespace Sample.Extra { public static class Twice { public static int Of(int x) => x * 2; } }')",
            $"SELECT save({Cli.Sql(saved)})");
        var refs = Cli.Run(saved, "SELECT group_concat(name) FROM asmrefs").Ok().Text();
        Assert.Contains("System.Runtime", refs);
        Assert.DoesNotContain("System.Private.CoreLib", refs);
    }

    [Fact]
    public void Undo_and_redo_reach_edits_made_before_a_whole_module_edit()
    {
        // add_type restructures the module; the rename before it must still undo and redo across it.
        const string check = "select count(*) from methods where name = 'Check'";
        const string zed = "select count(*) from types where name = 'Zed'";
        var r = Run("update methods set name = 'Check' where name = 'Checksum'",
            "select add_type('public class Zed { public int X() { return 1; } }')",
            "select undo(1)", zed, check,
            "select undo(1)", check, "select count(*) from methods where name = 'Checksum'",
            "select redo(2)", check, zed,
            "select decompile(resolve('Sample.MemberCard::IsValid')) like '%Check(%'"); // result sets: the UPDATE returns none
        Assert.Equal(0, r.Long(2));
        Assert.Equal(1, r.Long(3));
        Assert.Equal(0, r.Long(5));
        Assert.Equal(1, r.Long(6));
        Assert.Equal(2, r.Long(7));
        Assert.Equal(1, r.Long(8));
        Assert.Equal(1, r.Long(9));
        Assert.Equal(1, r.Long(10));
    }

    [Fact]
    public void A_failed_whole_module_edit_leaves_the_module_clean()
    {
        // a dirty module's breakpoints are left out of dnSpy.xml: a typo in add_type must not make it dirty
        using var live = new Live(Sample, "--no-project");
        Assert.NotNull(live.Error("select add_type('public class {')"));
        Assert.Equal(0, live.Long("select value from binary where key = 'dirty'"));
        Assert.Equal(0, live.Long("select undo(1)"));
    }

    [Fact]
    public void Annotations_do_not_invalidate_the_model()
    {
        // comments, tags and breakpoints live in the project file: the model revision (and the xref index built on it)
        // stays; a rename moves it on.
        const string rev = "select value from binary where key = 'revision'";
        var r = Run(rev, "select set_comment(resolve('Sample.MemberCard::IsValid'), 'checks the number'), tag(resolve('Sample.MemberCard'), 'cards'), "
                         + "bp_set(resolve('Sample.MemberCard::IsValid'))", rev,
                    "update methods set name = 'Check' where name = 'Checksum'", rev, "select count(*) from callers where method = resolve('Sample.MemberCard::Check')");
        Assert.Equal(r.Text(0), r.Text(2));
        Assert.NotEqual(r.Text(2), r.Text(3));
        Assert.Equal(1, r.Long(4));
    }

    [Fact]
    public void Delete_removes_rows()
    {
        var r = Run("select count(*) from resources", "delete from resources where name = 'Sample.readme.txt'", "select count(*) from resources");
        Assert.Equal(r.Long(0) - 1, r.Long(1));
    }
}
