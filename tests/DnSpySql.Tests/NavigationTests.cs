// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
namespace DnSpySql.Tests;

/// <summary>Addressing entities: handles as text, resolve() on overloads, and callers through virtual dispatch.</summary>
public sealed class NavigationTests : SampleTest
{
    [Fact]
    public void Tok_output_is_accepted_back_as_a_handle()
    {
        var r = Run("select tok(resolve('Sample.Square::Area'))");
        var text = r.Text();
        Assert.Matches("^0x1_06[0-9A-F]{6}$", text);
        var back = Run($"select name_of({Cli.Sql(text)})", $"select count(*) from methods where handle = {Cli.Sql(text)}",
                       $"select count(*) from pseudocode where handle = {Cli.Sql(text)}");
        Assert.Equal("System.Double Sample.Square::Area()", back.Text(0));
        Assert.Equal(1, back.Long(1));
        Assert.Equal(1, back.Long(2));
        // the token part is read as a token even with fewer digits; a malformed value is no handle at all
        var odd = Run("select name_of('0x1_6000001'), name_of('0x1_2_3'), name_of('0x_06000001')");
        Assert.Equal("System.Int32 Sample.Program::Main(System.String[])", odd.Values()[0].GetString());
        Assert.Equal(System.Text.Json.JsonValueKind.Null, odd.Values()[1].ValueKind);
        Assert.Equal(System.Text.Json.JsonValueKind.Null, odd.Values()[2].ValueKind);
    }

    [Fact]
    public void Resolve_names_overloads_and_says_when_a_name_is_ambiguous()
    {
        // an overload, saved so it has a token of its own (members added in a session have none until saved)
        var saved = PathIn("Overloads.dll");
        Cli.Run(Sample, "select add_members(resolve('Sample.Shapes'), 'public static string Name(object o, int n) => null;')",
                $"select save({Cli.Sql(saved)})").Ok();
        var r = Cli.Run(saved,
            "select 1",
            "select name_of(resolve('Sample.Shapes::Name'))",
            "select name_of(resolve('Sample.Shapes::Name(System.Object,System.Int32)'))",
            "select name_of(resolve('Sample.Shapes::Name(Sample.Shape)'))",
            "select resolve('Sample.Shapes::Name(System.String)')").Ok();
        Assert.Equal("System.String Sample.Shapes::Name(Sample.Shape)", r.Text(1));
        Assert.Equal("System.String Sample.Shapes::Name(System.Object,System.Int32)", r.Text(2));
        Assert.Equal("System.String Sample.Shapes::Name(Sample.Shape)", r.Text(3));
        Assert.Equal(System.Text.Json.JsonValueKind.Null, r.Scalar(4).ValueKind);
        // the note names the overload to write instead
        Assert.Contains("matches 2 methods", r.Error);
        Assert.Contains("'Sample.Shapes::Name(System.Object,System.Int32)'", r.Error);
        // a unique name, or one given with its parameters, has no note
        Assert.DoesNotContain("resolve:", Cli.Run(saved, "select resolve('Sample.Shapes::Total')", "select resolve('Sample.Shapes::Name(Sample.Shape)')").Ok().Error);
    }

    [Fact]
    public void Callers_include_calls_that_dispatch_through_base_and_interface_slots()
    {
        var r = Run("select caller_name, via from callers where method = resolve('Sample.Square::Area') order by caller_name",
                    "select slot_name, via, caller_name from dispatch_calls where method = resolve('Sample.Square::Area') order by caller_name",
                    "select via from callers where method = resolve('Sample.Shape::Area')",
                    "select count(*) from callers where method = resolve('Sample.Square::Describe') and caller_name like '%Square::Describe%'");
        var callers = r.Rows(0).Select(x => (x.GetProperty("caller_name").GetString()!, x.GetProperty("via").GetString()!)).ToList();
        // Direct(Square) calls Shape::Area and Total(IShape) calls IShape::Area: both can run Square.Area
        Assert.Contains(callers, c => c.Item1.Contains("Shapes::Direct") && c.Item2 == "virtual");
        Assert.Contains(callers, c => c.Item1.Contains("Shapes::Total") && c.Item2 == "interface");
        Assert.Contains(r.Rows(1), x => x.GetProperty("slot_name").GetString() == "System.Double Sample.IShape::Area()");
        // the slot itself is called directly
        Assert.Contains(r.Rows(2), x => x.GetProperty("via").GetString() == "direct");
        // base.Describe() is a plain call of Shape::Describe: it cannot dispatch back to the override
        Assert.Equal(0, r.Long(3));
        // a filter that names no method matches nothing, as before
        Assert.Equal(0, Run("select count(*) from callers where method = 0").Long());
        Assert.Equal(0, Run("select count(*) from callers where method = resolve('Sample.Square')").Long());
    }
}
