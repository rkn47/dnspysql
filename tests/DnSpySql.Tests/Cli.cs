// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace DnSpySql.Tests;

static class TestEnvironment
{
    // Every dnspysql the tests start inherits this: never touch the developer's real dnSpy.xml (tests that exercise the
    // sync pass --dnspy-xml with a file of their own).
    [System.Runtime.CompilerServices.ModuleInitializer]
    internal static void Init() => Environment.SetEnvironmentVariable("DNSPYSQL_DNSPY_XML", "off");
}

/// <summary>The result of one dnspysql run: one JSON result set per statement that returned rows.</summary>
public sealed record Result(int Exit, List<JsonElement> Sets, string Error)
{
    public Result Ok()
    {
        Assert.True(Exit == 0, $"dnspysql exited with {Exit}: {Error}");
        return this;
    }

    public List<JsonElement> Rows(int set = -1) => Sets[set < 0 ? Sets.Count + set : set].GetProperty("rows").EnumerateArray().ToList();

    /// <summary>A row's values in column order (the JSON objects' keys are sorted, so their order is not the query's).</summary>
    public JsonElement[] Values(int set = -1, int row = 0)
    {
        var s = Sets[set < 0 ? Sets.Count + set : set];
        var r = Rows(set)[row];
        return s.GetProperty("columns").EnumerateArray().Select(c => r.GetProperty(c.GetString()!)).ToArray();
    }

    /// <summary>The first column of the first row of a result set (the last one by default).</summary>
    public JsonElement Scalar(int set = -1) => Values(set)[0];

    public string Text(int set = -1) => Scalar(set).GetString()!;
    public long Long(int set = -1) => Scalar(set).GetInt64();
}

public static class Cli
{
    static readonly Lazy<string> exe = new(Find);

    public static string Exe => exe.Value;

    static string Find()
    {
        if (Environment.GetEnvironmentVariable("DNSPYSQL") is { Length: > 0 } env) return env;
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
        {
            if (!File.Exists(Path.Combine(dir.FullName, "CMakeLists.txt"))) continue;
            foreach (var rel in new[] { "build/dnspysql", "build/dnspysql.exe", "build/Release/dnspysql.exe" })
                if (File.Exists(Path.Combine(dir.FullName, rel))) return Path.Combine(dir.FullName, rel);
            throw new InvalidOperationException($"dnspysql is not built under {dir.FullName}/build: run ./build.sh (or set DNSPYSQL)");
        }
        throw new InvalidOperationException("repository root not found; set DNSPYSQL to the dnspysql binary");
    }

    /// <summary>Runs the statements in one session (one process) and parses every result set.</summary>
    public static Result Run(IEnumerable<string> assemblies, params string[] sql)
    {
        var psi = new ProcessStartInfo(Exe) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var o in new[] { "--no-project", "--format", "json" }) psi.ArgumentList.Add(o);
        foreach (var s in sql) { psi.ArgumentList.Add("-c"); psi.ArgumentList.Add(s); }
        foreach (var a in assemblies) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var stderr = p.StandardError.ReadToEndAsync();
        var stdout = p.StandardOutput.ReadToEnd();
        if (!p.WaitForExit(TimeSpan.FromMinutes(5))) { p.Kill(true); throw new TimeoutException(string.Join("; ", sql)); }
        var (sets, errors) = ParseAll(stdout);
        return new Result(p.ExitCode, sets, string.Join("\n", new[] { stderr.Result.Trim() }.Concat(errors).Where(e => e.Length > 0)));
    }

    public static Result Run(string assembly, params string[] sql) => Run([assembly], sql);

    /// <summary>The text output of one statement in a given format (table, csv, ...).</summary>
    public static string RunText(string assembly, string format, string sql)
    {
        var psi = new ProcessStartInfo(Exe) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var a in new[] { "--no-project", "--format", format, "-c", sql, assembly }) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var stderr = p.StandardError.ReadToEndAsync();
        var stdout = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        _ = stderr.Result;
        return stdout;
    }

    // The JSON output is one envelope per -c. Each statement that returned columns becomes a result set of
    // {columns, rows: [{column: value}]}; statement errors are collected.
    static (List<JsonElement> sets, List<string> errors) ParseAll(string text)
    {
        var sets = new List<JsonElement>();
        var errors = new List<string>();
        var bytes = Encoding.UTF8.GetBytes(text).AsSpan();
        while (true)
        {
            int start = bytes.IndexOfAnyExcept(" \t\r\n"u8);
            if (start < 0) break;
            bytes = bytes[start..];
            var reader = new Utf8JsonReader(bytes);
            var env = JsonElement.ParseValue(ref reader);
            bytes = bytes[(int)reader.BytesConsumed..];
            foreach (var r in env.GetProperty("results").EnumerateArray())
            {
                if (!r.GetProperty("success").GetBoolean()) { errors.Add(r.GetProperty("error").GetString() ?? ""); continue; }
                var cols = r.GetProperty("columns").EnumerateArray().Select(c => c.GetString()!).ToList();
                if (cols.Count == 0) continue;
                var rows = new System.Text.Json.Nodes.JsonArray();
                foreach (var row in r.GetProperty("rows").EnumerateArray())
                {
                    var o = new System.Text.Json.Nodes.JsonObject();
                    int i = 0;
                    foreach (var v in row.EnumerateArray()) o[cols[i++]] = System.Text.Json.Nodes.JsonNode.Parse(v.GetRawText());
                    rows.Add(o);
                }
                var set = new System.Text.Json.Nodes.JsonObject { ["columns"] = new System.Text.Json.Nodes.JsonArray(cols.Select(c => (System.Text.Json.Nodes.JsonNode?)c).ToArray()), ["rows"] = rows };
                sets.Add(JsonDocument.Parse(set.ToJsonString()).RootElement);
            }
        }
        return (sets, errors);
    }

    public static string Sql(string s) => "'" + s.Replace("'", "''") + "'";
}

/// <summary>A temporary directory holding a fresh copy of the sample assembly; removed after the test.</summary>
public abstract class SampleTest : IDisposable
{
    protected readonly string Dir = Path.Combine(Path.GetTempPath(), "dnspysql-tests-" + Guid.NewGuid().ToString("N"));
    protected readonly string Sample;

    protected SampleTest()
    {
        Directory.CreateDirectory(Dir);
        Sample = Path.Combine(Dir, "Sample.dll");
        File.Copy(Path.Combine(AppContext.BaseDirectory, "sample", "Sample.dll"), Sample);
    }

    public void Dispose()
    {
        try { Directory.Delete(Dir, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    protected Result Run(params string[] sql) => Cli.Run(Sample, sql).Ok();

    protected string PathIn(string name) => Path.Combine(Dir, name);
}
