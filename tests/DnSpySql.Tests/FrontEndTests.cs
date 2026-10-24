// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace DnSpySql.Tests;

/// <summary>The CLI options, output formats, REPL, HTTP API, --remote client and MCP server.</summary>
public sealed class FrontEndTests : SampleTest
{
    static Process Start(IEnumerable<string> args, bool stdin = false)
    {
        var psi = new ProcessStartInfo(Cli.Exe)
        {
            RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = stdin, UseShellExecute = false,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        return Process.Start(psi)!;
    }

    static (int exit, string stdout, string stderr) Exec(params string[] args)
    {
        using var p = Start(args);
        var err = p.StandardError.ReadToEndAsync();
        var outText = p.StandardOutput.ReadToEnd();
        Assert.True(p.WaitForExit(120_000));
        return (p.ExitCode, outText, err.Result);
    }

    [Fact]
    public void Version_names_the_commit_the_binary_was_built_from()
    {
        var (exit, stdout, _) = Exec("--version");
        Assert.Equal(0, exit);
        var m = System.Text.RegularExpressions.Regex.Match(stdout, @"^DnSpySql (\d+\.\d+\.\d+) \(commit ([0-9a-f]{7,}(-dirty)?|unknown), sqlite ");
        Assert.True(m.Success, stdout);
        var r = Run("select value from binary where key = 'tool_version'", "select value from binary where key = 'tool_commit'");
        Assert.Equal(m.Groups[1].Value, r.Text(0));
        Assert.Equal(m.Groups[2].Value, r.Text(1));
    }

    [Fact]
    public void Output_formats_have_their_documented_shapes()
    {
        const string q = "SELECT 1 AS a, 'x,y' AS b, x'00ff' AS c, NULL AS d UNION ALL SELECT 2, 'z', NULL, 1.5";
        var json = JsonDocument.Parse(Exec("--no-project", "--format", "json", "-c", q, Sample).stdout).RootElement;
        Assert.True(json.GetProperty("success").GetBoolean());
        Assert.Equal(1, json.GetProperty("statement_count").GetInt32());
        var r = json.GetProperty("results")[0];
        Assert.Equal(["a", "b", "c", "d"], r.GetProperty("columns").EnumerateArray().Select(c => c.GetString()));
        Assert.Equal(1, r.GetProperty("rows")[0][0].GetInt64());          // typed values, not strings
        Assert.Equal("00ff", r.GetProperty("rows")[0][2].GetString());    // blobs as lowercase hex
        Assert.Equal(JsonValueKind.Null, r.GetProperty("rows")[0][3].ValueKind);
        Assert.Equal(1.5, r.GetProperty("rows")[1][3].GetDouble());
        Assert.Equal(2, r.GetProperty("row_count").GetInt32());

        var jsonl = Exec("--no-project", "--format", "jsonl", "-c", q, Sample).stdout.Trim().Split('\n');
        Assert.Equal(2, jsonl.Length);
        Assert.Equal("x,y", JsonDocument.Parse(jsonl[0]).RootElement.GetProperty("b").GetString());

        var csv = Exec("--no-project", "--format", "csv", "-c", q, Sample).stdout;
        Assert.StartsWith("a,b,c,d\n1,\"x,y\",x'00ff',\n2,z,,1.5", csv);
        var tsv = Exec("--no-project", "--format", "tsv", "-c", q, Sample).stdout;
        Assert.StartsWith("a\tb\tc\td\n1\tx,y\tx'00ff'\t\n", tsv);

        var table = Exec("--no-project", "-c", q, Sample).stdout;
        Assert.Contains("(2 rows)", table);
        Assert.Contains("NULL", table);
    }

    [Fact]
    public void Statements_run_in_order_and_continue_on_error()
    {
        var script = PathIn("script.sql");
        File.WriteAllText(script, "SELECT 'from file' AS f;");
        var r = Exec("--no-project", "--format", "csv", "-c", "SELECT 'first' AS a", "-f", script, "-c", "SELECT 'last' AS z", Sample);
        Assert.Equal(0, r.exit);
        Assert.True(r.stdout.IndexOf("first") < r.stdout.IndexOf("from file") && r.stdout.IndexOf("from file") < r.stdout.IndexOf("last"));

        var stop = Exec("--no-project", "--format", "csv", "-c", "SELECT * FROM nope", "-c", "SELECT 'after' AS a", Sample);
        Assert.Equal(1, stop.exit);
        Assert.DoesNotContain("after", stop.stdout);
        var cont = Exec("--no-project", "--continue", "--format", "csv", "-c", "SELECT * FROM nope", "-c", "SELECT 'after' AS a", Sample);
        Assert.Equal(1, cont.exit);
        Assert.Contains("after", cont.stdout);

        var changed = Exec("--no-project", "-c", "INSERT INTO kv(key, value) VALUES ('a', '1'), ('b', '2')", Sample);
        Assert.Contains("(2 row(s) changed)", changed.stdout);
    }

    [Fact]
    public void Timeout_stops_pure_sql_and_engine_work()
    {
        var sw = Stopwatch.StartNew();
        var r = Exec("--no-project", "--timeout", "1000", "-c", "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT count(*) FROM c", Sample);
        Assert.Contains("interrupted", r.stdout);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(30));
    }

    [Fact]
    public void Repl_runs_dot_commands_and_multi_line_sql()
    {
        using var p = Start(["--no-project", Sample], stdin: true);
        var err = p.StandardError.ReadToEndAsync();
        p.StandardInput.WriteLine(".mode csv");
        p.StandardInput.WriteLine(".tables method");
        p.StandardInput.WriteLine("SELECT name");
        p.StandardInput.WriteLine("FROM methods WHERE name = 'IsValid';");
        p.StandardInput.WriteLine(".functions resolve");
        p.StandardInput.WriteLine(".quit");
        p.StandardInput.Close();
        var outText = p.StandardOutput.ReadToEnd();
        Assert.True(p.WaitForExit(60_000));
        Assert.Contains("methods,metadata,rw", outText);
        Assert.Contains("name\nIsValid", outText);
        Assert.Contains("resolve(", outText);
        Assert.Contains("module(s) loaded", err.Result);
    }

    [Fact]
    public void Http_api_and_remote_client()
    {
        using var server = Start(["--no-project", "--http", "0", "--token", "s3cret", Sample]);
        string? url = null;
        for (var line = server.StandardError.ReadLine(); line != null; line = server.StandardError.ReadLine())
            if (line.Contains("http listening on")) { url = line[line.IndexOf("http://")..].Split(' ')[0]; break; }
        Assert.NotNull(url);
        try
        {
            using var http = new HttpClient { BaseAddress = new Uri(url!) };
            Assert.Equal(System.Net.HttpStatusCode.Unauthorized, http.GetAsync("health").Result.StatusCode);
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "s3cret");
            Assert.Contains("\"ok\":true", http.GetStringAsync("health").Result);

            var raw = JsonDocument.Parse(http.PostAsync("query", new StringContent("SELECT count(*) AS n FROM types; SELECT 2")).Result.Content.ReadAsStringAsync().Result).RootElement;
            Assert.Equal(2, raw.GetProperty("statement_count").GetInt32());
            Assert.True(raw.GetProperty("results")[0].GetProperty("rows")[0][0].GetInt64() > 5);

            var body = JsonSerializer.Serialize(new { sql = "SELECT * FROM nope; SELECT 3 AS x", continue_on_error = true, include_sql = true });
            var cont = JsonDocument.Parse(http.PostAsync("query", new StringContent(body, Encoding.UTF8, "application/json")).Result.Content.ReadAsStringAsync().Result).RootElement;
            Assert.False(cont.GetProperty("success").GetBoolean());
            Assert.Equal(0, cont.GetProperty("first_error_index").GetInt32());
            Assert.Equal(3, cont.GetProperty("results")[1].GetProperty("rows")[0][0].GetInt64());
            Assert.Equal("SELECT 3 AS x", cont.GetProperty("results")[1].GetProperty("sql").GetString());

            Assert.StartsWith("x\n3", http.PostAsync("query?format=csv", new StringContent("SELECT 3 AS x")).Result.Content.ReadAsStringAsync().Result);
            var status = JsonDocument.Parse(http.GetStringAsync("status").Result).RootElement;
            Assert.Equal("dnspysql", status.GetProperty("tool").GetString());
            Assert.Equal(1, status.GetProperty("modules").GetArrayLength());
            Assert.Contains("dnspysql_tables", http.GetStringAsync("schema").Result.Replace("\"table_name\"", ""));
            Assert.Contains("cancelled", http.PostAsync("cancel", null).Result.Content.ReadAsStringAsync().Result);

            // --remote sends -c to the server and prints its answer.
            var remote = Exec("--remote", url!, "--token", "s3cret", "--format", "csv", "-c", "SELECT name FROM methods WHERE name = 'IsValid'");
            Assert.Equal(0, remote.exit);
            Assert.Contains("IsValid", remote.stdout);
            Assert.Equal(1, Exec("--remote", url!, "--token", "s3cret", "-c", "SELECT * FROM nope").exit);
            // the outcome comes in headers, whatever the format: a cell that reads like an error is only text, and the
            // notices of a save reach the remote client's stderr as they would a local run's
            Assert.Equal(0, Exec("--remote", url!, "--token", "s3cret", "-c", "SELECT 'error: only text' AS x, '\"success\":false' AS y").exit);
            var failed = http.PostAsync("query?format=csv", new StringContent("SELECT * FROM nope")).Result;
            Assert.Equal("false", failed.Headers.GetValues("X-DnSpySql-Success").Single());
            var saved = Exec("--remote", url!, "--token", "s3cret", "--format", "csv", "-c", $"SELECT save({Cli.Sql(PathIn("remote-saved.dll"))})");
            Assert.Equal(0, saved.exit);
            Assert.Contains("note: ", saved.stderr);

            Assert.Contains("shutting_down", http.PostAsync("shutdown", null).Result.Content.ReadAsStringAsync().Result);
            Assert.True(server.WaitForExit(30_000));
        }
        finally
        {
            if (!server.HasExited) server.Kill(true);
        }
    }

    [Fact]
    public void Mcp_negotiates_lists_tools_and_cancels()
    {
        using var p = Start(["--mcp", "--no-project", Sample], stdin: true);
        _ = p.StandardError.ReadToEndAsync();
        string Send(string json) { p.StandardInput.WriteLine(json); p.StandardInput.Flush(); return p.StandardOutput.ReadLine()!; }
        var init = JsonDocument.Parse(Send("""{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}""")).RootElement.GetProperty("result");
        Assert.Equal("2024-11-05", init.GetProperty("protocolVersion").GetString());
        Assert.Contains("dnspysql_tables", init.GetProperty("instructions").GetString());
        var tools = Send("""{"jsonrpc":"2.0","id":2,"method":"tools/list"}""");
        Assert.Contains("dnspysql_query", tools);
        Assert.Contains("dnspysql_schema", tools);

        // A long query cancelled by notifications/cancelled gets no response; ping is answered meanwhile.
        p.StandardInput.WriteLine("""{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"dnspysql_query","arguments":{"sql":"WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT count(*) FROM c"}}}""");
        p.StandardInput.Flush();
        Thread.Sleep(500);
        Assert.Contains("\"id\":4", Send("""{"jsonrpc":"2.0","id":4,"method":"ping"}"""));
        p.StandardInput.WriteLine("""{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3}}""");
        var next = Send("""{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"dnspysql_query","arguments":{"sql":"SELECT 42 AS answer","format":"json"}}}""");
        Assert.Contains("\"id\":5", next);
        Assert.Contains("42", next);
        var schema = Send("""{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"dnspysql_schema","arguments":{"table":"methods"}}}""");
        Assert.Contains("full_name", schema);

        // The workflow guides: as prompts (with the assembly as an argument) and through the dnspysql_guide tool.
        Assert.True(init.GetProperty("capabilities").TryGetProperty("prompts", out _));
        var prompts = JsonDocument.Parse(Send("""{"jsonrpc":"2.0","id":7,"method":"prompts/list"}""")).RootElement.GetProperty("result").GetProperty("prompts");
        Assert.Equal(["basics", "explore", "dnspy"], prompts.EnumerateArray().Select(x => x.GetProperty("name").GetString()));
        var explore = JsonDocument.Parse(Send("""{"jsonrpc":"2.0","id":8,"method":"prompts/get","params":{"name":"explore","arguments":{"path":"C:/cases/x.exe"}}}"""))
            .RootElement.GetProperty("result").GetProperty("messages")[0].GetProperty("content").GetProperty("text").GetString()!;
        Assert.StartsWith("Work on this assembly: C:/cases/x.exe", explore);
        Assert.Contains("# ", explore);
        Assert.Contains("\"code\":-32602", Send("""{"jsonrpc":"2.0","id":9,"method":"prompts/get","params":{"name":"nope"}}"""));
        Assert.Contains("dnspysql_guide", tools);
        var basics = JsonDocument.Parse(Send("""{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"dnspysql_guide","arguments":{"topic":"basics"}}}"""))
            .RootElement.GetProperty("result");
        Assert.False(basics.GetProperty("isError").GetBoolean());
        Assert.Contains("resolve(", basics.GetProperty("content")[0].GetProperty("text").GetString());
        p.StandardInput.Close();
        Assert.True(p.WaitForExit(30_000));
    }

    [Fact]
    public void Ctrl_c_cancels_the_running_statement_in_the_repl()
    {
        if (OperatingSystem.IsWindows()) return; // SIGINT delivery to a child process is POSIX-only here
        using var p = Start(["--no-project", Sample], stdin: true);
        var err = p.StandardError.ReadToEndAsync();
        p.StandardInput.WriteLine("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT count(*) FROM c;");
        p.StandardInput.Flush();
        Thread.Sleep(1500);
        Process.Start("kill", ["-INT", p.Id.ToString()])!.WaitForExit();
        p.StandardInput.WriteLine("SELECT 'still alive' AS s;");
        p.StandardInput.WriteLine(".quit");
        p.StandardInput.Close();
        var outText = p.StandardOutput.ReadToEnd();
        Assert.True(p.WaitForExit(60_000));
        Assert.Contains("interrupted", outText);
        Assert.Contains("still alive", outText);
    }

    [Fact]
    public void Schema_reference_is_generated()
    {
        var md = Exec("--schema-md").stdout;
        Assert.StartsWith("# DnSpySql schema reference", md);
        Assert.Contains("### `pseudocode`", md);
        Assert.Contains("`bp_patch([module])`", md);
    }
}
