// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Diagnostics;
using System.Text.Json;

namespace DnSpySql.Tests;

/// <summary>
/// A long-lived dnspysql session (the MCP server over stdio), for tests that need state across statements: undo/redo,
/// unsaved edits, breakpoints. Each query goes through the dnspysql_query tool and comes back as the JSON envelope.
/// </summary>
public sealed class Live : IDisposable
{
    readonly Process _p;
    int _id;

    public Live(string assembly, params string[] options)
    {
        var psi = new ProcessStartInfo(Cli.Exe)
        {
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false,
        };
        psi.ArgumentList.Add("--mcp");
        foreach (var o in options) psi.ArgumentList.Add(o);
        psi.ArgumentList.Add(assembly);
        _p = Process.Start(psi)!;
        _p.ErrorDataReceived += (_, _) => { };
        _p.BeginErrorReadLine();
        Call("initialize", new { protocolVersion = "2025-06-18", capabilities = new { }, clientInfo = new { name = "tests", version = "1" } });
    }

    JsonElement Call(string method, object @params)
    {
        var id = ++_id;
        _p.StandardInput.WriteLine(JsonSerializer.Serialize(new { jsonrpc = "2.0", id, method, @params }));
        _p.StandardInput.Flush();
        var line = _p.StandardOutput.ReadLine() ?? throw new InvalidOperationException("dnspysql --mcp exited");
        if (Environment.GetEnvironmentVariable("LIVE_LOG") is { } log) File.AppendAllText(log, $">> {id} {method}\n<< {line[..Math.Min(line.Length, 300)]}\n");
        var msg = JsonDocument.Parse(line).RootElement;
        if (msg.TryGetProperty("error", out var err)) throw new InvalidOperationException(err.GetRawText());
        return msg.GetProperty("result");
    }

    /// <summary>The JSON envelope of a script; failures are reported in it, not thrown.</summary>
    public JsonElement Envelope(string sql)
    {
        var r = Call("tools/call", new { name = "dnspysql_query", arguments = new { sql, format = "json", max_rows = 1_000_000 } });
        var text = r.GetProperty("content")[0].GetProperty("text").GetString()!;
        try { return JsonDocument.Parse(text).RootElement; }
        catch (JsonException) { throw new InvalidOperationException(text); }
    }

    /// <summary>Runs a script that must succeed and returns the envelope.</summary>
    public JsonElement Q(string sql)
    {
        var e = Envelope(sql);
        Assert.True(e.GetProperty("success").GetBoolean(), $"{sql}\n=> {Error(e)}");
        return e;
    }

    /// <summary>The first error of a script, or null when it succeeded.</summary>
    public string? Error(string sql) => Error(Envelope(sql));

    static string? Error(JsonElement e) =>
        e.GetProperty("results").EnumerateArray().Where(r => !r.GetProperty("success").GetBoolean())
            .Select(r => r.GetProperty("error").GetString()).FirstOrDefault();

    /// <summary>First column of the first row of the last statement (null when there is no row).</summary>
    public object? Scalar(string sql)
    {
        var last = Q(sql).GetProperty("results").EnumerateArray().Last();
        var rows = last.GetProperty("rows");
        return rows.GetArrayLength() == 0 ? null : Value(rows[0][0]);
    }

    public long Long(string sql) => Convert.ToInt64(Scalar(sql));

    public List<object?[]> Rows(string sql) =>
        Q(sql).GetProperty("results").EnumerateArray().Last().GetProperty("rows").EnumerateArray()
            .Select(r => r.EnumerateArray().Select(Value).ToArray()).ToList();

    static object? Value(JsonElement v) => v.ValueKind switch
    {
        JsonValueKind.Null => null,
        JsonValueKind.Number when v.TryGetInt64(out var l) => l,
        JsonValueKind.Number => v.GetDouble(),
        JsonValueKind.String => v.GetString(),
        JsonValueKind.True => 1L,
        JsonValueKind.False => 0L,
        _ => v.GetRawText(),
    };

    public void Dispose()
    {
        try
        {
            _p.StandardInput.Close();
            if (!_p.WaitForExit(30_000)) _p.Kill(true);
        }
        catch (InvalidOperationException) { }
        _p.Dispose();
    }
}
