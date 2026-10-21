// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Diagnostics;

namespace DnSpySql.Sql;

public sealed class FunctionInfo
{
    public required string Name { get; init; }
    /// <summary>Argument count of this overload (-1 = variadic).</summary>
    public int Args { get; init; }
    public required string Signature { get; init; }
    public string Doc { get; init; } = "";
    public string Domain { get; init; } = "";
    public bool Mutates { get; init; }
}

/// <summary>
/// The engine's side of the SQL connection. SQLite itself runs in the native host (libxsql); this class holds what the
/// host registers there (tables, functions, views) and the per-statement state the engine needs: read-only mode,
/// cancellation and the statement timeout, and undo grouping.
/// </summary>
public sealed class Database
{
    readonly List<VirtualTable> _tables = new();
    readonly Dictionary<string, VirtualTable> _byName = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<(string name, int args), (FunctionInfo info, Func<object?[], object?> impl)> _functions = new();

    volatile bool _interrupt;
    long _deadline = long.MaxValue;
    CancellationTokenSource _cts = new();

    public IReadOnlyList<VirtualTable> Tables => _tables;
    public List<FunctionInfo> Functions { get; } = new();
    /// <summary>CREATE VIEW statements the host runs after registering the tables.</summary>
    public List<(string name, string sql)> Views { get; } = new();
    public bool ReadOnly { get; set; }
    /// <summary>Maps a handle filter value to its canonical form (e.g. a bare metadata token to a module-qualified handle).</summary>
    public Func<long, long>? NormalizeHandle { get; set; }
    /// <summary>Invoked before each statement runs (used to group undo entries per statement).</summary>
    public Action? BeforeStatement { get; set; }
    /// <summary>SQLite version of the native host, reported once the host is up.</summary>
    public static string SqliteVersion { get; set; } = "";

    /// <summary>Cancelled by <see cref="Interrupt"/> or the statement timeout: lets long managed work (decompiler) stop too.</summary>
    public CancellationToken Cancellation => _cts.Token;

    /// <summary>The running statement's timeout, and the time it has left; null when it has none.</summary>
    public TimeSpan? Timeout { get; private set; }
    public TimeSpan? Remaining => _deadline == long.MaxValue ? null : TimeSpan.FromSeconds((double)(_deadline - Stopwatch.GetTimestamp()) / Stopwatch.Frequency);

    public VirtualTable Table(string name) =>
        _byName.TryGetValue(name, out var t) ? t : throw new SqlException($"no such table: {name}");

    public void Register(VirtualTable table)
    {
        if (!_byName.TryAdd(table.Name, table)) throw new InvalidOperationException($"table {table.Name} registered twice");
        _tables.Add(table);
    }

    /// <summary>Registers a scalar SQL function overload. nargs = -1 for variadic.</summary>
    public void Function(string name, int nargs, Func<object?[], object?> impl, string signature, string doc = "",
        bool deterministic = false, bool mutates = false, string domain = "")
    {
        var info = new FunctionInfo { Name = name, Args = nargs, Signature = signature, Doc = doc, Mutates = mutates, Domain = domain };
        if (!_functions.ContainsKey((name, nargs))) Functions.Add(info);
        _functions[(name, nargs)] = (info, impl);
    }

    public object? Invoke(string name, object?[] args)
    {
        if (!_functions.TryGetValue((name, args.Length), out var f) && !_functions.TryGetValue((name, -1), out f))
            throw new SqlException($"no function {name} taking {args.Length} argument(s)");
        if (f.info.Mutates && ReadOnly) throw new SqlException($"session is read-only; {name}() modifies the target");
        return f.impl(args);
    }

    /// <summary>Only CREATE VIEW is supported: the definition is handed to the host.</summary>
    public void Exec(string sql)
    {
        var m = System.Text.RegularExpressions.Regex.Match(sql, @"^\s*CREATE\s+VIEW\s+""?(\w+)""?\s+AS\s", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        if (!m.Success) throw new NotSupportedException("the engine only records CREATE VIEW; SQL runs in the native host");
        Views.Add((m.Groups[1].Value, sql));
    }

    public void CheckWritable(VirtualTable t)
    {
        if (ReadOnly) throw new SqlException($"session is read-only; cannot modify {t.Name}");
    }

    public void CheckInterrupt()
    {
        if (_interrupt || Stopwatch.GetTimestamp() > _deadline) throw new OperationCanceledException("query interrupted");
    }

    /// <summary>Starts a statement: undo group, fresh cancellation, optional timeout.</summary>
    public void BeginStatement(long timeoutMs)
    {
        _interrupt = false;
        if (_cts.IsCancellationRequested) { _cts.Dispose(); _cts = new CancellationTokenSource(); }
        _deadline = timeoutMs > 0 ? Stopwatch.GetTimestamp() + timeoutMs * Stopwatch.Frequency / 1000 : long.MaxValue;
        Timeout = timeoutMs > 0 ? TimeSpan.FromMilliseconds(timeoutMs) : null;
        if (timeoutMs > 0) _cts.CancelAfter(TimeSpan.FromMilliseconds(timeoutMs));
        foreach (var t in _tables) t.ResetRegistry();
        BeforeStatement?.Invoke();
    }

    /// <summary>Request cancellation of the running statement (thread-safe).</summary>
    public void Interrupt()
    {
        _interrupt = true;
        try { _cts.Cancel(); } catch (ObjectDisposedException) { }
    }

    /// <summary>The message the host reports for an exception thrown by a table or function.</summary>
    public static string Describe(Exception e) => e is OperationCanceledException
        ? "interrupted (timeout or cancel)"
        : e is SqlException or NotSupportedException or ArgumentException or InvalidOperationException or KeyNotFoundException
            ? e.Message
            : $"{e.GetType().Name}: {e.Message}";
}
