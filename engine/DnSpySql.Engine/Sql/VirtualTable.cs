// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Text;

namespace DnSpySql.Sql;

public enum SqlType { Integer, Real, Text, Blob, Any }

/// <summary>SQLite's xBestIndex operator codes, as the native host passes them with each pushed-down constraint.</summary>
public static class SqlOp
{
    public const byte EQ = 2, GT = 4, LE = 8, LT = 16, GE = 32, IS = 72;
}

/// <summary>How a column participates in query planning.</summary>
public enum Pushdown
{
    /// <summary>Post-filter only: SQLite scans and tests every row.</summary>
    None,
    /// <summary>Equality is answered by the table (bounded lookup).</summary>
    Eq,
    /// <summary>Equality identifies at most one row.</summary>
    Unique,
    /// <summary>Equality and range (&lt; &lt;= &gt; &gt;=) are answered by the table.</summary>
    Range,
}

public sealed class ColumnInfo
{
    public required string Name { get; init; }
    public SqlType Type { get; init; }
    public bool Hidden { get; init; }
    public Pushdown Pushdown { get; init; }
    /// <summary>The table refuses a scan unless at least one Required column has an equality filter.</summary>
    public bool Required { get; init; }
    public string? Doc { get; init; }
    public Func<object, object?> Get { get; init; } = _ => null;
    public Action<object, object?>? Set { get; init; }
    public bool Writable => Set != null;
    /// <summary>Column is only used as an input argument (hidden + required/eq), like a table-valued function parameter.</summary>
    public bool IsArgument { get; init; }
    /// <summary>
    /// Column holds entity handles: equality filters are normalized with <see cref="Database.NormalizeHandle"/> (bare tokens,
    /// '0x..' text) and enforced by the table instead of SQLite's strict re-check.
    /// </summary>
    public bool IsHandle { get; set; }
    /// <summary>
    /// An equality filter the table interprets rather than matches (search's kind = 'member' finds methods, fields, ...):
    /// rows are not re-checked against it.
    /// </summary>
    public bool Interpreted { get; set; }
}

/// <summary>Filter values that the planner pushed down into the table.</summary>
public sealed class Constraints
{
    readonly Dictionary<string, object?> _eq = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, (object? lo, bool loInc, object? hi, bool hiInc)> _range = new(StringComparer.OrdinalIgnoreCase);

    public void AddEq(string col, object? v) => _eq[col] = v;

    public void AddRange(string col, byte op, object? v)
    {
        _range.TryGetValue(col, out var r);
        switch (op)
        {
            case SqlOp.GT: r.lo = v; r.loInc = false; break;
            case SqlOp.GE: r.lo = v; r.loInc = true; break;
            case SqlOp.LT: r.hi = v; r.hiInc = false; break;
            case SqlOp.LE: r.hi = v; r.hiInc = true; break;
        }
        _range[col] = r;
    }

    public bool Has(string col) => _eq.ContainsKey(col);
    public bool TryGet(string col, out object? v) => _eq.TryGetValue(col, out v);
    public object? Get(string col) => _eq.TryGetValue(col, out var v) ? v : null;
    public long? Long(string col) => _eq.TryGetValue(col, out var v) ? Values.ToLong(v) : null;
    public string? Text(string col) => _eq.TryGetValue(col, out var v) ? Values.ToText(v) : null;
    public bool? Bool(string col) => _eq.TryGetValue(col, out var v) && v != null ? Values.ToLong(v) != 0 : null;

    /// <summary>Inclusive [lo, hi] long bounds from range and equality constraints.</summary>
    public (long lo, long hi) LongRange(string col, long min = long.MinValue, long max = long.MaxValue)
    {
        if (_eq.TryGetValue(col, out var e) && Values.ToLong(e) is long x) return (x, x);
        long lo = min, hi = max;
        if (_range.TryGetValue(col, out var r))
        {
            if (Values.ToLong(r.lo) is long l) lo = r.loInc ? l : l + 1;
            if (Values.ToLong(r.hi) is long h) hi = r.hiInc ? h : h - 1;
        }
        return (lo, hi);
    }

    public bool HasRange(string col) => _range.ContainsKey(col) || _eq.ContainsKey(col);
    public IEnumerable<string> EqColumns => _eq.Keys;
}

/// <summary>Receives every mutation done through SQL so the host can journal undo/redo and track dirty state.</summary>
public interface IWriteSink
{
    void Record(string table, string description, Action undo, Action redo);
}

public sealed class SqlException(string message) : Exception(message);

/// <summary>A table exposed to SQL. Rows are arbitrary managed objects; columns are projections over them.</summary>
public abstract class VirtualTable
{
    protected VirtualTable(string name, string doc) { Name = name; Doc = doc; }

    public string Name { get; }
    public string Doc { get; }
    public string Domain { get; set; } = "";
    public List<ColumnInfo> Columns { get; } = new();
    /// <summary>Rough unfiltered row count used for planning.</summary>
    public double EstimatedRows { get; set; } = 10_000;
    /// <summary>Relative cost per produced row (decompiler-backed tables are expensive).</summary>
    public double CostPerRow { get; set; } = 1;
    public IWriteSink? Sink { get; set; }
    public virtual bool CanInsert => false;
    public virtual bool CanDelete => false;
    public bool CanUpdate => Columns.Any(c => c.Writable);
    public bool IsKeyed { get; protected set; }

    public abstract IEnumerable<object> Rows(Constraints c);
    /// <summary>Fast path for a bare COUNT(*): the row count without building rows, or null to fall back to counting
    /// <see cref="Rows"/>. Set it only where the count is cheap to compute directly (e.g. a byte count from a length).</summary>
    public Func<Constraints, long?>? CountRows { get; set; }
    /// <summary>Stable row id for keyed tables (needed by UPDATE/DELETE).</summary>
    public virtual long RowId(object row) => throw new NotSupportedException();
    public virtual object? Find(long rowid) => null;

    // Per-statement registry for writable tables without a natural key: ids are handed out lazily (only when SQLite
    // asks for a rowid, i.e. for UPDATE/DELETE) and forgotten when the next statement starts.
    readonly Dictionary<long, object> _registry = new();
    readonly Dictionary<object, long> _registryIds = new(ReferenceEqualityComparer.Instance);
    long _nextRegistryId;
    internal void ResetRegistry() { if (_registry.Count > 0) { _registry.Clear(); _registryIds.Clear(); } }

    internal long RowIdFor(object row, long ordinal)
    {
        if (IsKeyed) return RowId(row);
        if (!CanUpdate && !CanDelete) return ordinal;
        if (_registryIds.TryGetValue(row, out var known)) return known;
        var id = ++_nextRegistryId;
        _registry[id] = row;
        _registryIds[row] = id;
        return id;
    }

    internal object? FindRow(long rowid) => IsKeyed ? Find(rowid) : _registry.TryGetValue(rowid, out var r) ? r : null;
    public virtual long Insert(IReadOnlyDictionary<string, object?> values) => throw new SqlException($"{Name}: INSERT is not supported");
    public virtual void Delete(object row) => throw new SqlException($"{Name}: DELETE is not supported");

    /// <summary>When false, column setters journal their own undo entries (e.g. IL edits snapshot the whole body).</summary>
    public bool JournalUpdates { get; set; } = true;

    public virtual void Update(object row, IReadOnlyList<(ColumnInfo col, object? value)> changes)
    {
        foreach (var (col, value) in changes)
        {
            if (!JournalUpdates) { col.Set!(row, value); continue; }
            var old = col.Get(row);
            col.Set!(row, value);
            var r = row; var c = col;
            Sink?.Record(Name, $"UPDATE {Name} SET {col.Name}", () => c.Set!(r, old), () => c.Set!(r, value));
        }
    }

    public string Declaration()
    {
        var sb = new StringBuilder("CREATE TABLE x(");
        for (int i = 0; i < Columns.Count; i++)
        {
            var c = Columns[i];
            if (i > 0) sb.Append(", ");
            sb.Append('"').Append(c.Name).Append("\" ").Append(c.Type switch
            {
                SqlType.Integer => "INTEGER", SqlType.Real => "REAL", SqlType.Text => "TEXT", SqlType.Blob => "BLOB", _ => "",
            });
            if (c.Hidden) sb.Append(" HIDDEN");
        }
        return sb.Append(')').ToString();
    }

    public string RequiredHint()
    {
        var req = Columns.Where(c => c.Required).Select(c => c.Name).ToList();
        return req.Count == 1 ? $"WHERE {req[0]} = ..." : $"WHERE one of ({string.Join(", ", req)}) = ...";
    }
}

/// <summary>Strongly typed table built from column lambdas.</summary>
public class Table<T> : VirtualTable
{
    Func<Constraints, IEnumerable<T>> _rows = _ => Array.Empty<T>();
    Func<T, long>? _key;
    Func<long, T?>? _find;
    Func<IReadOnlyDictionary<string, object?>, (long rowid, Action? undo, Action? redo)>? _insert;
    Func<T, (Action? undo, Action? redo)>? _delete;
    Action<T>? _changed;

    public Table(string name, string doc) : base(name, doc) { }

    public override bool CanInsert => _insert != null;
    public override bool CanDelete => _delete != null;

    public Table<T> Source(Func<Constraints, IEnumerable<T>> rows) { _rows = rows; return this; }

    public Table<T> Keyed(Func<T, long> key, Func<long, T?> find) { _key = key; _find = find; IsKeyed = true; return this; }

    public Table<T> OnInsert(Func<IReadOnlyDictionary<string, object?>, (long rowid, Action? undo, Action? redo)> insert) { _insert = insert; return this; }

    public Table<T> OnDelete(Func<T, (Action? undo, Action? redo)> delete) { _delete = delete; return this; }

    /// <summary>Called after any successful UPDATE of a row (e.g. to mark the module dirty).</summary>
    public Table<T> OnChanged(Action<T> changed) { _changed = changed; return this; }

    public Table<T> Estimate(double rows, double costPerRow = 1) { EstimatedRows = rows; CostPerRow = costPerRow; return this; }

    public Table<T> Col(string name, SqlType type, Func<T, object?> get, Action<T, object?>? set = null,
        Pushdown pushdown = Pushdown.None, bool hidden = false, bool required = false, string? doc = null)
    {
        Columns.Add(new ColumnInfo
        {
            Name = name, Type = type, Hidden = hidden, Pushdown = pushdown, Required = required, Doc = doc,
            Get = o => get((T)o),
            Set = set == null ? null : (o, v) => set((T)o, v),
        });
        return this;
    }

    /// <summary>A hidden input column (table-valued-function argument). Its value is echoed back from the constraint.</summary>
    public Table<T> Arg(string name, SqlType type, Func<T, object?> echo, bool required = true, string? doc = null)
    {
        Columns.Add(new ColumnInfo
        {
            Name = name, Type = type, Hidden = true, Pushdown = Pushdown.Eq, Required = required, Doc = doc, IsArgument = true,
            Get = o => echo((T)o),
        });
        return this;
    }

    public Table<T> Int(string name, Func<T, object?> get, Action<T, object?>? set = null, Pushdown pushdown = Pushdown.None, bool required = false, string? doc = null)
        => Col(name, SqlType.Integer, get, set, pushdown, false, required, doc);

    /// <summary>An entity-handle column with an equality filter: bare tokens and '0x..' text are normalized (see IsHandle).</summary>
    public Table<T> Handle(string name, Func<T, object?> get, bool required = false, string? doc = null)
    {
        Col(name, SqlType.Integer, get, null, Pushdown.Eq, false, required, doc);
        Columns[^1].IsHandle = true;
        return this;
    }

    public Table<T> Text(string name, Func<T, object?> get, Action<T, object?>? set = null, Pushdown pushdown = Pushdown.None, bool required = false, string? doc = null)
        => Col(name, SqlType.Text, get, set, pushdown, false, required, doc);

    public Table<T> Blob(string name, Func<T, object?> get, Action<T, object?>? set = null, string? doc = null)
        => Col(name, SqlType.Blob, get, set, Pushdown.None, false, false, doc);

    public Table<T> Real(string name, Func<T, object?> get, string? doc = null)
        => Col(name, SqlType.Real, get, null, Pushdown.None, false, false, doc);

    public Table<T> Bool(string name, Func<T, bool> get, Action<T, object?>? set = null, Pushdown pushdown = Pushdown.None, string? doc = null)
        => Col(name, SqlType.Integer, o => get(o) ? 1L : 0L, set, pushdown, false, false, doc);

    public override IEnumerable<object> Rows(Constraints c) { var r = _rows(c); return r as IEnumerable<object> ?? r.Select(x => (object)x!); }
    public override long RowId(object row) => _key!((T)row);
    public override object? Find(long rowid) => _find!(rowid);

    public override long Insert(IReadOnlyDictionary<string, object?> values)
    {
        if (_insert == null) return base.Insert(values);
        var (id, undo, redo) = _insert(values);
        if (undo != null && redo != null) Sink?.Record(Name, $"INSERT INTO {Name}", undo, redo);
        return id;
    }

    public override void Delete(object row)
    {
        if (_delete == null) { base.Delete(row); return; }
        var (undo, redo) = _delete((T)row);
        if (undo != null && redo != null) Sink?.Record(Name, $"DELETE FROM {Name}", undo, redo);
    }

    public override void Update(object row, IReadOnlyList<(ColumnInfo col, object? value)> changes)
    {
        base.Update(row, changes);
        _changed?.Invoke((T)row);
    }
}

public static class Values
{
    public static long? ToLong(object? v) => v switch
    {
        null => null,
        long l => l,
        int i => i,
        double d => (long)d,
        bool b => b ? 1 : 0,
        string s => ParseLong(s),
        _ => null,
    };

    public static long? ParseLong(string s)
    {
        s = s.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            var hex = s.AsSpan(2);
            // 0xM_TTTTTTTT is how tok() prints a handle (module, then the 32-bit token): read it back as one, so a value
            // copied from output works as input; the token part is a token even when written with fewer digits
            if (hex.IndexOf('_') is var sep and > 0 && hex[(sep + 1)..].IndexOf('_') < 0)
                return long.TryParse(hex[..sep], System.Globalization.NumberStyles.HexNumber, null, out var mod) && mod is >= 0 and <= int.MaxValue
                       && uint.TryParse(hex[(sep + 1)..], System.Globalization.NumberStyles.HexNumber, null, out var tok)
                    ? (mod << 32) | tok : null;
            return long.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out var h) ? h : null;
        }
        return long.TryParse(s, out var x) ? x : null;
    }

    public static string? ToText(object? v) => v switch
    {
        null => null,
        string s => s,
        byte[] b => Encoding.UTF8.GetString(b),
        _ => Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture),
    };

    public static bool ToBool(object? v) => ToLong(v) is long l && l != 0;

    public static byte[]? ToBytes(object? v) => v switch
    {
        null => null,
        byte[] b => b,
        string s => Encoding.UTF8.GetBytes(s),
        _ => null,
    };

    public static bool SameValue(object? a, object? b)
    {
        if (a is null || b is null) return a is null && b is null;
        if (a is byte[] x && b is byte[] y) return x.AsSpan().SequenceEqual(y);
        var la = ToLong(a); var lb = ToLong(b);
        if (a is not string && b is not string && la.HasValue && lb.HasValue) return la == lb;
        return string.Equals(ToText(a), ToText(b), StringComparison.Ordinal);
    }
}
