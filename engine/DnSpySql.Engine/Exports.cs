// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using DnSpySql.Sql;

namespace DnSpySql;

// Entry points called by the native host (src/engine.cpp) through hostfxr.
//
//   int Call(const char* op, const uint8_t* req, int req_len, uint8_t** resp, int* resp_len)
//     returns 0 and a response buffer on success, 1 and a UTF-8 error message on failure.
//     The response must be released with Free().
//
// The host owns SQLite (libxsql); the engine owns the tables, functions and views it describes. A scan carries the
// constraints SQLite pushed down; the host tells SQLite not to re-check them, so the engine applies every one of them
// (handle normalization included) before a row crosses back.
public static unsafe class Exports
{
    static Session? session;
    static Session S => session ?? throw new InvalidOperationException("engine not initialized");

    sealed class Cursor
    {
        public required VirtualTable Table;
        public required IEnumerator<object> Rows;
        public required List<(ColumnInfo col, int index, byte op, object? value)> Checks;
        public required ulong Used;
        public long Ordinal;
    }

    static readonly Dictionary<long, Cursor> cursors = [];
    // DNSPYSQL_TRACE=1 prints the time of every engine call to stderr.
    static readonly bool Trace = Environment.GetEnvironmentVariable("DNSPYSQL_TRACE") == "1";
    static long nextCursor = 1;

    [UnmanagedCallersOnly]
    public static int Call(byte* op, byte* req, int reqLen, byte** resp, int* respLen)
    {
        int status;
        ArraySegment<byte> result;
        try
        {
            var name = Marshal.PtrToStringUTF8((nint)op) ?? "";
            var args = Wire.ReadList(new ReadOnlySpan<byte>(req, reqLen));
            long t0 = Trace ? System.Diagnostics.Stopwatch.GetTimestamp() : 0;
            result = Dispatch(name, args);
            if (Trace) Console.Error.WriteLine($"[engine] {name} {System.Diagnostics.Stopwatch.GetElapsedTime(t0).TotalMilliseconds:F1} ms{(name == "scan_open" ? $" {args[0]} used=0x{Convert.ToInt64(args[1]):X} cons={args[3]}" : "")}");
            status = 0;
        }
        catch (Exception e)
        {
            result = Encoding.UTF8.GetBytes(Database.Describe(e));
            status = 1;
        }
        var p = (byte*)NativeMemory.Alloc((nuint)Math.Max(result.Count, 1));
        result.AsSpan().CopyTo(new Span<byte>(p, result.Count));
        *resp = p;
        *respLen = result.Count;
        return status;
    }

    [UnmanagedCallersOnly]
    public static void Free(byte* p) => NativeMemory.Free(p);

    static string Str(object? v, string what) => Values.ToText(v) ?? throw new ArgumentException($"{what} is NULL");

    static ArraySegment<byte> Dispatch(string op, List<object?> a)
    {
        switch (op)
        {
            case "init":
            {
                // init(options json): the CLI options that shape the session.
                using var j = JsonDocument.Parse(Str(a[0], "options"));
                var o = j.RootElement;
                string? Opt(string k) => o.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
                bool Flag(string k) => o.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.True;
                long Num(string k, long d) => o.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt64() : d;
                var opts = new SessionOptions
                {
                    ReadOnly = Flag("read_only"),
                    NoProject = Flag("no_project"),
                    ProjectPath = Opt("project"),
                    QueryTimeoutMs = (int)Num("timeout_ms", 0),
                    MaxRows = (int)Num("max_rows", 0),
                    DnSpyXml = Opt("dnspy_xml"),
                    NoEmulation = Flag("no_emulation"),
                };
                if (o.TryGetProperty("ref_paths", out var refs))
                    foreach (var r in refs.EnumerateArray()) if (r.GetString() is { } p) opts.ReferencePaths.Add(p);
                Database.SqliteVersion = Opt("sqlite_version") ?? "";
                if (Opt("version") is { } version) Session.ToolVersion = version;
                Session.ToolCommit = Opt("commit");
                session = new Session(opts);
                DnSpyDecompiler.Outer = () => S.Db.Cancellation;
                return Wire.EncodeList();
            }
            case "describe":
                return Describe();
            case "view_columns":
            {
                // view_columns(name, json [[column, type], ...]) once the host has created the view
                using var j = JsonDocument.Parse(Str(a[1], "columns"));
                S.ViewColumns[Str(a[0], "view")] = j.RootElement.EnumerateArray().Select(c => (c[0].GetString() ?? "", c[1].GetString() ?? "")).ToList();
                return Wire.EncodeList();
            }
            case "open":
                return Wire.EncodeList(S.Open(Str(a[0], "path")).Id);
            case "begin_statement":
                // -> the statement timeout in ms, which the host also enforces on SQLite itself, and the row cap (0 = none)
                S.BeginStatement();
                return Wire.EncodeList(S.Settings["query_timeout_ms"].AsLong ?? 0, S.Settings["max_rows"].AsLong ?? 0);
            case "end_statement":
            {
                // -> the statement's notices (text, one per line) or nothing
                foreach (var id in cursors.Keys.ToList()) Close(id);
                return S.EndStatement() is { } notice ? Wire.EncodeList(notice) : Wire.EncodeList();
            }
            case "interrupt":
                S.Interrupt();
                return Wire.EncodeList();
            case "scan_open":
            {
                // scan_open(table, used, first, n, (column index, op, value) * n) -> cursor id, then up to `first` rows
                // (a point lookup, one probe of a join, finishes in this one call)
                var t = S.Db.Table(Str(a[0], "table"));
                ulong used = a[1] != null ? unchecked((ulong)Convert.ToInt64(a[1])) : ulong.MaxValue;
                int first = Convert.ToInt32(a[2]);
                int n = Convert.ToInt32(a[3]);
                var cons = new Constraints();
                var checks = new List<(ColumnInfo, int, byte, object?)>();
                bool none = false;
                for (int k = 0; k < n; k++)
                {
                    int ci = Convert.ToInt32(a[4 + 3 * k]);
                    byte cop = Convert.ToByte(a[5 + 3 * k]);
                    object? v = a[6 + 3 * k];
                    var col = t.Columns[ci];
                    if (col.IsHandle && cop is SqlOp.EQ or SqlOp.IS)
                    {
                        long? h = Values.ToLong(v) is long l ? S.Db.NormalizeHandle?.Invoke(l) ?? l : null;
                        // '= NULL' and '= <non-number>' match nothing; 'IS NULL' matches NULL handles.
                        if (h == null && (v != null || cop == SqlOp.EQ)) none = true;
                        v = h;
                    }
                    if (cop is SqlOp.EQ or SqlOp.IS) cons.AddEq(col.Name, v); else cons.AddRange(col.Name, cop, v);
                    if (!col.IsArgument && !(col.Interpreted && cop == SqlOp.EQ)) checks.Add((col, ci, cop, v));
                }
                bool required = !t.Columns.Any(c => c.Required) || t.Columns.Any(c => c.Required && cons.Has(c.Name));
                if (!required)
                    throw new SqlException($"table '{t.Name}' needs a filter: {t.RequiredHint()} (see: SELECT * FROM dnspysql_columns WHERE table_name='{t.Name}')");
                S.Db.CheckInterrupt();
                var rows = none ? Enumerable.Empty<object>().GetEnumerator() : t.Rows(cons).GetEnumerator();
                long id = nextCursor++;
                var cursor = new Cursor { Table = t, Rows = rows, Checks = checks, Used = used };
                cursors[id] = cursor;
                var batch = Batch(id, cursor, first);
                return Wire.EncodeCursor(id, t.Columns.Count, batch);
            }
            case "scan_next":
            {
                // scan_next(cursor, n) -> up to n rows; fewer means the scan is done (and closed)
                long id = Convert.ToInt64(a[0]);
                int n = Convert.ToInt32(a[1]);
                if (!cursors.TryGetValue(id, out var c)) throw new ArgumentException($"no cursor {id}");
                return Wire.EncodeRows(c.Table.Columns.Count, Batch(id, c, n));
            }
            case "scan_close":
                Close(Convert.ToInt64(a[0]));
                return Wire.EncodeList();
            case "count":
            {
                var t = S.Db.Table(Str(a[0], "table"));
                if (t.Columns.Any(c => c.Required))
                    throw new SqlException($"table '{t.Name}' needs a filter: {t.RequiredHint()}");
                return Wire.EncodeList(t.Rows(new Constraints()).LongCount());
            }
            case "get":
            {
                var t = S.Db.Table(Str(a[0], "table"));
                var row = Find(t, a[1]);
                return Wire.EncodeRows(t.Columns.Count, [new Row(Convert.ToInt64(a[1]), RowValues(t, row, ulong.MaxValue))]);
            }
            case "update":
            {
                // update(table, key, column, value)
                var t = S.Db.Table(Str(a[0], "table"));
                S.Db.CheckWritable(t);
                var row = Find(t, a[1]);
                var col = t.Columns.FirstOrDefault(c => c.Name == Str(a[2], "column")) ?? throw new SqlException($"{t.Name}: no column {a[2]}");
                if (col.IsArgument || Sql.Values.SameValue(col.Get(row), a[3])) return Wire.EncodeList();
                if (!col.Writable) throw new SqlException($"{t.Name}.{col.Name} is read-only");
                t.Update(row, [(col, a[3])]);
                return Wire.EncodeList();
            }
            case "insert":
            {
                // insert(table, value per column) -> new row key
                var t = S.Db.Table(Str(a[0], "table"));
                S.Db.CheckWritable(t);
                if (!t.CanInsert) throw new SqlException($"{t.Name}: INSERT is not supported");
                var values = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                for (int i = 0; i < t.Columns.Count && 1 + i < a.Count; i++)
                    if (a[1 + i] != null) values[t.Columns[i].Name] = a[1 + i];
                return Wire.EncodeList(t.Insert(values));
            }
            case "delete":
            {
                var t = S.Db.Table(Str(a[0], "table"));
                S.Db.CheckWritable(t);
                if (!t.CanDelete) throw new SqlException($"{t.Name}: DELETE is not supported");
                t.Delete(Find(t, a[1]));
                return Wire.EncodeList();
            }
            case "invoke":
                return Wire.EncodeList(S.Db.Invoke(Str(a[0], "function"), a.Skip(1).ToArray()));
            case "schema_md":
                return Wire.EncodeList(SchemaDoc.Markdown(S));
            case "visible":
                // escapes invisible / bidi / private-use characters for terminal output (Output.Visible)
                return Wire.EncodeList(Output.Visible(Str(a[0], "text")));
            case "module_summary":
            {
                var lm = S.Ws.Get(Convert.ToInt32(a[0]));
                return Wire.EncodeList(Output.Visible($"[{lm.Id}] {lm.Path} ({lm.Name}, {lm.Module.Kind}, {Tables.MetaTables.TargetFramework(lm.Module)})"));
            }
            case "status":
                // JSON for GET /status
                return Wire.EncodeList(JsonSerializer.Serialize(new
                {
                    tool = Session.ToolName,
                    version = Session.ToolVersion,
                    modules = S.Ws.Modules.Select(m => new { id = m.Id, name = m.Name, path = m.Path, dirty = m.Dirty, sha256 = m.Sha256 }),
                    @readonly = S.Db.ReadOnly,
                    breakpoints = S.Store.Breakpoints.Count,
                }));
            case "dirty":
                // names of modules with unsaved changes (for /shutdown and the REPL's exit warning)
                return Wire.EncodeList(string.Join("\n", S.Ws.Modules.Where(m => m.HasUnsavedChanges).Select(m => m.Path)));
            default:
                throw new ArgumentException($"unknown op '{op}'");
        }
    }

    // Up to n rows of a cursor; fewer means the scan is done and the cursor is closed.
    static List<Row> Batch(long id, Cursor c, int n)
    {
        var batch = new List<Row>(Math.Min(n, 4096));
        try
        {
            while (batch.Count < n && Next(c) is { } row) batch.Add(row);
        }
        catch
        {
            Close(id);
            throw;
        }
        if (batch.Count < n) Close(id);
        return batch;
    }

    static object Find(VirtualTable t, object? key)
    {
        if (!t.IsKeyed && !t.CanUpdate && !t.CanDelete) throw new SqlException($"{t.Name} is read-only");
        var id = Sql.Values.ToLong(key) ?? throw new SqlException($"{t.Name}: bad row id");
        return t.FindRow(id) ?? throw new SqlException($"{t.Name}: row {id} no longer exists");
    }

    // The next row that satisfies every pushed-down constraint, with the columns the query reads.
    static Row? Next(Cursor c)
    {
        while (true)
        {
            S.Db.CheckInterrupt();
            if (!c.Rows.MoveNext()) return null;
            var row = c.Rows.Current;
            if (c.Checks.Count > 0 && !c.Checks.All(k => Satisfies(Get(k.col, row), k.op, k.value, k.col))) continue;
            c.Ordinal++;
            return new Row(c.Table.RowIdFor(row, c.Ordinal), RowValues(c.Table, row, c.Used));
        }
    }

    static object?[] RowValues(VirtualTable t, object row, ulong used)
    {
        var vals = new object?[t.Columns.Count];
        for (int i = 0; i < vals.Length; i++)
            if ((used & (1UL << Math.Min(i, 63))) != 0) vals[i] = Get(t.Columns[i], row);
        return vals;
    }

    // A column that cannot be computed (malformed metadata in a protected assembly) reads as NULL rather than
    // failing the whole query.
    static object? Get(ColumnInfo col, object row)
    {
        try { return col.Get(row) switch { bool b => b ? 1L : 0L, int i => (long)i, uint u => (long)u, var v => v }; }
        catch (Exception e) when (e is not OutOfMemoryException and not OperationCanceledException) { return null; }
    }

    // SQLite comparison semantics for a pushed-down constraint: NULL equals nothing (IS NULL matches it), numbers
    // compare numerically, text by ordinal; a numeric column compares against numeric text as a number.
    static bool Satisfies(object? v, byte op, object? c, ColumnInfo col)
    {
        if (op == SqlOp.IS) return c == null ? v == null : v != null && Compare(v, c, col) == 0;
        if (v == null || c == null) return false;
        int cmp = Compare(v, c, col);
        return op switch
        {
            SqlOp.EQ => cmp == 0,
            SqlOp.GT => cmp > 0,
            SqlOp.GE => cmp >= 0,
            SqlOp.LT => cmp < 0,
            SqlOp.LE => cmp <= 0,
            _ => true,
        };
    }

    static int Compare(object v, object c, ColumnInfo col)
    {
        static double? Num(object o) => o switch
        {
            long l => l, int i => i, double d => d, float f => f, bool b => b ? 1 : 0,
            _ => null,
        };
        var (nv, nc) = (Num(v), Num(c));
        if (nc == null && c is string sc && col.Type is SqlType.Integer or SqlType.Real && Sql.Values.ParseLong(sc) is long pl) nc = pl;
        if (nv != null && nc != null) return nv.Value.CompareTo(nc.Value);
        if (v is byte[] bv && c is byte[] bc) return bv.AsSpan().SequenceCompareTo(bc);
        // SQLite orders numbers before text before blobs.
        int Rank(object o) => Num(o) != null ? 0 : o is byte[] ? 2 : 1;
        if (Rank(v) != Rank(c)) return Rank(v).CompareTo(Rank(c));
        return string.CompareOrdinal(Sql.Values.ToText(v), Sql.Values.ToText(c));
    }

    static void Close(long id)
    {
        if (cursors.Remove(id, out var c)) c.Rows.Dispose();
    }

    static string Pushdown(ColumnInfo c) => c.Pushdown switch
    {
        Sql.Pushdown.Eq => "eq",
        Sql.Pushdown.Unique => "unique",
        Sql.Pushdown.Range => "range",
        _ => "none",
    };

    // The schema the host registers. Written by hand: the reflection-based serializer costs tens of milliseconds on
    // a cold start, and this runs once per process.
    static byte[] Describe()
    {
        var buf = new System.Buffers.ArrayBufferWriter<byte>(256 * 1024);
        using (var w = new Utf8JsonWriter(buf))
        {
            w.WriteStartObject();
            w.WriteStartArray("tables");
            foreach (var t in S.Db.Tables)
            {
                w.WriteStartObject();
                w.WriteString("name", t.Name);
                w.WriteString("doc", t.Doc);
                w.WriteString("domain", t.Domain);
                w.WriteBoolean("insertable", t.CanInsert);
                w.WriteBoolean("deletable", t.CanDelete);
                w.WriteNumber("estimated_rows", t.EstimatedRows);
                w.WriteNumber("cost_per_row", t.CostPerRow);
                if (t.Columns.Any(c => c.Required)) w.WriteString("required_hint", t.RequiredHint());
                w.WriteStartArray("columns");
                foreach (var c in t.Columns)
                {
                    w.WriteStartObject();
                    w.WriteString("name", c.Name);
                    w.WriteString("type", c.Type switch { SqlType.Integer => "int", SqlType.Real => "real", SqlType.Text => "text", _ => "blob" });
                    w.WriteBoolean("hidden", c.Hidden);
                    w.WriteString("pushdown", Pushdown(c));
                    w.WriteBoolean("required", c.Required);
                    w.WriteBoolean("writable", c.Writable);
                    w.WriteBoolean("argument", c.IsArgument);
                    w.WriteString("doc", c.Doc ?? "");
                    w.WriteEndObject();
                }
                w.WriteEndArray();
                w.WriteEndObject();
            }
            w.WriteEndArray();
            w.WriteStartArray("functions");
            foreach (var f in S.Db.Functions)
            {
                w.WriteStartObject();
                w.WriteString("name", f.Name);
                w.WriteNumber("args", f.Args);
                w.WriteString("signature", f.Signature);
                w.WriteString("doc", f.Doc);
                w.WriteString("domain", f.Domain);
                w.WriteBoolean("mutates", f.Mutates);
                w.WriteEndObject();
            }
            w.WriteEndArray();
            w.WriteStartArray("views");
            foreach (var (name, sql) in S.Db.Views)
            {
                w.WriteStartObject();
                w.WriteString("name", name);
                w.WriteString("sql", sql);
                w.WriteEndObject();
            }
            w.WriteEndArray();
            w.WriteEndObject();
        }
        return buf.WrittenSpan.ToArray();
    }
}
