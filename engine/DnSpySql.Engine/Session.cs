// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Tables;
using DnSpySql.Sql;

namespace DnSpySql;

public sealed class SessionOptions
{
    public bool ReadOnly { get; set; }
    /// <summary>Annotation store (comments, bookmarks, tags, notes, breakpoints). Default: &lt;first target&gt;.dnspysql.json</summary>
    public string? ProjectPath { get; set; }
    public bool NoProject { get; set; }
    public int QueryTimeoutMs { get; set; } = 0;
    public int MaxRows { get; set; } = 100_000;
    /// <summary>Extra reference directories (CLI --ref).</summary>
    public List<string> ReferencePaths { get; set; } = new();
    /// <summary>dnSpy settings file kept in step with breakpoints/bookmarks: null = auto, "off", or a path (CLI --dnspy-xml).</summary>
    public string? DnSpyXml { get; set; }
}

/// <summary>A DnSpySql session: workspace + services; SQLite itself lives in the native host.</summary>
public sealed class Session : IDisposable
{
    public const string ToolName = "dnspysql";
    /// <summary>The DnSpySql version, as the native host reports it at init.</summary>
    public static string ToolVersion { get; set; } = typeof(Session).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
    /// <summary>The commit the host was built from (git describe), so a stale build shows in the binary table.</summary>
    public static string? ToolCommit { get; set; }

    public Workspace Ws { get; } = new();
    public Database Db { get; }
    public SessionOptions Options { get; }
    public ProjectStore Store { get; private set; }
    public DecompilerService Decompiler { get; }
    public CodeIndex Index { get; }
    public DnSpySync DnSpy { get; }
    /// <summary>Messages for the caller about the current statement (sidecar files written, dnSpy.xml synced).</summary>
    public List<string> Notices { get; } = new();
    public Dictionary<string, RuntimeSetting> Settings { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Columns (name, declared type) of the SQL views in <see cref="Tables.Views"/>, for the catalog.</summary>
    public Dictionary<string, List<(string name, string type)>> ViewColumns { get; } = new(StringComparer.OrdinalIgnoreCase);
    readonly object _lock = new();

    public Session(SessionOptions? options = null)
    {
        Options = options ?? new SessionOptions();
        Db = new Database { ReadOnly = Options.ReadOnly };
        Db.BeforeStatement = Ws.BeginGroup;
        Store = new ProjectStore(null);
        Decompiler = new DecompilerService(this);
        Index = new CodeIndex(this);
        DnSpy = new DnSpySync(this);
        InitSettings();
        if (Options.ReferencePaths.Count > 0) SetSetting("reference_paths", string.Join(Path.PathSeparator, Options.ReferencePaths));
        Registry.RegisterAll(this);
    }

    public LoadedModule Open(string path)
    {
        lock (_lock)
        {
            var lm = Ws.Open(path);
            if (Ws.Modules.Count == 1 && !Options.NoProject && Store.Path == null)
            {
                Store = ProjectStore.Load(Options.ProjectPath ?? lm.DiskPath + ".dnspysql.json");
                _projectModule = lm.Id;
            }
            Index.Invalidate();
            return lm;
        }
    }

    public LoadedModule OpenBytes(byte[] bytes, string pseudoPath, bool memoryLayout, LoadedModule? untamperedFrom = null, uint untamperedBy = 0,
        LoadedModule? parent = null)
    {
        lock (_lock)
        {
            var lm = Ws.OpenBytes(bytes, pseudoPath, memoryLayout, untamperedFrom, untamperedBy, parent);
            Index.Invalidate();
            return lm;
        }
    }

    // ---- closing modules ----
    // The module whose project file holds the session's annotations, and the modules close() was asked for, closed when
    // the statement ends: a scan in the same statement may still be reading them.
    int? _projectModule;
    readonly List<int> _closing = new();

    /// <summary>
    /// Closed modules (DnSpySettings.ExportMarker): the entries an earlier export wrote into dnSpy.xml for them are kept (a
    /// closed module cannot be named, so its breakpoints would otherwise be taken out of dnSpy at the next sync).
    /// </summary>
    public HashSet<string> ParkedModules { get; } = new(StringComparer.Ordinal);

    /// <summary>The module, and with withDerived every module that came out of it (modules.derived_from, recursively), to close at the end of the statement.</summary>
    public List<int> Close(LoadedModule lm, bool withDerived)
    {
        lock (_lock)
        {
            var ids = new List<int> { lm.Id };
            for (int i = 0; withDerived && i < ids.Count; i++)
                ids.AddRange(Ws.Modules.Where(m => m.DerivedFrom == ids[i] && !ids.Contains(m.Id)).Select(m => m.Id));
            foreach (var m in ids.Select(Ws.Get))
            {
                if (m.Dirty || m.RawPatches.Count > 0)
                    throw new SqlException($"close: module {m.Id} ({m.Name}) has unsaved edits: save() it first, or undo() them" +
                                           (m.Id == lm.Id ? "" : $" (it came out of module {lm.Id}; close({lm.Id}, 0) closes that one alone)"));
                if (m.Id == _projectModule && Store.Path != null)
                    throw new SqlException($"close: module {m.Id} holds the session's project file ({Store.Path}), where annotations are saved: " +
                                           "close the other modules instead (close_all()), or start the session with --no-project");
            }
            foreach (var id in ids) if (!_closing.Contains(id)) _closing.Add(id);
            return ids;
        }
    }

    /// <summary>close() would take it: no unsaved edits, and not the module holding the project file.</summary>
    public bool Closable(LoadedModule m) => !m.Dirty && m.RawPatches.Count == 0 && !(m.Id == _projectModule && Store.Path != null);

    /// <summary>Every module that can be closed: all of them but the project file's (and, with keepFirst, the first one open).</summary>
    public List<int> CloseAll(bool keepFirst)
    {
        var keep = Ws.Modules.Where(m => m.Id == _projectModule && Store.Path != null || keepFirst && m == Ws.Modules[0]).Select(m => m.Id).ToHashSet();
        var ids = new List<int>();
        foreach (var m in Ws.Modules.Where(m => !keep.Contains(m.Id))) ids.AddRange(Close(m, withDerived: false));
        return ids;
    }

    void ApplyClose()
    {
        long before = Environment.WorkingSet;
        var closed = Release();
        if (closed.Count == 0) return;
        // The file bytes sit on the large object heap, which a collection does not compact by itself, and the GC keeps the
        // memory it freed for later: an aggressive collection compacts both and hands the memory back to the system, or
        // closing frees nothing anyone can see.
        System.Runtime.GCSettings.LargeObjectHeapCompactionMode = System.Runtime.GCLargeObjectHeapCompactionMode.CompactOnce;
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
        long after = Environment.WorkingSet;
        Notices.Add($"close: closed module{(closed.Count > 1 ? "s" : "")} {string.Join(", ", closed)}; the process holds " +
                    $"{after >> 20:N0} MB ({Math.Max(0, before - after) >> 20:N0} MB freed)");
    }

    // Takes the modules out and lets go of everything that knew them. A method of its own, so that no local of it (the
    // modules themselves) is still on the stack while the collection runs: they would all survive it.
    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    List<int> Release()
    {
        var ids = _closing.ToList();
        _closing.Clear();
        var closed = Ws.Modules.Where(m => ids.Contains(m.Id)).Select(m => m.Id).ToList();
        if (closed.Count == 0) return closed;
        foreach (var m in Ws.Modules.Where(m => closed.Contains(m.Id))) ParkedModules.Add(DnSpySettings.ExportMarker(this, m));
        Ws.Close(closed);
        Index.Reset();
        Decompiler.Forget(closed);
        Emulator.Reset(this);
        return closed;
    }

    // Warned once each time the process crosses the threshold, so an MCP client can tell the user before the machine runs
    // out: half the memory there is, or 1 GB once the machine is 90% full (other programs use memory too).
    bool _memoryWarned;

    string? MemoryNotice()
    {
        var info = GC.GetGCMemoryInfo();
        long total = info.TotalAvailableMemoryBytes, used = Environment.WorkingSet;
        if (total <= 0) return null;
        bool high = used * 2 >= total || info.MemoryLoadBytes * 10 >= total * 9 && used >= 1L << 30;
        if (!high || _memoryWarned) { _memoryWarned = high; return null; }
        _memoryWarned = true;
        return $"memory: the process holds {used >> 20:N0} MB, {used * 100 / total}% of the {total >> 20:N0} MB available, with {Ws.Modules.Count} " +
               "modules open: close() the samples you are done with (SELECT close(id) closes a module and the stages that came out of it)";
    }

    long _statementRevision;

    /// <summary>Called by the host before each SQL statement: undo group, timeout, cancellation.</summary>
    public void BeginStatement()
    {
        if (Ws.Revision != _statementRevision) Index.InvalidateIfChanged();
        Db.BeginStatement(Settings["query_timeout_ms"].AsLong ?? 0);
        Notices.Clear();
        DnSpy.BeginStatement();
    }

    /// <summary>Called by the host after each SQL statement; returns the statement's notices (one per line), or null.</summary>
    public string? EndStatement()
    {
        if (_closing.Count > 0) ApplyClose();
        if (Ws.Revision != _statementRevision) Index.InvalidateIfChanged();
        _statementRevision = Ws.Revision;
        if (DnSpy.EndStatement() is { } synced) Notices.Add(synced);
        if (MemoryNotice() is { } memory) Notices.Add(memory);
        var notices = Notices.Count == 0 ? null : string.Join("\n", Notices.Distinct());
        Notices.Clear();
        return notices;
    }

    public void Interrupt() => Db.Interrupt();

    public sealed class RuntimeSetting
    {
        public required string Key { get; init; }
        public required string Type { get; init; }
        public required string Doc { get; init; }
        public bool Settable { get; init; } = true;
        public string? Value { get; set; }
        public long? AsLong => Values.ParseLong(Value ?? "");
        public bool AsBool => Value is "1" or "true" or "on" or "yes";
    }

    void InitSettings()
    {
        void Add(string key, string type, string value, string doc, bool settable = true) =>
            Settings[key] = new RuntimeSetting { Key = key, Type = type, Value = value, Doc = doc, Settable = settable };
        Add("query_timeout_ms", "int", Options.QueryTimeoutMs.ToString(), "per-statement timeout in milliseconds (0 = none)");
        Add("max_rows", "int", Options.MaxRows.ToString(), "row cap per statement for CLI/HTTP/MCP output");
        Add("current_module", "int", "1", "module used when a bare metadata token is given");
        Add("decompiler_language", "string", "csharp", "default language for pseudocode/decompile(): csharp | vb | il");
        Add("decompiler_show_tokens", "bool", "0", "emit metadata token comments in IL text");
        Add("search_include_compiler_generated", "bool", "0", "search/jump_entities: include compiler-generated members");
        Add("save_preserve_tokens", "bool", "1", "save(): keep all metadata tokens/RIDs (dnSpy 'Preserve All')");
        Add("save_strip_ready_to_run", "bool", "1",
            "save(): write edited ReadyToRun images as IL-only (otherwise the runtime may keep running the precompiled native code and ignore IL edits)");
        Add("reference_paths", "string", string.Join(Path.PathSeparator, Options.ReferencePaths),
            $"extra directories with referenced assemblies, separated by '{Path.PathSeparator}' (e.g. .NET Framework reference assemblies on Linux)");
        Add("save_sidecars", "bool", "1",
            "save(): also write <file>.xml (comments and tags as XML documentation, which dnSpyEx shows as /// comments) and " +
            "<file>.dnspysql.json (the annotations), and point dnSpy exports at the saved file");
        Add("dnspy_xml", "string", Options.DnSpyXml ?? Environment.GetEnvironmentVariable("DNSPYSQL_DNSPY_XML") ?? "auto",
            "dnSpy settings file kept in step after every statement that changes breakpoints, bookmarks, module breakpoints or " +
            "exception settings: auto (dnSpyEx's choice: bin\\dnSpy.xml of a running dnSpy when it exists, else " +
            "%APPDATA%\\dnSpy\\dnSpy.xml; Windows only), off, or a path. SELECT dnspy_sync() syncs now");
        Add("max_modules", "int", "0",
            "most modules open at once (0 = no limit): opening one more is refused with a reminder to close() the samples you are done with");
        Add("read_only", "bool", Options.ReadOnly ? "1" : "0",
            "session refuses writes (--readonly); can be switched on, never off: set it to 1 to lock a session for analysis only");
    }

    public void SetSetting(string key, string? value)
    {
        if (!Settings.TryGetValue(key, out var s)) throw new SqlException($"unknown setting '{key}'");
        if (!s.Settable) throw new SqlException($"setting '{key}' is read-only");
        if (s.Type == "int" && Values.ParseLong(value ?? "") is null) throw new SqlException($"setting '{key}' needs an integer");
        if (key == "read_only")
        {
            // one way: a server registered without --readonly can be locked for an analysis-only task, and a session that
            // was promised read-only (by the user, or by an earlier statement) cannot be unlocked by a later one
            bool on = value is "1" or "true" or "on" or "yes";
            if (!on && Db.ReadOnly) throw new SqlException("read_only can only be switched on; restart without --readonly to write");
            if (!on && value is not ("0" or "false" or "off" or "no")) throw new SqlException("setting 'read_only' needs 1 or 0");
            Db.ReadOnly |= on;
            value = Db.ReadOnly ? "1" : "0";
        }
        if (key == "current_module")
        {
            var id = (int)Values.ParseLong(value!)!.Value;
            Ws.Get(id);
            Ws.CurrentModuleId = id;
        }
        if (key == "save_strip_ready_to_run") Ws.StripReadyToRun = value is "1" or "true" or "on" or "yes";
        if (key == "max_modules") Ws.MaxModules = (int)Math.Clamp(Values.ParseLong(value!)!.Value, 0, int.MaxValue);
        if (key == "reference_paths")
        {
            var dirs = (value ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
            foreach (var d in dirs) if (!Directory.Exists(d)) throw new SqlException($"reference path does not exist: {d}");
            Ws.SetUserReferencePaths(dirs);
            Index.Invalidate();
        }
        s.Value = value;
    }

    public void Dispose() => Ws.Dispose();
}
