// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
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

/// <summary>A dnspysql session: workspace + services; SQLite itself lives in the native host.</summary>
public sealed class Session : IDisposable
{
    public const string ToolName = "dnspysql";
    /// <summary>The dnspysql version, as the native host reports it at init.</summary>
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
                Store = ProjectStore.Load(Options.ProjectPath ?? lm.DiskPath + ".dnspysql.json");
            Index.Invalidate();
            return lm;
        }
    }

    public LoadedModule OpenBytes(byte[] bytes, string pseudoPath, bool memoryLayout)
    {
        lock (_lock)
        {
            var lm = Ws.OpenBytes(bytes, pseudoPath, memoryLayout);
            Index.Invalidate();
            return lm;
        }
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
        if (Ws.Revision != _statementRevision) Index.InvalidateIfChanged();
        _statementRevision = Ws.Revision;
        if (DnSpy.EndStatement() is { } synced) Notices.Add(synced);
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
        Add("read_only", "bool", Options.ReadOnly ? "1" : "0", "session refuses writes", settable: false);
    }

    public void SetSetting(string key, string? value)
    {
        if (!Settings.TryGetValue(key, out var s)) throw new SqlException($"unknown setting '{key}'");
        if (!s.Settable) throw new SqlException($"setting '{key}' is read-only");
        if (s.Type == "int" && Values.ParseLong(value ?? "") is null) throw new SqlException($"setting '{key}' needs an integer");
        if (key == "current_module")
        {
            var id = (int)Values.ParseLong(value!)!.Value;
            Ws.Get(id);
            Ws.CurrentModuleId = id;
        }
        if (key == "save_strip_ready_to_run") Ws.StripReadyToRun = value is "1" or "true" or "on" or "yes";
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
