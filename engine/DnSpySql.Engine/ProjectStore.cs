// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DnSpySql;

/// <summary>Location of an annotation, stable across sessions: module MVID + metadata token + optional IL offset.</summary>
public sealed class AnnLocation
{
    public string Mvid { get; set; } = "";
    public uint Token { get; set; }
    public int Offset { get; set; } = -1;

    public bool SameEntity(AnnLocation o) => Mvid == o.Mvid && Token == o.Token;
    public bool Same(AnnLocation o) => SameEntity(o) && Offset == o.Offset;
}

public sealed class CommentRec
{
    public long Id { get; set; }
    public AnnLocation At { get; set; } = new();
    public string Kind { get; set; } = "eol";
    public string Text { get; set; } = "";
    public DateTime Updated { get; set; } = DateTime.UtcNow;
}

public sealed class BookmarkRec
{
    public long Id { get; set; }
    public AnnLocation At { get; set; } = new();
    public string Name { get; set; } = "";
    public string Category { get; set; } = "";
    public string Comment { get; set; } = "";
    public bool Enabled { get; set; } = true;
}

public sealed class TagRec
{
    public long Id { get; set; }
    public AnnLocation At { get; set; } = new();
    public string Tag { get; set; } = "";
    public string Comment { get; set; } = "";
}

/// <summary>A dnSpy code breakpoint / tracepoint (DbgCodeBreakpointSettings) at a method + IL offset.</summary>
public sealed class BreakpointRec
{
    public long Id { get; set; }
    public AnnLocation At { get; set; } = new();
    public bool Enabled { get; set; } = true;
    /// <summary>C# expression evaluated by the debugger.</summary>
    public string? Condition { get; set; }
    /// <summary>IsTrue | WhenChanged</summary>
    public string ConditionKind { get; set; } = "IsTrue";
    /// <summary>Equals | MultipleOf | GreaterThanOrEquals (null = no hit-count condition)</summary>
    public string? HitCountKind { get; set; }
    public int HitCount { get; set; }
    /// <summary>Filter expression over MachineName, ProcessId, ProcessName, ThreadId, ThreadName.</summary>
    public string? Filter { get; set; }
    /// <summary>Tracepoint message; when set the breakpoint prints it ($FUNCTION, $TID, {expr} ...).</summary>
    public string? Message { get; set; }
    /// <summary>Tracepoint continues execution (true) or also breaks (false).</summary>
    public bool Continue { get; set; } = true;
    public string Labels { get; set; } = "";
    /// <summary>Method full name when set (dnSpy drops a breakpoint whose method no longer matches).</summary>
    public string? MethodName { get; set; }
    /// <summary>Module path written to dnSpy's file when dnSpy opens the module somewhere else (set by import or UPDATE).</summary>
    public string? DnSpyModule { get; set; }
}

/// <summary>A dnSpy module breakpoint (break when a matching module loads/unloads).</summary>
public sealed class ModuleBreakpointRec
{
    public long Id { get; set; }
    public bool Enabled { get; set; } = true;
    /// <summary>Module name/path pattern; wildcards * and ? allowed.</summary>
    public string? ModuleName { get; set; }
    public bool? IsDynamic { get; set; }
    public bool? IsInMemory { get; set; }
    /// <summary>true = on load, false = on unload, null = both.</summary>
    public bool? IsLoaded { get; set; }
    public int? Order { get; set; }
    public string? AppDomainName { get; set; }
    public string? ProcessName { get; set; }
}

/// <summary>dnSpy exception setting (Exception Settings window): break on first/second chance, with module conditions.</summary>
public sealed class ExceptionSettingRec
{
    public long Id { get; set; }
    /// <summary>DotNet | MDA</summary>
    public string Category { get; set; } = "DotNet";
    /// <summary>Exception type full name (or MDA name). Empty = the category's default entry.</summary>
    public string Name { get; set; } = "";
    public bool StopFirstChance { get; set; }
    public bool StopSecondChance { get; set; } = true;
    /// <summary>"ModuleNameEquals:pattern; ModuleNameNotEquals:pattern" (all must hold).</summary>
    public string Conditions { get; set; } = "";
    public string Description { get; set; } = "";
    /// <summary>true = not in dnSpy's built-in list (exported as Add), false = override of a built-in entry (Update).</summary>
    public bool IsCustom { get; set; }
}

/// <summary>A Watch-window expression DnSpySql adds to dnSpy (window 0-3, like dnSpy's Watch 1-4).</summary>
public sealed class WatchRec
{
    public long Id { get; set; }
    public int Window { get; set; }
    public string Expression { get; set; } = "";
}

/// <summary>A file DnSpySql adds to dnSpy's current document list (opened when dnSpy starts).</summary>
public sealed class DocumentRec
{
    public long Id { get; set; }
    public string Path { get; set; } = "";
    /// <summary>Module key when save() added it (a later save of the same module replaces the path).</summary>
    public string? Mvid { get; set; }
}

/// <summary>Persistent per-project user data (the dnSpy settings/bookmarks analogue, idasql's netnodes).</summary>
public sealed class ProjectStore
{
    [JsonIgnore] public string? Path { get; private set; }
    public int Version { get; set; } = 1;
    public long NextId { get; set; } = 1;
    public List<CommentRec> Comments { get; set; } = new();
    public List<BookmarkRec> Bookmarks { get; set; } = new();
    public List<TagRec> Tags { get; set; } = new();
    public List<BreakpointRec> Breakpoints { get; set; } = new();
    public List<ModuleBreakpointRec> ModuleBreakpoints { get; set; } = new();
    public List<ExceptionSettingRec> ExceptionSettings { get; set; } = new();
    /// <summary>dnSpy debugger settings DnSpySql overrides (DebuggerSettings property name → value).</summary>
    public SortedDictionary<string, bool> DebuggerSettings { get; set; } = new(StringComparer.Ordinal);
    public List<WatchRec> Watch { get; set; } = new();
    public List<DocumentRec> Documents { get; set; } = new();
    public SortedDictionary<string, string> Kv { get; set; } = new(StringComparer.Ordinal);
    /// <summary>Module key (MVID) → the file save() last wrote for it: the copy dnSpy opens, so exports name that path.</summary>
    public Dictionary<string, string> DnSpyTargets { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>dnSpy settings/export file (full path, upper case) → keys of the entries DnSpySql last wrote there.</summary>
    public Dictionary<string, List<string>> DnSpyExports { get; set; } = new(StringComparer.Ordinal);

    public ProjectStore(string? path) { Path = path; }
    public ProjectStore() { }

    static readonly JsonSerializerOptions Json = new() { WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    public static ProjectStore Load(string path)
    {
        path = System.IO.Path.GetFullPath(path);
        ProjectStore s;
        if (File.Exists(path))
        {
            try { s = JsonSerializer.Deserialize<ProjectStore>(File.ReadAllText(path), Json) ?? new ProjectStore(); }
            catch (JsonException e) { throw new InvalidOperationException($"project file {path} is corrupt: {e.Message}"); }
        }
        else s = new ProjectStore();
        s.Path = path;
        return s;
    }

    public long NewId() => NextId++;

    /// <summary>
    /// Captures the debugger lists (breakpoints, bookmarks, module breakpoints, exception settings) so a bulk change such as
    /// bp_import journals as one step; the returned action puts them back. It keeps the same record objects, because other
    /// journal entries hold them, and restores their values.
    /// </summary>
    public Action DebuggerSnapshot()
    {
        var parts = new[] { Snap(Breakpoints), Snap(Bookmarks), Snap(ModuleBreakpoints), Snap(ExceptionSettings) };
        return () => { foreach (var p in parts) p(); Changed(); };
    }

    static readonly JsonSerializerOptions Exact = new();

    static Action Snap<T>(List<T> list) where T : class
    {
        var items = list.Select(x => (Item: x, Json: JsonSerializer.Serialize(x, Exact))).ToArray();
        return () =>
        {
            list.Clear();
            foreach (var (item, json) in items)
            {
                var saved = JsonSerializer.Deserialize<T>(json, Exact)!;
                foreach (var p in typeof(T).GetProperties())
                    if (p.CanWrite) p.SetValue(item, p.GetValue(saved));
                list.Add(item);
            }
        };
    }

    public bool AutoSave { get; set; } = true;

    public void Changed()
    {
        if (AutoSave) Save();
    }

    public void Save(string? path = null)
    {
        path ??= Path;
        if (path == null) return;
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, Json));
        File.Move(tmp, path, overwrite: true);
    }
}
