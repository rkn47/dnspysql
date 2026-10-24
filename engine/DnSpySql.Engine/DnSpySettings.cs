// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Xml.Linq;
using DnSpySql.Tables;
using DnSpySql.Sql;
using dnlib.DotNet;

namespace DnSpySql;

/// <summary>
/// Reads/writes dnSpy's settings file (dnSpy.xml) sections for code breakpoints, bookmarks, module breakpoints and exception
/// settings, in the exact layout dnSpy's serializers use:
/// &lt;settings&gt;&lt;section _="{guid}"&gt;&lt;section _="Breakpoint" IsEnabled="True"&gt;&lt;section _="BPL" __BPT="DotNet" Token=.. Offset=.. AssemblyFullName=.. ModuleName=.. Method=../&gt;...
/// </summary>
public static class DnSpySettings
{
    public static readonly Guid CodeBreakpointsGuid = new("FBC6039C-8A7A-49DC-9C32-52C1B73DE0A3");
    public static readonly Guid ModuleBreakpointsGuid = new("A7C5956E-593B-4B04-A237-F837CF17E44E");
    public static readonly Guid ExceptionSettingsGuid = new("102DCD2E-BE0A-477C-B4D0-600C5CA28A6A");
    public static readonly Guid BookmarksGuid = new("EAA1BE38-7A55-44AF-AD93-5B7EE2327EDD");
    /// <summary>DebuggerSettingsImpl: one boolean attribute per setting, named after the property.</summary>
    public static readonly Guid DebuggerSettingsGuid = new("91F1ED94-1BEA-4853-9240-B542A7D022CA");
    /// <summary>WatchWindowExpressionsSettingsImpl: Watch Index=N → Expression Value=...</summary>
    public static readonly Guid WatchGuid = new("4052EF89-2381-4CD0-B296-A5497C204B98");
    /// <summary>DocumentTabServiceLoader: FileLists (current list) → FileList → File, and the saved tabs (TabGroupWindow).</summary>
    public static readonly Guid DocumentTabsGuid = new("53863C11-DF95-43F2-8F86-5E9DFCCE6893");
    /// <summary>dnSpy's DocumentList.DEFAULT_NAME.</summary>
    public const string DefaultDocumentList = "(Default)";

    /// <summary>Joins a bookmark's name and comment in dnSpy's single Name field (split again on import).</summary>
    public const string BookmarkCommentSeparator = " — ";

    const char EscapeChar = '©';

    static string Esc(string s)
    {
        var sb = new System.Text.StringBuilder(s.Length);
        foreach (var c in s)
            if (c < ' ' || c == EscapeChar) sb.Append(EscapeChar).Append(((int)c).ToString("X4")); else sb.Append(c);
        return sb.ToString();
    }

    static string Unesc(string? s)
    {
        if (string.IsNullOrEmpty(s) || s.IndexOf(EscapeChar) < 0) return s ?? "";
        var parts = s.Split(EscapeChar);
        var sb = new System.Text.StringBuilder(parts[0]);
        for (int i = 1; i < parts.Length; i++)
        {
            var p = parts[i];
            if (p.Length >= 4 && int.TryParse(p[..4], System.Globalization.NumberStyles.HexNumber, null, out var v)) sb.Append((char)v).Append(p[4..]);
            else sb.Append(p);
        }
        return sb.ToString();
    }

    // dnSpy sorts attributes by upper-cased name with a culture comparer (so "__BPT" comes first) and child sections
    // by name; keep its layout.
    static XElement Section(string name, params (string key, object? value)[] attrs)
    {
        var e = new XElement("section", new XAttribute("_", Esc(name)));
        foreach (var (k, v) in attrs.OrderBy(a => a.key.ToUpperInvariant(), StringComparer.InvariantCulture))
            if (v != null) e.SetAttributeValue(k, Esc(v switch { bool b => b ? "True" : "False", _ => Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture)! }));
        return e;
    }

    static XElement With(XElement e, IEnumerable<XElement> children)
    {
        foreach (var c in children.OrderBy(c => ((string)c.Attribute("_")!).ToUpperInvariant(), StringComparer.InvariantCulture)) e.Add(c);
        return e;
    }

    static string ModulePath(Session s, BreakpointRec? b, LoadedModule lm, string? moduleDir)
    {
        // save() retargets a module to the file it wrote (the copy dnSpy opens), see DnSpyTarget.
        var path = DnSpyTarget(s, lm);
        if (moduleDir == null) return b?.DnSpyModule ?? path;
        var file = Path.GetFileName(path);
        var sep = moduleDir.Contains('\\') ? "\\" : "/";
        return moduleDir.TrimEnd('\\', '/') + sep + file;
    }

    /// <summary>The file dnSpy is expected to open for a module: the last save() of it, else where it was loaded from.</summary>
    public static string DnSpyTarget(Session s, LoadedModule lm) =>
        s.Store.DnSpyTargets.TryGetValue(AnnotationTables.ModuleKey(lm), out var t) ? t : lm.Path;

    static string FileOf(string? path) => (path ?? "")[((path ?? "").LastIndexOfAny(['/', '\\']) + 1)..].ToUpperInvariant();

    /// <summary>What every key of a module's breakpoints and bookmarks contains (":FILE|assembly|"), for keeping them once it is closed.</summary>
    internal static string ExportMarker(Session s, LoadedModule lm) => $":{FileOf(DnSpyTarget(s, lm))}|{lm.Module.Assembly?.FullName ?? ""}|";

    // Exports are remembered per target file (see ProjectStore.DnSpyExports), so the next export to the same file also
    // removes what DnSpySql wrote there before and no longer has: deleted breakpoints, or entries at a module's old path.
    internal static string ExportKey(string path) => Path.GetFullPath(path).ToUpperInvariant();

    /// <summary>
    /// Writes breakpoints and bookmarks (of one module, or all), module breakpoints and exception settings in dnSpy's settings layout.
    /// An existing file (dnSpy.xml, or an earlier export) is merged into: an entry at the same location as one of ours is
    /// replaced, an entry an earlier export to this file wrote and that is gone now is removed, every other entry and
    /// section is kept, and the file is replaced atomically. A new file is what dnSpy's Breakpoints window imports.
    /// Returns the number of entries written.
    /// </summary>
    public static int Export(Session s, string path, LoadedModule? only, string? moduleDir)
    {
        XDocument doc;
        if (File.Exists(path))
        {
            try { doc = XDocument.Load(path); }
            catch (System.Xml.XmlException e) { throw new SqlException($"{path} is not a valid dnSpy settings file: {e.Message}"); }
            if (doc.Root?.Name != "settings") throw new SqlException($"{path}: root element must be <settings>");
        }
        else doc = new XDocument(new XElement("settings"));
        var root = doc.Root!;
        int count = 0;

        // Keys written by earlier exports to this file. A one-module export only owns that module's entries.
        var asmOnly = only == null ? null : "|" + (only.Module.Assembly?.FullName ?? "") + "|";
        var prevAll = s.Store.DnSpyExports.TryGetValue(ExportKey(path), out var p) ? p : [];
        // What an earlier export wrote for a module close() took out of the session stays: it cannot be named now, and
        // closing a sample must not take its breakpoints and bookmarks out of dnSpy.
        var loaded = s.Ws.Modules.Select(m => ExportMarker(s, m)).ToHashSet(StringComparer.Ordinal);
        var parked = s.ParkedModules.Where(x => !loaded.Contains(x)).ToList();
        var prev = prevAll.Where(k => (asmOnly == null || k.Contains(asmOnly, StringComparison.Ordinal))
                                      && !parked.Any(a => k.Contains(a, StringComparison.Ordinal))).ToHashSet();
        var written = new HashSet<string>();
        // Removes the entries at our locations and the ones an earlier export wrote, then adds ours.
        void Merge(XElement? sect, string child, Func<XElement, string?> key, List<(string key, XElement e)> mine)
        {
            var drop = mine.Select(m => m.key).Concat(prev).ToHashSet();
            if (sect != null)
                foreach (var old in Children(sect, child).Where(x => key(x) is { } k && drop.Contains(k)).ToList()) old.Remove();
            foreach (var (k, e) in mine) { sect!.Add(e); written.Add(k); count++; }
        }
        XElement? SectFor(Guid g, bool create) => create ? Sect(root, g) : FindSection(root, g);

        // ---- code breakpoints: ours replace dnSpy's at the same location (file name, assembly, token, offset) ----
        static string Where(XElement bpl) => $"{Kind.Breakpoint}{FileOf(A(bpl, "ModuleName"))}|{A(bpl, "AssemblyFullName")}|{A(bpl, "Token")}|{A(bpl, "Offset")}";
        var ours = new List<(string, XElement)>();
        foreach (var b in s.Store.Breakpoints.OrderBy(b => b.Id))
        {
            var lm = s.Ws.Modules.FirstOrDefault(m => AnnotationTables.ModuleKey(m) == b.At.Mvid);
            if (lm == null || only != null && lm != only) continue; // cannot name a module that is not loaded
            var md = lm.Module.ResolveToken(b.At.Token) as MethodDef;
            var bpl = Section("BPL", ("__BPT", "DotNet"), ("Token", b.At.Token), ("Offset", (uint)b.At.Offset),
                ("AssemblyFullName", lm.Module.Assembly?.FullName ?? ""), ("ModuleName", ModulePath(s, b, lm, moduleDir)),
                ("Method", lm.Dirty ? null : md?.ToString())); // like TokenString below: dnSpy drops a mismatch
            var children = new List<XElement> { bpl };
            if (b.Condition != null) children.Add(Section("Condition", ("Kind", b.ConditionKind), ("Condition", b.Condition)));
            if (b.HitCountKind != null) children.Add(Section("HitCount", ("Kind", b.HitCountKind), ("Count", b.HitCount)));
            if (b.Filter != null) children.Add(Section("Filter", ("Filter", b.Filter)));
            if (b.Message != null) children.Add(Section("Trace", ("Message", b.Message), ("Continue", b.Continue ? null : (object)false)));
            ours.Add((Where(bpl), With(Section("Breakpoint", ("IsEnabled", b.Enabled), ("Labels", b.Labels.Length > 0 ? b.Labels : null)), children)));
        }
        Merge(Sect(root, CodeBreakpointsGuid), "Breakpoint", x => Children(x, "BPL").FirstOrDefault() is { } l ? Where(l) : null, ours);

        // ---- bookmarks (the section is only created when there are any, so dnSpy's own list is kept otherwise): ours
        // replace dnSpy's at the same location. dnSpy has no bookmark comment, so a comment follows the name after
        // BookmarkCommentSeparator.
        static string Mark(XElement bml) => $"{Kind.Bookmark}{FileOf(A(bml, "ModuleName"))}|{A(bml, "AssemblyFullName")}|{A(bml, "__BMT")}|{A(bml, "Token")}|{A(bml, "Offset")}";
        var marks = new List<(string, XElement)>();
        foreach (var b in s.Store.Bookmarks.OrderBy(b => b.Id))
        {
            var lm = s.Ws.Modules.FirstOrDefault(m => AnnotationTables.ModuleKey(m) == b.At.Mvid);
            if (lm == null || only != null && lm != only) continue;
            if (lm.Module.ResolveToken(b.At.Token) is not IMemberDef def) continue; // dnSpy bookmarks only definitions
            bool body = b.At.Offset >= 0 && def is MethodDef;
            var name = b.Comment.Length == 0 ? b.Name : b.Name + BookmarkCommentSeparator + b.Comment;
            // dnSpy compares TokenString with the module on disk and drops the bookmark on a mismatch, so it is left out
            // while the module has unsaved edits (a rename would not be in the file dnSpy opens yet).
            var bml = Section("BML", ("__BMT", body ? "DotNetBody" : "DotNetToken"), ("Token", b.At.Token), ("Offset", body ? (uint)b.At.Offset : null),
                ("AssemblyFullName", lm.Module.Assembly?.FullName ?? ""), ("ModuleName", ModulePath(s, null, lm, moduleDir)),
                ("TokenString", lm.Dirty ? null : def.ToString()));
            marks.Add((Mark(bml), With(Section("Bookmark", ("IsEnabled", b.Enabled), ("Name", name), ("Labels", b.Category.Length > 0 ? b.Category : null)), [bml])));
        }
        Merge(SectFor(BookmarksGuid, marks.Count > 0), "Bookmark", x => Children(x, "BML").FirstOrDefault() is { } l ? Mark(l) : null, marks);

        // ---- module breakpoints (the section is only created when configured) ----
        static string Key(XElement x) => Kind.ModuleBreakpoint + string.Join("|", new[] { "ModuleName", "IsDynamic", "IsInMemory", "IsLoaded", "Order", "AppDomainName", "ProcessName" }.Select(n => A(x, n)));
        var mine = only != null ? [] : s.Store.ModuleBreakpoints.OrderBy(b => b.Id).Select(b => Section("Breakpoint", ("IsEnabled", b.Enabled),
            ("ModuleName", string.IsNullOrEmpty(b.ModuleName) ? null : b.ModuleName), ("IsDynamic", b.IsDynamic), ("IsInMemory", b.IsInMemory),
            ("IsLoaded", b.IsLoaded), ("Order", b.Order), ("AppDomainName", string.IsNullOrEmpty(b.AppDomainName) ? null : b.AppDomainName),
            ("ProcessName", string.IsNullOrEmpty(b.ProcessName) ? null : b.ProcessName))).Select(e => (Key(e), e)).ToList();
        Merge(SectFor(ModuleBreakpointsGuid, mine.Count > 0), "Breakpoint", Key, mine);

        // ---- exception settings (the section is only created when configured): ours replace dnSpy's entry for the same
        // exception; removing an earlier Update entry returns dnSpy to its default for that exception ----
        static string ExKey(string category, string name) => $"{Kind.Exception}{category}|{name}";
        var exs = SectFor(ExceptionSettingsGuid, only == null && s.Store.ExceptionSettings.Count > 0);
        if (exs != null)
            foreach (var cs in Children(exs, "Category").ToList())
            {
                var cat = A(cs, "Name") ?? "";
                var mineHere = only != null ? [] : s.Store.ExceptionSettings.Where(e => e.Category == cat).Select(e => e.Name).ToHashSet();
                foreach (var old in Children(cs, "Exception").ToList())
                {
                    var name = A(old, "IdKind") == "DefaultId" ? "" : A(old, "Name") ?? "";
                    if (mineHere.Contains(name) || prev.Contains(ExKey(cat, name))) old.Remove();
                }
            }
        if (exs != null && only == null)
            foreach (var cat in s.Store.ExceptionSettings.GroupBy(e => e.Category).OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase))
            {
                var cs = Children(exs, "Category").FirstOrDefault(c => A(c, "Name") == cat.Key);
                if (cs == null) exs.Add(cs = Section("Category", ("Name", cat.Key)));
                foreach (var e in cat.OrderBy(e => e.Name.Length == 0 ? 0 : 1).ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase))
                {
                    var flags = new List<string>();
                    if (e.StopFirstChance) flags.Add("StopFirstChance");
                    if (e.StopSecondChance) flags.Add("StopSecondChance");
                    var es = Section("Exception", ("IdKind", e.Name.Length == 0 ? "DefaultId" : "Name"), ("Name", e.Name.Length == 0 ? null : e.Name),
                        ("Description", e.Description.Length > 0 ? e.Description : null), ("DiffType", e.IsCustom ? "Add" : "Update"),
                        ("Flags", flags.Count == 0 ? "None" : string.Join(", ", flags)));
                    // "Type:pattern; ..." (BreakpointTables.ParseConditions); an imported pattern may itself hold ';' or ':'
                    foreach (var c in e.Conditions.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                        if (c.Split(':', 2) is [var type, var cond])
                            es.Add(Section("Conditions", ("Type", type), ("Condition", cond)));
                    cs.Add(es);
                    written.Add(ExKey(cat.Key, e.Name));
                    count++;
                }
            }

        if (only == null) count += ExportDnSpyState(s, root, prev, written);

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        doc.Save(tmp);
        File.Move(tmp, path, overwrite: true);
        // A one-module export keeps what earlier exports wrote for the other modules.
        s.Store.DnSpyExports[ExportKey(path)] = prevAll.Where(k => !prev.Contains(k)).Concat(written).Distinct().ToList();
        s.Store.Changed();
        return count;
    }

    // The section for `guid`, created at the end of the file when missing.
    static XElement Sect(XElement root, Guid guid)
    {
        var e = FindSection(root, guid);
        if (e == null) root.Add(e = new XElement("section", new XAttribute("_", guid.ToString())));
        return e;
    }

    // A top-level section by the GUID dnSpy names it with (export, import and the dnspy_* tables all look it up so).
    static XElement? FindSection(XElement? root, Guid guid) =>
        root?.Elements("section").FirstOrDefault(x => Guid.TryParse(Unesc((string?)x.Attribute("_")), out var g) && g == guid);

    // What an export remembers it wrote (ProjectStore.DnSpyExports), by kind: the prefix and what follows it are stored in
    // project files, so they stay as they are.
    static class Kind
    {
        public const string Breakpoint = "bp:", Bookmark = "bm:", ModuleBreakpoint = "mod:", Exception = "ex:", Debugger = "dbg:", Watch = "watch:",
            Document = "doc:";
    }

    static IEnumerable<XElement> Children(XElement e, string name) =>
        e.Elements("section").Where(x => Unesc((string?)x.Attribute("_")) == name);

    internal static string? A(XElement e, string name) => e.Attribute(name) is { } a ? Unesc(a.Value) : null;

    // Debugger settings, Watch expressions and the files dnSpy opens: what DnSpySql set is merged in, what it set before
    // and no longer has is taken back (`prev`), and everything else in dnSpy's sections is left alone.
    static int ExportDnSpyState(Session s, XElement root, HashSet<string> prev, HashSet<string> written)
    {
        int count = 0;
        var st = s.Store;
        IEnumerable<string> Prev(string kind) => prev.Where(k => k.StartsWith(kind, StringComparison.Ordinal)).Select(k => k[kind.Length..]);

        // ---- debugger settings: attributes named after DebuggerSettings properties ----
        var dbgPrev = Prev(Kind.Debugger).ToList();
        if (st.DebuggerSettings.Count > 0 || dbgPrev.Count > 0)
        {
            var dbg = Sect(root, DebuggerSettingsGuid);
            foreach (var name in dbgPrev.Where(n => !st.DebuggerSettings.ContainsKey(n))) dbg.Attribute(name)?.Remove();
            foreach (var (name, value) in st.DebuggerSettings) { dbg.SetAttributeValue(name, value ? "True" : "False"); written.Add(Kind.Debugger + name); count++; }
        }

        // ---- Watch windows: Watch Index=N → Expression Value=... ----
        static string WatchKey(int window, string expr) => $"{window}|{expr}";
        var watchPrev = Prev(Kind.Watch).ToHashSet();
        if (st.Watch.Count > 0 || watchPrev.Count > 0)
        {
            var w = Sect(root, WatchGuid);
            var mine = st.Watch.Select(x => WatchKey(x.Window, x.Expression)).ToHashSet();
            foreach (var win in Children(w, "Watch").ToList())
                foreach (var e in Children(win, "Expression").ToList())
                    if (WatchKey(int.TryParse(A(win, "Index"), out var i) ? i : -1, A(e, "Value") ?? "") is var k && watchPrev.Contains(k) && !mine.Contains(k)) e.Remove();
            foreach (var x in st.Watch.OrderBy(x => x.Id))
            {
                var win = Children(w, "Watch").FirstOrDefault(e => A(e, "Index") == x.Window.ToString(System.Globalization.CultureInfo.InvariantCulture));
                if (win == null) w.Add(win = Section("Watch", ("Index", x.Window)));
                if (!Children(win, "Expression").Any(e => A(e, "Value") == x.Expression)) win.Add(Section("Expression", ("Value", x.Expression)));
                written.Add(Kind.Watch + WatchKey(x.Window, x.Expression));
                count++;
            }
        }

        // ---- files dnSpy opens at startup: File name=... in the current FileList ----
        var docPrev = Prev(Kind.Document).ToHashSet();
        if (st.Documents.Count > 0 || docPrev.Count > 0)
        {
            var tabs = Sect(root, DocumentTabsGuid);
            var lists = Children(tabs, "FileLists").FirstOrDefault();
            if (lists == null) tabs.AddFirst(lists = Section("FileLists", ("name", DefaultDocumentList)));
            var list = Children(lists, "FileList").FirstOrDefault(l => A(l, "name") == A(lists, "name")) ?? Children(lists, "FileList").FirstOrDefault();
            if (list == null)
            {
                lists.Add(list = Section("FileList", ("name", DefaultDocumentList)));
                lists.SetAttributeValue("name", DefaultDocumentList);
            }
            var mine = st.Documents.Select(d => d.Path.ToUpperInvariant()).ToHashSet();
            foreach (var f in Children(list, "File").ToList())
                if ((A(f, "name") ?? "").ToUpperInvariant() is var k && docPrev.Contains(k) && !mine.Contains(k)) f.Remove();
            foreach (var d in st.Documents.OrderBy(d => d.Id))
            {
                if (!Children(list, "File").Any(f => string.Equals(A(f, "name"), d.Path, StringComparison.OrdinalIgnoreCase)))
                    list.Add(Section("File", ("name", d.Path)));
                written.Add(Kind.Document + d.Path.ToUpperInvariant());
                count++;
            }
        }
        return count;
    }

    /// <summary>One top-level section of a dnSpy settings file, or null (no file, unreadable, no such section).</summary>
    public static XElement? ReadSection(string? path, Guid guid)
    {
        if (path == null) return null;
        try
        {
            // The dnspy_* tables read a section per row, so the parsed file is kept until it changes on disk.
            var info = new FileInfo(path);
            if (!info.Exists) return null;
            var read = _read; // one reference: a reader on another thread sees a whole entry or none
            if (read == null || read.Path != path || read.Time != info.LastWriteTimeUtc || read.Length != info.Length)
                _read = read = new ParsedFile(path, info.LastWriteTimeUtc, info.Length, XDocument.Load(path).Root);
            return FindSection(read.Root, guid);
        }
        catch (Exception e) when (e is System.Xml.XmlException or IOException or UnauthorizedAccessException) { return null; }
    }

    sealed record ParsedFile(string Path, DateTime Time, long Length, XElement? Root);
    static ParsedFile? _read;

    /// <summary>The child sections of a dnSpy settings section with the given name.</summary>
    public static IEnumerable<XElement> Sections(XElement e, string name) => Children(e, name);
    static bool? Bool(XElement e, string name) => A(e, name) is string v && bool.TryParse(v, out var b) ? b : null;

    /// <summary>Imports breakpoints and bookmarks of loaded modules, module breakpoints and exception settings. Returns entries imported.</summary>
    public static int Import(Session s, string path)
    {
        if (!File.Exists(path)) throw new SqlException($"no such file: {path}");
        XElement root;
        try { root = XDocument.Load(path).Root ?? throw new SqlException("empty settings file"); }
        catch (System.Xml.XmlException e) { throw new SqlException($"{path} is not valid XML: {e.Message}"); }
        int count = 0;
        var before = s.Store.DebuggerSnapshot();
        XElement? Sect(Guid g) => FindSection(root, g);
        // The loaded module a dnSpy location names: same file name (and assembly), else the same assembly elsewhere.
        LoadedModule? ModuleOf(XElement loc)
        {
            var asm = A(loc, "AssemblyFullName") ?? "";
            var file = Path.GetFileName((A(loc, "ModuleName") ?? "").Replace('\\', '/'));
            return s.Ws.Modules.FirstOrDefault(m => string.Equals(Path.GetFileName(m.Path), file, StringComparison.OrdinalIgnoreCase)
                                                    && (asm.Length == 0 || m.Module.Assembly?.FullName == asm))
                   ?? s.Ws.Modules.FirstOrDefault(m => asm.Length > 0 && m.Module.Assembly?.FullName == asm);
        }

        if (Sect(CodeBreakpointsGuid) is { } code)
            foreach (var bp in Children(code, "Breakpoint"))
            {
                var bpl = Children(bp, "BPL").FirstOrDefault();
                if (bpl == null || A(bpl, "__BPT") != "DotNet") continue;
                if (!uint.TryParse(A(bpl, "Token"), out var token) || !uint.TryParse(A(bpl, "Offset"), out var offset)) continue;
                var lm = ModuleOf(bpl);
                if (lm == null || lm.Module.ResolveToken(token) is not MethodDef md) continue;
                if (A(bpl, "Method") is { Length: > 0 } mname && mname != md.ToString()) continue; // dnSpy drops these too
                BreakpointRec rec;
                try { rec = BreakpointTables.SetBreakpoint(s, lm.H(md), offset, out _); }
                catch (SqlException) { continue; }
                rec.Enabled = Bool(bp, "IsEnabled") ?? true;
                if (A(bpl, "ModuleName") is { Length: > 0 } dnspyPath && !string.Equals(dnspyPath, lm.Path, StringComparison.OrdinalIgnoreCase)) rec.DnSpyModule = dnspyPath;
                rec.Labels = A(bp, "Labels") ?? "";
                if (Children(bp, "Condition").FirstOrDefault() is { } c) { rec.Condition = A(c, "Condition"); rec.ConditionKind = A(c, "Kind") ?? "IsTrue"; }
                if (Children(bp, "HitCount").FirstOrDefault() is { } h && int.TryParse(A(h, "Count"), out var n)) { rec.HitCountKind = A(h, "Kind") ?? "Equals"; rec.HitCount = n; }
                if (Children(bp, "Filter").FirstOrDefault() is { } f) rec.Filter = A(f, "Filter");
                if (Children(bp, "Trace").FirstOrDefault() is { } t) { rec.Message = A(t, "Message"); rec.Continue = Bool(t, "Continue") ?? true; }
                count++;
            }

        if (Sect(BookmarksGuid) is { } bms)
            foreach (var bm in Children(bms, "Bookmark"))
            {
                var bml = Children(bm, "BML").FirstOrDefault();
                var kind = bml == null ? null : A(bml, "__BMT");
                if (bml == null || kind is not ("DotNetBody" or "DotNetToken") || !uint.TryParse(A(bml, "Token"), out var token)) continue;
                int offset = -1;
                if (kind == "DotNetBody") { if (!uint.TryParse(A(bml, "Offset"), out var o)) continue; offset = (int)o; }
                var lm = ModuleOf(bml);
                if (lm == null || lm.Module.ResolveToken(token) is not IMemberDef def) continue;
                if (A(bml, "TokenString") is { Length: > 0 } ts && ts != def.ToString()) continue; // dnSpy drops these too
                var at = new AnnLocation { Mvid = AnnotationTables.ModuleKey(lm), Token = token, Offset = offset };
                var rec = s.Store.Bookmarks.FirstOrDefault(x => x.At.Mvid == at.Mvid && x.At.Token == at.Token && x.At.Offset == at.Offset);
                if (rec == null) s.Store.Bookmarks.Add(rec = new BookmarkRec { Id = s.Store.NewId(), At = at });
                var name = A(bm, "Name") ?? "";
                var sep = name.IndexOf(BookmarkCommentSeparator, StringComparison.Ordinal);
                rec.Name = sep < 0 ? name : name[..sep];
                rec.Comment = sep < 0 ? "" : name[(sep + BookmarkCommentSeparator.Length)..];
                rec.Category = A(bm, "Labels") ?? "";
                rec.Enabled = Bool(bm, "IsEnabled") ?? true;
                count++;
            }

        if (Sect(ModuleBreakpointsGuid) is { } mods)
            foreach (var bp in Children(mods, "Breakpoint"))
            {
                var imported = new ModuleBreakpointRec
                {
                    Id = s.Store.NewId(), Enabled = Bool(bp, "IsEnabled") ?? true, ModuleName = A(bp, "ModuleName"),
                    IsDynamic = Bool(bp, "IsDynamic"), IsInMemory = Bool(bp, "IsInMemory"), IsLoaded = Bool(bp, "IsLoaded"),
                    Order = int.TryParse(A(bp, "Order"), out var o) ? o : null, AppDomainName = A(bp, "AppDomainName"), ProcessName = A(bp, "ProcessName"),
                };
                // the same breakpoint again (a second import, or one an export wrote) updates the existing one
                var rec = s.Store.ModuleBreakpoints.FirstOrDefault(x => x.SameTarget(imported));
                if (rec != null) rec.Enabled = imported.Enabled; else s.Store.ModuleBreakpoints.Add(imported);
                count++;
            }

        if (Sect(ExceptionSettingsGuid) is { } exs)
            foreach (var cat in Children(exs, "Category"))
                foreach (var e in Children(cat, "Exception"))
                {
                    var diff = A(e, "DiffType");
                    if (diff is not ("Add" or "Update")) continue;
                    var category = A(cat, "Name") ?? "DotNet";
                    var name = A(e, "IdKind") == "DefaultId" ? "" : A(e, "Name") ?? A(e, "Code") ?? "";
                    var flags = A(e, "Flags") ?? "";
                    var rec = s.Store.ExceptionSettings.FirstOrDefault(x => x.Category == category && x.Name == name);
                    if (rec == null) s.Store.ExceptionSettings.Add(rec = new ExceptionSettingRec { Id = s.Store.NewId(), Category = category, Name = name });
                    rec.StopFirstChance = flags.Contains("StopFirstChance");
                    rec.StopSecondChance = flags.Contains("StopSecondChance");
                    rec.Description = A(e, "Description") ?? "";
                    rec.IsCustom = diff == "Add";
                    rec.Conditions = string.Join("; ", Children(e, "Conditions").Select(c => $"{A(c, "Type")}:{A(c, "Condition")}"));
                    count++;
                }

        s.Store.Changed();
        // Records are updated in place above, so the import journals as a whole: undo puts every list back as it was.
        s.Ws.Record("breakpoints", $"bp_import('{path}')", before, s.Store.DebuggerSnapshot());
        return count;
    }
}
