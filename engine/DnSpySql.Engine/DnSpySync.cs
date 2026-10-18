// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using DnSpySql.Tables;
using dnlib.DotNet;
using dnSpy.Contracts.Decompiler.XmlDoc;

namespace DnSpySql;

/// <summary>
/// Keeps dnSpy's settings file in step with the session: after a statement that changed breakpoints, bookmarks, module
/// breakpoints, exception settings or where a module was saved, they are merged into dnSpy.xml (DnSpySettings.Export).
/// The runtime setting dnspy_xml picks the file: auto (dnSpyEx's own choice), off, or a path.
/// </summary>
public sealed class DnSpySync
{
    readonly Session _s;
    string? _before;
    // The path found for a mode, until the next statement: 'auto' looks for running dnSpy processes, which is too slow to
    // repeat for every row of the dnspy_* tables.
    (string mode, string? path)? _resolved;

    public DnSpySync(Session s) { _s = s; }

    string Mode => (_s.Settings["dnspy_xml"].Value ?? "auto").Trim();

    static bool IsOff(string mode) =>
        mode.Length == 0 || mode.Equals("off", StringComparison.OrdinalIgnoreCase)
        || mode.Equals("auto", StringComparison.OrdinalIgnoreCase) && !OperatingSystem.IsWindows();

    /// <summary>The dnSpy settings file to keep in step, or null when syncing is off (or there is no dnSpy, off Windows).</summary>
    public string? SettingsPath()
    {
        var mode = Mode;
        if (_resolved is { } r && r.mode == mode) return r.path;
        string? path = null;
        if (IsOff(mode)) { }
        else if (!mode.Equals("auto", StringComparison.OrdinalIgnoreCase)) path = Path.GetFullPath(mode);
        else
        {
            // dnSpyEx (AppDirectories): dnSpy.xml next to its binaries (the bin sub directory) when that file exists, otherwise
            // %APPDATA%\dnSpy\dnSpy.xml. A portable dnSpy is only found while it runs; set dnspy_xml for one that is closed.
            path = RunningDnSpy().Where(exe => exe.Length > 0)
                .SelectMany(exe => new[] { Path.Combine(Path.GetDirectoryName(exe)!, "bin", "dnSpy.xml"), Path.Combine(Path.GetDirectoryName(exe)!, "dnSpy.xml") })
                .FirstOrDefault(File.Exists)
                ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "dnSpy", "dnSpy.xml");
        }
        _resolved = (mode, path);
        return path;
    }

    static List<string> RunningDnSpy()
    {
        var found = new List<string>();
        if (!OperatingSystem.IsWindows()) return found;
        foreach (var name in new[] { "dnSpy", "dnSpy-x86" })
            foreach (var p in Process.GetProcessesByName(name))
                using (p)
                    try { if (p.MainModule?.FileName is { } f) found.Add(f); }
                    catch (Exception) { found.Add(""); } // running, but its path is not readable (other user / elevation)
        return found;
    }

    // Everything an export writes depends on. Module dirtiness is part of it: Method/TokenString are written once saved.
    string Fingerprint() => JsonSerializer.Serialize(new
    {
        _s.Store.Breakpoints, _s.Store.Bookmarks, _s.Store.ModuleBreakpoints, _s.Store.ExceptionSettings, _s.Store.DnSpyTargets,
        _s.Store.DebuggerSettings, _s.Store.Watch, _s.Store.Documents,
        Modules = _s.Ws.Modules.Select(m => new { m.Path, m.Dirty }).ToList(), // (a tuple would serialize as {}: its items are fields)
    });

    public void BeginStatement()
    {
        _resolved = null;
        _before = IsOff(Mode) ? null : Fingerprint();
    }

    /// <summary>After a statement: syncs when something dnSpy shows changed. Returns a notice for the caller, or null.</summary>
    public string? EndStatement()
    {
        if (_before == null) return null;
        var after = Fingerprint();
        if (after == _before) return null;
        _before = after;
        if (SettingsPath() is not { } path) return null;
        // Nothing of ours to write or to take back (say, an assembly was just opened): leave dnSpy.xml alone.
        var st = _s.Store;
        if (st.Breakpoints.Count + st.Bookmarks.Count + st.ModuleBreakpoints.Count + st.ExceptionSettings.Count
            + st.DebuggerSettings.Count + st.Watch.Count + st.Documents.Count == 0
            && !st.DnSpyExports.ContainsKey(DnSpySettings.ExportKey(path))) return null;
        return Sync(out _);
    }

    /// <summary>Merges everything into dnSpy's settings file now; returns the notice (path, count, or why it failed).</summary>
    public string Sync(out int count)
    {
        count = 0;
        var path = SettingsPath();
        if (path == null) return "dnSpy sync is off (runtime setting dnspy_xml = off; set it to auto or to the path of dnSpy.xml)";
        try { count = DnSpySettings.Export(_s, path, null, null); }
        catch (Exception e) { return $"dnSpy sync failed ({path}): {e.Message}"; }
        var notice = $"dnSpy.xml updated: {path} ({count} entries)";
        if (RunningDnSpy().Count > 0)
            notice += ". dnSpy is running: it reads dnSpy.xml only at startup and overwrites it when it exits, so close dnSpy, " +
                      "run SELECT dnspy_sync(), then start dnSpy again";
        return notice;
    }
}

/// <summary>
/// What save() writes next to an assembly so dnSpy shows the analysis: an XML documentation file (dnSpyEx loads
/// &lt;assembly&gt;.xml from next to the file and shows it as /// comments) and the annotation project for the new file.
/// The saved module keeps its MVID and tokens, so every annotation still applies to it.
/// </summary>
public static class AnnotatedSave
{
    /// <summary>Writes the sidecar files for the module just saved to `path` and retargets dnSpy exports to it.</summary>
    public static string After(Session s, LoadedModule lm, string path)
    {
        var key = AnnotationTables.ModuleKey(lm);
        s.Store.DnSpyTargets[key] = path;
        // dnSpy opens the saved copy at its next start (a later save of the same module replaces it).
        s.Store.Documents.RemoveAll(d => d.Mvid == key);
        s.Store.Documents.Add(new DocumentRec { Id = s.Store.NewId(), Path = path, Mvid = key });
        s.Store.Changed();
        var notes = new List<string>();

        var doc = XmlDoc(s, lm, out int members);
        var xmlPath = Path.ChangeExtension(path, ".xml");
        if (members > 0)
        {
            doc.Save(xmlPath);
            notes.Add($"{xmlPath} ({members} documented members, shown by dnSpy as /// comments)");
        }
        else if (IsOurs(xmlPath))
        {
            // nothing annotated any more: a sidecar an earlier save wrote would show comments that are gone
            File.Delete(xmlPath);
            notes.Add($"removed {xmlPath} (no comments or tags left)");
        }

        var projectPath = path + ".dnspysql.json";
        if (!string.Equals(Path.GetFullPath(projectPath), s.Store.Path, StringComparison.OrdinalIgnoreCase))
        {
            var p = new ProjectStore
            {
                NextId = s.Store.NextId,
                Comments = s.Store.Comments.Where(x => x.At.Mvid == key).ToList(),
                Bookmarks = s.Store.Bookmarks.Where(x => x.At.Mvid == key).ToList(),
                Tags = s.Store.Tags.Where(x => x.At.Mvid == key).ToList(),
                Breakpoints = s.Store.Breakpoints.Where(x => x.At.Mvid == key).ToList(),
                ModuleBreakpoints = s.Store.ModuleBreakpoints.ToList(),
                ExceptionSettings = s.Store.ExceptionSettings.ToList(),
                Kv = new(s.Store.Kv, StringComparer.Ordinal),
                DnSpyTargets = new(StringComparer.OrdinalIgnoreCase) { [key] = path },
            };
            p.Save(projectPath);
            notes.Add($"{projectPath} (annotations for the new file)");
        }
        return notes.Count == 0 ? "" : "wrote " + string.Join(" and ", notes);
    }

    // Marks the XML documentation files save() writes, so a later save may remove one it wrote but never a real one.
    const string Marker = " written by dnspysql save(): comments and tags from the analysis project ";

    static bool IsOurs(string path)
    {
        try { return File.Exists(path) && XDocument.Load(path).Root?.Nodes().OfType<XComment>().Any(c => c.Value == Marker) == true; }
        catch (Exception) { return false; } // unreadable or not XML: not ours
    }

    /// <summary>
    /// The module's comments and tags as an XML documentation file: comments on a type or member become its summary,
    /// comments at IL offsets are listed in the method's remarks with the decompiled statement, tags close the remarks.
    /// </summary>
    public static XDocument XmlDoc(Session s, LoadedModule lm, out int members)
    {
        var key = AnnotationTables.ModuleKey(lm);
        var entries = new SortedDictionary<string, (List<string> summary, List<string> remarks, List<string> tags, Dictionary<string, List<string>> pars)>(StringComparer.Ordinal);
        (List<string> summary, List<string> remarks, List<string> tags, Dictionary<string, List<string>> pars)? Entry(IMemberDef def)
        {
            var id = XmlDocKeyProvider.GetKey(def, new StringBuilder())?.ToString();
            if (id == null) return null;
            if (!entries.TryGetValue(id, out var e)) entries[id] = e = (new(), new(), new(), new());
            return e;
        }
        // A parameter's comment goes into its method's <param>.
        IMemberDef? Owner(uint token, out string? param)
        {
            param = null;
            var r = lm.Module.ResolveToken(token);
            if (r is ParamDef pd) { param = pd.Name; return pd.DeclaringMethod; }
            return r as IMemberDef;
        }

        Dictionary<uint, List<DecompiledLine>> lines = new();
        string? Statement(MethodDef md, int offset)
        {
            if (!lines.TryGetValue(md.MDToken.Raw, out var ls))
            {
                try { ls = s.Decompiler.Decompile(lm.H(md)).Lines; } catch (Exception) { ls = []; }
                lines[md.MDToken.Raw] = ls;
            }
            var h = lm.H(md);
            return ls.FirstOrDefault(l => l.Method == h && l.ILOffset <= offset && offset < (l.ILEnd ?? l.ILOffset + 1))?.Text.Trim();
        }

        foreach (var c in s.Store.Comments.Where(x => x.At.Mvid == key).OrderBy(x => x.At.Token).ThenBy(x => x.At.Offset).ThenBy(x => x.Id))
        {
            if (Owner(c.At.Token, out var param) is not { } def || Entry(def) is not { } e || c.Text.Length == 0) continue;
            if (param != null) { if (!e.pars.TryGetValue(param, out var l)) e.pars[param] = l = new(); l.Add(c.Text); }
            else if (c.At.Offset < 0 || def is not MethodDef md) e.summary.Add(c.Text);
            else
            {
                var st = Statement(md, c.At.Offset);
                e.remarks.Add($"IL_{c.At.Offset:X4}{(st is { Length: > 0 } ? $" ({st})" : "")}: {c.Text}");
            }
        }
        foreach (var t in s.Store.Tags.Where(x => x.At.Mvid == key))
            if (Owner(t.At.Token, out _) is { } def && Entry(def) is { } e && !e.tags.Contains(t.Tag)) e.tags.Add(t.Tag);

        static string Block(IEnumerable<string> ls) => "\n" + string.Join("\n", ls) + "\n";
        var root = new XElement("members");
        foreach (var (id, e) in entries)
        {
            var m = new XElement("member", new XAttribute("name", id));
            if (e.summary.Count > 0) m.Add(new XElement("summary", Block(e.summary)));
            foreach (var (name, texts) in e.pars) m.Add(new XElement("param", new XAttribute("name", name), string.Join(" ", texts)));
            var remarks = e.remarks.ToList();
            if (e.tags.Count > 0) remarks.Add("Tags: " + string.Join(", ", e.tags));
            if (remarks.Count > 0) m.Add(new XElement("remarks", Block(remarks)));
            root.Add(m);
        }
        members = entries.Count;
        return new XDocument(new XDeclaration("1.0", "utf-8", null),
            new XElement("doc", new XComment(Marker), new XElement("assembly", new XElement("name", lm.Module.Assembly?.Name.String ?? lm.Module.Name.String)), root));
    }
}
