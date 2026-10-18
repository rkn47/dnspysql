// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Text;
using System.Xml.Linq;
using DnSpySql.Functions;
using DnSpySql.Sql;
using dnlib.DotNet;
using dnSpy.Contracts.Decompiler.XmlDoc;

namespace DnSpySql.Tables;

/// <summary>
/// XML documentation of the APIs an assembly uses, as dnSpy shows it in tooltips (Contracts.Logic/Decompiler/XmlDoc).
/// dnSpy's XmlDocLoader looks next to the assembly, in the .NET Framework reference assemblies and in the .NET reference
/// pack of the assembly's target framework. Documentation IDs carry no assembly name, so when that finds nothing (a .NET
/// Framework sample on a machine without the Framework reference assemblies) the ID is looked up across the .NET
/// reference packs of the runtime dnspysql runs on.
/// </summary>
public static class ApiDocTables
{
    public sealed record Doc(long? Member, string DocId, string Xml, string Source);

    static List<string>? _packFiles;
    static readonly Dictionary<string, XmlDocumentationProvider?> _providers = new(StringComparer.OrdinalIgnoreCase);
    static readonly object _lock = new();

    public static void Register(Session s)
    {
        var ws = s.Ws;
        s.Db.Register(new Table<Doc>("api_docs",
                "XML documentation of a type or member (dnSpy's tooltips): WHERE member = <handle> (definitions, member and type " +
                "references, as in memberrefs/typerefs) or WHERE doc_id = 'M:System.Net.Sockets.Socket.Connect(System.String,System.Int32)'") { Domain = "metadata" }
            .Source(c =>
            {
                if (c.Long("member") is long h) return Lookup(s, ws.Normalize(h)) is { } d ? [d] : [];
                if (c.Text("doc_id") is { } id) return Find(id, null) is { } x ? [new Doc(null, id, x.xml, x.source)] : [];
                throw new SqlException("api_docs needs WHERE member = <handle> or WHERE doc_id = '...'");
            })
            .Int("member", d => d.Member, pushdown: Pushdown.Eq, required: true)
            .Text("doc_id", d => d.DocId, pushdown: Pushdown.Eq, required: true, doc: "XML documentation ID (T:, M:, F:, P:, E: prefix)")
            .Text("summary", d => Part(d.Xml, "summary"))
            .Text("returns", d => Part(d.Xml, "returns"))
            .Text("params", d => Named(d.Xml, "param"), doc: "name: text, one per line")
            .Text("exceptions", d => Named(d.Xml, "exception"), doc: "exception type: when, one per line")
            .Text("remarks", d => Part(d.Xml, "remarks"))
            .Text("xml", d => d.Xml)
            .Text("source", d => d.Source, doc: "documentation file")
            .Estimate(1, 50));

        s.Fn("api_doc", 1, 1, a =>
            {
                var v = a[0];
                var d = Values.ToLong(v) is long h ? Lookup(s, ws.Normalize(h)) : Values.ToText(v) is { } id && Find(id, null) is { } x ? new Doc(null, id, x.xml, x.source) : null;
                return d == null ? null : Part(d.Xml, "summary");
            }, "api_doc(handle | doc_id)", "summary of a type or member's XML documentation (dnSpy's tooltip), NULL when none is found", "metadata");
    }

    static Doc? Lookup(Session s, long handle)
    {
        var (lm, item) = s.Ws.Resolve(handle);
        IMemberRef? member = item switch
        {
            MethodSpec ms => ms.Method,
            IMemberRef mr => mr,
            _ => null,
        };
        if (member == null) throw new SqlException($"{Handle.Hex(handle)} is not a type or member");
        var id = XmlDocKeyProvider.GetKey(member, new StringBuilder())?.ToString();
        if (string.IsNullOrEmpty(id)) return null;
        // the module that defines it: the referenced definition when it resolves, else this module for its own members
        ModuleDef? defModule = item switch
        {
            IMemberDef d => d.Module,
            MemberRef mr => Try(() => (IMemberDef?)mr.ResolveMethod() ?? mr.ResolveField())?.Module,
            ITypeDefOrRef t => Try(() => t.ResolveTypeDef())?.Module,
            MethodSpec ms => Try(() => ms.ResolveMethodDef())?.Module,
            _ => null,
        };
        return Find(id, defModule) is { } x ? new Doc(handle, id, x.xml, x.source) : null;
    }

    static T? Try<T>(Func<T?> f) where T : class { try { return f(); } catch (Exception) { return null; } }

    static (string xml, string source)? Find(string id, ModuleDef? module)
    {
        if (module != null && !string.IsNullOrEmpty(module.Location))
        {
            XmlDocGuard.Check(module);
            var p = XmlDocLoader.LoadDocumentation(module);
            if (p?.GetDocumentation(id) is { Length: > 0 } x) return (x, Path.ChangeExtension(module.Location, ".xml") is var f && File.Exists(f) ? f : "reference assemblies");
        }
        foreach (var (file, provider) in PacksFor(id))
            if (provider.GetDocumentation(id) is { Length: > 0 } x) return (x, file);
        return null;
    }

    // XML documentation files of the newest .NET reference packs next to the runtime dnspysql runs on
    // (<dotnet>/packs/Microsoft.NETCore.App.Ref/<version>/ref/<tfm>/*.xml, and the desktop and ASP.NET packs).
    static List<string> PackFiles()
    {
        lock (_lock)
        {
            if (_packFiles != null) return _packFiles;
            var list = new List<string>();
            var runtime = System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory().TrimEnd('/', '\\');
            var root = Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(runtime)));
            foreach (var pack in new[] { "Microsoft.NETCore.App.Ref", "Microsoft.WindowsDesktop.App.Ref", "Microsoft.AspNetCore.App.Ref" })
                try // one unreadable pack (say, a version folder without ref/) does not hide the others
                {
                    var dir = root == null ? null : Path.Combine(root, "packs", pack);
                    if (dir == null || !Directory.Exists(dir)) continue;
                    var newest = Directory.GetDirectories(dir).OrderByDescending(d => Version.TryParse(Path.GetFileName(d).Split('-')[0], out var v) ? v : new Version()).FirstOrDefault();
                    var tfm = newest == null ? null : Directory.GetDirectories(Path.Combine(newest, "ref")).OrderByDescending(x => x).FirstOrDefault();
                    if (tfm != null) list.AddRange(Directory.GetFiles(tfm, "*.xml").Order(StringComparer.Ordinal));
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
            return _packFiles = list;
        }
    }

    // The pack files in the order most likely to document the id, each parsed on first use (parsing all ~250 of them
    // up front cost seconds per process): the file named after the longest namespace prefix of the member
    // (System.Net.Sockets.xml for System.Net.Sockets.Socket), System.Runtime.xml (the core types), the files of the same
    // namespace family (System.Drawing.*), then the rest. A documented member is usually found in the first few; only an
    // undocumented one reads them all (on a 20-sample check the first three groups held 2157 of 2159 hits).
    static IEnumerable<(string File, XmlDocumentationProvider Provider)> PacksFor(string id)
    {
        var name = id.Length > 2 && id[1] == ':' ? id[2..] : id;
        if (name.IndexOf('(') is var paren and >= 0) name = name[..paren];
        var parts = name.Split('.');
        var family = parts.Length > 2 ? parts[0] + "." + parts[1] + "." : name + ".";
        int Rank(string f)
        {
            var a = Path.GetFileNameWithoutExtension(f);
            return name.StartsWith(a + ".", StringComparison.Ordinal) ? 1000 + a.Length
                : a == "System.Runtime" ? 500
                : (a + ".").StartsWith(family, StringComparison.Ordinal) ? 100 : 0;
        }
        var ordered = PackFiles().OrderByDescending(Rank);
        foreach (var f in ordered)
        {
            XmlDocumentationProvider? p;
            lock (_lock)
                if (!_providers.TryGetValue(f, out p)) _providers[f] = p = XmlDocumentationProvider.Create(f);
            if (p != null) yield return (f, p);
        }
    }

    // ---- reading the documentation XML ---------------------------------------------------------------------------------

    static XElement? Parse(string xml)
    {
        try { return XElement.Parse("<member>" + xml + "</member>", LoadOptions.PreserveWhitespace); }
        catch (System.Xml.XmlException) { return null; }
    }

    static string? Part(string xml, string name) => Parse(xml)?.Element(name) is { } e ? Text(e) : null;

    static string? Named(string xml, string name)
    {
        var parts = Parse(xml)?.Elements(name).Select(e => $"{(string?)e.Attribute("name") ?? Cref((string?)e.Attribute("cref"))}: {Text(e)}").ToList();
        return parts is { Count: > 0 } ? string.Join("\n", parts) : null;
    }

    static string Cref(string? cref) => cref == null ? "" : cref.Length > 2 && cref[1] == ':' ? cref[2..] : cref;

    // The text of a documentation element: <see cref>, <paramref> and <typeparamref> become their names, whitespace collapses.
    static string Text(XElement e)
    {
        var sb = new StringBuilder();
        void Walk(XNode n)
        {
            switch (n)
            {
                case XText t: sb.Append(t.Value); break;
                case XElement x when x.Name.LocalName is "see" or "seealso":
                    // <see href="...">text</see> has neither langword nor cref: its text is what to show
                    sb.Append((string?)x.Attribute("langword") ?? (x.Attribute("cref") is { } cref ? Cref(cref.Value) : x.Value)); break;
                case XElement x when x.Name.LocalName is "paramref" or "typeparamref": sb.Append((string?)x.Attribute("name")); break;
                case XElement x when x.Name.LocalName == "para": sb.Append('\n'); foreach (var c in x.Nodes()) Walk(c); sb.Append('\n'); break;
                case XElement x: foreach (var c in x.Nodes()) Walk(c); break;
            }
        }
        foreach (var n in e.Nodes()) Walk(n);
        return string.Join("\n", sb.ToString().Split('\n').Select(l => System.Text.RegularExpressions.Regex.Replace(l, @"\s+", " ").Trim()).Where(l => l.Length > 0));
    }
}
