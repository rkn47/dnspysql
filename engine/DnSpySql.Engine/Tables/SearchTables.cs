// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Text.RegularExpressions;
using DnSpySql.Sql;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DnSpySql.Tables;

public sealed record SearchHit(string Kind, LoadedModule M, string Name, string FullName, long? Handle, long? Location, int? Offset, string Match);

/// <summary>dnSpy Search window + unified entity search (jump_entities).</summary>
public static class SearchTables
{
    public static readonly string[] Kinds =
    {
        "any", "type", "class", "interface", "struct", "enum", "delegate", "method", "field", "property", "event", "member",
        "param", "local", "namespace", "resource", "resource_element", "assembly", "module", "asmref", "modref", "literal", "string", "number",
    };

    public static void Register(Session s)
    {
        var ws = s.Ws;
        var db = s.Db;

        db.Register(new Table<SearchHit>("jump_entities",
                "Every named entity (types, members, namespaces, resources) for quick lookup; filter with LIKE on name/full_name") { Domain = "search" }
            .Source(c => Entities(s, c.Text("kind"), c.Long("module")))
            .Text("kind", h => h.Kind, pushdown: Pushdown.Eq)
            .Text("name", h => h.Name)
            .Text("full_name", h => h.FullName)
            .Int("handle", h => h.Handle)
            .Int("module", h => h.M.Id, pushdown: Pushdown.Eq)
            .Int("parent", h => h.Location, doc: "declaring type / owner handle")
            .Estimate(100_000));

        var search = new Table<SearchHit>("search",
                "dnSpy search: WHERE query = 'text' [AND kind = 'any|type|method|field|property|event|member|param|local|resource|literal|string|number|...'] " +
                "[AND match_mode = 'contains|exact|word|regex'] [AND case_sensitive = 1]. /regex/ queries are regexes; several words = all must match") { Domain = "search" }
            .Source(c => Search(s, c))
            .Arg("query", SqlType.Text, _ => null)
            .Arg("match_mode", SqlType.Text, _ => null, required: false)
            .Arg("case_sensitive", SqlType.Integer, _ => null, required: false)
            .Arg("max_results", SqlType.Integer, _ => null, required: false)
            .Text("kind", h => h.Kind, pushdown: Pushdown.Eq)
            .Text("name", h => h.Name)
            .Text("full_name", h => h.FullName)
            .Int("handle", h => h.Handle)
            .Int("module", h => h.M.Id, pushdown: Pushdown.Eq)
            .Int("location", h => h.Location, doc: "containing entity (method for locals/literals/params, owner for resources)")
            .Int("offset", h => h.Offset, doc: "IL offset for literal/string hits")
            .Text("match", h => h.Match);
        // kind is a category ('any', 'member', 'literal', 'class', ...); each hit reports its own kind
        search.Columns.Single(c => c.Name == "kind").Interpreted = true;
        db.Register(search);
    }

    static bool HideCg(Session s) => !s.Settings["search_include_compiler_generated"].AsBool;

    static IEnumerable<SearchHit> Entities(Session s, string? kind, long? module)
    {
        bool hide = HideCg(s);
        foreach (var m in s.Ws.Modules.Where(m => module is null || m.Id == module))
        {
            if (kind is null or "assembly" && m.Module.Assembly != null) yield return new SearchHit("assembly", m, m.Module.Assembly.Name, m.Module.Assembly.FullName, m.H(m.Module.Assembly), null, null, "");
            if (kind is null or "module") yield return new SearchHit("module", m, m.Module.Name, m.Path, m.H(m.Module), null, null, "");
            if (kind is null or "namespace")
                foreach (var ns in m.Module.Types.Select(t => t.Namespace.String).Distinct())
                    yield return new SearchHit("namespace", m, ns, ns, null, null, null, "");
            foreach (var t in m.Module.GetTypes())
            {
                if (hide && TableKit.IsCompilerGenerated(t)) continue;
                if (kind is null or "type") yield return new SearchHit("type", m, t.Name, t.FullName, m.H(t), t.DeclaringType is { } dt ? m.H(dt) : null, null, "");
                if (kind is null or "method")
                    foreach (var x in t.Methods) if (!(hide && TableKit.IsCompilerGenerated(x))) yield return new SearchHit("method", m, x.Name, x.FullName, m.H(x), m.H(t), null, "");
                if (kind is null or "field")
                    foreach (var x in t.Fields) if (!(hide && TableKit.IsCompilerGenerated(x))) yield return new SearchHit("field", m, x.Name, x.FullName, m.H(x), m.H(t), null, "");
                if (kind is null or "property")
                    foreach (var x in t.Properties) yield return new SearchHit("property", m, x.Name, x.FullName, m.H(x), m.H(t), null, "");
                if (kind is null or "event")
                    foreach (var x in t.Events) yield return new SearchHit("event", m, x.Name, x.FullName, m.H(x), m.H(t), null, "");
            }
            if (kind is null or "resource")
                foreach (var r in m.Module.Resources) yield return new SearchHit("resource", m, r.Name, r.Name, null, null, null, "");
        }
    }

    static IEnumerable<SearchHit> Search(Session s, Constraints c)
    {
        var query = c.Text("query") ?? throw new SqlException("search needs WHERE query = '...'");
        var kind = (c.Text("kind") ?? "any").ToLowerInvariant();
        if (!Kinds.Contains(kind)) throw new SqlException($"unknown search kind '{kind}'; one of {string.Join(", ", Kinds)}");
        var mode = (c.Text("match_mode") ?? "contains").ToLowerInvariant();
        bool cs = c.Bool("case_sensitive") ?? false;
        long max = c.Long("max_results") ?? 10_000;
        var match = Matcher(query, mode, cs);
        bool hide = HideCg(s);
        long n = 0;
        foreach (var hit in Run())
        {
            yield return hit;
            if (++n >= max) yield break;
        }

        IEnumerable<SearchHit> Run()
        {
            bool K(params string[] ks) => kind == "any" || ks.Contains(kind);
            foreach (var m in s.Ws.Modules(c))
            {
                if (K("assembly") && m.Module.Assembly is { } a && match(a.FullName) is string am) yield return new SearchHit("assembly", m, a.Name, a.FullName, m.H(a), null, null, am);
                if (K("module") && match(m.Module.Name) is string mm) yield return new SearchHit("module", m, m.Module.Name, m.Path, m.H(m.Module), null, null, mm);
                if (K("asmref")) foreach (var r in m.Module.GetAssemblyRefs()) if (match(r.FullName) is string x) yield return new SearchHit("asmref", m, r.Name, r.FullName, m.H(r), null, null, x);
                if (K("modref")) foreach (var r in m.Module.GetModuleRefs()) if (match(r.Name) is string x) yield return new SearchHit("modref", m, r.Name, r.Name, m.H(r), null, null, x);
                if (K("namespace"))
                    foreach (var ns in m.Module.Types.Select(t => t.Namespace.String).Distinct())
                        if (match(ns) is string x) yield return new SearchHit("namespace", m, ns, ns, null, null, null, x);
                foreach (var t in m.Module.GetTypes())
                {
                    if (hide && TableKit.IsCompilerGenerated(t)) continue;
                    var tk = TableKit.TypeKind(t);
                    if ((K("type") || kind == tk || kind == "class" && tk == "static class") && (match(t.FullName) ?? match(t.Name)) is string tm)
                        yield return new SearchHit("type", m, t.Name, t.FullName, m.H(t), t.DeclaringType is { } dt ? m.H(dt) : null, null, tm);
                    foreach (var md in t.Methods)
                    {
                        if (hide && TableKit.IsCompilerGenerated(md)) continue;
                        if (K("method", "member") && (match(md.Name) ?? match(md.FullName) ?? (md.ImplMap is { } im ? match(im.Name) ?? match(im.Module?.Name ?? "") : null)) is string x)
                            yield return new SearchHit("method", m, md.Name, md.FullName, m.H(md), m.H(t), null, x);
                        if (K("param"))
                            foreach (var p in md.Parameters.Where(p => p.IsNormalMethodParameter))
                                if (match(p.Name) is string px) yield return new SearchHit("param", m, p.Name, $"{md.FullName} :: {p.Name}", null, m.H(md), null, px);
                        if (!md.HasBody) continue;
                        if (K("local"))
                            foreach (var l in md.Body.Variables.Where(l => !string.IsNullOrEmpty(l.Name)))
                                if (match(l.Name) is string lx) yield return new SearchHit("local", m, l.Name, $"{md.FullName} :: {l.Name}", null, m.H(md), null, lx);
                        if (K("literal", "string", "number"))
                            foreach (var ins in md.Body.Instructions)
                            {
                                string? text = ins.OpCode.Code switch
                                {
                                    Code.Ldstr when kind is "any" or "literal" or "string" => ins.Operand as string,
                                    Code.Ldc_I4 or Code.Ldc_I4_S or Code.Ldc_I4_0 or Code.Ldc_I4_1 or Code.Ldc_I4_2 or Code.Ldc_I4_3 or Code.Ldc_I4_4
                                        or Code.Ldc_I4_5 or Code.Ldc_I4_6 or Code.Ldc_I4_7 or Code.Ldc_I4_8 or Code.Ldc_I4_M1 when kind is "literal" or "number" => NumText(ins.GetLdcI4Value()),
                                    Code.Ldc_I8 when kind is "literal" or "number" => NumText((long)ins.Operand),
                                    Code.Ldc_R4 or Code.Ldc_R8 when kind is "literal" or "number" => Convert.ToDouble(ins.Operand).ToString(System.Globalization.CultureInfo.InvariantCulture),
                                    _ => null,
                                };
                                if (text != null && match(text) is string lit)
                                    yield return new SearchHit(ins.OpCode.Code == Code.Ldstr ? "string" : "number", m, text, md.FullName, null, m.H(md), (int)ins.Offset, lit);
                            }
                    }
                    if (K("field", "member", "literal"))
                        foreach (var f in t.Fields)
                        {
                            if (hide && TableKit.IsCompilerGenerated(f)) continue;
                            if (kind != "literal" && (match(f.Name) ?? match(f.FullName)) is string x) yield return new SearchHit("field", m, f.Name, f.FullName, m.H(f), m.H(t), null, x);
                            else if (kind is "literal" or "any" && f.Constant?.Value is { } cv && match(Convert.ToString(cv, System.Globalization.CultureInfo.InvariantCulture) ?? "") is string cx)
                                yield return new SearchHit("field", m, f.Name, f.FullName, m.H(f), m.H(t), null, cx);
                        }
                    if (K("property", "member"))
                        foreach (var p in t.Properties) if ((match(p.Name) ?? match(p.FullName)) is string x) yield return new SearchHit("property", m, p.Name, p.FullName, m.H(p), m.H(t), null, x);
                    if (K("event", "member"))
                        foreach (var e in t.Events) if ((match(e.Name) ?? match(e.FullName)) is string x) yield return new SearchHit("event", m, e.Name, e.FullName, m.H(e), m.H(t), null, x);
                }
                if (K("resource", "resource_element", "literal"))
                    foreach (var r in m.Module.Resources)
                    {
                        if (kind != "resource_element" && match(r.Name) is string x) yield return new SearchHit("resource", m, r.Name, r.Name, null, null, null, x);
                        if (kind is "resource" ) continue;
                        if (ResourceTables.ReadSet(m, r) is { } set)
                            foreach (var e in set.ResourceElements)
                            {
                                var val = ResourceTables.ElementValue(e) as string;
                                if ((match(e.Name) ?? (val != null ? match(val) : null)) is string ex)
                                    yield return new SearchHit("resource_element", m, e.Name, $"{r.Name}/{e.Name}", null, null, null, ex);
                            }
                    }
            }
        }
    }

    static string NumText(long v) => v.ToString(System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>Returns a matcher yielding the matched text (or null). dnSpy semantics: /re/ regex, multiple terms all match.</summary>
    static Func<string, string?> Matcher(string query, string mode, bool cs)
    {
        var cmp = cs ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
        if (mode == "regex" || query.Length > 2 && query.StartsWith('/') && query.EndsWith('/'))
        {
            var pat = mode == "regex" ? query : query[1..^1];
            var re = new Regex(pat, (cs ? RegexOptions.None : RegexOptions.IgnoreCase) | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
            return t => re.Match(t) is { Success: true } mm ? mm.Value : null;
        }
        if (mode == "exact") return t => string.Equals(t, query, cmp) ? t : null;
        if (Values.ParseLong(query) is long num && mode == "contains") // decimal or 0x hex; anything else is text
        {
            var dec = num.ToString(System.Globalization.CultureInfo.InvariantCulture);
            return t => string.Equals(t, dec, StringComparison.Ordinal) || t.Contains(query, cmp) ? t : null;
        }
        var terms = query.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (mode == "word")
        {
            var res = terms.Select(x => new Regex(@"\b" + Regex.Escape(x) + @"\b", cs ? RegexOptions.None : RegexOptions.IgnoreCase)).ToArray();
            return t => res.All(r => r.IsMatch(t)) ? t : null;
        }
        return t => terms.All(x => t.Contains(x, cmp)) ? t : null;
    }
}
