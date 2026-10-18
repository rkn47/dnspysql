// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Sql;
using dnlib.DotNet;

namespace DnSpySql.Tables;

/// <summary>Decompiler output (ILSpy engine): whole text per entity and per-line rows with IL offsets.</summary>
public static class DecompilerTables
{
    public static void Register(Session s)
    {
        var ws = s.Ws;
        var db = s.Db;

        IEnumerable<(long h, string lang, DecompileResult r)> One(Constraints c)
        {
            var h = ws.Normalize(c.Long("handle") ?? throw new SqlException("needs WHERE handle = <type/method/field/property/event handle>"));
            var lang = c.Text("language");
            yield return (h, lang ?? s.Settings["decompiler_language"].Value ?? "csharp", s.Decompiler.Decompile(h, lang));
        }

        string? NameOf(long h)
        {
            try { return (ws.Resolve(h).item as IFullName)?.FullName; } catch { return null; }
        }

        db.Register(new Table<(long h, string lang, DecompileResult r)>("pseudocode",
                "Decompiled source, one row per entity: WHERE handle = ... [AND language = 'csharp'|'il']. Exact output, no annotations") { Domain = "decompiler" }
            .Source(One)
            .Int("handle", r => r.h, pushdown: Pushdown.Eq, required: true)
            .Text("language", r => r.lang, pushdown: Pushdown.Eq)
            .Text("name", r => NameOf(r.h))
            .Text("text", r => r.r.Text)
            .Int("line_count", r => r.r.Lines.Count)
            .Bool("completed", r => r.r.Completed)
            .Text("error", r => r.r.Error)
            .Estimate(1, 500));

        db.Register(new Table<(long h, string lang, DecompiledLine l)>("pseudocode_lines",
                "Decompiled source, one row per line with the IL offset of the statement starting on it") { Domain = "decompiler" }
            .Source(c => One(c).SelectMany(x => x.r.Lines.Select(l => (x.h, x.lang, l))))
            .Int("handle", r => r.h, pushdown: Pushdown.Eq, required: true)
            .Text("language", r => r.lang, pushdown: Pushdown.Eq)
            .Int("line_num", r => r.l.Line)
            .Text("line", r => r.l.Text)
            .Int("il_offset", r => r.l.ILOffset)
            .Int("method", r => r.l.Method, doc: "method (or state-machine MoveNext) the IL offset belongs to")
            .Text("comment", r => r.l.ILOffset is int off && r.l.Method is long mh ? AnnotationTables.CommentAt(s, mh, off, r.l.ILEnd ?? off + 1) : null, doc: "comments whose IL offset falls in this line's statement range")
            .Estimate(100, 500));

        db.Register(new Table<(long h, string lang, DecompiledRef r)>("pseudocode_refs",
                "Names in the decompiled source and what they refer to (dnSpy's click-to-definition): types, members, locals, " +
                "parameters, labels. Same output and line numbers as pseudocode_lines") { Domain = "decompiler" }
            .Source(c => One(c).SelectMany(x => x.r.Refs.Select(r => (x.h, x.lang, r))))
            .Int("handle", r => r.h, pushdown: Pushdown.Eq, required: true)
            .Text("language", r => r.lang, pushdown: Pushdown.Eq)
            .Int("line_num", r => r.r.Line)
            .Int("column", r => r.r.Column, doc: "1-based column of the name on its line")
            .Int("length", r => r.r.Length)
            .Text("text", r => r.r.Text)
            .Text("kind", r => r.r.Kind, doc: "type | method | field | property | event | local | parameter | label | data | opcode | namespace | keyword | other")
            .Int("target", r => r.r.Target, doc: "handle of the referenced definition when it is in a loaded module (NULL for locals, parameters and external members)")
            .Text("target_name", r => r.r.TargetName, doc: "full name of the referenced member, or the variable/label name")
            .Bool("is_definition", r => r.r.IsDefinition, doc: "the name is declared here")
            .Bool("is_write", r => r.r.IsWrite, doc: "the reference writes (assignment to a field or variable)")
            .Bool("is_local", r => r.r.IsLocal, doc: "the reference stays within this method (variables, labels)")
            .Bool("is_hidden", r => r.r.IsHidden, doc: "dnSpy keeps it for highlighting only (not shown as a link)")
            .Estimate(200, 500));

        db.Register(new Table<ResElemRow>("baml", "BAML resources decompiled to XAML (WPF)") { Domain = "decompiler" }
            .Source(c => ws.Modules(c).SelectMany(m => m.Module.Resources.Select((r, i) => (r, i)).SelectMany(x =>
                ResourceTables.ReadSet(m, x.r) is { } set
                    ? set.ResourceElements.Select((e, k) => new ResElemRow(m, x.r, x.i, e, k)).Where(e => ResourceTables.ElementValue(e.E) is byte[] b && ResourceTables.IsBaml(b))
                    : Array.Empty<ResElemRow>())))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Text("resource", r => r.R.Name.String)
            .Text("name", r => r.E.Name)
            .Int("size", r => ((byte[])ResourceTables.ElementValue(r.E)!).Length)
            .Text("xaml", r =>
            {
                try { return s.Decompiler.BamlToXaml(r.M, (byte[])ResourceTables.ElementValue(r.E)!); }
                catch (Exception e) { return $"<!-- BAML decompilation failed: {e.Message} -->"; }
            }));
    }
}
