// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Sql;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using static DnSpySql.Tables.TableKit;

namespace DnSpySql.Tables;

public sealed record AnalyzerHit(string Relation, LoadedModule M, IMemberDef? Def, string Name, uint? Offset, string Detail, long? Handle = null);

/// <summary>Cross references (from IL) and the dnSpy analyzer.</summary>
public static class XrefTables
{
    public static void Register(Session s)
    {
        var ws = s.Ws;
        var db = s.Db;
        var ix = s.Index;

        IEnumerable<XRef> Scope(Constraints c)
        {
            if (c.Long("from_method") is long fm) return ix.From(ws.Normalize(fm));
            if (c.Long("to_def") is long td) return ix.To(ws.Normalize(td));
            if (c.Text("to_name") is string tn) return ix.ToName(tn);
            var all = ix.All.AsEnumerable();
            if (c.Text("kind") is string k) all = all.Where(x => x.Kind == k);
            if (c.Long("module") is long mid) all = all.Where(x => x.M.Id == mid);
            return all;
        }

        db.Register(new Table<XRef>("xrefs",
                "Every IL reference: calls, field read/write/addr, type and token uses, ldstr. Filter on from_method, to_def or to_name. " +
                "Bodies that are not IL (encrypted until runtime, see method_bodies) are left out: SELECT untamper() first") { Domain = "xrefs" }
            .Source(Scope)
            .Int("module", x => x.M.Id, pushdown: Pushdown.Eq)
            .Int("from_method", x => x.FromHandle, pushdown: Pushdown.Eq)
            .Text("from_name", x => x.From.FullName)
            .Int("idx", x => x.Index)
            .Int("offset", x => x.Offset)
            .Text("opcode", x => x.OpCode)
            .Text("kind", x => x.Kind, pushdown: Pushdown.Eq, doc: "call|callvirt|newobj|ldftn|ldvirtftn|jmp|async (an async method or iterator starting its state machine's MoveNext)|read|write|addr|type|token|string")
            .Int("to_def", x => x.DefHandle, pushdown: Pushdown.Eq, doc: "resolved definition handle (NULL when external/unresolved)")
            .Int("to_module", x => x.DefModule?.Id)
            .Text("to_name", x => x.ToName, pushdown: Pushdown.Eq)
            .Int("to_token", x => (x.Operand as IMDTokenProvider)?.MDToken.Raw is uint t ? t : null, doc: "raw operand token in the referencing module")
            .Text("to_kind", x => x.Def switch { MethodDef => "method", FieldDef => "field", TypeDef => "type", _ => x.Kind == "string" ? "string" : x.Operand is IMethod ? "method" : x.Operand is IField ? "field" : x.Operand is ITypeDefOrRef ? "type" : null })
            .Bool("is_external", x => x.Def == null && x.Kind != "string")
            .Text("string_value", x => x.StringValue)
            .Estimate(200_000));

        db.Register(new Table<XRef>("call_edges", "Call graph edges (call, callvirt, newobj, ldftn, ldvirtftn, jmp). dst = 0 when the callee is external") { Domain = "xrefs" }
            .Source(c =>
            {
                if (c.Long("src") is long sm) return ix.From(ws.Normalize(sm)).Where(x => x.IsCall);
                if (c.Long("dst") is 0) return ix.All.Where(x => x.IsCall && x.DefHandle == null);
                if (c.Long("dst") is long dm) return ix.To(ws.Normalize(dm)).Where(x => x.IsCall);
                return ix.All.Where(x => x.IsCall);
            })
            .Int("module", x => x.M.Id)
            .Int("src", x => x.FromHandle, pushdown: Pushdown.Eq)
            .Text("src_name", x => x.From.FullName)
            .Int("call_site", x => x.Offset, doc: "IL offset in src")
            .Int("idx", x => x.Index)
            .Text("kind", x => x.Kind)
            .Int("dst", x => x.DefHandle ?? 0, pushdown: Pushdown.Eq)
            .Text("dst_name", x => x.ToName)
            .Text("dst_assembly", x => x.Def?.Module?.Assembly?.Name.String ?? ExternalAssembly(x.Operand))
            .Bool("is_external", x => x.Def == null)
            .Estimate(100_000));

        // ================= string references (dnSpy String References window) =================
        db.Register(new Table<(LoadedModule m, string kind, string literal, IMDTokenProvider referrer, uint? offset, string detail)>("string_refs",
                "String literals with their referrers: ldstr in IL, string constants, string attribute arguments (dnSpy StringSearcher)") { Domain = "xrefs" }
            .Source(c => StringRefs(s, c))
            .Int("module", r => r.m.Id, pushdown: Pushdown.Eq)
            .Text("kind", r => r.kind, pushdown: Pushdown.Eq, doc: "il | constant | attribute")
            .Text("value", r => r.literal)
            .Int("referrer", r => r.m.H(r.referrer), pushdown: Pushdown.Eq, doc: "method (il), field/property/param (constant) or attribute owner")
            .Text("referrer_name", r => (r.referrer as IFullName)?.FullName ?? r.referrer.ToString())
            .Int("offset", r => r.offset)
            .Text("detail", r => r.detail));

        // ================= analyzer =================
        db.Register(new Table<AnalyzerHit>("analyze",
                "dnSpy Analyzer as a table-valued function: SELECT * FROM analyze WHERE target = <handle> [AND relation = '...']") { Domain = "xrefs" }
            .Source(c =>
            {
                var target = c.Long("target") ?? throw new SqlException("analyze needs WHERE target = <handle>");
                return Analyzer.Run(s, ws.Normalize(target), c.Text("relation"));
            })
            .Arg("target", SqlType.Integer, _ => null)
            .Text("relation", h => h.Relation, pushdown: Pushdown.Eq)
            .Int("handle", h => h.Handle ?? (h.Def == null ? null : h.M.H(h.Def)))
            .Text("kind", h => h.Def switch
            {
                TypeDef => "type", MethodDef => "method", FieldDef => "field", PropertyDef => "property", EventDef => "event", null => "external", _ => "?",
            })
            .Text("name", h => h.Name)
            .Int("module", h => h.M.Id)
            .Int("offset", h => h.Offset, doc: "IL offset of the first hit inside the method (uses / used_by / read_by ...)")
            .Text("detail", h => h.Detail));
    }

    static string? ExternalAssembly(object? operand) => operand switch
    {
        MemberRef mr => (mr.DeclaringType?.Scope as AssemblyRef)?.Name.String,
        IMethod im => (im.DeclaringType?.Scope as AssemblyRef)?.Name.String,
        _ => null,
    };

    static IEnumerable<(LoadedModule, string, string, IMDTokenProvider, uint?, string)> StringRefs(Session s, Constraints c)
    {
        var kind = c.Text("kind");
        IEnumerable<XRef> il = c.Long("referrer") is long rf ? s.Index.From(s.Ws.Normalize(rf)) : s.Index.All;
        if (kind is null or "il")
            foreach (var x in il.Where(x => x.Kind == "string" && !string.IsNullOrEmpty(x.StringValue)))
                if (c.Long("module") is not long mm || x.M.Id == mm)
                    yield return (x.M, "il", x.StringValue!, x.From, x.Offset, $"{x.From.Name}+IL_{x.Offset:X4}");
        if (c.Long("referrer") is long) yield break;
        foreach (var m in s.Ws.Modules(c))
        {
            if (kind is null or "constant")
                foreach (var t in m.Module.GetTypes())
                {
                    foreach (var f in t.Fields) if (f.Constant?.Value is string fs && fs.Length > 0) yield return (m, "constant", fs, f, null, "field");
                    foreach (var p in t.Properties) if (p.Constant?.Value is string ps && ps.Length > 0) yield return (m, "constant", ps, p, null, "property");
                    foreach (var md in t.Methods)
                        foreach (var pd in md.ParamDefs) if (pd.Constant?.Value is string pds && pds.Length > 0) yield return (m, "constant", pds, md, null, $"param {pd.Name}");
                }
            if (kind is null or "attribute")
                foreach (var owner in MemberTables.AttributeOwners(m.Module))
                    foreach (var ca in owner.CustomAttributes)
                    {
                        if (ca.IsRawBlob) continue;
                        int i = 0;
                        foreach (var a in ca.ConstructorArguments)
                        {
                            foreach (var str in Strings(a.Value)) yield return (m, "attribute", str, owner, null, $"{ca.TypeFullName} arg #{i}");
                            i++;
                        }
                        foreach (var na in ca.NamedArguments)
                            foreach (var str in Strings(na.Argument.Value)) yield return (m, "attribute", str, owner, null, $"{ca.TypeFullName}.{na.Name}");
                    }
        }
    }

    static IEnumerable<string> Strings(object? v)
    {
        switch (v)
        {
            case UTF8String u when !UTF8String.IsNullOrEmpty(u): yield return u.String; break;
            case string str when str.Length > 0: yield return str; break;
            case CAArgument a: foreach (var x in Strings(a.Value)) yield return x; break;
            case IList<CAArgument> list: foreach (var a in list) foreach (var x in Strings(a.Value)) yield return x; break;
        }
    }
}

/// <summary>Implementation of the dnSpy analyzer relations over the code index and type hierarchy.</summary>
public static class Analyzer
{
    public static readonly string[] Relations =
    {
        "type.used_by", "type.instantiated_by", "type.exposed_by", "type.subtypes", "type.derived_types", "type.base_types",
        "type.extension_methods", "type.applied_to",
        "method.uses", "method.used_by", "method.virtual_used_by", "method.overrides", "method.overridden_by", "method.implemented_by", "method.implements",
        "field.read_by", "field.assigned_by",
        "property.read_by", "property.written_by", "property.overrides", "property.overridden_by", "property.implemented_by",
        "event.raised_by", "event.subscribed_by", "event.unsubscribed_by", "event.overrides", "event.overridden_by", "event.implemented_by",
    };

    public static IEnumerable<AnalyzerHit> Run(Session s, long target, string? relation)
    {
        var (lm, item) = s.Ws.Resolve(target);
        var prefix = item switch { TypeDef => "type.", MethodDef => "method.", FieldDef => "field.", PropertyDef => "property.", EventDef => "event.", _ => null }
                     ?? throw new SqlException($"{Handle.Hex(target)} ({Handle.KindOf(Handle.Token(target))}) cannot be analyzed; use a type, method, field, property or event");
        var rels = relation != null ? new[] { relation } : Relations.Where(r => r.StartsWith(prefix)).ToArray();
        foreach (var r in rels)
        {
            if (!r.StartsWith(prefix)) throw new SqlException($"relation '{r}' does not apply to a {prefix.TrimEnd('.')}; valid: {string.Join(", ", Relations.Where(x => x.StartsWith(prefix)))}");
            var seen = new HashSet<(string, object)>();
            foreach (var hit in Relation(s, r, lm, (IMemberDef)item))
                if (seen.Add((hit.Relation, (object?)hit.Def ?? hit.Name + "|" + hit.Detail))) yield return hit;
        }
    }

    static AnalyzerHit Hit(Session s, string rel, IMemberDef def, uint? offset = null, string detail = "")
    {
        var lm = s.Ws.Find(def.Module)!;
        return new AnalyzerHit(rel, lm, def, def.FullName, offset, detail);
    }

    /// <summary>Distinct methods (first hit offset) from a set of xrefs, remapping compiler-generated code to its user method.</summary>
    static IEnumerable<AnalyzerHit> Methods(Session s, string rel, IEnumerable<XRef> refs, string detail = "") =>
        refs.GroupBy(x => x.From).Select(g => Hit(s, rel, g.Key, g.First().Offset, detail + (g.Count() > 1 ? $"{(detail.Length > 0 ? ", " : "")}{g.Count()} sites" : "")));

    static IEnumerable<AnalyzerHit> Relation(Session s, string rel, LoadedModule lm, IMemberDef item)
    {
        var ix = s.Index;
        var ws = s.Ws;
        var types = ws.Modules.SelectMany(m => m.Module.GetTypes()).ToList();
        switch (rel)
        {
            // ---------------- types ----------------
            case "type.used_by":
                {
                    var t = (TypeDef)item;
                    var seen = new HashSet<IMemberDef>();
                    foreach (var x in ix.All.Where(x => x.Def != null && (x.Def == t || x.Def is IMemberDef d && d.DeclaringType == t && x.Kind is "type" or "token")))
                        if (x.From.DeclaringType != t && seen.Add(x.From)) yield return Hit(s, rel, x.From, x.Offset, "code");
                    foreach (var other in types.Where(o => o != t))
                    {
                        if (Mentions(other.BaseType, t) || other.Interfaces.Any(i => Mentions(i.Interface, t)))
                            if (seen.Add(other)) yield return Hit(s, rel, other, null, "base/interface");
                        foreach (var f in other.Fields) if (Mentions(f.FieldType, t) && seen.Add(f)) yield return Hit(s, rel, f, null, "field type");
                        foreach (var m in other.Methods)
                            if ((Mentions(m.ReturnType, t) || m.MethodSig?.Params.Any(p => Mentions(p, t)) == true
                                 || m.HasBody && (m.Body.Variables.Any(v => Mentions(v.Type, t)) || m.Body.ExceptionHandlers.Any(e => Mentions(e.CatchType, t))))
                                && seen.Add(m))
                                yield return Hit(s, rel, m, null, "signature/locals");
                        foreach (var p in other.Properties) if (Mentions(p.PropertySig?.RetType, t) && seen.Add(p)) yield return Hit(s, rel, p, null, "property type");
                        foreach (var e in other.Events) if (Mentions(e.EventType, t) && seen.Add(e)) yield return Hit(s, rel, e, null, "event type");
                    }
                    break;
                }
            case "type.instantiated_by":
                {
                    var t = (TypeDef)item;
                    foreach (var h in Methods(s, rel, ix.All.Where(x => x.Kind == "newobj" && x.Def is MethodDef { IsConstructor: true } c && c.DeclaringType == t))) yield return h;
                    break;
                }
            case "type.exposed_by":
                {
                    var t = (TypeDef)item;
                    foreach (var other in types)
                    {
                        foreach (var f in other.Fields) if (!f.IsPrivate && Mentions(f.FieldType, t)) yield return Hit(s, rel, f);
                        foreach (var p in other.Properties)
                            if (Mentions(p.PropertySig?.RetType, t) && (p.GetMethod is { IsPrivate: false } || p.SetMethod is { IsPrivate: false })) yield return Hit(s, rel, p);
                        foreach (var e in other.Events) if (Mentions(e.EventType, t) && e.AddMethod is { IsPrivate: false }) yield return Hit(s, rel, e);
                        foreach (var m in other.Methods)
                            if (!m.IsPrivate && m.SemanticsAttributes == 0 && (Mentions(m.ReturnType, t) || m.MethodSig?.Params.Any(p => Mentions(p, t)) == true))
                                yield return Hit(s, rel, m);
                    }
                    break;
                }
            case "type.derived_types":
                foreach (var other in types)
                    if (other.BaseType?.ResolveTypeDef() == item || other.Interfaces.Any(i => i.Interface?.ResolveTypeDef() == item))
                        yield return Hit(s, rel, other, null, other.BaseType?.ResolveTypeDef() == item ? "base" : "interface");
                break;
            case "type.subtypes":
                {
                    var t = (TypeDef)item;
                    foreach (var other in types.Where(o => o != t && DerivesFrom(o, t))) yield return Hit(s, rel, other);
                    break;
                }
            case "type.base_types":
                {
                    var t = (TypeDef)item;
                    int depth = 0;
                    for (var b = t.BaseType; b != null && depth < 64; depth++)
                    {
                        var bd = Try(() => b.ResolveTypeDef());
                        yield return bd != null && ws.Find(bd.Module) != null ? Hit(s, rel, bd, null, $"base depth {depth + 1}")
                            : new AnalyzerHit(rel, lm, null, b.FullName, null, $"base depth {depth + 1} (external)");
                        b = bd?.BaseType;
                    }
                    foreach (var i in AllInterfaces(t))
                    {
                        var idf = Try(() => i.ResolveTypeDef());
                        yield return idf != null && ws.Find(idf.Module) != null ? Hit(s, rel, idf, null, "interface")
                            : new AnalyzerHit(rel, lm, null, i.FullName, null, "interface (external)");
                    }
                    break;
                }
            case "type.extension_methods":
                {
                    var t = (TypeDef)item;
                    foreach (var m in types.Where(x => x.IsSealed && x.IsAbstract).SelectMany(x => x.Methods))
                        if (m.IsStatic && m.CustomAttributes.IsDefined("System.Runtime.CompilerServices.ExtensionAttribute")
                            && m.MethodSig?.Params.Count > 0 && Try(() => m.MethodSig.Params[0].ToTypeDefOrRef()?.ScopeType?.ResolveTypeDef()) == t)
                            yield return Hit(s, rel, m);
                    break;
                }
            case "type.applied_to":
                {
                    var t = (TypeDef)item;
                    foreach (var m in ws.Modules)
                        foreach (var owner in MemberTables.AttributeOwners(m.Module))
                            if (owner.CustomAttributes.Any(ca => Try(() => ca.AttributeType?.ResolveTypeDef()) == t))
                                yield return owner is IMemberDef d ? Hit(s, rel, d)
                                    : new AnalyzerHit(rel, m, null, (owner as IFullName)?.FullName ?? owner.ToString()!, null, Handle.KindOf(owner.MDToken.Raw), m.H(owner));
                    break;
                }

            // ---------------- methods ----------------
            case "method.uses":
                {
                    var m = (MethodDef)item;
                    foreach (var g in ix.From(lm.H(m)).Where(x => x.Kind != "string").GroupBy(x => (object?)x.Def ?? x.ToName))
                    {
                        var x = g.First();
                        yield return x.Def != null ? Hit(s, rel, x.Def, x.Offset, x.Kind) : new AnalyzerHit(rel, lm, null, x.ToName, x.Offset, x.Kind + " (external)");
                    }
                    break;
                }
            case "method.used_by":
                {
                    var m = (MethodDef)item;
                    var targets = new List<MethodDef> { m };
                    if (m.IsVirtual) targets.AddRange(BaseMethods(m));
                    var refs = targets.SelectMany(t => ws.Find(t.Module) is { } tl ? ix.To(tl.H(t)) : Array.Empty<XRef>()).Where(x => x.IsCall);
                    foreach (var h in Methods(s, rel, refs)) yield return h;
                    if (m.IsPinvokeImpl && m.ImplMap != null)
                    {
                        var entry = m.ImplMap.Name.String;
                        var dll = NormalizeDll(m.ImplMap.Module?.Name.String);
                        foreach (var other in types.SelectMany(x => x.Methods))
                            if (other != m && other.ImplMap is { } im && im.Name == entry && NormalizeDll(im.Module?.Name.String) == dll)
                                yield return Hit(s, rel, other, null, "same P/Invoke import");
                    }
                    break;
                }
            case "method.virtual_used_by":
                {
                    // dnSpy's VirtualMethodUsedBy: callers that reach the method only through a base or interface slot it
                    // overrides or implements. Only a virtual call (callvirt, ldvirtftn) on that slot can dispatch here; a
                    // plain `call` of a base method (base.M()) runs that method itself.
                    var m = (MethodDef)item;
                    if (!m.IsVirtual) break;
                    var slots = BaseMethods(m).Concat(Relation(s, "method.implements", lm, m).Select(h => h.Def).OfType<MethodDef>()).Distinct().ToList();
                    foreach (var slot in slots)
                        if (ws.Find(slot.Module) is { } sl)
                            foreach (var h in Methods(s, rel, ix.To(sl.H(slot)).Where(x => x.Kind is "callvirt" or "ldvirtftn"), $"via {slot.DeclaringType?.Name}::{slot.Name}"))
                                yield return h;
                    break;
                }
            case "method.overrides":
                foreach (var b in BaseMethods((MethodDef)item)) yield return Hit(s, rel, b);
                break;
            case "method.overridden_by":
                {
                    var m = (MethodDef)item;
                    if (!m.IsVirtual || m.DeclaringType.IsInterface) break;
                    foreach (var t in types.Where(t => DerivesFrom(t, m.DeclaringType)))
                        foreach (var cand in t.Methods)
                            if (cand.IsVirtual && BaseMethods(cand).Contains(m)) yield return Hit(s, rel, cand, null, cand.IsNewSlot ? "hides" : "");
                    break;
                }
            case "method.implemented_by":
                {
                    var m = (MethodDef)item;
                    if (!m.DeclaringType.IsInterface) break;
                    foreach (var t in types.Where(t => !t.IsInterface && AllInterfaces(t).Any(i => Try(() => i.ResolveTypeDef()) == m.DeclaringType)))
                        if (FindImplementation(t, m) is { } impl) yield return Hit(s, rel, impl);
                    break;
                }
            case "method.implements":
                {
                    var m = (MethodDef)item;
                    foreach (var o in m.Overrides)
                        if (Try(() => o.MethodDeclaration.ResolveMethodDef()) is { } d && d.DeclaringType.IsInterface) yield return Hit(s, rel, d, null, "explicit");
                    if (!m.IsVirtual) break;
                    foreach (var i in AllInterfaces(m.DeclaringType))
                        if (Try(() => i.ResolveTypeDef()) is { } itd)
                            foreach (var im in itd.Methods.Where(x => x.Name == m.Name && SameSig(x, m)))
                                if (ws.Find(im.Module) != null) yield return Hit(s, rel, im, null, "implicit");
                    break;
                }

            // ---------------- fields ----------------
            case "field.read_by":
                foreach (var h in Methods(s, rel, ix.To(lm.H(item)).Where(x => x.Kind is "read" or "addr" or "token"))) yield return h;
                break;
            case "field.assigned_by":
                foreach (var h in Methods(s, rel, ix.To(lm.H(item)).Where(x => x.Kind is "write" or "addr"))) yield return h;
                break;

            // ---------------- properties ----------------
            case "property.read_by":
                if (((PropertyDef)item).GetMethod is { } getter) foreach (var h in Methods(s, rel, ix.To(lm.H(getter)).Where(x => x.IsCall))) yield return h;
                break;
            case "property.written_by":
                if (((PropertyDef)item).SetMethod is { } st) foreach (var h in Methods(s, rel, ix.To(lm.H(st)).Where(x => x.IsCall))) yield return h;
                break;
            case "property.overrides":
            case "property.overridden_by":
            case "property.implemented_by":
                {
                    var p = (PropertyDef)item;
                    var acc = p.GetMethod ?? p.SetMethod;
                    if (acc == null) break;
                    var mrel = "method." + rel["property.".Length..];
                    foreach (var h in Relation(s, mrel, lm, acc))
                        if (h.Def is MethodDef am && OwnerProperty(am) is { } op) yield return Hit(s, rel, op, null, h.Detail);
                    break;
                }

            // ---------------- events ----------------
            case "event.subscribed_by":
                if (((EventDef)item).AddMethod is { } add) foreach (var h in Methods(s, rel, ix.To(lm.H(add)).Where(x => x.IsCall))) yield return h;
                break;
            case "event.unsubscribed_by":
                if (((EventDef)item).RemoveMethod is { } rem) foreach (var h in Methods(s, rel, ix.To(lm.H(rem)).Where(x => x.IsCall))) yield return h;
                break;
            case "event.raised_by":
                {
                    var e = (EventDef)item;
                    var backing = e.DeclaringType.Fields.FirstOrDefault(f => (f.Name == e.Name || f.Name == e.Name + "Event") && new SigComparer().Equals(f.FieldType, e.EventType?.ToTypeSig()));
                    if (backing == null) break;
                    foreach (var grp in ix.To(lm.H(backing)).Where(x => x.Kind is "read" or "addr").GroupBy(x => x.From))
                    {
                        var body = grp.Key.Body.Instructions;
                        foreach (var x in grp)
                        {
                            var invoke = body.Skip(x.Index + 1).Take(32).FirstOrDefault(i => i.OpCode.Code is Code.Call or Code.Callvirt && (i.Operand as IMethod)?.Name == "Invoke");
                            if (invoke != null) { yield return Hit(s, rel, grp.Key, x.Offset); break; }
                        }
                    }
                    break;
                }
            case "event.overrides":
            case "event.overridden_by":
            case "event.implemented_by":
                {
                    var e = (EventDef)item;
                    var acc = e.AddMethod ?? e.RemoveMethod;
                    if (acc == null) break;
                    var mrel = "method." + rel["event.".Length..];
                    foreach (var h in Relation(s, mrel, lm, acc))
                        if (h.Def is MethodDef am && am.DeclaringType.Events.FirstOrDefault(x => x.AddMethod == am || x.RemoveMethod == am) is { } oe)
                            yield return Hit(s, rel, oe, null, h.Detail);
                    break;
                }
        }
    }

    static T? Try<T>(Func<T?> f) { try { return f(); } catch { return default; } }

    static string NormalizeDll(string? n)
    {
        n = (n ?? "").ToLowerInvariant();
        foreach (var suffix in new[] { ".dll", ".so", ".dylib", ".a", ".sl" }) if (n.EndsWith(suffix)) n = n[..^suffix.Length];
        if (n.StartsWith("lib")) n = n[3..];
        return n;
    }

    static bool Mentions(ITypeDefOrRef? r, TypeDef t) => r != null && Mentions(r.ToTypeSig(), t);

    static bool Mentions(TypeSig? sig, TypeDef t)
    {
        for (int depth = 0; sig != null && depth < 32; depth++)
        {
            switch (sig)
            {
                case TypeDefOrRefSig tdr:
                    return Try(() => tdr.TypeDefOrRef.ResolveTypeDef()) == t;
                case GenericInstSig gi:
                    return Mentions(gi.GenericType, t) || gi.GenericArguments.Any(a => Mentions(a, t));
                case FnPtrSig fp:
                    return fp.MethodSig is { } ms && (Mentions(ms.RetType, t) || ms.Params.Any(p => Mentions(p, t)));
                default:
                    sig = sig.Next;
                    break;
            }
        }
        return false;
    }

    public static bool DerivesFrom(TypeDef t, TypeDef baseType)
    {
        if (baseType.IsInterface) return AllInterfaces(t).Any(i => Try(() => i.ResolveTypeDef()) == baseType);
        int depth = 0;
        for (var b = t.BaseType; b != null && depth < 64; depth++)
        {
            var bd = Try(() => b.ResolveTypeDef());
            if (bd == null) return false;
            if (bd == baseType) return true;
            b = bd.BaseType;
        }
        return false;
    }

    public static IEnumerable<ITypeDefOrRef> AllInterfaces(TypeDef t)
    {
        var seen = new HashSet<string>();
        int depth = 0;
        for (TypeDef? cur = t; cur != null && depth < 64; depth++)
        {
            foreach (var i in cur.Interfaces)
                if (i.Interface != null && seen.Add(i.Interface.FullName))
                {
                    yield return i.Interface;
                    if (Try(() => i.Interface.ResolveTypeDef()) is { } itd)
                        foreach (var ii in AllInterfaces(itd)) if (seen.Add(ii.FullName)) yield return ii;
                }
            cur = Try(() => cur.BaseType?.ResolveTypeDef());
        }
    }

    // A method whose signature blob does not parse (obfuscators break them on purpose) has no MethodSig and matches nothing.
    static bool SameSig(MethodDef a, MethodDef b) =>
        a.MethodSig is { } sa && b.MethodSig is { } sb
        && (new SigComparer(SigComparerOptions.DontCompareTypeScope | SigComparerOptions.DontCompareReturnType).Equals(sa, sb)
            || sa.Params.Count == sb.Params.Count && sa.Params.Select(p => p?.TypeName).SequenceEqual(sb.Params.Select(p => p?.TypeName)));

    /// <summary>Base methods (virtual chain + explicit .override targets) that this method overrides.</summary>
    public static IEnumerable<MethodDef> BaseMethods(MethodDef m)
    {
        foreach (var o in m.Overrides)
            if (Try(() => o.MethodDeclaration.ResolveMethodDef()) is { } d) yield return d;
        if (!m.IsVirtual || m.IsNewSlot) yield break;
        int depth = 0;
        for (var b = Try(() => m.DeclaringType.BaseType?.ResolveTypeDef()); b != null && depth < 64; depth++)
        {
            var hit = b.Methods.FirstOrDefault(x => x.IsVirtual && x.Name == m.Name && SameSig(x, m));
            if (hit != null)
            {
                yield return hit;
                if (hit.IsNewSlot) yield break;
            }
            b = Try(() => b.BaseType?.ResolveTypeDef());
        }
    }

    static MethodDef? FindImplementation(TypeDef t, MethodDef ifaceMethod)
    {
        for (TypeDef? cur = t; cur != null; cur = Try(() => cur.BaseType?.ResolveTypeDef()))
        {
            var explicitImpl = cur.Methods.FirstOrDefault(x => x.Overrides.Any(o => Try(() => o.MethodDeclaration.ResolveMethodDef()) == ifaceMethod));
            if (explicitImpl != null) return explicitImpl;
            var implicitImpl = cur.Methods.FirstOrDefault(x => x.IsVirtual && x.IsPublic && x.Name == ifaceMethod.Name && SameSig(x, ifaceMethod));
            if (implicitImpl != null) return implicitImpl;
        }
        return null;
    }

    static PropertyDef? OwnerProperty(MethodDef m) =>
        m.DeclaringType.Properties.FirstOrDefault(p => p.GetMethods.Contains(m) || p.SetMethods.Contains(m) || p.OtherMethods.Contains(m));
}
