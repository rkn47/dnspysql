// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Compile;
using DnSpySql.Tables;
using DnSpySql.Sql;
using dnlib.DotNet;

namespace DnSpySql.Functions;

/// <summary>dnSpy 'Edit Method (C#)', 'Add Class Members (C#)', 'Add Class (C#)' through Roslyn.</summary>
public static class CompileFunctions
{
    public static void Register(Session s)
    {
        var ws = s.Ws;

        s.Fn("compile_method", 2, 2, a =>
        {
            var m = ws.Resolve<MethodDef>(a[0], "method");
            return CompileMethod(s, m, TableKit.Str(a[1], "source"));
        }, "compile_method(method, 'C# method declaration')",
            "dnSpy 'Edit Method (C#)': compile a full method declaration (same name/signature) in the context of its type and replace the body. " +
            "Private members are accessible; lambdas/iterators/async are supported", "compile", mutates: true);

        s.Fn("add_members", 2, 2, a =>
        {
            var t = ws.Resolve<TypeDef>(a[0], "type");
            return (long)AddMembers(s, t, TableKit.Str(a[1], "source"));
        }, "add_members(type, 'C# member declarations')", "dnSpy 'Add Class Members (C#)': compile new fields/methods/properties/nested types into an existing type", "compile", mutates: true);

        // add_type is registered by DnSpyFunctions (type splicer, SDK reference pack).

        s.Fn("compile_preview", 2, 2, a =>
        {
            var m = ws.Resolve<MethodDef>(a[0], "method");
            var cc = new CSharpCompile(s, ws.ModuleOf(m));
            return cc.Skeleton(m.DeclaringType, TableKit.Str(a[1], "source"), d => ReferenceEquals(d, m) || OwnerOf(m) is { } o && ReferenceEquals(d, o));
        }, "compile_preview(method, source)", "show the generated C# compilation unit used by compile_method (for debugging compile errors)", "compile");
    }

    static IMemberDef? OwnerOf(MethodDef m) =>
        (IMemberDef?)m.DeclaringType.Properties.FirstOrDefault(p => p.GetMethods.Contains(m) || p.SetMethods.Contains(m))
        ?? m.DeclaringType.Events.FirstOrDefault(e => e.AddMethod == m || e.RemoveMethod == m || e.InvokeMethod == m);

    static long CompileMethod(Session s, MethodDef m, string source)
    {
        var ws = s.Ws;
        var lm = ws.ModuleOf(m);
        var owner = OwnerOf(m);
        var t = m.DeclaringType;
        var cc = new CSharpCompile(s, lm);
        var src = cc.Skeleton(t, source, d => ReferenceEquals(d, m) || owner != null && ReferenceEquals(d, owner)
                                              || owner is PropertyDef p && d is MethodDef am && (p.GetMethods.Contains(am) || p.SetMethods.Contains(am)));
        var compiled = cc.Compile(src);
        var ct = compiled.Find(t.FullName, false) ?? throw new SqlException($"compiled output has no type {t.FullName}");
        var merger = new Merger(lm.Module, compiled);
        merger.MapExisting(ct, t);
        var cm = ct.Methods.FirstOrDefault(x => x.Name == m.Name && x.MethodSig.Params.Count == m.MethodSig.Params.Count && x.HasBody
                                                && x.MethodSig.Params.Select(p => p.FullName).SequenceEqual(m.MethodSig.Params.Select(p => p.FullName)))
                 ?? throw new SqlException($"the source does not declare {m.Name} with the original signature ({MemberTables.Signature(m)})");
        var added = CloneNew(merger, ct, t);
        merger.Complete();
        var before = new BodySnapshot(m);
        var newBody = merger.CloneBody(cm, m);
        void Redo()
        {
            foreach (var (list, item) in added) list(true, item);
            m.Body = newBody;
            m.ImplAttributes = (m.ImplAttributes & ~MethodImplAttributes.CodeTypeMask & ~MethodImplAttributes.InternalCall) | MethodImplAttributes.IL;
            m.Attributes &= ~(MethodAttributes.Abstract | MethodAttributes.PinvokeImpl);
            ws.Touch(lm);
        }
        Redo();
        var after = new BodySnapshot(m);
        ws.Record("compile", $"compile_method {m.FullName}", () =>
        {
            before.Restore();
            foreach (var (list, item) in added) list(false, item);
            ws.Touch(lm);
        }, () => { Redo(); after.Restore(); });
        return lm.H(m);
    }

    /// <summary>Clones compiled members of `ct` that have no counterpart in `t` (lambdas, display classes, state machines, new members).</summary>
    static List<(Action<bool, object> apply, object item)> CloneNew(Merger merger, TypeDef ct, TypeDef t)
    {
        var added = new List<(Action<bool, object>, object)>();
        foreach (var n in ct.NestedTypes.Where(n => !merger.IsMapped(n)).ToList())
        {
            var nt = merger.CloneType(n, t);
            added.Add(((add, x) => { if (add) { if (!t.NestedTypes.Contains((TypeDef)x)) t.NestedTypes.Add((TypeDef)x); } else t.NestedTypes.Remove((TypeDef)x); }, nt));
        }
        foreach (var f in ct.Fields.Where(f => !merger.IsMapped(f)).ToList())
        {
            var nf = (FieldDef)merger.CloneMember(f, t);
            added.Add(((add, x) => { if (add) { if (!t.Fields.Contains((FieldDef)x)) t.Fields.Add((FieldDef)x); } else t.Fields.Remove((FieldDef)x); }, nf));
        }
        foreach (var cm in ct.Methods.Where(x => !merger.IsMapped(x)).ToList())
        {
            var nm = (MethodDef)merger.CloneMember(cm, t);
            added.Add(((add, x) => { if (add) { if (!t.Methods.Contains((MethodDef)x)) t.Methods.Add((MethodDef)x); } else t.Methods.Remove((MethodDef)x); }, nm));
        }
        return added;
    }

    static int AddMembers(Session s, TypeDef t, string source)
    {
        var ws = s.Ws;
        var lm = ws.ModuleOf(t);
        var cc = new CSharpCompile(s, lm);
        var compiled = cc.Compile(cc.Skeleton(t, source, _ => false));
        var ct = compiled.Find(t.FullName, false) ?? throw new SqlException($"compiled output has no type {t.FullName}");
        var merger = new Merger(lm.Module, compiled);
        merger.MapExisting(ct, t);
        var added = CloneNew(merger, ct, t);
        merger.Complete();
        // properties/events whose accessors were added
        var props = new List<PropertyDef>();
        foreach (var p in ct.Properties.Where(p => !merger.IsMapped(p)))
        {
            var np = new PropertyDefUser(p.Name, (PropertySig)new Importer(lm.Module, ImporterOptions.TryToUseDefs).Import(p.PropertySig), p.Attributes);
            foreach (var g in p.GetMethods) np.GetMethods.Add((MethodDef)merger.MapOperand(g)!);
            foreach (var x in p.SetMethods) np.SetMethods.Add((MethodDef)merger.MapOperand(x)!);
            props.Add(np);
        }
        void Apply(bool add)
        {
            foreach (var (fn, item) in added) fn(add, item);
            foreach (var p in props) { if (add) { if (!t.Properties.Contains(p)) t.Properties.Add(p); } else t.Properties.Remove(p); }
            ws.Touch(lm);
        }
        Apply(true);
        ws.Record("compile", $"add_members {t.FullName}", () => Apply(false), () => Apply(true));
        return added.Count + props.Count;
    }

    static int AddTypes(Session s, LoadedModule lm, string source)
    {
        var ws = s.Ws;
        var cc = new CSharpCompile(s, lm);
        var compiled = cc.Compile(source);
        var merger = new Merger(lm.Module, compiled);
        var newTypes = compiled.Types.Where(t => !t.IsGlobalModuleType).Select(t => merger.CloneType(t, null)).ToList();
        merger.Complete();
        void Apply(bool add)
        {
            foreach (var t in newTypes) { if (add) { if (!lm.Module.Types.Contains(t)) lm.Module.Types.Add(t); } else lm.Module.Types.Remove(t); }
            ws.Touch(lm);
        }
        Apply(true);
        ws.Record("compile", "add_type", () => Apply(false), () => Apply(true));
        return newTypes.Count;
    }
}
