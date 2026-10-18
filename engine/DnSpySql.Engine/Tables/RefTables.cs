// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Sql;
using dnlib.DotNet;
using static DnSpySql.Tables.TableKit;

namespace DnSpySql.Tables;

/// <summary>What a module uses from elsewhere: TypeRef, MemberRef, TypeSpec, MethodSpec, StandAloneSig, #US.</summary>
public static class RefTables
{
    public static void Register(Session s)
    {
        var ws = s.Ws;
        var db = s.Db;

        db.Register(s.DefTable<TypeRef>("typerefs", "metadata", "TypeRef rows: external types referenced by the module",
                m => m.Module.GetTypeRefs())
            .Text("namespace", r => r.Item.Namespace.String)
            .Text("name", r => r.Item.Name.String)
            .Text("full_name", r => r.Item.FullName, pushdown: Pushdown.None)
            .Text("scope", r => r.Item.ResolutionScope switch
            {
                AssemblyRef a => a.Name.String,
                ModuleRef mr => mr.Name.String,
                TypeRef tr => tr.FullName,
                ModuleDef md => md.Name.String,
                _ => null,
            })
            .Text("scope_kind", r => r.Item.ResolutionScope switch
            {
                AssemblyRef => "asmref", ModuleRef => "modref", TypeRef => "nested", ModuleDef => "module", _ => null,
            })
            .Int("resolved", r => MemberTables.DefHandle(ws, r.Item), doc: "handle of the TypeDef if it is in a loaded module")
            .Text("resolved_assembly", r => Try(() => r.Item.Resolve()?.Module?.Assembly?.FullName)));

        db.Register(s.DefTable<MemberRef>("memberrefs", "metadata", "MemberRef rows: external (or generic-instance) methods and fields",
                m => Enumerable.Range(1, (int)m.Module.Metadata.TablesStream.MemberRefTable.Rows).Select(i => m.Module.ResolveMemberRef((uint)i)).OfType<MemberRef>())
            .Text("kind", r => r.Item.IsMethodRef ? "method" : "field")
            .Text("name", r => r.Item.Name.String, pushdown: Pushdown.None)
            .Text("declaring_type_name", r => r.Item.DeclaringType?.FullName)
            .Int("parent", r => r.Item.Class is IMDTokenProvider p ? r.M.H(p) : null)
            .Text("signature", r => r.Item.Signature?.ToString())
            .Text("full_name", r => r.Item.FullName)
            .Int("resolved", r => MemberTables.DefHandle(ws, r.Item))
            .Text("resolved_assembly", r => Try(() => ((IMemberDef?)r.Item.ResolveMethod() ?? r.Item.ResolveField())?.Module?.Assembly?.FullName)));

        db.Register(s.DefTable<TypeSpec>("typespecs", "metadata", "TypeSpec rows (generic instances, arrays, pointers used as types)",
                m => Enumerable.Range(1, (int)m.Module.Metadata.TablesStream.TypeSpecTable.Rows).Select(i => m.Module.ResolveTypeSpec((uint)i)).OfType<TypeSpec>())
            .Text("signature", r => r.Item.FullName)
            .Int("generic_type", r => MemberTables.DefHandle(ws, (r.Item.TypeSig as GenericInstSig)?.GenericType?.TypeDefOrRef)));

        db.Register(s.DefTable<MethodSpec>("methodspecs", "metadata", "MethodSpec rows (generic method instantiations)",
                m => Enumerable.Range(1, (int)m.Module.Metadata.TablesStream.MethodSpecTable.Rows).Select(i => m.Module.ResolveMethodSpec((uint)i)).OfType<MethodSpec>())
            .Int("method", r => MemberTables.DefHandle(ws, r.Item.Method))
            .Text("method_name", r => r.Item.Method?.FullName)
            .Text("instantiation", r => string.Join(", ", r.Item.GenericInstMethodSig?.GenericArguments.Select(a => a.FullName) ?? Array.Empty<string>()))
            .Text("full_name", r => r.Item.FullName));

        db.Register(s.DefTable<StandAloneSig>("standalonesigs", "metadata", "StandAloneSig rows (local variable and calli signatures)",
                m => Enumerable.Range(1, (int)m.Module.Metadata.TablesStream.StandAloneSigTable.Rows).Select(i => m.Module.ResolveStandAloneSig((uint)i)).OfType<StandAloneSig>())
            .Text("kind", r => r.Item.Signature switch { LocalSig => "locals", MethodSig => "method", null => null, _ => "other" })
            .Text("signature", r => r.Item.Signature switch
            {
                LocalSig ls => string.Join(", ", ls.Locals.Select(l => l.FullName)),
                var x => x?.ToString(),
            }));

        db.Register(new Table<Row<(uint offset, string value)>>("user_strings", "The #US heap: every ldstr literal of the module (token = 0x70000000 | offset)") { Domain = "metadata" }
            .Source(c => ws.Modules(c).SelectMany(m => UserStrings(m).Select(x => new Row<(uint, string)>(m, x))))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Int("token", r => 0x70000000L | r.Item.offset)
            .Int("offset", r => r.Item.offset)
            .Text("value", r => r.Item.value)
            .Int("length", r => r.Item.value.Length));
    }

    static T? Try<T>(Func<T?> f) { try { return f(); } catch { return default; } }

    public static IEnumerable<(uint offset, string value)> UserStrings(LoadedModule lm)
    {
        var us = lm.Module.Metadata.USStream;
        if (us == null || us.StreamLength <= 1) yield break;
        var r = us.CreateReader();
        r.Position = 1;
        while (r.Position < r.Length)
        {
            var start = r.Position;
            if (!r.TryReadCompressedUInt32(out var len)) yield break;
            if (len == 0) continue;
            if (r.Position + len > r.Length) yield break;
            var bytes = r.ReadBytes((int)len);
            var chars = (int)(len - 1) / 2;
            yield return (start, System.Text.Encoding.Unicode.GetString(bytes, 0, chars * 2));
        }
    }
}
