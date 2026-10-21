// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using dnlib.DotNet;

namespace DnSpySql;

/// <summary>dnSpy-style reference fix-ups applied when a definition is renamed (same module only).</summary>
public static class Fixups
{
    public static void RenameType(TypeDef type, string? ns, string? name)
    {
        var module = type.Module;
        if (module != null)
        {
            var cmp = new SigComparer();
            foreach (var tr in module.GetTypeRefs().ToList())
            {
                if (!cmp.Equals(tr, type)) continue;
                if (ns != null) tr.Namespace = ns;
                if (name != null) tr.Name = name;
            }
        }
        if (ns != null) type.Namespace = ns;
        if (name != null) type.Name = name;
    }

    public static void RenameMember(IMemberDef def, string name)
    {
        var module = def.Module;
        if (module is ModuleDefMD md && def is MethodDef or FieldDef)
        {
            // Only references that resolve to exactly this definition (e.g. members of generic instances of the declaring
            // type). Signature equality is not enough: a call to an overridden base method (Object::GetHashCode) must keep
            // its name when the override is renamed.
            var rows = md.Metadata.TablesStream.MemberRefTable.Rows;
            for (uint rid = 1; rid <= rows; rid++)
            {
                var mr = md.ResolveMemberRef(rid);
                if (mr == null || mr.Name != def.Name) continue;
                IMemberDef? target;
                try { target = mr.IsMethodRef ? mr.ResolveMethod() : mr.ResolveField(); }
                catch { target = null; }
                if (ReferenceEquals(target, def)) mr.Name = name;
            }
        }
        switch (def)
        {
            case MethodDef m: m.Name = name; break;
            case FieldDef f: f.Name = name; break;
            case PropertyDef p: p.Name = name; break;
            case EventDef e: e.Name = name; break;
            case TypeDef t: t.Name = name; break;
        }
    }
}
