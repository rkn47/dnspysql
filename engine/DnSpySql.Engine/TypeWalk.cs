// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using dnlib.DotNet;

namespace DnSpySql;

/// <summary>
/// Walks over a type hierarchy that stay finite on hostile metadata: a base chain or an interface graph can be a ring
/// (A : B, B : A, or a type that is its own base), and resolving a reference can throw. Every walk visits a type once,
/// stops after <see cref="MaxDepth"/> levels, and treats an unresolvable reference as the end of its branch.
/// </summary>
public static class TypeWalk
{
    public const int MaxDepth = 256;

    public static TypeDef? Resolve(ITypeDefOrRef? r)
    {
        try { return r?.ResolveTypeDef(); } catch (Exception) { return null; }
    }

    /// <summary>
    /// The base chain, nearest first, as each reference and what it resolves to. An unresolvable base is the last entry
    /// (Def null); a base already seen ends the chain before it is repeated.
    /// </summary>
    public static IEnumerable<(ITypeDefOrRef Ref, TypeDef? Def)> BaseChain(TypeDef t)
    {
        var seen = new HashSet<TypeDef> { t };
        var b = t.BaseType;
        for (int depth = 0; b != null && depth < MaxDepth; depth++)
        {
            var bd = Resolve(b);
            if (bd != null && !seen.Add(bd)) yield break;
            yield return (b, bd);
            if (bd == null) yield break;
            b = bd.BaseType;
        }
    }

    /// <summary>The resolvable base types, nearest first.</summary>
    public static IEnumerable<TypeDef> Bases(TypeDef t)
    {
        foreach (var (_, d) in BaseChain(t))
            if (d != null) yield return d;
    }

    /// <summary>The type itself, then its resolvable bases.</summary>
    public static IEnumerable<TypeDef> SelfAndBases(TypeDef t) => Bases(t).Prepend(t);

    /// <summary>
    /// Every interface the type implements: its own and its bases' declared interfaces, each followed by the interfaces
    /// it inherits, once each by full name.
    /// </summary>
    public static IEnumerable<ITypeDefOrRef> Interfaces(TypeDef t)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var expanded = new HashSet<TypeDef>();
        foreach (var d in SelfAndBases(t))
            foreach (var i in Declared(d, 0))
                yield return i;

        IEnumerable<ITypeDefOrRef> Declared(TypeDef d, int depth)
        {
            if (depth >= MaxDepth || !expanded.Add(d)) yield break;
            foreach (var impl in d.Interfaces)
                if (impl.Interface is { } i && seen.Add(i.FullName))
                {
                    yield return i;
                    if (Resolve(i) is { } itd)
                        foreach (var inherited in Declared(itd, depth + 1))
                            yield return inherited;
                }
        }
    }
}
