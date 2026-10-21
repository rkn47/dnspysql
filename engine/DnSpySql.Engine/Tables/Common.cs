// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Sql;
using dnlib.DotNet;

namespace DnSpySql.Tables;

public interface IHasModule { LoadedModule M { get; } }

/// <summary>A row that belongs to a loaded module.</summary>
public sealed record Row<T>(LoadedModule M, T Item) : IHasModule
{
    public int ModuleId => M.Id;
}

public static class TableKit
{
    /// <summary>Modules selected by an optional `module` equality filter.</summary>
    public static IEnumerable<LoadedModule> Modules(this Workspace ws, Constraints c)
    {
        if (c.Long("module") is long id) return ws.Modules.Where(m => m.Id == id);
        return ws.Modules;
    }

    /// <summary>
    /// Standard definition table: module, handle (unique pushdown), token (eq pushdown).
    /// Handles both full handles and bare tokens for the current module.
    /// </summary>
    public static Table<Row<T>> DefTable<T>(this Session s, string name, string domain, string doc,
        Func<LoadedModule, IEnumerable<T>> all, Func<IMDTokenProvider, T?>? cast = null,
        Func<LoadedModule, Constraints, IEnumerable<T>?>? fast = null) where T : class, IMDTokenProvider
    {
        var ws = s.Ws;
        cast ??= x => x as T;
        var t = new Table<Row<T>>(name, doc) { Domain = domain };
        t.Source(c =>
        {
            if (c.Long("handle") is long h) return One(ws, h, cast);
            if (c.Long("token") is long tok)
            {
                return ws.Modules(c).SelectMany(m =>
                {
                    var item = m.Module.ResolveToken((uint)tok);
                    return item != null && cast(item) is T x ? new[] { new Row<T>(m, x) } : Array.Empty<Row<T>>();
                });
            }
            return ws.Modules(c).SelectMany(m => (fast?.Invoke(m, c) ?? all(m)).Select(x => new Row<T>(m, x)));
        });
        t.Keyed(r => r.M.H(r.Item), id => One(ws, id, cast).FirstOrDefault());
        t.Int("module", r => r.M.Id, pushdown: Pushdown.Eq, doc: "module id (see modules)");
        t.Int("handle", r => r.M.H(r.Item), pushdown: Pushdown.Unique, doc: "universal key: module<<32 | token");
        t.Int("token", r => (long)r.Item.MDToken.Raw, pushdown: Pushdown.Eq, doc: "ECMA-335 metadata token");
        return t;
    }

    static IEnumerable<Row<T>> One<T>(Workspace ws, long h, Func<IMDTokenProvider, T?> cast) where T : class
    {
        h = ws.Normalize(h);
        var lm = ws.Modules.FirstOrDefault(m => m.Id == Handle.Module(h));
        if (lm == null) yield break;
        IMDTokenProvider? item;
        try { item = lm.Module.ResolveToken(Handle.Token(h)); } catch { item = null; }
        if (item != null && cast(item) is T x) yield return new Row<T>(lm, x);
    }

    /// <summary>Wraps a setter so it marks the row's module dirty.</summary>
    public static Action<R, object?> Setter<R>(this Session s, Action<R, object?> set) => (r, v) =>
    {
        set(r, v);
        switch (r)
        {
            case IHasModule hm: s.Ws.Touch(hm.M); break;
            case LoadedModule lm: s.Ws.Touch(lm); break;
        }
    };

    public static string Str(object? v, string what) => Values.ToText(v) ?? throw new SqlException($"{what} cannot be NULL");
    public static long Lng(object? v, string what) => Values.ToLong(v) ?? throw new SqlException($"{what} must be an integer");

    public static string Visibility(TypeAttributes a) => (a & TypeAttributes.VisibilityMask) switch
    {
        TypeAttributes.NotPublic => "internal",
        TypeAttributes.Public => "public",
        TypeAttributes.NestedPublic => "public",
        TypeAttributes.NestedPrivate => "private",
        TypeAttributes.NestedFamily => "protected",
        TypeAttributes.NestedAssembly => "internal",
        TypeAttributes.NestedFamANDAssem => "private protected",
        TypeAttributes.NestedFamORAssem => "protected internal",
        _ => "?",
    };

    public static string Visibility(MethodAttributes a) => (a & MethodAttributes.MemberAccessMask) switch
    {
        MethodAttributes.PrivateScope => "privatescope",
        MethodAttributes.Private => "private",
        MethodAttributes.FamANDAssem => "private protected",
        MethodAttributes.Assembly => "internal",
        MethodAttributes.Family => "protected",
        MethodAttributes.FamORAssem => "protected internal",
        MethodAttributes.Public => "public",
        _ => "?",
    };

    public static string Visibility(FieldAttributes a) => Visibility((MethodAttributes)(ushort)(a & FieldAttributes.FieldAccessMask));

    public static MethodAttributes ParseMethodVisibility(string s) => s.Trim().ToLowerInvariant() switch
    {
        "privatescope" or "compilercontrolled" => MethodAttributes.PrivateScope,
        "private" => MethodAttributes.Private,
        "private protected" or "famandassem" => MethodAttributes.FamANDAssem,
        "internal" or "assembly" => MethodAttributes.Assembly,
        "protected" or "family" => MethodAttributes.Family,
        "protected internal" or "famorassem" => MethodAttributes.FamORAssem,
        "public" => MethodAttributes.Public,
        _ => throw new SqlException($"unknown visibility '{s}' (public, internal, protected, private, protected internal, private protected)"),
    };

    public static TypeAttributes ParseTypeVisibility(string s, bool nested) => (s.Trim().ToLowerInvariant(), nested) switch
    {
        ("public", false) => TypeAttributes.Public,
        ("internal", false) => TypeAttributes.NotPublic,
        ("public", true) => TypeAttributes.NestedPublic,
        ("private", true) => TypeAttributes.NestedPrivate,
        ("protected", true) => TypeAttributes.NestedFamily,
        ("internal", true) => TypeAttributes.NestedAssembly,
        ("private protected", true) => TypeAttributes.NestedFamANDAssem,
        ("protected internal", true) => TypeAttributes.NestedFamORAssem,
        _ => throw new SqlException($"visibility '{s}' is not valid for a {(nested ? "nested" : "top-level")} type"),
    };

    public static string TypeKind(TypeDef t)
    {
        if (t.IsInterface) return "interface";
        if (t.IsEnum) return "enum";
        if (t.IsValueType) return "struct";
        if (t.IsDelegate) return "delegate";
        if (t.IsGlobalModuleType) return "module";
        if (t.IsAbstract && t.IsSealed) return "static class";
        return "class";
    }

    public static bool IsCompilerGenerated(IHasCustomAttribute? m) =>
        m != null && m.CustomAttributes.IsDefined("System.Runtime.CompilerServices.CompilerGeneratedAttribute");

    /// <summary>Converts a dnlib constant / CA value to a SQL value.</summary>
    public static object? SqlValue(object? v) => v switch
    {
        null => null,
        UTF8String u => u.String,
        string s => s,
        bool b => b ? 1L : 0L,
        char ch => ch.ToString(),
        byte or sbyte or short or ushort or int or uint or long => Convert.ToInt64(v),
        ulong ul => unchecked((long)ul),
        float f => (double)f,
        double d => d,
        byte[] bytes => bytes,
        TypeSig ts => ts.FullName,
        IList<CAArgument> list => "[" + string.Join(", ", list.Select(a => Fmt(a.Value))) + "]",
        CAArgument a => SqlValue(a.Value),
        _ => v.ToString(),
    };

    public static string Fmt(object? v) => v switch
    {
        null => "null",
        UTF8String u => "\"" + u.String + "\"",
        string s => "\"" + s + "\"",
        CAArgument a => Fmt(a.Value),
        IList<CAArgument> list => "[" + string.Join(", ", list.Select(x => Fmt(x.Value))) + "]",
        TypeSig ts => "typeof(" + ts.FullName + ")",
        bool b => b ? "true" : "false",
        _ => Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture) ?? "",
    };

    public static object? CoerceConstant(object? value, TypeSig? type)
    {
        if (value == null) return null;
        var et = type?.RemovePinnedAndModifiers().ElementType ?? ElementType.Object;
        if (type is ValueTypeSig vt && vt.TypeDefOrRef.ResolveTypeDef() is TypeDef { IsEnum: true } en)
            et = en.GetEnumUnderlyingType()?.ElementType ?? ElementType.I4;
        try
        {
            return et switch
            {
                ElementType.Boolean => Values.ToBool(value),
                ElementType.Char => (Values.ToText(value) ?? "\0")[0],
                ElementType.I1 => (sbyte)Values.ToLong(value)!.Value,
                ElementType.U1 => (byte)Values.ToLong(value)!.Value,
                ElementType.I2 => (short)Values.ToLong(value)!.Value,
                ElementType.U2 => (ushort)Values.ToLong(value)!.Value,
                ElementType.I4 => (int)Values.ToLong(value)!.Value,
                ElementType.U4 => (uint)Values.ToLong(value)!.Value,
                ElementType.I8 => Values.ToLong(value)!.Value,
                ElementType.U8 => (ulong)Values.ToLong(value)!.Value,
                ElementType.R4 => (float)Convert.ToDouble(value),
                ElementType.R8 => Convert.ToDouble(value),
                ElementType.String => Values.ToText(value),
                _ => value is long or double or string ? value : Values.ToText(value),
            };
        }
        catch (Exception e) when (e is InvalidCastException or OverflowException or FormatException or InvalidOperationException)
        {
            throw new SqlException($"cannot convert {Fmt(value)} to {type?.FullName}");
        }
    }
}
