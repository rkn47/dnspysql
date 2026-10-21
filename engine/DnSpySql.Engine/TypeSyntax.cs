// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Sql;
using dnlib.DotNet;

namespace DnSpySql;

/// <summary>
/// Parses C#-style type names ("int", "string[]", "System.Collections.Generic.List&lt;int&gt;", "Outer+Inner", "!0", "!!0",
/// "byte*", "int&amp;") into TypeSigs owned by a target module, resolving names against the target module, every loaded module
/// and the target's referenced assemblies.
/// </summary>
public sealed class TypeSyntax
{
    readonly Workspace _ws;
    readonly ModuleDef _target;
    string _s = "";
    int _p;

    public TypeSyntax(Workspace ws, ModuleDef target) { _ws = ws; _target = target; }

    public static TypeSig Parse(Workspace ws, ModuleDef target, string text) => new TypeSyntax(ws, target).Parse(text);

    public static ITypeDefOrRef ParseTypeRef(Workspace ws, ModuleDef target, string text)
    {
        var sig = Parse(ws, target, text);
        return sig.ToTypeDefOrRef() ?? throw new SqlException($"'{text}' is not a type reference");
    }

    public TypeSig Parse(string text)
    {
        _s = text.Trim();
        _p = 0;
        var t = ParseType();
        Ws();
        if (_p != _s.Length) throw Error($"unexpected '{_s[_p..]}'");
        return t;
    }

    SqlException Error(string msg) => new($"type '{_s}': {msg}");

    void Ws() { while (_p < _s.Length && char.IsWhiteSpace(_s[_p])) _p++; }
    bool Eat(char c) { Ws(); if (_p < _s.Length && _s[_p] == c) { _p++; return true; } return false; }

    TypeSig ParseType()
    {
        var t = ParsePrimary();
        while (true)
        {
            Ws();
            if (_p >= _s.Length) break;
            if (_s[_p] == '[')
            {
                _p++;
                int rank = 1;
                while (Eat(',')) rank++;
                if (!Eat(']')) throw Error("expected ']'");
                t = rank == 1 ? new SZArraySig(t) : new ArraySig(t, (uint)rank);
            }
            else if (_s[_p] == '*') { _p++; t = new PtrSig(t); }
            else if (_s[_p] == '&') { _p++; t = new ByRefSig(t); }
            else break;
        }
        return t;
    }

    TypeSig ParsePrimary()
    {
        Ws();
        if (Eat('!'))
        {
            bool method = Eat('!');
            var n = ReadNumber();
            return method ? new GenericMVar(n) : new GenericVar(n);
        }
        var name = ReadName();
        var args = new List<TypeSig>();
        if (Eat('<'))
        {
            do args.Add(ParseType()); while (Eat(','));
            if (!Eat('>')) throw Error("expected '>'");
        }
        var corlib = _target.CorLibTypes;
        if (args.Count == 0)
        {
            var kw = name switch
            {
                "void" => corlib.Void, "bool" => corlib.Boolean, "char" => corlib.Char, "sbyte" => corlib.SByte, "byte" => corlib.Byte,
                "short" => corlib.Int16, "ushort" => corlib.UInt16, "int" => corlib.Int32, "uint" => corlib.UInt32,
                "long" => corlib.Int64, "ulong" => corlib.UInt64, "float" => corlib.Single, "double" => corlib.Double,
                "string" => corlib.String, "object" => corlib.Object, "nint" => corlib.IntPtr, "nuint" => corlib.UIntPtr,
                "typedref" => corlib.TypedReference,
                _ => (TypeSig?)null,
            };
            if (kw != null) return kw;
            if (name == "decimal") name = "System.Decimal";
        }
        var lookup = args.Count > 0 && !name.Contains('`') ? $"{name}`{args.Count}" : name;
        var tdr = ResolveName(lookup) ?? throw Error($"cannot resolve type '{lookup}'");
        var isValue = tdr.ResolveTypeDef()?.IsValueType ?? false;
        if (args.Count == 0) return (TypeSig?)corlib.GetCorLibTypeSig(tdr) ?? (isValue ? new ValueTypeSig(tdr) : new ClassSig(tdr));
        ClassOrValueTypeSig gen = isValue ? new ValueTypeSig(tdr) : new ClassSig(tdr);
        return new GenericInstSig(gen, args);
    }

    uint ReadNumber()
    {
        Ws();
        int st = _p;
        while (_p < _s.Length && char.IsDigit(_s[_p])) _p++;
        if (st == _p) throw Error("expected a number");
        return uint.Parse(_s[st.._p]);
    }

    string ReadName()
    {
        Ws();
        int st = _p;
        while (_p < _s.Length && (char.IsLetterOrDigit(_s[_p]) || _s[_p] is '_' or '.' or '+' or '/' or '`' or '$')) _p++;
        // compiler-generated names (<>c, <Foo>d__1): '<' starts a name segment only at the start or right after a separator
        while (_p < _s.Length && _s[_p] == '<' && (_p == st || _s[_p - 1] is '.' or '+' or '/'))
        {
            int depth = 0;
            while (_p < _s.Length) { if (_s[_p] == '<') depth++; else if (_s[_p] == '>') { depth--; if (depth == 0) { _p++; break; } } _p++; }
            while (_p < _s.Length && (char.IsLetterOrDigit(_s[_p]) || _s[_p] is '_' or '.' or '+' or '/' or '`' or '$')) _p++;
        }
        if (st == _p) throw Error($"expected a type name at {_p}");
        return _s[st.._p].Replace('+', '/');
    }

    ITypeDefOrRef? ResolveName(string fullName)
    {
        var importer = new Importer(_target, ImporterOptions.TryToUseDefs);
        // 1. target module
        if (_target.Find(fullName, false) is TypeDef own) return own;
        // 2. other loaded modules
        foreach (var lm in _ws.Modules)
            if (!ReferenceEquals(lm.Module, _target) && lm.Module.Find(fullName, false) is TypeDef td) return importer.Import(td);
        // 3. referenced assemblies (and their forwarders)
        foreach (var ar in _target.GetAssemblyRefs())
        {
            AssemblyDef? asm = null;
            try { asm = _ws.Resolver.Resolve(ar, _target); } catch { }
            if (asm?.Find(fullName, false) is TypeDef rtd) return importer.Import(rtd);
            if (asm?.ManifestModule?.ExportedTypes.FirstOrDefault(e => e.FullName == fullName.Replace('/', '+') || e.FullName == fullName)?.Resolve() is TypeDef fwd)
                return importer.Import(fwd);
        }
        // 4. corlib
        try
        {
            var corlib = _ws.Resolver.Resolve(_target.CorLibTypes.AssemblyRef, _target);
            if (corlib?.Find(fullName, false) is TypeDef ctd) return importer.Import(ctd);
        }
        catch { }
        // 5. unqualified simple name: unique match in loaded modules
        if (!fullName.Contains('.') && !fullName.Contains('/'))
        {
            var hits = _ws.Modules.SelectMany(m => m.Module.GetTypes()).Where(t => t.Name == fullName).Take(2).ToList();
            if (hits.Count == 1) return ReferenceEquals(hits[0].Module, _target) ? hits[0] : importer.Import(hits[0]);
            if (TryResolveSystem("System." + fullName) is { } sys) return sys;
        }
        return null;
    }

    ITypeDefOrRef? TryResolveSystem(string fullName)
    {
        var importer = new Importer(_target, ImporterOptions.TryToUseDefs);
        try
        {
            var corlib = _ws.Resolver.Resolve(_target.CorLibTypes.AssemblyRef, _target);
            if (corlib?.Find(fullName, false) is TypeDef ctd) return importer.Import(ctd);
        }
        catch { }
        return null;
    }
}
