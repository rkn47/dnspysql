// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Sql;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DnSpySql.Compile;

/// <summary>
/// Maps entities of a freshly compiled module onto a target module: skeleton members map to the existing definitions,
/// references to the target assembly map back to definitions, new (compiler-generated or user-added) types/members are
/// cloned. Everything else is imported as references.
/// </summary>
public sealed class Merger
{
    readonly ModuleDef _target;
    readonly ModuleDef _compiled;
    readonly string _targetAsm;
    readonly Importer _importer;
    readonly Dictionary<IMemberDef, IMemberDef> _map = new();
    public List<TypeDef> NewTypes { get; } = new();

    public Merger(ModuleDef target, ModuleDef compiled)
    {
        _target = target;
        _compiled = compiled;
        _targetAsm = target.Assembly?.Name.String ?? target.Name.String;
        _importer = new Importer(target, ImporterOptions.TryToUseDefs, default, new Mapper(this));
    }

    public void MapExisting(TypeDef compiledType, TypeDef targetType)
    {
        _map[compiledType] = targetType;
        foreach (var f in compiledType.Fields)
            if (targetType.Fields.FirstOrDefault(x => x.Name == f.Name) is { } tf) _map[f] = tf;
        foreach (var m in compiledType.Methods)
            if (FindMethod(targetType, m) is { } tm) _map[m] = tm;
        foreach (var p in compiledType.Properties)
            if (targetType.Properties.FirstOrDefault(x => x.Name == p.Name) is { } tp) _map[p] = tp;
        foreach (var e in compiledType.Events)
            if (targetType.Events.FirstOrDefault(x => x.Name == e.Name) is { } te) _map[e] = te;
        foreach (var n in compiledType.NestedTypes)
            if (targetType.NestedTypes.FirstOrDefault(x => x.Name == n.Name) is { } tn && !IsCompilerGenerated(n)) MapExisting(n, tn);
    }

    public static bool IsCompilerGenerated(TypeDef t) => t.Name.String.StartsWith('<') || t.CustomAttributes.IsDefined("System.Runtime.CompilerServices.CompilerGeneratedAttribute");

    MethodDef? FindMethod(TypeDef target, MethodDef m) =>
        target.Methods.FirstOrDefault(x => x.Name == m.Name && x.MethodSig.Params.Count == m.MethodSig.Params.Count
            && x.MethodSig.GenParamCount == m.MethodSig.GenParamCount && x.MethodSig.HasThis == m.MethodSig.HasThis
            && x.MethodSig.Params.Select(SigName).SequenceEqual(m.MethodSig.Params.Select(SigName)));

    static string SigName(TypeSig t) => t.FullName.Replace("&", "").Trim();

    public bool IsMapped(IMemberDef d) => _map.ContainsKey(d);

    /// <summary>Clones a compiled type (and nested types) into the target as a nested type of `owner` (or top level when null).</summary>
    public TypeDef CloneType(TypeDef src, TypeDef? owner)
    {
        var name = src.Name.String;
        var siblings = owner?.NestedTypes ?? (IList<TypeDef>)_target.Types;
        var ns = owner == null ? src.Namespace : (UTF8String)"";
        int k = 1;
        while (siblings.Any(t => t.Name == name && t.Namespace == ns)) name = src.Name.String + "_" + k++;
        var t = new TypeDefUser(ns, name) { Attributes = src.Attributes, ClassLayout = src.ClassLayout == null ? null : new ClassLayoutUser(src.ClassLayout.PackingSize, src.ClassLayout.ClassSize) };
        _map[src] = t;
        NewTypes.Add(t);
        foreach (var gp in src.GenericParameters) t.GenericParameters.Add(new GenericParamUser(gp.Number, gp.Flags, gp.Name));
        foreach (var n in src.NestedTypes) t.NestedTypes.Add(CloneType(n, t));
        // fields/method shells now so cross references resolve; signatures and bodies in Complete().
        foreach (var f in src.Fields) { var nf = new FieldDefUser(f.Name, null, f.Attributes); _map[f] = nf; t.Fields.Add(nf); }
        foreach (var m in src.Methods) { var nm = new MethodDefUser(m.Name, null, m.ImplAttributes, m.Attributes); _map[m] = nm; t.Methods.Add(nm); }
        return t;
    }

    /// <summary>Clones a single member into an existing target type (Add Class Members).</summary>
    public IMemberDef CloneMember(IMemberDef src, TypeDef into)
    {
        switch (src)
        {
            case FieldDef f:
                {
                    var nf = new FieldDefUser(f.Name, null, f.Attributes); _map[f] = nf; into.Fields.Add(nf); return nf;
                }
            case MethodDef m:
                {
                    var nm = new MethodDefUser(m.Name, null, m.ImplAttributes, m.Attributes); _map[m] = nm; into.Methods.Add(nm); return nm;
                }
            case TypeDef nt:
                return CloneType(nt, into);
            default: throw new SqlException($"cannot clone {src}");
        }
    }

    /// <summary>Fills signatures, bodies, properties, events, interfaces and attributes of everything cloned.</summary>
    public void Complete()
    {
        foreach (var (src, dst) in _map.ToList())
        {
            switch (src)
            {
                case TypeDef st when dst is TypeDef dt && NewTypes.Contains(dt):
                    dt.BaseType = st.BaseType == null ? null : ImportType(st.BaseType);
                    foreach (var ii in st.Interfaces) dt.Interfaces.Add(new InterfaceImplUser(ImportType(ii.Interface)));
                    foreach (var p in st.Properties)
                    {
                        var np = new PropertyDefUser(p.Name, (PropertySig)_importer.Import(p.PropertySig), p.Attributes);
                        foreach (var g in p.GetMethods) np.GetMethods.Add((MethodDef)_map[g]);
                        foreach (var x in p.SetMethods) np.SetMethods.Add((MethodDef)_map[x]);
                        dt.Properties.Add(np);
                    }
                    foreach (var e in st.Events)
                    {
                        var ne = new EventDefUser(e.Name, ImportType(e.EventType), e.Attributes)
                        {
                            AddMethod = e.AddMethod == null ? null : (MethodDef)_map[e.AddMethod],
                            RemoveMethod = e.RemoveMethod == null ? null : (MethodDef)_map[e.RemoveMethod],
                            InvokeMethod = e.InvokeMethod == null ? null : (MethodDef)_map[e.InvokeMethod],
                        };
                        dt.Events.Add(ne);
                    }
                    CopyAttributes(st, dt);
                    break;
                case FieldDef sf when dst is FieldDefUser df && df.FieldSig == null:
                    df.FieldSig = new FieldSig(_importer.Import(sf.FieldType));
                    if (sf.Constant != null) df.Constant = new ConstantUser(sf.Constant.Value, sf.Constant.Type);
                    if (sf.HasFieldRVA) df.InitialValue = sf.InitialValue;
                    CopyAttributes(sf, df);
                    break;
                case MethodDef sm when dst is MethodDefUser dm && dm.MethodSig == null:
                    dm.MethodSig = _importer.Import(sm.MethodSig);
                    foreach (var gp in sm.GenericParameters) dm.GenericParameters.Add(new GenericParamUser(gp.Number, gp.Flags, gp.Name));
                    foreach (var pd in sm.ParamDefs) dm.ParamDefs.Add(new ParamDefUser(pd.Name, pd.Sequence, pd.Attributes));
                    foreach (var o in sm.Overrides) dm.Overrides.Add(new MethodOverride(dm, (IMethodDefOrRef)MapOperand(o.MethodDeclaration)!));
                    dm.Parameters.UpdateParameterTypes();
                    if (sm.HasBody) dm.Body = CloneBody(sm, dm);
                    CopyAttributes(sm, dm);
                    break;
            }
        }
    }

    void CopyAttributes(IHasCustomAttribute src, IHasCustomAttribute dst)
    {
        foreach (var ca in src.CustomAttributes)
        {
            if (ca.Constructor is not { } ctor) continue;
            var nctor = (ICustomAttributeType)MapOperand(ctor)!;
            var args = ca.ConstructorArguments.Select(a => new CAArgument(_importer.Import(a.Type), a.Value)).ToList();
            var named = ca.NamedArguments.Select(n => new CANamedArgument(n.IsField, _importer.Import(n.Type), n.Name, new CAArgument(_importer.Import(n.Argument.Type), n.Argument.Value))).ToList();
            dst.CustomAttributes.Add(new CustomAttribute(nctor, args, named));
        }
    }

    ITypeDefOrRef ImportType(ITypeDefOrRef t) => (ITypeDefOrRef)MapOperand(t)!;

    /// <summary>Builds a target-module body equivalent to `src`'s body.</summary>
    public CilBody CloneBody(MethodDef src, MethodDef dst)
    {
        var sb = src.Body;
        var body = new CilBody { InitLocals = sb.InitLocals, MaxStack = sb.MaxStack };
        var locals = new Dictionary<Local, Local>();
        foreach (var l in sb.Variables) { var nl = new Local(_importer.Import(l.Type), l.Name); locals[l] = nl; body.Variables.Add(nl); }
        var ins = new Dictionary<Instruction, Instruction>();
        foreach (var i in sb.Instructions) { var ni = new Instruction(i.OpCode, i.Operand); ins[i] = ni; body.Instructions.Add(ni); }
        foreach (var ni in body.Instructions)
        {
            ni.Operand = ni.Operand switch
            {
                Instruction t => ins[t],
                Instruction[] ts => ts.Select(t => ins[t]).ToArray(),
                Local l => locals[l],
                Parameter p => dst.Parameters[p.Index],
                MethodSig ms => _importer.Import(ms),
                string or null or int or long or float or double or sbyte or byte => ni.Operand,
                var o => MapOperand(o),
            };
        }
        foreach (var eh in sb.ExceptionHandlers)
            body.ExceptionHandlers.Add(new ExceptionHandler(eh.HandlerType)
            {
                TryStart = eh.TryStart == null ? null : ins[eh.TryStart], TryEnd = eh.TryEnd == null ? null : ins[eh.TryEnd],
                HandlerStart = eh.HandlerStart == null ? null : ins[eh.HandlerStart], HandlerEnd = eh.HandlerEnd == null ? null : ins[eh.HandlerEnd],
                FilterStart = eh.FilterStart == null ? null : ins[eh.FilterStart],
                CatchType = eh.CatchType == null ? null : ImportType(eh.CatchType),
            });
        body.UpdateInstructionOffsets();
        return body;
    }

    /// <summary>Maps any operand (def or ref) from the compiled module to the target module.</summary>
    public object? MapOperand(object? o)
    {
        switch (o)
        {
            case null: return null;
            case IMemberDef d when _map.TryGetValue(d, out var mapped): return mapped;
            case TypeDef td when ReferenceEquals(td.Module, _compiled): throw new SqlException($"compiled type {td.FullName} has no counterpart in the target");
            case MethodDef md when ReferenceEquals(md.Module, _compiled): throw new SqlException($"compiled method {md.FullName} has no counterpart in the target (is it declared extern in the skeleton?)");
            case FieldDef fd when ReferenceEquals(fd.Module, _compiled): throw new SqlException($"compiled field {fd.FullName} has no counterpart in the target");
            case MemberRef mr when ToTargetDef(mr) is { } def: return def;
            case MemberRef mr: return _importer.Import(mr);
            case MethodSpec ms: return new MethodSpecUser((IMethodDefOrRef)MapOperand(ms.Method)!, (GenericInstMethodSig)_importer.Import(ms.GenericInstMethodSig));
            case TypeSpec ts: return _importer.Import(ts);
            case ITypeDefOrRef tr: return _importer.Import(tr);
            case IMethod im: return _importer.Import(im);
            case IField f: return _importer.Import(f);
            default: return o;
        }
    }

    bool IsTargetScope(IScope? scope) => scope switch
    {
        AssemblyRef ar => ar.Name == _targetAsm,
        ModuleRef mr => mr.Name == _target.Name,
        _ => false,
    };

    TypeDef? TargetType(ITypeDefOrRef? t)
    {
        if (t is TypeRef tr && IsTargetScope(tr.Scope)) return _target.Find(tr.FullName, false) ?? _target.Find(tr.ReflectionFullName, true);
        if (t is TypeDef td && _map.TryGetValue(td, out var m)) return m as TypeDef;
        return null;
    }

    /// <summary>A MemberRef that targets a non-generic type of the target assembly becomes the definition itself.</summary>
    IMemberDef? ToTargetDef(MemberRef mr)
    {
        if (mr.Class is not ITypeDefOrRef owner || owner is TypeSpec) return null;
        var t = TargetType(owner);
        if (t == null) return null;
        if (mr.IsFieldRef) return t.Fields.FirstOrDefault(f => f.Name == mr.Name);
        var sig = mr.MethodSig;
        return t.Methods.FirstOrDefault(m => m.Name == mr.Name && m.MethodSig.Params.Count == sig.Params.Count && m.MethodSig.HasThis == sig.HasThis
                                             && m.MethodSig.GenParamCount == sig.GenParamCount
                                             && m.MethodSig.Params.Select(SigName).SequenceEqual(sig.Params.Select(SigName)));
    }

    sealed class Mapper : ImportMapper
    {
        readonly Merger _m;
        public Mapper(Merger m) { _m = m; }

        public override ITypeDefOrRef? Map(ITypeDefOrRef source)
        {
            if (source is TypeDef td && _m._map.TryGetValue(td, out var mapped)) return (ITypeDefOrRef)mapped;
            return _m.TargetType(source);
        }

        public override IField? Map(FieldDef source) => _m._map.TryGetValue(source, out var x) ? (IField)x : null;
        public override IMethod? Map(MethodDef source) => _m._map.TryGetValue(source, out var x) ? (IMethod)x : null;
    }
}
