// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using MD = dnlib.DotNet;

namespace DnSpySql;

// C# source editing, the way dnSpy's "Edit Class (C#)" works: the caller supplies
// a complete type definition, Roslyn compiles it against the target assembly (with
// access to its internals), and the recompiled method bodies are spliced back into
// the original type. References inside the new IL are imported into the target
// module; self-references are redirected to the original members through an
// ImportMapper, and compiler-generated nested types (lambda closures, async state
// machines, iterators) are copied in wholesale.
static class TypeSplice
{
    // Reference assemblies for the Roslyn compilation: the framework reference pack
    // (so emitted references go to System.Runtime & co. like the original compiler's,
    // not System.Private.CoreLib), falling back to the running framework's trusted
    // platform assemblies; plus the target and whatever sits next to it.
    // <dotnet root>/packs/Microsoft.NETCore.App.Ref/<ver>/ref/netX.Y for a .NET Core
    // target: the pack matching its TargetFramework when installed, else the newest.
    // Null when no SDK packs exist (runtime-only install) or the target is not .NET Core.
    public static string? RefPack(LoadedModule m)
    {
        if (m.Module.CorLibTypes.AssemblyRef.Name != "System.Runtime") return null;
        // runtime dir = <root>/shared/Microsoft.NETCore.App/<ver>/
        var runtimeDir = System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory();
        var root = Path.GetFullPath(Path.Combine(runtimeDir, "..", "..", ".."));
        var packs = Path.Combine(root, "packs", "Microsoft.NETCore.App.Ref");
        if (!Directory.Exists(packs)) return null;

        var tfm = m.Module.Assembly?.CustomAttributes
            .Find("System.Runtime.Versioning.TargetFrameworkAttribute")?
            .ConstructorArguments.FirstOrDefault().Value?.ToString();   // ".NETCoreApp,Version=v8.0"
        var want = tfm?.Split("Version=v").ElementAtOrDefault(1);

        var candidates = Directory.EnumerateDirectories(packs)
            .Select(d => (dir: d, ver: Version.TryParse(Path.GetFileName(d).Split('-')[0], out var v) ? v : null))
            .Where(c => c.ver != null)
            .OrderByDescending(c => c.ver)
            .SelectMany(c => Directory.Exists(Path.Combine(c.dir, "ref"))
                ? Directory.EnumerateDirectories(Path.Combine(c.dir, "ref")) : [])
            .ToList();
        return candidates.FirstOrDefault(d => want != null && Path.GetFileName(d) == "net" + want)
            ?? candidates.FirstOrDefault();
    }

    // Compiled in the context of the target the way dnSpy compiles edited code: private and internal members are
    // accessible, and references are the target's own (see Compile/CSharpCompile.cs).
    static ModuleDefMD CompileToModule(Session s, LoadedModule m, string source) =>
        new Compile.CSharpCompile(s, m).Compile(WithoutReservedAttributes(source));

    // Attributes the C# compiler emits itself and refuses in source (CS8335, CS8623). Decompiled text carries them,
    // so they are dropped before compiling, as dnSpy's Edit Class does by not printing them.
    static readonly HashSet<string> ReservedAttributes = new(StringComparer.Ordinal)
    {
        "Nullable", "NullableContext", "NullablePublicOnly", "IsReadOnly", "IsByRefLike", "IsUnmanaged", "IsExternalInit",
        "RefSafetyRules", "ScopedRef", "RequiredMember", "CompilerFeatureRequired", "Dynamic", "TupleElementNames",
        "NativeInteger", "IsReadOnlyAttribute",
    };

    static string WithoutReservedAttributes(string source)
    {
        var root = CSharpSyntaxTree.ParseText(source).GetRoot();
        static string Name(Microsoft.CodeAnalysis.CSharp.Syntax.AttributeSyntax a)
        {
            var n = a.Name.ToString();
            n = n[(n.LastIndexOf('.') + 1)..];
            return n.EndsWith("Attribute", StringComparison.Ordinal) ? n[..^"Attribute".Length] : n;
        }
        var lists = root.DescendantNodes().OfType<Microsoft.CodeAnalysis.CSharp.Syntax.AttributeListSyntax>()
            .Where(l => l.Attributes.All(a => ReservedAttributes.Contains(Name(a)))).ToList();
        return lists.Count == 0 ? source : root.RemoveNodes(lists, Microsoft.CodeAnalysis.SyntaxRemoveOptions.KeepNoTrivia)!.ToFullString();
    }

    public static int EditType(Session s, LoadedModule m, uint token, string source)
    {
        if (m.Module.ResolveToken(token) is not TypeDef orig)
            throw new ArgumentException($"0x{token:X8} is not a type in module {m.Id}");

        var editMod = CompileToModule(s, m, source);
        var edited = editMod.GetTypes().FirstOrDefault(t => t.Name == orig.Name && t.Namespace == orig.Namespace);
        // dnSpy's decompiled text has no namespace block, so edit_type(t, decompile(t)) compiles the type at the
        // top level; place it in the original namespace and compile again.
        if (edited == null && !UTF8String.IsNullOrEmpty(orig.Namespace)
            && editMod.GetTypes().Any(t => t.Name == orig.Name && UTF8String.IsNullOrEmpty(t.Namespace)))
        {
            editMod = CompileToModule(s, m, $"namespace {orig.Namespace}\n{{\n{source}\n}}\n");
            edited = editMod.GetTypes().FirstOrDefault(t => t.Name == orig.Name && t.Namespace == orig.Namespace);
        }
        if (edited == null) throw new ArgumentException($"compiled code has no type named {orig.FullName}");

        new TypeSplicer(m.Module, orig, edited).Apply();
        return 1;
    }

    public static int AddType(Session s, LoadedModule m, string source)
    {
        var editMod = CompileToModule(s, m, source);

        // Add every top-level type the agent defined that isn't already present.
        var added = editMod.Types
            .Where(t => !t.IsGlobalModuleType && t.Namespace != "System.Runtime.CompilerServices")
            .Where(t => !TypeSplicer.IsPrivateImpl(t))
            .Where(t => m.Module.Find(t.FullName, isReflectionName: false) == null)
            .ToList();
        if (added.Count == 0)
            throw new ArgumentException("compiled code defines no new top-level type (use edit_type to change an existing one)");
        TypeSplicer.AddNewTypes(m.Module, editMod, added);
        return added.Count;
    }
}

// Copies recompiled method bodies (and any compiler-generated helper types) from a
// freshly compiled `edited` type into the live `orig` type, importing every
// reference into the target module and redirecting self-references back to orig.
sealed class TypeSplicer
{
    readonly ModuleDef target;
    readonly TypeDef? orig;
    readonly TypeDef edited;
    readonly Dictionary<TypeDef, TypeDef> typeMap = [];   // edited-side def -> target-side def
    readonly Dictionary<MethodDef, MethodDef> methodMap = [];
    readonly Dictionary<FieldDef, FieldDef> fieldMap = [];
    readonly Importer importer;

    public TypeSplicer(ModuleDef target, TypeDef? orig, TypeDef edited)
    {
        this.target = target; this.orig = orig; this.edited = edited;
        importer = new Importer(target, ImporterOptions.TryToUseDefs, default, new Mapper(this));
    }

    // Clone whole new top-level types (with their members, bodies and nested types)
    // into the target module.
    public static void AddNewTypes(ModuleDef target, ModuleDef editMod, IReadOnlyList<TypeDef> types)
    {
        var s = new TypeSplicer(target, null, types[0]);
        foreach (var t in types) s.CloneType(t, c => target.Types.Add(c));
        s.MergePrivateImpl(editMod);
        s.FinishClones();
        foreach (var (src, dst) in s.methodMap)
            if (src.HasBody) dst.Body = s.ImportBody(src, dst);
        s.CopyOverrides();
    }

    public void Apply()
    {
        Merge(edited, orig!);
        MergePrivateImpl(edited.Module);
        FinishClones();

        foreach (var (src, dst) in methodMap)
            if (src.HasBody) dst.Body = ImportBody(src, dst);
        CopyOverrides();
    }

    // Copy explicit interface implementations (.override records) onto freshly
    // created methods — e.g. a state machine's IAsyncStateMachine.MoveNext — without
    // which the runtime reports the interface method as unimplemented.
    void CopyOverrides()
    {
        foreach (var (src, dst) in methodMap)
        {
            if (!src.HasOverrides || dst.Overrides.Count > 0) continue;
            foreach (var ov in src.Overrides)
                dst.Overrides.Add(new MethodOverride(dst,
                    (IMethodDefOrRef)FixMethod(importer.Import(ov.MethodDeclaration))));
        }
    }

    // Reconcile an edited type against its live counterpart: map matching members
    // (their bodies get replaced), create members the agent added, and recurse into
    // nested types. Compiler-generated state machines (per-method, with their own
    // field layout) are replaced wholesale; shared closure caches like `<>c` and
    // user nested types are merged in place.
    void Merge(TypeDef from, TypeDef to)
    {
        typeMap[from] = to;
        cloneIsValueType[to.FullName] = IsValueTypeByBase(from);

        foreach (var sm in from.Methods)
        {
            var dm = to.Methods.FirstOrDefault(d => d.Name == sm.Name && SigEquals(d, sm));
            if (dm != null) methodMap[sm] = dm;
            else
            {
                var nm = new MethodDefUser(sm.Name) { ImplAttributes = sm.ImplAttributes, Attributes = sm.Attributes };
                to.Methods.Add(nm);
                CopyGenericParams(sm.GenericParameters, nm.GenericParameters);
                methodMap[sm] = nm;
                newMethods.Add((sm, nm));
            }
        }
        foreach (var sf in from.Fields)
        {
            var df = to.Fields.FirstOrDefault(d => d.Name == sf.Name);
            if (df != null) fieldMap[sf] = df;
            else
            {
                var nf = NewField(sf);
                to.Fields.Add(nf);
                fieldMap[sf] = nf;
                newFields.Add((sf, nf));
            }
        }
        foreach (var sn in from.NestedTypes.ToArray())
        {
            var dn = to.NestedTypes.FirstOrDefault(d => d.Name == sn.Name);
            if (dn != null && IsStateMachine(sn)) { to.NestedTypes.Remove(dn); dn = null; }
            if (dn != null) Merge(sn, dn);
            else CloneNestedType(sn, to);
        }
    }

    public static bool IsPrivateImpl(TypeDef t) =>
        t.DeclaringType == null && t.Namespace == "" && t.Name == "<PrivateImplementationDetails>";

    // Roslyn puts array/span initializer data and string-switch hashing into a
    // module-level <PrivateImplementationDetails> class. Merge the edit's one into
    // the target's (field names are content hashes, so equal names = equal data).
    void MergePrivateImpl(ModuleDef editMod)
    {
        if (editMod.Types.FirstOrDefault(IsPrivateImpl) is not { } src) return;
        if (target.Types.FirstOrDefault(IsPrivateImpl) is { } dst) Merge(src, dst);
        else CloneType(src, c => target.Types.Add(c));
    }

    static FieldDef NewField(FieldDef f) => new FieldDefUser(f.Name)
    {
        Attributes = f.Attributes,
        InitialValue = f.HasFieldRVA ? f.InitialValue : null,
    };

    // Does this reference point back into the assembly being edited? Roslyn sees the
    // target through a metadata reference, so its own types come back as TypeRefs.
    bool IsTargetRef(TypeRef tr) =>
        target.Assembly != null && tr.DefinitionAssembly?.Name == target.Assembly.Name;

    TypeDef? TargetType(ITypeDefOrRef? t) =>
        t is TypeRef tr && IsTargetRef(tr) ? target.Find(tr.FullName, isReflectionName: false) : null;

    const SigComparerOptions LooseSig = SigComparerOptions.DontCompareTypeScope;

    // A method/field MemberRef on one of the target's own (non-generic) types
    // becomes the real MethodDef/FieldDef instead of a self-referencing MemberRef.
    IMethod? TargetMethod(IMethod m) =>
        m is MemberRef { IsMethodRef: true } mr && TargetType(mr.Class as ITypeDefOrRef) is { } td
            ? td.FindMethod(mr.Name, mr.MethodSig, LooseSig) : null;

    IField? TargetField(IField f) =>
        f is MemberRef { IsFieldRef: true } mr && TargetType(mr.Class as ITypeDefOrRef) is { } td
            ? td.FindField(mr.Name, mr.FieldSig, LooseSig) : null;

    static bool IsValueTypeByBase(TypeDef t) =>
        t.BaseType?.FullName is "System.ValueType" or "System.Enum";

    readonly List<(FieldDef src, FieldDef dst)> newFields = [];
    readonly List<(MethodDef src, MethodDef dst)> newMethods = [];

    static bool SigEquals(MethodDef a, MethodDef b) =>
        new SigComparer().Equals(a.MethodSig, b.MethodSig);

    // Import a TypeSig, then correct class/valuetype encoding for any cloned type:
    // dnlib wraps an ImportMapper result as ClassSig even when the clone is a value
    // type, which makes the runtime reject the metadata ("value type mismatch").
    TypeSig ImportSig(TypeSig sig) => FixValueTypes(importer.Import(sig));

    TypeSig FixValueTypes(TypeSig sig)
    {
        switch (sig)
        {
            case GenericInstSig g:
                return new GenericInstSig((ClassOrValueTypeSig)FixValueTypes(g.GenericType),
                    g.GenericArguments.Select(FixValueTypes).ToList());
            case SZArraySig a: return new SZArraySig(FixValueTypes(a.Next));
            case ArraySig a: return new ArraySig(FixValueTypes(a.Next), a.Rank, a.Sizes, a.LowerBounds);
            case ByRefSig b: return new ByRefSig(FixValueTypes(b.Next));
            case PtrSig p: return new PtrSig(FixValueTypes(p.Next));
            case PinnedSig p: return new PinnedSig(FixValueTypes(p.Next));
            case CModReqdSig m: return new CModReqdSig(m.Modifier, FixValueTypes(m.Next));
            case CModOptSig m: return new CModOptSig(m.Modifier, FixValueTypes(m.Next));
            case ClassOrValueTypeSig cv when cv.TypeDefOrRef is { } tr && cloneIsValueType.TryGetValue(tr.FullName, out var vt):
                return vt ? new ValueTypeSig(tr) : new ClassSig(tr);
            default:
                return sig;
        }
    }

    MethodSig ImportMethodSig(MethodSig src)
    {
        var sig = importer.Import(src) as MethodSig ?? throw new ArgumentException("bad method signature");
        sig.RetType = FixValueTypes(sig.RetType);
        for (int i = 0; i < sig.Params.Count; i++) sig.Params[i] = FixValueTypes(sig.Params[i]);
        return sig;
    }

    // clone full name -> is it a value type, decided from the SOURCE base type's name
    // (reliable even when the corlib is referenced through a facade, which defeats
    // IsValueType). Keyed by name so both TypeDef and TypeRef leaves are matched.
    readonly Dictionary<string, bool> cloneIsValueType = [];

    static bool IsStateMachine(TypeDef t) =>
        t.Interfaces.Any(i => i.Interface?.FullName is
            "System.Runtime.CompilerServices.IAsyncStateMachine" or
            "System.Collections.IEnumerator");

    void CloneNestedType(TypeDef src, TypeDef parent) => CloneType(src, c => parent.NestedTypes.Add(c));

    TypeDef CloneType(TypeDef src, Action<TypeDef> attach)
    {
        var clone = new TypeDefUser(src.Namespace, src.Name) { Attributes = src.Attributes };
        attach(clone);
        CopyGenericParams(src.GenericParameters, clone.GenericParameters);
        typeMap[src] = clone;
        MapNewMembers(src, clone);
        foreach (var inner in src.NestedTypes.ToArray()) CloneNestedType(inner, clone);
        return clone;
    }

    // Create placeholder defs for every member of a freshly cloned type, so that
    // references between them resolve through the maps before bodies are imported.
    // Signatures (base type, field/method types) are imported after the whole type
    // graph is mapped, so self-references resolve through the maps.
    readonly List<(TypeDef src, TypeDef clone)> cloned = [];

    void MapNewMembers(TypeDef src, TypeDef clone)
    {
        cloned.Add((src, clone));
        foreach (var f in src.Fields)
        {
            var nf = NewField(f);
            clone.Fields.Add(nf);
            fieldMap[f] = nf;
        }
        foreach (var md in src.Methods)
        {
            var nm = new MethodDefUser(md.Name) { ImplAttributes = md.ImplAttributes, Attributes = md.Attributes };
            clone.Methods.Add(nm);
            CopyGenericParams(md.GenericParameters, nm.GenericParameters);
            methodMap[md] = nm;
        }
    }

    // A generic type or method keeps its parameters (Gen`1 without one, its fields typed !0, would not load); their
    // constraints name types, so they are imported with the signatures, once every clone is mapped.
    readonly List<(GenericParam src, GenericParam dst)> genericParams = [];

    void CopyGenericParams(IList<GenericParam> from, IList<GenericParam> to)
    {
        foreach (var gp in from)
        {
            var ngp = new GenericParamUser(gp.Number, gp.Flags, gp.Name);
            to.Add(ngp);
            genericParams.Add((gp, ngp));
        }
    }

    // Import a base type, but bind System.ValueType/System.Enum to the target's real
    // corlib: the compiled edit references them through a facade (System.Runtime),
    // which dnlib would not recognise as corlib, leaving the clone's IsValueType
    // false and its value-type layout encoded as a reference type.
    ITypeDefOrRef? ImportBaseType(ITypeDefOrRef? bt) => bt?.FullName switch
    {
        null => null,
        "System.ValueType" => target.CorLibTypes.GetTypeRef("System", "ValueType"),
        "System.Enum" => target.CorLibTypes.GetTypeRef("System", "Enum"),
        _ => importer.Import(bt),
    };

    // Fill in the signatures of every cloned type once all placeholders exist.
    void FinishClones()
    {
        foreach (var (src, clone) in cloned)
            cloneIsValueType[clone.FullName] = src.BaseType?.FullName is "System.ValueType" or "System.Enum";

        // Base types first: a struct's value-type-ness is read from its base type,
        // so every clone must know it before any field/signature referencing another
        // clone is imported (otherwise structs encode as classes -> "value type mismatch").
        foreach (var (src, clone) in cloned)
            clone.BaseType = ImportBaseType(src.BaseType);
        foreach (var (src, dst) in genericParams)
            foreach (var c in src.GenericParamConstraints)
                dst.GenericParamConstraints.Add(new GenericParamConstraintUser(FixTypeDefOrRef(importer.Import(c.Constraint))));
        foreach (var (src, clone) in cloned)
        {
            clone.ClassLayout = src.ClassLayout == null ? null
                : new ClassLayoutUser(src.ClassLayout.PackingSize, src.ClassLayout.ClassSize);
            foreach (var i in src.Interfaces)
                clone.Interfaces.Add(new InterfaceImplUser(importer.Import(i.Interface)));
            for (int k = 0; k < src.Fields.Count; k++)
                clone.Fields[k].FieldSig = new FieldSig(ImportSig(src.Fields[k].FieldType));
            RebuildPropsAndEvents(src, clone);
        }

        // New members added directly to the original type.
        foreach (var (src, dst) in newFields)
            dst.FieldSig = new FieldSig(ImportSig(src.FieldType));
        foreach (var (src, dst) in newMethods)
        {
            dst.MethodSig = ImportMethodSig(src.MethodSig);
            dst.Parameters.UpdateParameterTypes();
        }
    }

    CilBody ImportBody(MethodDef src, MethodDef dst)
    {
        FinishSignature(src, dst);
        var body = new CilBody { InitLocals = src.Body.InitLocals, MaxStack = src.Body.MaxStack };

        var localMap = new Dictionary<Local, Local>();
        foreach (var l in src.Body.Variables)
        {
            var nl = new Local(ImportSig(l.Type)) { Name = l.Name };
            body.Variables.Add(nl);
            localMap[l] = nl;
        }

        var map = new Dictionary<Instruction, Instruction>(src.Body.Instructions.Count);
        foreach (var ins in src.Body.Instructions)
        {
            var clone = new Instruction(ins.OpCode) { Offset = ins.Offset };
            map[ins] = clone;
            body.Instructions.Add(clone);
        }

        for (int i = 0; i < src.Body.Instructions.Count; i++)
            body.Instructions[i].Operand = ImportOperand(src.Body.Instructions[i].Operand, dst, src, localMap, map);

        foreach (var eh in src.Body.ExceptionHandlers)
            body.ExceptionHandlers.Add(new ExceptionHandler(eh.HandlerType)
            {
                TryStart = Target(eh.TryStart, map), TryEnd = Target(eh.TryEnd, map),
                HandlerStart = Target(eh.HandlerStart, map), HandlerEnd = Target(eh.HandlerEnd, map),
                FilterStart = Target(eh.FilterStart, map),
                CatchType = eh.CatchType == null ? null : importer.Import(eh.CatchType),
            });

        body.UpdateInstructionOffsets();
        return body;
    }

    // A placeholder method/field clone needs its signature and parameters before a
    // body can reference its own arguments.
    void FinishSignature(MethodDef src, MethodDef dst)
    {
        if (dst.MethodSig != null) return;   // matched original: already complete
        dst.MethodSig = ImportMethodSig(src.MethodSig);
        dst.Parameters.UpdateParameterTypes();
    }

    // Recreate property/event metadata rows on a cloned type, wiring their accessor
    // methods to the already-mapped clones so reflection sees real members.
    void RebuildPropsAndEvents(TypeDef src, TypeDef clone)
    {
        MethodDef? Acc(MethodDef? m) => m != null && methodMap.TryGetValue(m, out var d) ? d : null;

        foreach (var p in src.Properties)
        {
            var psig = importer.Import(p.PropertySig) as PropertySig;
            if (psig != null)
            {
                psig.RetType = FixValueTypes(psig.RetType);
                for (int i = 0; i < psig.Params.Count; i++) psig.Params[i] = FixValueTypes(psig.Params[i]);
            }
            var np = new PropertyDefUser(p.Name, psig) { Attributes = p.Attributes };
            if (Acc(p.GetMethod) is { } g) np.GetMethod = g;
            if (Acc(p.SetMethod) is { } st) np.SetMethod = st;
            clone.Properties.Add(np);
        }
        foreach (var e in src.Events)
        {
            var ne = new EventDefUser(e.Name, e.EventType == null ? null : importer.Import(e.EventType), e.Attributes);
            if (Acc(e.AddMethod) is { } ad) ne.AddMethod = ad;
            if (Acc(e.RemoveMethod) is { } rm) ne.RemoveMethod = rm;
            if (Acc(e.InvokeMethod) is { } inv) ne.InvokeMethod = inv;
            clone.Events.Add(ne);
        }
    }

    static Instruction? Target(Instruction? i, Dictionary<Instruction, Instruction> map) =>
        i != null && map.TryGetValue(i, out var t) ? t : null;

    object? ImportOperand(object? op, MethodDef dst, MethodDef src,
        Dictionary<Local, Local> locals, Dictionary<Instruction, Instruction> map) => op switch
    {
        null => null,
        Instruction i => Target(i, map),
        IList<Instruction> sw => sw.Select(x => Target(x, map)!).ToArray(), // an array, as dnlib's reader makes it and every reader of a switch expects
        Local l => locals[l],
        Parameter p => dst.Parameters[p.Index],
        ITypeDefOrRef t => FixTypeDefOrRef(importer.Import(t)),
        MD.TypeSig ts => FixValueTypes(importer.Import(ts)).ToTypeDefOrRef(),
        IField f => TargetField(f) ?? FixField(importer.Import(f)),
        IMethod im => TargetMethod(im) ?? FixMethod(importer.Import(im)),
        _ => op,   // string / numeric literals copy verbatim
    };

    IField FixField(IField f) => f is MemberRef mr ? FixMember(mr) : f;

    // The same class/valuetype correction, for type references that appear as IL
    // operands: generic instances (TypeSpec), generic method calls (MethodSpec) and
    // members on generic value-type instances (MemberRef with a TypeSpec parent).
    ITypeDefOrRef FixTypeDefOrRef(ITypeDefOrRef t) =>
        t is TypeSpec ts ? new TypeSpecUser(FixValueTypes(ts.TypeSig)) : t;

    MemberRef FixMember(MemberRef mr)
    {
        if (mr.Class is TypeSpec ts) mr.Class = FixTypeDefOrRef(ts);
        return mr;
    }

    IMethod FixMethod(IMethod m)
    {
        if (m is MemberRef mr) return FixMember(mr);
        if (m is MethodSpec ms)
        {
            if (ms.Method is MemberRef inner) ms.Method = FixMember(inner);
            if (ms.GenericInstMethodSig is { } g)
                for (int i = 0; i < g.GenericArguments.Count; i++)
                    g.GenericArguments[i] = FixValueTypes(g.GenericArguments[i]);
        }
        return m;
    }

    // Redirects references to the edited type and its members onto the live target
    // defs, so recompiled IL points at the original members, not duplicates.
    sealed class Mapper(TypeSplicer s) : ImportMapper
    {
        public override ITypeDefOrRef? Map(ITypeDefOrRef source) => source switch
        {
            TypeDef td when s.typeMap.TryGetValue(td, out var t) => t,
            TypeRef tr => s.TargetType(tr),
            _ => null,
        };
        public override IMethod? Map(MethodDef source) =>
            s.methodMap.TryGetValue(source, out var m) ? m : null;
        public override IField? Map(FieldDef source) =>
            s.fieldMap.TryGetValue(source, out var f) ? f : null;
    }
}
