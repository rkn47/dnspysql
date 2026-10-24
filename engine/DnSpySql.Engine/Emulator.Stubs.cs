// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DnSpySql;

// What the interpreter models instead of running: reflection over the sample's own metadata (methods, fields, types,
// resources, assemblies loaded from bytes) and the environment a decryptor may ask about, answered with placeholders.
public sealed partial class Emulator
{
    /// <summary>ldftn/ldvirtftn: the method a delegate will call.</summary>
    sealed record FnPtr(IMethod Method, MethodDef? Def);

    /// <summary>A delegate: invoking it interprets its method (a sample method is never run, only interpreted).</summary>
    sealed record DelegateStub(object? Target, FnPtr Fn);

    /// <summary>The sample's own assembly (GetExecutingAssembly): its manifest resources, read from the file.</summary>
    sealed record AsmStub(LoadedModule M);

    /// <summary>AppDomain.CurrentDomain: subscribing to its resolve events is accepted and ignored.</summary>
    sealed record AppDomainStub;

    // Assemblies the code loads from bytes (Assembly.Load(byte[])): parsed, never run, and kept here by name, so a
    // resource linked to one is found where the CLR's AssemblyResolve would find it.
    readonly Dictionary<string, LoadedModule> _loaded = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Assembly.GetName() of a sample assembly: name, version, culture and public key token from its manifest.</summary>
    static AssemblyName AssemblyNameOf(LoadedModule m)
    {
        if (m.Module.Assembly is not { } asm) return new AssemblyName { Name = m.Module.Name.String };
        try { return new AssemblyName(asm.FullName); }
        catch (Exception e) when (e is ArgumentException or FileLoadException) // a hostile name the parser refuses: the parts it can hold
        { return new AssemblyName { Name = asm.Name.String, Version = asm.Version }; }
    }

    AsmStub LoadAssembly(byte[] bytes)
    {
        if (bytes.Length > 256 << 20) throw new Failed("Assembly.Load of more than 256 MB");
        ModuleDefMD md;
        try { md = ModuleDefMD.Load(bytes, new ModuleCreationOptions { TryToLoadPdbFromDisk = false }); }
        catch (Exception e) when (e is BadImageFormatException or IOException or ArgumentException or InvalidDataException)
        { throw new Failed($"Assembly.Load of bytes that are not a .NET module ({e.GetType().Name})"); }
        var name = md.Assembly?.Name.String ?? md.Name.String;
        if (!_loaded.TryGetValue(name, out var lm))
            _loaded[name] = lm = new LoadedModule { Id = 0, Module = md, Path = $"{name} (loaded by the code)", OriginalBytes = bytes };
        return new AsmStub(lm);
    }

    /// <summary>new Thread(start): started, its code is not run (one thread here; startup threads are usually watchdogs).</summary>
    sealed record ThreadStub(object? Start);

    /// <summary>Process.GetCurrentProcess(), for anti-debug checks: a pseudo handle and an id, nothing else.</summary>
    sealed record ProcessStub;

    /// <summary>typeof(SampleType).Module: its name (as loaded from bytes) and its base address (GetHINSTANCE).</summary>
    sealed record ModuleStub(LoadedModule M);

    /// <summary>typeof(SampleType): its module, assembly and members, for reflection.</summary>
    sealed record TypeStub(TypeDef Type);

    /// <summary>
    /// typeof(T) of a type the interpreter models (primitives, string, allowed framework types, arrays of them; T resolved
    /// in generic code): a wrapper, not a System.Type, answering the few questions generic code asks of a type.
    /// </summary>
    sealed record ClrTypeStub(Type Type, TypeDef? Def = null)
    {
        public bool Equals(ClrTypeStub? o) => o != null && o.Type == Type;
        public override int GetHashCode() => Type.GetHashCode();
    }

    /// <summary>typeof(T) of a framework type outside the allowlist (Environment, say): its name and members, for lookups.</summary>
    sealed record RefTypeStub(TypeDef Def);

    /// <summary>
    /// A method or field reflection found (ldtoken, GetMethod, ResolveMethod, ...): a description, never a MethodInfo.
    /// Invoking the method is a call like any other: a sample method is interpreted, a framework one goes through the
    /// allowlist. Def is set for sample methods only.
    /// </summary>
    sealed record MethodStub(IMethod Method, MethodDef? Def);
    sealed record FieldStub(IField Field, FieldDef? Def);

    /// <summary>A ResourceManager over one of the sample's .resources files.</summary>
    sealed record RmStub(LoadedModule M, string BaseName);

    // ---- reflection over the code's own metadata ------------------------------------------------------------------------

    // typeof(T) as the interpreter models it: a sample type, an allowed framework type (a System.Type the allowlist
    // knows), or another framework type known by name only.
    object? TypeOf(TypeSig sig, IList<TypeSig>? context)
    {
        var tdr = sig.ToTypeDefOrRef();
        TypeDef? def = null;
        try { def = sig is TypeDefOrRefSig ? tdr?.ResolveTypeDef() : null; } catch (Exception) { }
        if (def != null && Sample(def)) return new TypeStub(def);
        if (Clr(sig, context) is { } clr) return new ClrTypeStub(clr, def);
        return def != null ? new RefTypeStub(def) : null;
    }

    MethodStub MethodOf(IMethod m) => new(m, Fn(m, null).Def);

    FieldDef? FieldOf(IField f)
    {
        try { return f.ResolveFieldDef() is { } d && Sample(d.DeclaringType) ? d : null; } catch (Exception) { return null; }
    }

    static TypeDef? DefOfType(object? t) => t switch { TypeStub s => s.Type, RefTypeStub r => r.Def, ClrTypeStub c => c.Def, _ => null };
    static string? NameOfType(object? t) => t switch { TypeStub s => s.Type.ReflectionFullName, RefTypeStub r => r.Def.ReflectionFullName, ClrTypeStub c => c.Type.FullName, _ => null };
    static bool IsTypeStub(object? t) => t is TypeStub or RefTypeStub or ClrTypeStub;

    // BindingFlags as GetMethods/GetFields filter by them: Instance 4, Static 8, Public 16, NonPublic 32, DeclaredOnly 2
    static bool Binds(int flags, bool isStatic, bool isPublic) =>
        (flags & (isStatic ? 8 : 4)) != 0 && (flags & (isPublic ? 16 : 32)) != 0;

    static IEnumerable<TypeDef> Hierarchy(TypeDef? t, bool declaredOnly) => t == null ? [] : declaredOnly ? [t] : Bases(t);

    // A type and its bases, each once (TypeWalk stops on a ring of bases and on an unresolvable one)
    static IEnumerable<TypeDef> Bases(TypeDef? t) => t == null ? [] : TypeWalk.SelfAndBases(t);

    // Members as Type.GetMethods/GetFields see them: the type's own, then the bases' non-private ones (statics of a base
    // only with FlattenHierarchy, 0x40), a method hidden or overridden by a more derived one with the same name and
    // signature not again
    IEnumerable<MethodDef> ReflectedMethods(TypeDef def, int flags)
    {
        var cmp = new SigComparer();
        var seen = new List<MethodDef>();
        bool first = true;
        foreach (var t in Hierarchy(def, (flags & 2) != 0))
        {
            foreach (var m in t.Methods)
            {
                if (m.IsConstructor || !Binds(flags, m.IsStatic, m.IsPublic)) continue;
                if (!first && (m.IsPrivate || m.IsStatic && (flags & 0x40) == 0)) continue;
                if (seen.Any(d => d.Name == m.Name && cmp.Equals(d.MethodSig, m.MethodSig))) continue;
                seen.Add(m);
                yield return m;
            }
            first = false;
        }
    }

    IEnumerable<FieldDef> ReflectedFields(TypeDef def, int flags)
    {
        bool first = true;
        foreach (var t in Hierarchy(def, (flags & 2) != 0))
        {
            foreach (var f in t.Fields)
                if (Binds(flags, f.IsStatic, f.IsPublic) && (first || !f.IsPrivate && (!f.IsStatic || (flags & 0x40) != 0)))
                    yield return f;
            first = false;
        }
    }

    bool Reflected(IMethod target, string full, object? self, object?[] a, Code op, MethodDef caller, out object? result)
    {
        result = null;
        object? Arg(int i) => i < a.Length ? (a[i] is Ref r ? r.Get() : a[i]) : null;
        var name = target.Name.String;
        // the declaring type, from the cached full name ("ret Declaring::Name(...)"): this runs on every framework call
        int colons = full.IndexOf("::", StringComparison.Ordinal), space = colons < 0 ? -1 : full.LastIndexOf(' ', colons);
        if (colons < 0 || !full.AsSpan(space + 1).StartsWith("System.", StringComparison.Ordinal)) return false;
        var declaring = full[(space + 1)..colons];
        switch (declaring)
        {
            case "System.Reflection.MethodBase" or "System.Reflection.MethodInfo" or "System.Reflection.MemberInfo" or "System.Reflection.FieldInfo"
                or "System.Reflection.ConstructorInfo" or "System.Type" or "System.Reflection.TypeInfo" or "System.RuntimeMethodHandle"
                or "System.RuntimeFieldHandle" or "System.RuntimeTypeHandle" or "System.ModuleHandle" or "System.Reflection.Module"
                or "System.Delegate" or "System.Reflection.Assembly" or "System.Activator":
                break;
            default: return false;
        }
        switch (name)
        {
            case "op_Equality" or "op_Inequality" when a.Length == 2 && Arg(0) is null or MethodStub or FieldStub or ModuleStub or AsmStub
                                                                     && Arg(1) is null or MethodStub or FieldStub or ModuleStub or AsmStub:
                result = (Equals(Arg(0), Arg(1)) ^ name == "op_Inequality") ? 1 : 0; return true;
            case "GetMethodFromHandle" when Arg(0) is MethodStub:
            case "GetFieldFromHandle" when Arg(0) is FieldStub:
                result = Arg(0); return true;
            case "get_MethodHandle" or "get_FieldHandle" or "get_TypeHandle" when self is MethodStub or FieldStub or TypeStub or RefTypeStub or ClrTypeStub:
                result = self; return true;
            case "get_ModuleHandle" when self is ModuleStub:
                result = self; return true;
            case "get_ManifestModule" when self is AsmStub am:
                result = new ModuleStub(am.M); return true;
            case "GetModules" or "GetLoadedModules" when self is AsmStub am2:
                result = new object?[] { new ModuleStub(am2.M) }; return true;
            case "get_Assembly" when self is ModuleStub mas:
                result = new AsmStub(mas.M); return true;
            case "GetType" when self is AsmStub at && Arg(1) is string typeName:
                {
                    var found = at.M.Module.Find(typeName, true);
                    if (found == null && Arg(2) is int and not 0) throw new Failed($"Assembly.GetType(\"{typeName}\"): no such type");
                    result = found == null ? null : new TypeStub(found); return true;
                }
            // tokens of the module: ModuleHandle.ResolveMethodHandle, Module.ResolveMethod, ...
            case "ResolveMethodHandle" or "ResolveMethod" or "ResolveFieldHandle" or "ResolveField" or "ResolveTypeHandle" or "ResolveType" or "ResolveMember"
                when self is ModuleStub rm && Arg(1) is int token:
                {
                    object? resolved;
                    try { resolved = rm.M.Module.ResolveToken(token); } catch (Exception) { resolved = null; }
                    result = resolved switch
                    {
                        IMethod rmeth when resolved is MethodDef or MethodSpec or MemberRef { IsMethodRef: true } => MethodOf(rmeth),
                        IField rf => new FieldStub(rf, FieldOf(rf)),
                        ITypeDefOrRef rt => TypeOf(rt.ToTypeSig(), null),
                        _ => null,
                    } ?? throw new Failed($"Module.{name}(0x{token:X8}): no such member");
                    return true;
                }
            case "GetMethod" or "GetField" or "GetProperty" when IsTypeStub(self) && Arg(1) is string member:
                {
                    var def = DefOfType(self) ?? throw new Failed($"Type.{name} on {NameOfType(self)}, whose members are not known");
                    int flags = a.Skip(2).Select(v => v is Ref r ? r.Get() : v).OfType<int>().FirstOrDefault(16 | 8 | 4);
                    var types = a.Skip(2).Select(v => v is Ref r ? r.Get() : v).OfType<Array>().FirstOrDefault()?.Cast<object?>().Select(NameOfType).ToArray();
                    if (name == "GetField")
                    {
                        var fd = ReflectedFields(def, flags).FirstOrDefault(f => f.Name == member);
                        result = fd == null ? null : new FieldStub(fd, FieldOf(fd));
                        return true;
                    }
                    var methodName = name == "GetProperty" ? "get_" + member : member;
                    var candidates = ReflectedMethods(def, flags).Where(m => m.Name == methodName
                        && (types == null || m.MethodSig?.Params.Count == types.Length
                            && m.MethodSig.Params.Select(p => p.ReflectionFullName).SequenceEqual(types))).ToList();
                    if (candidates.Count > 1 && types == null) throw new Failed($"Type.{name}(\"{member}\"): ambiguous match");
                    result = candidates.Count == 0 ? null : MethodOf(candidates[0]);
                    return true;
                }
            case "GetMethods" or "GetFields" when IsTypeStub(self):
                {
                    var def = DefOfType(self) ?? throw new Failed($"Type.{name} on {NameOfType(self)}, whose members are not known");
                    int flags = Arg(1) is int f ? f : 16 | 8 | 4;
                    result = name == "GetMethods"
                        ? ReflectedMethods(def, flags).Select(m => (object?)MethodOf(m)).ToArray()
                        : ReflectedFields(def, flags).Select(fd => (object?)new FieldStub(fd, FieldOf(fd))).ToArray();
                    return true;
                }
            case "get_Name" when self is MethodStub or FieldStub or TypeStub or RefTypeStub:
                result = self switch
                {
                    MethodStub ms => ms.Method.Name.String, FieldStub fs => fs.Field.Name.String,
                    TypeStub ts => ts.Type.Name.String, _ => ((RefTypeStub)self).Def.Name.String,
                };
                return true;
            case "get_FullName" when self is TypeStub or RefTypeStub:
                result = NameOfType(self); return true;
            case "get_MetadataToken" when self is MethodStub or FieldStub or TypeStub:
                result = self switch
                {
                    MethodStub ms => (int)ms.Method.MDToken.Raw, FieldStub fs => (int)fs.Field.MDToken.Raw, _ => (int)((TypeStub)self).Type.MDToken.Raw,
                };
                return true;
            case "get_IsStatic" when self is MethodStub or FieldStub:
                result = (self is MethodStub ms2 ? ms2.Method.MethodSig?.HasThis == false : Resolves((FieldStub)self)?.IsStatic == true) ? 1 : 0;
                return true;
            case "get_FieldType" when self is FieldStub fst && fst.Field.FieldSig?.Type is { } ft:
                result = TypeOf(ft, null); return true;
            case "get_ReturnType" when self is MethodStub mrt && mrt.Method.MethodSig?.RetType is { } rt:
                result = TypeOf(rt, null); return true;
            case "get_DeclaringType" when self is MethodStub or FieldStub:
                result = (self is MethodStub md ? md.Method.DeclaringType : ((FieldStub)self).Field.DeclaringType) is { } dt ? TypeOf(dt.ToTypeSig(), null) : null;
                return true;
            // statics through FieldInfo
            case "GetValue" when self is FieldStub gv:
                if (Resolves(gv) is { IsLiteral: true } constant) { result = Stack(constant.Constant?.Value); return true; }
                if (gv.Def is not { IsStatic: true }) throw new Failed($"FieldInfo.GetValue of {gv.Field.FullName}");
                result = LoadStatic(gv.Def, _depth + 1); return true;
            case "SetValue" when self is FieldStub sv && a.Length == 3:
                if (sv.Def is not { IsStatic: true }) throw new Failed($"FieldInfo.SetValue of {sv.Field.FullName}");
                StoreStatic(sv.Def, Arg(2), _depth + 1); return true;
            // calls through MethodBase.Invoke and Type.InvokeMember: like a direct call
            case "Invoke" when self is MethodStub iv && a.Length == 3:
                result = InvokeStub(iv, Arg(1), Arg(2) as Array, caller); return true;
            case "InvokeMember" when IsTypeStub(self) && Arg(1) is string im && a.Length >= 6:
                {
                    var def = DefOfType(self) ?? throw new Failed($"Type.InvokeMember on {NameOfType(self)}, whose members are not known");
                    // InvokeMethod (0x100) calls the method, GetProperty (0x1000) the getter; fields, setters and
                    // constructors through InvokeMember are not modelled
                    int imFlags = Arg(2) is int imf ? imf : 0;
                    bool invoke = (imFlags & 0x100) != 0, getter = (imFlags & 0x1000) != 0;
                    if (!invoke && !getter || (imFlags & (0x200 | 0x400 | 0x800 | 0x2000)) != 0)
                        throw new Failed($"Type.InvokeMember(\"{im}\") with binding flags 0x{imFlags:X} (only methods and getters are modelled)");
                    var args = Arg(5) as Array;
                    int count = args?.Length ?? 0;
                    var m = ReflectedMethods(def, imFlags | 4 | 8 | 16 | 32)
                                .FirstOrDefault(x => (invoke && x.Name == im || getter && x.Name == "get_" + im) && x.MethodSig?.Params.Count == count)
                            ?? throw new Failed($"Type.InvokeMember(\"{im}\"): {NameOfType(self)} has no method of {count} parameter(s)");
                    result = InvokeStub(MethodOf(m), Arg(4), args, caller); return true;
                }
            case "CreateDelegate" when declaring == "System.Delegate":
                {
                    // CreateDelegate(type, method[, throw]) and CreateDelegate(type, target, method)
                    var ms = a.Select(v => v is Ref r ? r.Get() : v).OfType<MethodStub>().FirstOrDefault()
                             ?? throw new Failed("Delegate.CreateDelegate of something other than a method");
                    var targetObj = a.Length == 3 && Arg(1) is not MethodStub && Arg(2) is MethodStub ? Arg(1) : null;
                    result = new DelegateStub(targetObj, new FnPtr(ms.Method, ms.Def)); return true;
                }
            case "CreateDelegate" when self is MethodStub cd:
                result = new DelegateStub(a.Length == 3 ? Arg(2) : null, new FnPtr(cd.Method, cd.Def)); return true;
            case "CreateInstance" when declaring == "System.Activator" && a.Length == 1 && Arg(0) is TypeStub ct && ct.Type.FindDefaultConstructor() is { } ctor:
                result = CallTarget(ctor, [], Code.Newobj, null, _depth, caller); return true;
        }
        return false;
    }

    // Reflected calls nest without an interpreted frame between them (Invoke of MethodBase.Invoke itself): each one is
    // a frame and a step of its own, so a cycle ends at the depth limit instead of the native stack.
    int _reflectedDepth;

    object? InvokeStub(MethodStub m, object? instance, Array? args, MethodDef caller)
    {
        if (++_steps > _limit) throw new Failed($"stopped after {_limit:N0} IL instructions");
        var list = args?.Cast<object?>().Select(Stack).ToArray() ?? [];
        var sig = m.Method.MethodSig ?? throw new Failed($"MethodBase.Invoke of {m.Method.Name}, whose signature does not parse");
        if (list.Length != sig.Params.Count)
            throw new Failed($"MethodBase.Invoke of {m.Method.Name} with {list.Length} argument(s) for {sig.Params.Count} parameter(s)");
        if (sig.HasThis && instance == null) throw new Failed($"MethodBase.Invoke of instance method {m.Method.Name} on null");
        if (++_reflectedDepth > MaxDepth) { _reflectedDepth--; throw new Failed("reflected calls nested too deep"); }
        try { return CallTarget(m.Method, sig.HasThis ? [instance, .. list] : list, sig.HasThis ? Code.Callvirt : Code.Call, null, _depth + 1, caller); }
        finally { _reflectedDepth--; }
    }

    // What a decryptor may ask of the code around it, answered from the file: its own assembly and resources, types and
    // modules, assemblies it loads from bytes. What it asks of the machine is in Emulator.Environment.cs.
    bool Stubbed(IMethod target, object?[] a, Code op, MethodDef caller, out object? result)
    {
        result = null;
        var full = NameOf(target);
        var self = a.Length > 0 && target.MethodSig?.HasThis == true && op != Code.Newobj ? (a[0] is Ref r ? r.Get() : a[0]) : null;
        string? Arg(int i) => i < a.Length ? (a[i] is Ref rr ? rr.Get() : a[i]) as string : null;
        var module = ModuleOf(caller.Module) ?? throw new Failed("caller outside the loaded modules");
        if (Reflected(target, full, self, a, op, caller, out result)) return true;
        if (AnsweredManaged(full, caller, self, a, out result)) return true;
        switch (full)
        {
            case "System.Reflection.Assembly System.Reflection.Assembly::GetExecutingAssembly()":
            case "System.Reflection.Assembly System.Reflection.Assembly::GetCallingAssembly()":
            case "System.Reflection.Assembly System.Reflection.Assembly::GetEntryAssembly()":
                result = new AsmStub(module); return true;
            case "System.Void System.Resources.ResourceManager::.ctor(System.String,System.Reflection.Assembly)" when a[1] is AsmStub asm:
                result = new RmStub(asm.M, Arg(0) ?? throw new Failed("ResourceManager without a name")); return true;
            case "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)" when a[0] is TypeStub or ClrTypeStub or RefTypeStub:
                result = a[0]; return true;
            case "System.Type System.Type::GetElementType()" when self is ClrTypeStub ct:
                result = ct.Type.GetElementType() is { } et ? new ClrTypeStub(et) : null; return true;
            case "System.Boolean System.Type::get_IsArray()" when self is ClrTypeStub ct:
                result = ct.Type.IsArray ? 1 : 0; return true;
            case "System.Boolean System.Type::get_IsValueType()" when self is ClrTypeStub ct:
                result = ct.Type.IsValueType ? 1 : 0; return true;
            case "System.Boolean System.Type::get_IsPrimitive()" when self is ClrTypeStub ct:
                result = ct.Type.IsPrimitive ? 1 : 0; return true;
            case "System.TypeCode System.Type::GetTypeCode(System.Type)" when a[0] is ClrTypeStub ct:
                result = (int)Type.GetTypeCode(ct.Type); return true;
            case "System.Boolean System.Type::op_Equality(System.Type,System.Type)":
            case "System.Boolean System.Type::op_Inequality(System.Type,System.Type)":
                if (a[0] is not (null or TypeStub or ClrTypeStub or RefTypeStub) || a[1] is not (null or TypeStub or ClrTypeStub or RefTypeStub)) return false;
                result = (Equals(a[0], a[1]) ^ target.Name == "op_Inequality") ? 1 : 0; return true;
            case "System.Array System.Array::CreateInstance(System.Type,System.Int32)" when a[0] is ClrTypeStub or TypeStub:
                {
                    var length = Convert.ToInt64(a[1]);
                    if (length < 0 || length > MaxArray) throw new Failed($"Array.CreateInstance of {length:N0} elements");
                    result = Array.CreateInstance(a[0] is ClrTypeStub ce ? ce.Type : ElementClr(((TypeStub)a[0]!).Type), (int)length);
                    return true;
                }
            case "System.Reflection.Module System.Type::get_Module()" when self is TypeStub tm:
                result = new ModuleStub(ModuleOf(tm.Type.Module)!); return true;
            case "System.String System.Reflection.Module::get_FullyQualifiedName()" when self is ModuleStub:
                result = "<Unknown>"; return true; // loaded from bytes: the image is in the file layout
            case "System.String System.Reflection.Module::get_ScopeName()" when self is ModuleStub ms:
                result = ms.M.Module.Name.String; return true;
            case "System.IntPtr System.Runtime.InteropServices.Marshal::GetHINSTANCE(System.Reflection.Module)" when a[0] is ModuleStub hm:
                ImageOf(hm.M);
                result = ImageBase; return true;
            case "System.Reflection.Assembly System.Type::get_Assembly()" when self is TypeStub ts2:
                result = new AsmStub(ModuleOf(ts2.Type.Module)!); return true;
            case "System.Boolean System.Reflection.Assembly::op_Equality(System.Reflection.Assembly,System.Reflection.Assembly)":
            case "System.Boolean System.Reflection.Assembly::op_Inequality(System.Reflection.Assembly,System.Reflection.Assembly)":
                result = (Equals(a[0], a[1]) ^ target.Name == "op_Inequality") ? 1 : 0; return true;
            case "System.Reflection.Assembly System.Reflection.Assembly::Load(System.Byte[])" when a[0] is byte[] asmBytes:
                result = LoadAssembly(asmBytes); return true;
            case "System.Object System.Runtime.CompilerServices.RuntimeHelpers::GetObjectValue(System.Object)":
                result = Copy(a[0] is Ref gr ? gr.Get() : a[0]); return true;
        }
        // pointers are numbers here: IntPtr/UIntPtr conversions keep the value
        if (target.DeclaringType?.FullName is "System.IntPtr" or "System.UIntPtr"
            && target.Name.String is "op_Explicit" or "op_Implicit" or "ToPointer" or "ToInt64" or "ToInt32" or "ToUInt64" or "ToUInt32" or ".ctor")
        {
            var v = (a.Length > 0 ? (op == Code.Newobj ? a[0] : a[^1]) : null) is var x && x is Ref xr ? xr.Get() : x;
            if (op == Code.Newobj && a.Length == 1) { result = v; return true; }
            result = target.Name.String is "ToInt32" or "ToUInt32" ? (object)(int)AsLong(v) : AsLong(v);
            return true;
        }
        if (target.FullName == "System.Int32 System.IntPtr::get_Size()") { result = 8; return true; }
        if (self is AsmStub sa)
        {
            var resources = sa.M.Module.Resources;
            switch (target.Name.String)
            {
                case "GetManifestResourceStream" when Arg(1) is { } rn:
                    // the CLR returns null and the code then fails on it; the reason names the resource instead
                    var res = resources.FirstOrDefault(x => x.Name == rn);
                    // linked to another assembly: the one the code loaded under that name
                    if (res is AssemblyLinkedResource linked && _loaded.TryGetValue(linked.Assembly.Name.String, out var holder))
                        res = holder.Module.Resources.FirstOrDefault(x => x.Name == rn);
                    // a name the module does not have gives null, as in the CLR: code that probes for an optional resource goes on
                    result = res switch
                    {
                        EmbeddedResource er => new MemoryStream(er.CreateReader().ToArray(), false),
                        AssemblyLinkedResource al => throw new Failed(
                            $"GetManifestResourceStream(\"{rn}\"): linked to assembly {al.Assembly.Name}, which the code has not loaded"),
                        _ => null,
                    };
                    return true;
                case "GetManifestResourceNames":
                    result = resources.Select(x => x.Name.String).ToArray(); return true;
                case "Equals":
                    result = Equals(sa, a[1] is Ref ar ? ar.Get() : a[1]) ? 1 : 0; return true;
                // its identity, from the manifest: a key or a salt derived from the assembly's own name or version
                case "GetName" when a.Length == 1:
                    result = AssemblyNameOf(sa.M); return true;
                case "get_FullName":
                    result = AssemblyNameOf(sa.M).FullName; return true;
                default: throw new Failed($"Assembly.{target.Name} on the sample's assembly");
            }
        }
        if (self is RmStub rm)
        {
            if (target.Name.String is not ("GetString" or "GetObject" or "GetStream")) throw new Failed($"ResourceManager.{target.Name}");
            var res = rm.M.Module.Resources.FirstOrDefault(x => x.Name == rm.BaseName + ".resources")
                      ?? throw new Failed($"no resource {rm.BaseName}.resources");
            var set = DnSpySql.Tables.ResourceTables.ReadSet(rm.M, res) ?? throw new Failed($"{res.Name} does not parse");
            var e = set.ResourceElements.FirstOrDefault(x => x.Name == Arg(1));
            result = e == null ? null : DnSpySql.Tables.ResourceTables.ElementValue(e) is var v && target.Name == "GetStream" && v is byte[] b ? new MemoryStream(b, false) : Stack(v);
            return true;
        }
        return false;
    }
}
