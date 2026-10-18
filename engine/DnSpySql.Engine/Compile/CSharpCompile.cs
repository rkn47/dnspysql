// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Reflection;
using System.Text;
using DnSpySql.Sql;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace DnSpySql.Compile;

/// <summary>
/// Compiles C# against a module (with accessibility checks disabled, like dnSpy's edit-code compiler) and merges the
/// result back into the dnlib model.
/// </summary>
public sealed class CSharpCompile
{
    readonly Session _s;
    readonly LoadedModule _lm;

    public CSharpCompile(Session s, LoadedModule lm) { _s = s; _lm = lm; }

    // ---------------------------------------------------------------- compilation
    public ModuleDefMD Compile(string source)
    {
        var tree = CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.Latest));
        var opts = new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary,
                allowUnsafe: true, optimizationLevel: OptimizationLevel.Release, metadataImportOptions: MetadataImportOptions.All,
                nullableContextOptions: NullableContextOptions.Disable)
            .WithSpecificDiagnosticOptions(new Dictionary<string, ReportDiagnostic>
            {
                ["CS0436"] = ReportDiagnostic.Suppress, ["CS0626"] = ReportDiagnostic.Suppress, ["CS0824"] = ReportDiagnostic.Suppress,
                ["CS0169"] = ReportDiagnostic.Suppress, ["CS0649"] = ReportDiagnostic.Suppress, ["CS0414"] = ReportDiagnostic.Suppress,
            });
        opts = IgnoreAccessibility(opts);
        var comp = CSharpCompilation.Create("dnspysql_" + Guid.NewGuid().ToString("N"), new[] { tree }, References(), opts);
        using var ms = new MemoryStream();
        var result = comp.Emit(ms);
        if (!result.Success)
        {
            var errors = result.Diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error).Take(12)
                .Select(d => $"{d.Id} ({d.Location.GetLineSpan().StartLinePosition.Line + 1},{d.Location.GetLineSpan().StartLinePosition.Character + 1}): {d.GetMessage()}");
            throw new SqlException("C# compilation failed:\n" + string.Join("\n", errors) + "\n--- generated source ---\n" + Numbered(source));
        }
        return ModuleDefMD.Load(ms.ToArray(), new ModuleCreationOptions(_s.Ws.Context));
    }

    static string Numbered(string src) => string.Join("\n", src.Split('\n').Select((l, i) => $"{i + 1,4}: {l.TrimEnd('\r')}"));

    static CSharpCompilationOptions IgnoreAccessibility(CSharpCompilationOptions o)
    {
        // Roslyn's internal BinderFlags.IgnoreAccessibility (used by debugger expression compilers and dnSpy).
        var asm = typeof(CSharpCompilationOptions).Assembly;
        var flagsType = asm.GetType("Microsoft.CodeAnalysis.CSharp.BinderFlags");
        var with = typeof(CSharpCompilationOptions).GetMethod("WithTopLevelBinderFlags", BindingFlags.NonPublic | BindingFlags.Instance);
        if (flagsType == null || with == null) return o;
        var flag = Enum.Parse(flagsType, "IgnoreAccessibility");
        return (CSharpCompilationOptions)with.Invoke(o, new[] { flag })!;
    }

    IEnumerable<MetadataReference> References()
    {
        var refs = new List<MetadataReference>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var targetName = _lm.Module.Assembly?.Name.String ?? _lm.Module.Name.String;
        seen.Add(targetName);
        refs.Add(MetadataReference.CreateFromImage(_lm.Dirty ? _s.Ws.Serialize(_lm) : _lm.OriginalBytes));
        foreach (var other in _s.Ws.Modules.Where(m => m != _lm && m.Module.Assembly != null))
            if (seen.Add(other.Module.Assembly!.Name.String))
                refs.Add(MetadataReference.CreateFromImage(other.Dirty ? _s.Ws.Serialize(other) : other.OriginalBytes));

        // The framework comes first, as one consistent set, so the target's own references cannot pull in a mix of
        // facades from elsewhere.
        if (RefPaths.UsesNetFramework(_lm.Module))
        {
            // .NET Framework target: the whole Framework reference set (never the running .NET's corlib).
            var fx = _s.Ws.FrameworkPaths.FirstOrDefault(d => File.Exists(Path.Combine(d, "mscorlib.dll")));
            if (fx == null && !_s.Ws.Modules.Any(m => m.Module.Assembly?.Name == "mscorlib"))
                throw new SqlException(
                    "cannot compile for a .NET Framework target: mscorlib reference assemblies were not found. " +
                    "Point reference_paths at a Framework folder (e.g. the Microsoft.NETFramework.ReferenceAssemblies.net48 package's " +
                    "build/.NETFramework/v4.8, or a Windows Framework64\\v4.0.30319 copy), or restore that package so it is auto-detected");
            if (fx != null) AddDir(fx, refs, seen);
            if (fx != null && Directory.Exists(Path.Combine(fx, "Facades"))) AddDir(Path.Combine(fx, "Facades"), refs, seen);
        }
        else
        {
            // .NET (Core) / .NET Standard target: the SDK's reference pack for its framework version when one is
            // installed, so the output references System.Runtime like a normal build; else the running shared
            // framework (System.Private.CoreLib). Either way every BCL API is available, as dnSpy does.
            AddDir(TypeSplice.RefPack(_lm) ?? RefPaths.NetCoreRuntime, refs, seen);
        }

        // The rest of what the target references, resolved like the decompiler does (not every DLL in its folder).
        var queue = new Queue<(ModuleDef mod, int depth)>();
        queue.Enqueue((_lm.Module, 0));
        while (queue.Count > 0)
        {
            var (mod, depth) = queue.Dequeue();
            foreach (var ar in mod.GetAssemblyRefs())
            {
                if (!seen.Add(ar.Name.String)) continue;
                AssemblyDef? asm = null;
                try { asm = _s.Ws.Resolver.Resolve(ar, mod); } catch { }
                var loc = asm?.ManifestModule?.Location;
                if (string.IsNullOrEmpty(loc) || !File.Exists(loc)) continue;
                refs.Add(MetadataReference.CreateFromFile(loc));
                if (depth < 3) queue.Enqueue((asm!.ManifestModule, depth + 1));
            }
        }
        foreach (var d in _s.Ws.UserReferencePaths) AddDir(d, refs, seen);
        return refs;
    }

    static void AddDir(string dir, List<MetadataReference> refs, HashSet<string> seen)
    {
        if (!Directory.Exists(dir)) return;
        foreach (var f in Directory.GetFiles(dir, "*.dll"))
        {
            var n = Path.GetFileNameWithoutExtension(f);
            if (seen.Contains(n) || !IsManaged(f)) continue;
            seen.Add(n);
            refs.Add(MetadataReference.CreateFromFile(f));
        }
    }

    static bool IsManaged(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            using var pe = new System.Reflection.PortableExecutable.PEReader(fs);
            return pe.HasMetadata && System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe).IsAssembly;
        }
        catch { return false; }
    }

    // ---------------------------------------------------------------- skeleton source
    /// <summary>Source of the type's outer nesting + a skeleton of its members, with `inner` inserted into the innermost type.</summary>
    public string Skeleton(TypeDef type, string inner, Func<IMemberDef, bool> skip)
    {
        var chain = new List<TypeDef>();
        for (var t = type; t != null; t = t.DeclaringType) chain.Insert(0, t);
        foreach (var t in chain)
            if (t.IsGlobalModuleType || !ValidId(StripArity(t.Name)))
                throw new SqlException($"cannot compile C# into {t.FullName}: the type name is not expressible in C# " +
                    "(global <Module> functions of C++/CLI images, compiler-generated or obfuscated names). Edit its IL with the il table / il_* functions instead");
        var sb = new StringBuilder();
        sb.AppendLine("#pragma warning disable");
        var ns = chain[0].Namespace.String;
        if (ns.Length > 0) sb.Append("namespace ").Append(string.Join(".", ns.Split('.').Select(Id))).AppendLine(" {");
        for (int i = 0; i < chain.Count; i++)
        {
            var t = chain[i];
            sb.Append(TypeHeader(t)).AppendLine(" {");
            if (i == chain.Count - 1)
            {
                foreach (var line in Members(t, skip)) sb.Append("    ").AppendLine(line);
                sb.AppendLine(inner);
            }
        }
        for (int i = 0; i < chain.Count; i++) sb.AppendLine("}");
        if (ns.Length > 0) sb.AppendLine("}");
        return sb.ToString();
    }

    string TypeHeader(TypeDef t)
    {
        var name = Id(StripArity(t.Name));
        var gps = t.GenericParameters.Where(g => t.DeclaringType == null || g.Number >= t.DeclaringType.GenericParameters.Count).ToList();
        var gen = gps.Count > 0 ? "<" + string.Join(", ", gps.Select(g => Id(g.Name))) + ">" : "";
        var mods = "public " + (t.IsAbstract && t.IsSealed ? "static " : t.IsAbstract && !t.IsInterface ? "abstract " : "") + "unsafe partial ";
        if (t.IsInterface) return mods + "interface " + name + gen;
        if (t.IsValueType) return mods + "struct " + name + gen;
        var bt = t.BaseType != null && t.BaseType.FullName != "System.Object" && !(t.IsAbstract && t.IsSealed) ? " : " + Cs(t.BaseType.ToTypeSig()) : "";
        return mods + "class " + name + gen + bt;
    }

    IEnumerable<string> Members(TypeDef t, Func<IMemberDef, bool> skip)
    {
        bool isStatic = t.IsAbstract && t.IsSealed;
        foreach (var f in t.Fields)
        {
            if (skip(f) || !ValidId(f.Name) || f.IsSpecialName) continue;
            if (t.Events.Any(e => e.Name == f.Name) || t.Properties.Any(p => p.Name == f.Name)) continue; // event/property backing field
            if (f.IsLiteral && f.Constant != null && Literal(f.Constant.Value) is string lit)
                yield return $"internal const {Cs(f.FieldType)} {Id(f.Name)} = {lit};";
            else if (!t.IsInterface)
                yield return $"internal {(f.IsStatic ? "static " : "")}{Cs(f.FieldType)} {Id(f.Name)};";
        }
        foreach (var p in t.Properties)
        {
            if (skip(p) || p.PropertySig == null) continue;
            var acc = p.GetMethod ?? p.SetMethod;
            if (acc == null) continue;
            var st = acc.IsStatic ? "static " : "";
            var accessors = (p.GetMethod != null ? "get; " : "") + (p.SetMethod != null ? "set; " : "");
            if (p.PropertySig.Params.Count > 0)
            {
                if (p.Name != "Item") continue;
                var ps = string.Join(", ", p.PropertySig.Params.Select((x, i) => $"{Cs(x)} p{i}"));
                yield return t.IsInterface ? $"{Cs(p.PropertySig.RetType)} this[{ps}] {{ {accessors}}}" : $"internal extern {Cs(p.PropertySig.RetType)} this[{ps}] {{ {accessors}}}";
            }
            else if (ValidId(p.Name))
                yield return t.IsInterface ? $"{st}{Cs(p.PropertySig.RetType)} {Id(p.Name)} {{ {accessors}}}" : $"internal {st}extern {Cs(p.PropertySig.RetType)} {Id(p.Name)} {{ {accessors}}}";
        }
        foreach (var e in t.Events)
        {
            if (skip(e) || !ValidId(e.Name) || e.EventType == null) continue;
            var st = e.AddMethod?.IsStatic == true ? "static " : "";
            yield return $"internal {st}event {Cs(e.EventType.ToTypeSig())} {Id(e.Name)};";
        }
        foreach (var m in t.Methods)
        {
            if (skip(m) || m.SemanticsAttributes != 0 || m.IsStaticConstructor) continue;
            if (!m.IsConstructor && !ValidId(m.Name)) continue;
            var ps = string.Join(", ", m.Parameters.Where(p => p.IsNormalMethodParameter).Select(p => $"{ParamMod(p)}{Cs(p.Type is ByRefSig br ? br.Next : p.Type)} {Id(string.IsNullOrEmpty(p.Name) ? "a" + p.Index : p.Name)}"));
            if (m.IsInstanceConstructor)
            {
                if (isStatic || t.IsInterface) continue;
                yield return $"internal extern {Id(StripArity(t.Name))}({ps});";
                continue;
            }
            var gen = m.HasGenericParameters ? "<" + string.Join(", ", m.GenericParameters.Select(g => Id(g.Name))) + ">" : "";
            var name = m.Name.String.StartsWith("op_") ? m.Name.String : Id(m.Name);
            if (t.IsInterface) yield return $"{(m.IsStatic ? "static " : "")}{Cs(m.ReturnType)} {name}{gen}({ps});";
            else yield return $"internal {(m.IsStatic ? "static " : "")}{(m.IsVirtual && !m.IsFinal && !t.IsSealed && !t.IsValueType ? "virtual " : "")}extern {Cs(m.ReturnType)} {name}{gen}({ps});";
        }
    }

    static string ParamMod(Parameter p) => p.Type is ByRefSig ? (p.ParamDef?.IsOut == true && p.ParamDef?.IsIn != true ? "out " : p.ParamDef?.IsIn == true ? "in " : "ref ") : "";

    static string? Literal(object? v) => v switch
    {
        null => "null",
        string str => "@\"" + str.Replace("\"", "\"\"") + "\"",
        bool b => b ? "true" : "false",
        char c => $"(char){(int)c}",
        float f => float.IsFinite(f) ? f.ToString("R", System.Globalization.CultureInfo.InvariantCulture) + "f" : null,
        double d => double.IsFinite(d) ? d.ToString("R", System.Globalization.CultureInfo.InvariantCulture) + "d" : null,
        long l => l == long.MinValue ? "long.MinValue" : l + "L",
        ulong ul => ul + "UL",
        uint ui => ui + "U",
        int i => i == int.MinValue ? "int.MinValue" : i.ToString(),
        sbyte or byte or short or ushort => Convert.ToInt64(v).ToString(),
        _ => null,
    };

    public static string StripArity(string name) => name.IndexOf('`') is var i && i > 0 ? name[..i] : name;

    static readonly HashSet<string> Keywords = new(StringComparer.Ordinal)
    {
        "abstract","as","base","bool","break","byte","case","catch","char","checked","class","const","continue","decimal","default","delegate","do","double",
        "else","enum","event","explicit","extern","false","finally","fixed","float","for","foreach","goto","if","implicit","in","int","interface","internal",
        "is","lock","long","namespace","new","null","object","operator","out","override","params","private","protected","public","readonly","ref","return",
        "sbyte","sealed","short","sizeof","stackalloc","static","string","struct","switch","this","throw","true","try","typeof","uint","ulong","unchecked",
        "unsafe","ushort","using","virtual","void","volatile","while",
    };

    public static bool ValidId(string n) => n.Length > 0 && (char.IsLetter(n[0]) || n[0] == '_') && n.All(c => char.IsLetterOrDigit(c) || c == '_');
    public static string Id(string n) => Keywords.Contains(n) ? "@" + n : n;

    /// <summary>C# syntax for a type signature (global:: qualified).</summary>
    public static string Cs(TypeSig? sig)
    {
        if (sig == null) return "object";
        switch (sig.ElementType)
        {
            case ElementType.Void: return "void";
            case ElementType.Boolean: return "bool";
            case ElementType.Char: return "char";
            case ElementType.I1: return "sbyte";
            case ElementType.U1: return "byte";
            case ElementType.I2: return "short";
            case ElementType.U2: return "ushort";
            case ElementType.I4: return "int";
            case ElementType.U4: return "uint";
            case ElementType.I8: return "long";
            case ElementType.U8: return "ulong";
            case ElementType.R4: return "float";
            case ElementType.R8: return "double";
            case ElementType.String: return "string";
            case ElementType.Object: return "object";
            case ElementType.I: return "nint";
            case ElementType.U: return "nuint";
            case ElementType.Ptr: return Cs(sig.Next) + "*";
            case ElementType.ByRef: return Cs(sig.Next);
            case ElementType.SZArray: return Cs(sig.Next) + "[]";
            case ElementType.Array: return Cs(sig.Next) + "[" + new string(',', (int)((ArraySig)sig).Rank - 1) + "]";
            case ElementType.Var: case ElementType.MVar: return Id(((GenericSig)sig).GenericParam?.Name ?? $"T{((GenericSig)sig).Number}");
            case ElementType.CModReqd: case ElementType.CModOpt: case ElementType.Pinned: return Cs(sig.Next);
            case ElementType.GenericInst:
                {
                    var gi = (GenericInstSig)sig;
                    return TypeName(gi.GenericType.TypeDefOrRef, gi.GenericArguments.Select(Cs).ToList());
                }
            case ElementType.FnPtr: return "nint";
            default:
                return sig is TypeDefOrRefSig tdr ? TypeName(tdr.TypeDefOrRef, new List<string>()) : "object";
        }
    }

    static string TypeName(ITypeDefOrRef t, List<string> args)
    {
        // Distribute generic args over the nesting chain (Outer`1+Inner`1).
        var chain = new List<ITypeDefOrRef>();
        for (ITypeDefOrRef? cur = t; cur != null; cur = cur.DeclaringType) chain.Insert(0, cur);
        var sb = new StringBuilder("global::");
        string ns0 = chain[0].Namespace;
        if (ns0.Length > 0) sb.Append(string.Join(".", ns0.Split('.').Select(Id))).Append('.');
        int used = 0;
        for (int i = 0; i < chain.Count; i++)
        {
            if (i > 0) sb.Append('.');
            string n = chain[i].Name;
            sb.Append(Id(StripArity(n)));
            var tick = n.IndexOf('`');
            if (tick > 0 && int.TryParse(n[(tick + 1)..], out var arity) && arity > 0 && used + arity <= args.Count)
            {
                sb.Append('<').Append(string.Join(", ", args.Skip(used).Take(arity))).Append('>');
                used += arity;
            }
        }
        return sb.ToString();
    }
}
