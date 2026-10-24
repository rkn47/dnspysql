// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace DnSpySql;

// Calls into the framework: the allowlist of types that compute on data in memory, the bounds put on them before they
// run, and the delegates that let the framework call back into interpreted code.
public sealed partial class Emulator
{
    // ---- framework calls (allowlist) -----------------------------------------------------------------------------------

#pragma warning disable SYSLIB0021, SYSLIB0022, SYSLIB0023, SYSLIB0041, SYSLIB0045
    // Types whose members compute on data in memory. The emulated code can only obtain instances of these, so none of
    // their members can reach a file, the network, a process or reflection either (no FileStream or Type ever exists).
    static readonly Dictionary<string, Type> Allowed = new Type[]
    {
        typeof(object), typeof(string), typeof(char), typeof(bool), typeof(byte), typeof(sbyte), typeof(short), typeof(ushort), typeof(int),
        typeof(uint), typeof(long), typeof(ulong), typeof(float), typeof(double), typeof(decimal), typeof(IntPtr), typeof(UIntPtr),
        typeof(StringBuilder), typeof(Encoding), typeof(UTF8Encoding), typeof(ASCIIEncoding), typeof(UnicodeEncoding), typeof(UTF32Encoding),
        typeof(Convert), typeof(Math), typeof(BitConverter), typeof(Array), typeof(Buffer), typeof(Enumerable), typeof(StringComparison),
        typeof(IEnumerable<>), typeof(List<>), typeof(Dictionary<,>), typeof(System.Collections.IEnumerable), typeof(System.Collections.Hashtable),
        typeof(System.Collections.ArrayList), typeof(System.Collections.Generic.IEnumerator<>), typeof(System.Collections.IEnumerator),
        typeof(System.IO.Stream), typeof(System.IO.MemoryStream), typeof(System.IO.BinaryReader), typeof(System.IO.Compression.GZipStream),
        typeof(System.IO.Compression.DeflateStream), typeof(System.IO.Compression.CompressionMode), typeof(System.IO.SeekOrigin),
        typeof(CryptoStream), typeof(CryptoStreamMode), typeof(ICryptoTransform), typeof(HashAlgorithm), typeof(MD5), typeof(MD5CryptoServiceProvider),
        typeof(SHA1), typeof(SHA1Managed), typeof(SHA1CryptoServiceProvider), typeof(SHA256), typeof(SHA256Managed), typeof(SHA256CryptoServiceProvider),
        typeof(SHA384), typeof(SHA512), typeof(SHA512Managed), typeof(KeyedHashAlgorithm), typeof(HMAC), typeof(HMACMD5), typeof(HMACSHA1),
        typeof(HMACSHA256), typeof(SymmetricAlgorithm), typeof(Aes), typeof(AesManaged), typeof(AesCryptoServiceProvider), typeof(Rijndael),
        typeof(RijndaelManaged), typeof(TripleDES), typeof(TripleDESCryptoServiceProvider), typeof(DES), typeof(DESCryptoServiceProvider),
        typeof(RC2), typeof(RC2CryptoServiceProvider), typeof(DeriveBytes), typeof(Rfc2898DeriveBytes), typeof(PasswordDeriveBytes),
        typeof(CipherMode), typeof(PaddingMode), typeof(HashAlgorithmName), typeof(System.Globalization.CultureInfo),
        typeof(System.Runtime.InteropServices.OSPlatform), typeof(System.Runtime.InteropServices.RuntimeInformation),
        typeof(Func<>), typeof(Func<,>), typeof(Func<,,>), typeof(Func<,,,>), typeof(Action<>), typeof(Action<,>), typeof(Predicate<>),
        typeof(Microsoft.VisualBasic.CompilerServices.Conversions), typeof(Microsoft.VisualBasic.CompilerServices.Operators),
        typeof(Microsoft.VisualBasic.Strings), typeof(Microsoft.VisualBasic.CompilerServices.StringType), typeof(IDisposable),
        typeof(AssemblyName), typeof(Version), // identities as data (Assembly.GetName() of the sample hands one out)
    }.ToDictionary(t => t.FullName!.Split('`')[0] + (t.IsGenericTypeDefinition ? "`" + t.GetGenericArguments().Length : ""), t => t);
#pragma warning restore SYSLIB0021, SYSLIB0022, SYSLIB0023, SYSLIB0041, SYSLIB0045

    // Types allowed only for the members named: System.IO.Path's string helpers, not GetTempFileName (which creates a
    // file) or GetFullPath (which reads the current directory).
    static readonly Dictionary<string, (Type Type, HashSet<string> Members)> Partly = new()
    {
        ["System.IO.Path"] = (typeof(Path), ["Combine", "GetFileName", "GetFileNameWithoutExtension", "GetExtension", "ChangeExtension",
                                            "GetDirectoryName", "HasExtension", "IsPathRooted", "GetInvalidFileNameChars", "GetInvalidPathChars"]),
    };

    // Members of allowed types that hand out something outside the allowlist or touch the environment.
    // (AssemblyName.GetAssemblyName(path) reads a file)
    static readonly string[] Blocked = ["GetType", "CreateInstance", "ChangeType", "CreateFromName", "Create(System.String)", "set_CurrentCulture",
                                        "GetAssemblyName"];

    object? Framework(IMethod target, object?[] a, Code op, List<TypeSig>? generic, IList<TypeSig>? context, MethodDef caller)
    {
        if (Stubbed(target, a, op, caller, out var stubbed)) return stubbed;
        var full = NameOf(target);
        // a member bound before, with no generic context in its signature: same type, same member
        var cacheable = generic == null && !full.Contains('!');
        var bound = cacheable && _bound.TryGetValue(target, out var hit) ? hit : null;
        var declaring = target.DeclaringType;
        var name = target.Name.String;
        if (Nondeterministic(full)) throw new Failed($"call into {full}: random or time-dependent, the result differs on every run");
        var type = bound?.Type ?? Clr(declaring?.ToTypeSig(), context)
                   ?? (declaring != null && Partly.TryGetValue(declaring.FullName, out var partly) && partly.Members.Contains(name) ? partly.Type : null)
                   ?? throw new Failed($"call into {full} (not on the allowlist)");
        if (bound == null && Blocked.Any(b => name == b || full.Contains("::" + b, StringComparison.Ordinal)))
            throw new Failed($"call into {full} (blocked)");
        var sig = target.MethodSig!;
        var ps = bound?.Ps ?? sig.Params.Select(p => Clr(p, context, generic) ?? throw new Failed($"parameter type {p.FullName} of {full}")).ToArray();
        object? self = null;
        object?[] args;
        if (op == Code.Newobj || !sig.HasThis) args = a;
        else
        {
            self = a[0] is Ref r ? r.Get() : a[0];
            if (self == null) throw new Failed($"{full} on null");
            if (self is Obj) throw new Failed($"{full} on a sample object");
            if (type.IsValueType) self = ToClr(self, type); // char.ToString(): the stack holds the char as an int
            args = a[1..];
        }
        // byref parameters (Array.Resize<T>(ref T[], int)) are passed as their value and written back after
        var refs = new Ref?[args.Length];
        var call = new object?[args.Length];
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] is Ref rf && ps[i].IsByRef) { refs[i] = rf; call[i] = ToClr(rf.Get(), ps[i].GetElementType()!); }
            else if (args[i] is DelegateStub ds && typeof(Delegate).IsAssignableFrom(ps[i])) call[i] = MakeDelegate(ds, ps[i]);
            else call[i] = ToClr(args[i] is Ref r2 ? r2.Get() : args[i], ps[i]);
        }
        object? result;
        try
        {
            if (op == Code.Newobj)
            {
                var ctor = bound?.Member as ConstructorInfo
                           ?? type.GetConstructor(BindingFlags.Public | BindingFlags.Instance, ps) ?? throw new Failed($"constructor {full}");
                var cps = bound?.Params ?? ctor.GetParameters();
                if (cacheable && bound == null) _bound[target] = new Bound(type, ps, ctor, cps);
                Bounded(ctor, cps, call);
                result = ctor.Invoke(call);
            }
            else
            {
                MethodInfo method;
                ParameterInfo[] mps;
                if (bound?.Member is MethodInfo bm) (method, mps) = (bm, bound.Params);
                else
                {
                    method = Find(type, name, ps, generic?.Select(g => Clr(g, context) ?? throw new Failed($"type argument {g.FullName}")).ToArray(),
                                  sig.HasThis) ?? throw new Failed($"{full} not found in this runtime");
                    // the member actually called must be declared by an allowed type (an inherited member of a base outside the
                    // allowlist, such as MarshalByRefObject's, is not), or be one of object's few value members
                    if (!DeclaredAllowed(method)) throw new Failed($"call into {method.DeclaringType}.{method.Name} (not on the allowlist)");
                    mps = method.GetParameters();
                    // a delegate argument can only be one MakeDelegate built (nothing else creates delegates), which interprets
                    if (mps.Any(p => p.ParameterType == typeof(Type))) throw new Failed($"{full} takes a type");
                    if (method.ReturnType == typeof(Type)) throw new Failed($"{full} returns a type");
                    if (cacheable) _bound[target] = new Bound(type, ps, method, mps);
                }
                Bounded(method, mps, call);
                result = method.Invoke(method.IsStatic ? null : self, call);
                if (result is Type || result is Delegate) throw new Failed($"{full} returned a type or delegate");
            }
        }
        catch (TargetInvocationException e) when (e.InnerException is Failed inner) { throw inner; } // from a delegate the framework called back
        catch (TargetInvocationException e) { throw new Failed($"{full} threw {e.InnerException?.GetType().Name}: {e.InnerException?.Message}"); }
        catch (Exception e) when (e is ArgumentException or InvalidCastException or OverflowException or FormatException or AmbiguousMatchException
                                       or TargetException or TargetParameterCountException or NotSupportedException or IndexOutOfRangeException)
        { throw new Failed($"{full}: {e.Message}"); }
        for (int i = 0; i < refs.Length; i++) refs[i]?.Set(Stack(call[i]));
        if (result is string { Length: > MaxArray } || result is Array { Length: > MaxArray }) throw new Failed("result too large");
        return Stack(result);
    }

    // A real delegate for the framework (Enumerable.Select(s, c => ...)) whose body calls back into the interpreter: the
    // framework calls it, the sample's lambda is interpreted, never run.
    Delegate MakeDelegate(DelegateStub d, Type delegateType)
    {
        var invoke = delegateType.GetMethod("Invoke")!;
        var ps = invoke.GetParameters().Select(p => System.Linq.Expressions.Expression.Parameter(p.ParameterType)).ToArray();
        var args = System.Linq.Expressions.Expression.NewArrayInit(typeof(object), ps.Select(p => System.Linq.Expressions.Expression.Convert(p, typeof(object))));
        var call = System.Linq.Expressions.Expression.Call(System.Linq.Expressions.Expression.Constant(this),
            typeof(Emulator).GetMethod(nameof(Callback), BindingFlags.NonPublic | BindingFlags.Instance)!,
            System.Linq.Expressions.Expression.Constant(d), args, System.Linq.Expressions.Expression.Constant(invoke.ReturnType, typeof(Type)));
        System.Linq.Expressions.Expression body = invoke.ReturnType == typeof(void)
            ? System.Linq.Expressions.Expression.Block(typeof(void), call)
            : System.Linq.Expressions.Expression.Convert(call, invoke.ReturnType);
        return System.Linq.Expressions.Expression.Lambda(delegateType, body, ps).Compile();
    }

    object? Callback(DelegateStub d, object?[] args, Type returns)
    {
        var a = args.Select(Stack).ToArray();
        object? r = d.Fn.Def is { } fd
            ? Invoke(fd, fd.IsStatic ? a : [d.Target, .. a], null, _depth + 1)
            : throw new Failed("a delegate to a framework method passed to the framework");
        return returns == typeof(void) ? null : ToClr(r, returns);
    }

    static readonly HashSet<string> ObjectMembers = ["ToString", "Equals", "GetHashCode", "CompareTo"];

    static bool Nondeterministic(string full) =>
        full.Contains(" System.Random::", StringComparison.Ordinal) || full.Contains(" System.Security.Cryptography.RandomNumberGenerator::", StringComparison.Ordinal)
        || full.Contains(" System.Guid::NewGuid(", StringComparison.Ordinal) || full.Contains(" System.DateTime::get_Now(", StringComparison.Ordinal)
        || full.Contains(" System.DateTime::get_UtcNow(", StringComparison.Ordinal) || full.Contains(" System.Environment::get_TickCount", StringComparison.Ordinal)
        || full.Contains(" System.Diagnostics.Stopwatch::", StringComparison.Ordinal);

    // A parameter type the interpreter can hand to the framework: a value it models (primitives, strings, enums, arrays
    // of them) or an instance of an allowed type
    static bool Modelled(Type t) =>
        t.IsPrimitive || t.IsEnum || t == typeof(string) || t == typeof(object) || t == typeof(decimal)
        || t.IsArray && Modelled(t.GetElementType()!) || Allowed.ContainsValue(t.IsGenericType ? t.GetGenericTypeDefinition() : t);

    static bool DeclaredAllowed(MethodInfo method)
    {
        var declared = method.DeclaringType!.IsGenericType ? method.DeclaringType.GetGenericTypeDefinition() : method.DeclaringType;
        return Allowed.ContainsValue(declared)
               || Partly.TryGetValue(declared.FullName!, out var pt) && pt.Members.Contains(method.Name)
               || (declared == typeof(object) || declared == typeof(ValueType) || declared == typeof(Enum)) && ObjectMembers.Contains(method.Name);
    }

    // A framework call is one step to the interpreter and cannot be interrupted, so what it is asked to do is bounded
    // before it runs: key-derivation iterations, and the sizes of what it allocates or produces.
    const long MaxIterations = 1_000_000;
    static readonly HashSet<string> SizeParameters = new(StringComparer.OrdinalIgnoreCase)
        { "count", "length", "capacity", "newSize", "totalWidth", "repeatCount", "cb", "numBytes", "minimumLength", "maxCapacity" };

    static void Bounded(MethodBase m, ParameterInfo[] ps, object?[] args)
    {
        for (int i = 0; i < ps.Length && i < args.Length; i++)
        {
            if (args[i] is not (int or long or uint or ulong or short or ushort)) continue;
            long v = Convert.ToInt64(args[i]);
            var name = ps[i].Name ?? "";
            if (name.Equals("iterations", StringComparison.OrdinalIgnoreCase) || m.Name is "set_IterationCount")
            {
                if (v > MaxIterations) throw new Failed($"{m.DeclaringType?.Name}.{m.Name} with {v:N0} iterations (more than {MaxIterations:N0})");
            }
            else if (SizeParameters.Contains(name) || m.Name is "SetLength" or "set_Capacity" or "set_Length")
            {
                if (v > MaxArray) throw new Failed($"{m.DeclaringType?.Name}.{m.Name} with {name} {v:N0} (more than {MaxArray:N0})");
            }
        }
    }

    static MethodInfo? Find(Type type, string name, Type[] ps, Type[]? generic, bool instance)
    {
        var flags = BindingFlags.Public | (instance ? BindingFlags.Instance : BindingFlags.Static);
        foreach (var m in type.GetMethods(flags | BindingFlags.FlattenHierarchy).Where(m => m.Name == name && m.GetParameters().Length == ps.Length))
            {
                var mm = m;
                if (m.IsGenericMethodDefinition)
                {
                    if (generic == null || generic.Length != m.GetGenericArguments().Length) continue;
                    try { mm = m.MakeGenericMethod(generic); } catch (ArgumentException) { continue; }
                }
                if (mm.GetParameters().Select(p => p.ParameterType).SequenceEqual(ps, ParamEq.Instance)) return mm;
            }
        return null;
    }

    // dnlib names a generic method's parameter by its generic parameter (!!0); here it is already the closed type.
    sealed class ParamEq : IEqualityComparer<Type>
    {
        public static readonly ParamEq Instance = new();
        public bool Equals(Type? a, Type? b) => a == b || a != null && b != null && (a.IsByRef ? a.GetElementType() : a) == (b.IsByRef ? b.GetElementType() : b);
        public int GetHashCode(Type t) => 0;
    }
}
