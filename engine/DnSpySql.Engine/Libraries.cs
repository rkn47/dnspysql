// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using dnlib.DotNet;

namespace DnSpySql;

/// <summary>
/// What is framework or library code rather than the sample's own, by structure where there is one: an assembly signed
/// with one of Microsoft's keys is the framework (a self-contained bundle's runtime pack is in its deps.json: Bundle).
/// Code merged into the sample (ILMerge, an embedded copy) has no key of its own, so there the test is a well-known
/// library's namespace. Every is_library column, the triage lists and dnSpy's exception settings use this one test.
/// </summary>
public static class Libraries
{
    // the public key tokens Microsoft signs the framework with (.NET Framework, .NET, ASP.NET, Silverlight, WPF, Roslyn)
    static readonly HashSet<string> FrameworkTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "b77a5c561934e089", "b03f5f7f11d50a3a", "31bf3856ad364e35", "cc7b13ffcd2ddd51", "7cec85d7bea7798e", "adb9793829ddae60",
    };

    // libraries malware embeds or merges, by namespace (the framework's own namespaces too, for merged framework code)
    static readonly string[] LibraryNamespaces = ["System.", "Microsoft.", "Newtonsoft.", "Org.BouncyCastle", "Google.Protobuf", "MessagePack",
        "Costura", "ICSharpCode.", "Mono.", "NAudio", "AForge", "Ionic.", "SharpCompress", "Renci.", "ProtoBuf", "Dapper", "SQLite", "AsyncIO", "NetMQ"];

    /// <summary>The module is part of the framework: its assembly is signed with one of Microsoft's keys.</summary>
    public static bool IsFramework(ModuleDef? m)
    {
        var token = m?.Assembly?.PublicKeyToken;
        return token != null && !PublicKeyBase.IsNullOrEmpty2(token) && FrameworkTokens.Contains(token.ToString());
    }

    /// <summary>A namespace of the framework or of a library samples commonly carry.</summary>
    public static bool IsLibraryNamespace(string ns) =>
        LibraryNamespaces.Any(p => ns.StartsWith(p, StringComparison.Ordinal) || ns == p.TrimEnd('.'));

    /// <summary>Library code: a method of a framework assembly, or of a library namespace (outermost type's).</summary>
    public static bool IsLibrary(MethodDef m)
    {
        if (IsFramework(m.Module)) return true;
        var t = m.DeclaringType;
        while (t?.DeclaringType != null) t = t.DeclaringType;
        return IsLibraryNamespace(t?.Namespace.String ?? "");
    }
}
