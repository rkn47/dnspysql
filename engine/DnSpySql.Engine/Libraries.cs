// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using dnlib.DotNet;

namespace DnSpySql;

/// <summary>
/// What is framework code rather than the sample's own, by structure: an assembly signed with one of Microsoft's keys is
/// the framework. dnSpy's exception settings use this test.
/// </summary>
public static class Libraries
{
    // the public key tokens Microsoft signs the framework with (.NET Framework, .NET, ASP.NET, Silverlight, WPF, Roslyn)
    static readonly HashSet<string> FrameworkTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "b77a5c561934e089", "b03f5f7f11d50a3a", "31bf3856ad364e35", "cc7b13ffcd2ddd51", "7cec85d7bea7798e", "adb9793829ddae60",
    };

    /// <summary>The module is part of the framework: its assembly is signed with one of Microsoft's keys.</summary>
    public static bool IsFramework(ModuleDef? m)
    {
        var token = m?.Assembly?.PublicKeyToken;
        return token != null && !PublicKeyBase.IsNullOrEmpty2(token) && FrameworkTokens.Contains(token.ToString());
    }
}
