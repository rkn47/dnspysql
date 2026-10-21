// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
namespace DnSpySql;

/// <summary>
/// Locates reference/implementation assemblies a target needs when they are not next to it: the .NET Framework
/// (mscorlib, WPF ...) on Linux/macOS, and the full shared framework for .NET (Core) targets.
/// </summary>
public static class RefPaths
{
    static readonly string Home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    /// <summary>Directories with .NET Framework 4.x assemblies, best first.</summary>
    public static IEnumerable<string> NetFramework(IEnumerable<string> user)
    {
        var dirs = new List<string>();
        dirs.AddRange(user);
        // Shipped next to the engine (build.sh / the Docker image put the net48 reference pack in engine/refs). The
        // engine is hosted by DnSpySql's native host, so the app base directory is the host's, not this assembly's.
        var appRefs = Path.Combine(Path.GetDirectoryName(typeof(RefPaths).Assembly.Location) ?? AppContext.BaseDirectory, "refs");
        if (Directory.Exists(appRefs)) dirs.AddRange(Directory.GetDirectories(appRefs, "v4.*", SearchOption.AllDirectories).OrderByDescending(d => d));
        if (OperatingSystem.IsWindows())
        {
            var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            dirs.Add(Path.Combine(win, @"Microsoft.NET\Framework64\v4.0.30319"));
            dirs.Add(Path.Combine(win, @"Microsoft.NET\Framework64\v4.0.30319\WPF"));
            dirs.Add(Path.Combine(win, @"Microsoft.NET\Framework\v4.0.30319"));
            var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            var refRoot = Path.Combine(pf86, @"Reference Assemblies\Microsoft\Framework\.NETFramework");
            if (Directory.Exists(refRoot)) dirs.AddRange(Directory.GetDirectories(refRoot, "v4.*").OrderByDescending(d => d));
        }
        // NuGet reference packs (Microsoft.NETFramework.ReferenceAssemblies.net4xx), any restored version.
        foreach (var nugetRoot in new[] { Environment.GetEnvironmentVariable("NUGET_PACKAGES"), Path.Combine(Home, ".nuget", "packages") })
        {
            if (string.IsNullOrEmpty(nugetRoot) || !Directory.Exists(nugetRoot)) continue;
            foreach (var pkg in Directory.GetDirectories(nugetRoot, "microsoft.netframework.referenceassemblies.net4*").OrderByDescending(d => d))
                dirs.AddRange(Directory.GetDirectories(pkg, "v4.*", SearchOption.AllDirectories).OrderByDescending(d => d));
        }
        // Mono's reference assemblies.
        foreach (var mono in new[] { "/usr/lib/mono", "/usr/local/lib/mono", "/Library/Frameworks/Mono.framework/Versions/Current/lib/mono" })
            if (Directory.Exists(mono))
            {
                dirs.AddRange(Directory.GetDirectories(mono, "4.*-api").OrderByDescending(d => d));
                dirs.Add(Path.Combine(mono, "4.5"));
            }
        var result = new List<string>();
        foreach (var d in dirs.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            result.Add(d);
            var facades = Path.Combine(d, "Facades");
            if (Directory.Exists(facades)) result.Add(facades);
        }
        return result;
    }

    /// <summary>The running .NET shared framework directory (System.*.dll implementation assemblies).</summary>
    public static string NetCoreRuntime => System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory();

    public static bool UsesNetFramework(dnlib.DotNet.ModuleDef m) =>
        m.CorLibTypes.AssemblyRef.Name == "mscorlib" || m.Assembly?.Name == "mscorlib";
}
