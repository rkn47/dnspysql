// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using dnlib.DotNet;
using dnSpy.Decompiler.MSBuild;

namespace DnSpySql;

// export_project(): dnSpy's own project exporter (dnSpy.Decompiler/MSBuild, vendored under engine/vendor) with
// the defaults of dnSpy's File > Export to Project dialog: a solution, one project per module, resources
// unpacked and turned into .resx files, VS2010-format projects (SDK-style on request).
static class Export
{
    // dnSpy names files after types and resources, replacing the characters the OS rejects. On Linux that is
    // only '/' and NUL, but obfuscated names are full of '\', '"', '?', '*', ... and an export is meant to be
    // opened on Windows (in dnSpy or Visual Studio), so the Windows set is added to dnSpy's own.
    static Export()
    {
        var field = typeof(dnSpy.Decompiler.FilenameUtils).GetField("invalidFileNameChars",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        if (field?.GetValue(null) is not HashSet<char> invalid)
            throw new InvalidOperationException("dnSpy's FilenameUtils changed; update Export's file name cleanup");
        lock (invalid) invalid.UnionWith("<>:\"/\\|?*".Concat(Enumerable.Range(0, 32).Select(c => (char)c)));
    }

    public static string Project(IReadOnlyList<LoadedModule> modules, string dir, bool sdkStyle)
    {
        // timeouts under the parallel export's contention say little about a method: not remembered past it
        try { return ProjectCore(modules, dir, sdkStyle); }
        finally { DnSpyDecompiler.ForgetTimeouts(); }
    }

    static string ProjectCore(IReadOnlyList<LoadedModule> modules, string dir, bool sdkStyle)
    {
        dir = Path.GetFullPath(dir);
        Directory.CreateDirectory(dir);
        foreach (var m in modules) XmlDocGuard.Check(m.Module);
        var log = new Log();
        var ctx = DnSpyDecompiler.ExportContext();
        var options = new ProjectCreatorOptions(dir, CancellationToken.None)
        {
            ProjectVersion = ProjectVersion.VS2010,
            GenerateSDKStyleProjects = sdkStyle,
            SolutionFilename = SolutionName(modules),
            Logger = log,
        };
        bool corlib = modules.Any(m => m.Module.Assembly?.IsCorLib() == true);
        foreach (var m in modules.OrderBy(m => m.Path, StringComparer.InvariantCultureIgnoreCase))
            options.ProjectModules.Add(new ProjectModuleOptions(m.Module, DnSpyDecompiler.Exporter, ctx)
            {
                DontReferenceStdLib = corlib,
                UnpackResources = true,
                CreateResX = true,
                // dnSpy decompiles BAML to XAML when its BAML decompiler is present, as here.
                DecompileXaml = true,
                // A BAML resource that cannot be decompiled (e.g. WPF assemblies not found) becomes a .xaml file that says
                // why, instead of failing the whole export.
                DecompileBamlTypeName = (md, data, ct) =>
                {
                    try { return Baml.TypeName(md, data, ct); }
                    catch (Exception e) when (e is not OperationCanceledException) { return null; }
                },
                DecompileBaml = (md, data, ct, stream) =>
                {
                    try { return Baml.ToStream(md, data, ct, stream); }
                    catch (Exception e) when (e is not OperationCanceledException)
                    {
                        var note = System.Text.Encoding.UTF8.GetBytes($"<!-- dnspysql: BAML decompilation failed: {e.Message.Replace("--", "- -")} -->\n");
                        stream.Write(note, 0, note.Length);
                        return [];
                    }
                },
                ProjectGuid = Guid.NewGuid(),
            });
        var creator = new MSBuildProjectCreator(options);
        creator.Create();
        if (log.Errors.Count == 0) return creator.SolutionFilename;
        var errors = Path.Combine(dir, "export-errors.txt");
        File.WriteAllLines(errors, log.Errors);
        return $"{creator.SolutionFilename} ({log.Errors.Count} error(s), see {errors})";
    }

    // Same naming as dnSpy: the first EXE's assembly name, else the first DLL's.
    static string SolutionName(IReadOnlyList<LoadedModule> modules)
    {
        foreach (var md in modules.Select(m => m.Module).OrderBy(md => (md.Characteristics & dnlib.PE.Characteristics.Dll) == 0 ? 0 : 1))
        {
            string name = md.IsManifestModule && md.Assembly is not null ? md.Assembly.Name : md.Name;
            foreach (var ext in new[] { ".exe", ".dll", ".netmodule" })
                if (name.EndsWith(ext, StringComparison.OrdinalIgnoreCase)) name = name[..^ext.Length];
            if (!string.IsNullOrWhiteSpace(name)) return name + ".sln";
        }
        return "solution.sln";
    }

    sealed class Log : IMSBuildProjectWriterLogger
    {
        public List<string> Errors { get; } = [];
        public void Error(string message) { lock (Errors) Errors.Add(message); }
    }
}
