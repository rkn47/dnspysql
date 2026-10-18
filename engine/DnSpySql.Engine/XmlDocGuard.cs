// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Xml;
using dnlib.DotNet;
using dnSpy.Contracts.Decompiler.XmlDoc;

namespace DnSpySql;

/// <summary>
/// dnSpy's decompiler and api_docs read the XML documentation next to an assembly (XmlDocLoader), and dnSpyEx follows a
/// root `redirect` attribute to any path, a UNC share included: a .xml planted next to a sample would make the analyst's
/// machine open \\host\share (and send its NTLM credentials) when the sample is decompiled. A document type declaration
/// is refused too (entity expansion). XmlDocLoader caches its answer per module object, so for a module whose
/// neighbouring documentation is unsafe the cache is primed with "none" before anything else asks.
/// </summary>
static class XmlDocGuard
{
    static readonly System.Runtime.CompilerServices.ConditionalWeakTable<ModuleDef, object> _checked = new();

    public static void Check(ModuleDef? module)
    {
        if (module == null || string.IsNullOrEmpty(module.Location) || _checked.TryGetValue(module, out _)) return;
        _checked.AddOrUpdate(module, module);
        if (Candidates(module.Location).All(Safe)) return;
        // a file name that exists nowhere: the loader finds nothing for it, and caches that for this module
        try { XmlDocLoader.LoadDocumentation(module, Path.Combine(Path.GetTempPath(), "dnspysql-no-xmldoc-" + Guid.NewGuid().ToString("N") + ".dll")); }
        catch (Exception) { }
    }

    // The files XmlDocLoader looks at next to an assembly (its GetXmlDocFileCandidates).
    static IEnumerable<string> Candidates(string location)
    {
        var xml = Path.ChangeExtension(location, ".xml");
        var dir = Path.GetDirectoryName(xml) ?? "";
        var ui = Thread.CurrentThread.CurrentUICulture;
        foreach (var lang in new[] { ui.Name, ui.TwoLetterISOLanguageName, "en" })
            yield return Path.Combine(dir, lang, Path.GetFileName(xml));
        yield return xml;
    }

    static bool Safe(string path)
    {
        try
        {
            if (!File.Exists(path)) return true;
            using var r = XmlReader.Create(path, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
            r.MoveToContent();
            // the reference assemblies' own redirects name the Program Files or runtime directory; a relative one stays
            // next to the file. A rooted one (C:\, \\server\share, \\?\UNC\...) can go anywhere.
            var target = r.GetAttribute("redirect");
            return string.IsNullOrEmpty(target)
                   || target.StartsWith("%PROGRAMFILESDIR%", StringComparison.Ordinal) && !target.Contains("..")
                   || target.StartsWith("%CORSYSDIR%", StringComparison.Ordinal) && !target.Contains("..")
                   || !target.Contains('%') && !Path.IsPathRooted(target) && !target.StartsWith('\\') && !target.StartsWith('/');
        }
        catch (Exception) { return false; } // a DTD, or not XML at all: dnSpy gets nothing from it either way
    }
}
