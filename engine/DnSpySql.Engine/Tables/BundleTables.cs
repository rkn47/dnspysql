// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Functions;
using DnSpySql.Sql;
using static DnSpySql.Tables.TableKit;

namespace DnSpySql.Tables;

/// <summary>Single-file bundles: the files a bundled app host carries, and opening more of its assemblies.</summary>
public static class BundleTables
{
    public static void Register(Session s)
    {
        var ws = s.Ws;
        s.Db.Register(new Table<(LoadedModule m, BundleEntry e, int i)>("bundle_entries",
                "Files inside a .NET single-file bundle (PublishSingleFile) the module was opened from: assemblies, deps.json, " +
                "runtimeconfig.json, native libraries. open_bundle_entry(path) loads another embedded assembly") { Domain = "meta" }
            .Source(c => ws.Modules(c).Where(m => m.Bundle != null)
                .GroupBy(m => m.Bundle!.HostPath).Select(g => g.First())
                .SelectMany(m => m.Bundle!.Entries.Select((e, i) => (m, e, i))))
            .Int("module", r => r.m.Id, pushdown: Pushdown.Eq, doc: "a module opened from this bundle")
            .Text("bundle", r => r.m.Bundle!.HostPath, doc: "the app host file")
            .Int("idx", r => r.i)
            .Text("path", r => r.e.Path, pushdown: Pushdown.Eq, doc: "relative path inside the bundle")
            .Text("kind", r => r.e.Kind, doc: "assembly | native | deps.json | runtimeconfig.json | symbols | unknown")
            .Int("offset", r => r.e.Offset, doc: "file offset in the host")
            .Int("size", r => r.e.Size)
            .Int("compressed_size", r => r.e.CompressedSize == 0 ? null : r.e.CompressedSize, doc: "deflate size when compressed (.NET 6+)")
            .Int("opened_as", r => ws.Modules.FirstOrDefault(m => m.Path == $"{r.m.Bundle!.HostPath}!/{r.e.Path}")?.Id, doc: "module id when loaded")
            .Text("bundle_id", r => r.m.Bundle!.Id)
            .Text("bundle_version", r => $"{r.m.Bundle!.Major}.{r.m.Bundle!.Minor}")
            .Blob("data", r => Bundle.Extract(r.m.BundleHost!, r.e), doc: "the entry's bytes (inflated)")
            .Estimate(200));

        s.Fn("open_bundle_entry", 1, 2, a =>
        {
            var lm = a.Arg(1) == null ? ws.Modules.FirstOrDefault(m => m.Bundle != null) : ws.ModuleArg(a[1]);
            if (lm?.Bundle == null) throw new SqlException("no module was opened from a single-file bundle");
            var path = Str(a[0], "path");
            var entry = lm.Bundle.Entries.FirstOrDefault(e => string.Equals(e.Path, path, StringComparison.OrdinalIgnoreCase))
                        ?? throw new SqlException($"the bundle has no entry {path} (see bundle_entries)");
            var opened = ws.OpenBundleEntry(lm.Bundle.HostPath, lm.BundleHost!, lm.Bundle, entry);
            s.Index.Invalidate();
            return (long)opened.Id;
        }, "open_bundle_entry(path [, module])", "load an assembly embedded in a single-file bundle as another module; returns its id", "session", mutates: true);
    }
}
