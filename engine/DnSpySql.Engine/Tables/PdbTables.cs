// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Sql;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Pdb;

namespace DnSpySql.Tables;

/// <summary>Debug symbols (portable/embedded/Windows PDB via dnlib): documents, sequence points, scopes, locals, CDI.</summary>
public static class PdbTables
{
    public static void Register(Session s)
    {
        var ws = s.Ws;
        var db = s.Db;

        db.Register(new Table<Row<(int idx, PdbDocument d)>>("pdb_documents", "Source documents referenced by the PDB") { Domain = "pdb" }
            .Source(c => ws.Modules(c).Where(m => m.Module.PdbState != null)
                .SelectMany(m => m.Module.PdbState!.Documents.Select((d, i) => new Row<(int, PdbDocument)>(m, (i, d)))))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Int("idx", r => r.Item.idx)
            .Text("url", r => r.Item.d.Url)
            .Text("language", r => Lang(r.Item.d.Language))
            .Text("hash_algorithm", r => r.Item.d.CheckSumAlgorithmId == Guid.Empty ? null : r.Item.d.CheckSumAlgorithmId.ToString())
            .Text("checksum", r => r.Item.d.CheckSum is { Length: > 0 } cs ? Convert.ToHexString(cs) : null)
            .Text("embedded_source", r => r.Item.d.CustomDebugInfos.OfType<PdbEmbeddedSourceCustomDebugInfo>().FirstOrDefault() is { } es
                ? System.Text.Encoding.UTF8.GetString(Decompress(es.SourceCodeBlob)) : null));

        db.Register(new Table<(LoadedModule m, MethodDef md, Instruction i, int idx)>("sequence_points", "IL offset to source line mapping from the PDB") { Domain = "pdb" }
            .Source(c => MemberTables.MethodScope(ws, c).Where(r => r.Item.HasBody && r.M.Module.PdbState != null)
                .SelectMany(r => r.Item.Body.Instructions.Select((i, k) => (r.M, r.Item, i, k)).Where(x => x.i.SequencePoint != null)))
            .Int("module", r => r.m.Id, pushdown: Pushdown.Eq)
            .Int("method", r => r.m.H(r.md), pushdown: Pushdown.Eq)
            .Int("idx", r => r.idx)
            .Int("offset", r => r.i.Offset)
            .Text("document", r => r.i.SequencePoint!.Document?.Url)
            .Int("start_line", r => r.i.SequencePoint!.StartLine)
            .Int("start_column", r => r.i.SequencePoint!.StartColumn)
            .Int("end_line", r => r.i.SequencePoint!.EndLine)
            .Int("end_column", r => r.i.SequencePoint!.EndColumn)
            .Bool("is_hidden", r => r.i.SequencePoint!.StartLine == 0xFEEFEE));

        db.Register(new Table<(LoadedModule m, MethodDef md, PdbScope sc, int id, int parent)>("pdb_scopes", "Local scopes per method (PDB)") { Domain = "pdb" }
            .Source(c => MemberTables.MethodScope(ws, c).Where(r => r.Item.HasBody && r.Item.Body.PdbMethod?.Scope != null)
                .SelectMany(r => Flatten(r.Item.Body.PdbMethod!.Scope).Select(x => (r.M, r.Item, x.sc, x.id, x.parent))))
            .Int("module", r => r.m.Id, pushdown: Pushdown.Eq)
            .Int("method", r => r.m.H(r.md), pushdown: Pushdown.Eq)
            .Int("scope_id", r => r.id)
            .Int("parent_id", r => r.parent < 0 ? null : r.parent)
            .Int("start_offset", r => r.sc.Start?.Offset ?? 0)
            .Int("end_offset", r => r.sc.End?.Offset)
            .Int("local_count", r => r.sc.Variables.Count)
            .Int("constant_count", r => r.sc.Constants.Count)
            .Text("imports", r => r.sc.ImportScope == null ? null : string.Join("; ", r.sc.ImportScope.Imports.Select(ImportText))));

        db.Register(new Table<(LoadedModule m, MethodDef md, int scope, string kind, string name, string? type, object? value, int? index)>("pdb_locals",
                "Named locals and constants from PDB scopes") { Domain = "pdb" }
            .Source(c => MemberTables.MethodScope(ws, c).Where(r => r.Item.HasBody && r.Item.Body.PdbMethod?.Scope != null)
                .SelectMany(r => Flatten(r.Item.Body.PdbMethod!.Scope).SelectMany(x =>
                    x.sc.Variables.Select(v => (r.M, r.Item, x.id, "local", v.Name, v.Local?.Type?.FullName, (object?)null, (int?)v.Index))
                        .Concat(x.sc.Constants.Select(k => (r.M, r.Item, x.id, "constant", k.Name, k.Type?.FullName, TableKit.SqlValue(k.Value), (int?)null))))))
            .Int("module", r => r.m.Id, pushdown: Pushdown.Eq)
            .Int("method", r => r.m.H(r.md), pushdown: Pushdown.Eq)
            .Int("scope_id", r => r.scope)
            .Text("kind", r => r.kind)
            .Text("name", r => r.name)
            .Text("type", r => r.type)
            .Int("local_index", r => r.index)
            .Col("value", SqlType.Any, r => r.value));

        db.Register(new Table<(LoadedModule m, IMDTokenProvider owner, PdbCustomDebugInfo cdi)>("custom_debug_info",
                "Custom debug information (state machines, async info, source link, embedded source, dynamic locals, tuple names ...)") { Domain = "pdb" }
            .Source(c => ws.Modules(c).Where(m => m.Module.PdbState != null).SelectMany(m =>
                m.Module.CustomDebugInfos.Select(x => (m, (IMDTokenProvider)m.Module, x))
                    .Concat(m.Module.GetTypes().SelectMany(t => t.Methods).Where(md => md.HasCustomDebugInfos)
                        .SelectMany(md => md.CustomDebugInfos.Select(x => (m, (IMDTokenProvider)md, x))))))
            .Int("module", r => r.m.Id, pushdown: Pushdown.Eq)
            .Int("owner", r => r.m.H(r.owner))
            .Text("owner_name", r => (r.owner as IFullName)?.FullName ?? "module")
            .Text("kind", r => r.cdi.Kind.ToString())
            .Text("guid", r => r.cdi.Guid == Guid.Empty ? null : r.cdi.Guid.ToString())
            .Text("detail", r => r.cdi switch
            {
                PdbSourceLinkCustomDebugInfo sl => System.Text.Encoding.UTF8.GetString(sl.FileBlob),
                PdbStateMachineTypeNameCustomDebugInfo sm => sm.Type?.FullName,
                PdbStateMachineHoistedLocalScopesCustomDebugInfo h => $"{h.Scopes.Count} hoisted scopes",
                PdbAsyncMethodCustomDebugInfo am => $"kickoff={am.KickoffMethod?.FullName}; steps={am.StepInfos.Count}",
                PdbIteratorMethodCustomDebugInfo it => $"kickoff={it.KickoffMethod?.FullName}",
                PdbTupleElementNamesCustomDebugInfo tn => string.Join(",", tn.Names),
                PdbDynamicLocalsCustomDebugInfo dl => string.Join(",", dl.Locals.Select(l => l.Name)),
                PdbCompilationOptionsCustomDebugInfo co => string.Join("; ", co.Options.Select(o => $"{o.Key}={o.Value}")),
                PdbCompilationMetadataReferencesCustomDebugInfo mr => string.Join("; ", mr.References.Select(x => x.Name)),
                _ => null,
            }));
    }

    static IEnumerable<(PdbScope sc, int id, int parent)> Flatten(PdbScope root)
    {
        int next = 0;
        var stack = new Stack<(PdbScope, int)>();
        stack.Push((root, -1));
        while (stack.Count > 0)
        {
            var (sc, parent) = stack.Pop();
            int id = next++;
            yield return (sc, id, parent);
            for (int i = sc.Scopes.Count - 1; i >= 0; i--) stack.Push((sc.Scopes[i], id));
        }
    }

    static string ImportText(PdbImport i) => i switch
    {
        PdbImportNamespace n => "using " + n.TargetNamespace,
        PdbAliasNamespace a => $"using {a.Alias} = {a.TargetNamespace}",
        PdbImportType t => "using static " + t.TargetType?.FullName,
        PdbAliasType at => $"using {at.Alias} = {at.TargetType?.FullName}",
        _ => i.Kind.ToString(),
    };

    static string Lang(Guid g) => g.ToString().ToUpperInvariant() switch
    {
        "3F5162F8-07C6-11D3-9053-00C04FA302A1" => "C#",
        "3A12D0B8-C26C-11D0-B442-00A0244A1DD2" => "Visual Basic",
        "AB4F38C9-B6E6-43BA-BE3B-58080B2CCCE3" => "F#",
        "00000000-0000-0000-0000-000000000000" => "",
        var x => x,
    };

    // Embedded source: the uncompressed size, then the text (size 0) or its deflate stream. The output is bounded by
    // that size, and a size deflate could not reach from this blob (about 1032:1 at most) is not trusted at all.
    static byte[] Decompress(byte[] blob)
    {
        if (blob.Length < 4) return blob;
        int size = BitConverter.ToInt32(blob, 0);
        if (size == 0) return blob[4..];
        if (size < 0 || size > (blob.Length - 4L) * 1032 + 1024) throw new InvalidDataException($"embedded source claims {size} bytes");
        using var ms = new MemoryStream(blob, 4, blob.Length - 4);
        using var ds = new System.IO.Compression.DeflateStream(ms, System.IO.Compression.CompressionMode.Decompress);
        var output = new byte[size];
        int got = ds.ReadAtLeast(output, size, throwOnEndOfStream: false);
        return got == size ? output : output[..got];
    }
}
