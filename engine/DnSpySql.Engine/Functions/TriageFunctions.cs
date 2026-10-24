// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using DnSpySql.Tables;
using dnlib.DotNet;

namespace DnSpySql.Functions;

/// <summary>
/// triage(): the first look at a sample in one call, as JSON: what it is, how it is protected, what it carries, what it
/// does, its config candidates, and what to run next. The same findings as the triage tables (it reads their sources),
/// capped so the answer stays readable; every entry names the method and offset to follow up with SQL. It reads the
/// file and its IL only: what interpreting code would add (decryptor_calls, decoded_fields) is in the next queries.
/// </summary>
public static class TriageFunctions
{
    const int MaxShown = 50, MaxInits = 100, MaxExamples = 3;

    public static void Register(Session s)
    {
        s.Fn("triage", 0, 1, a => Triage(s, s.Ws.ModuleArg(a.Arg(0))).ToJsonString(new JsonSerializerOptions { WriteIndented = true }),
            "triage([module])",
            "the first look at a module as one JSON object: identity and anomalies, protections, embedded PEs, string decryptors, " +
            "capabilities by kind, config candidates (field_inits), settings decoders, resources, and the next queries to run. Library " +
            "code is left out; each list says how many entries it had. Static: nothing is interpreted, the next queries say where that helps " +
            "(decryptor_calls, decoded_fields)",
            "triage");
    }

    static JsonObject Triage(Session s, LoadedModule m)
    {
        var md = m.Module;
        var o = new JsonObject();
        var next = new List<string>();

        o["module"] = new JsonObject
        {
            ["id"] = m.Id,
            ["file"] = m.Path,
            ["origin"] = m.Origin,
            ["derived_from"] = m.DerivedFrom,
            ["assembly"] = md.Assembly?.FullName,
            ["kind"] = md.Kind.ToString(),
            ["target_framework"] = MetaTables.TargetFramework(md),
            ["sha256"] = Convert.ToHexString(SHA256.HashData(m.DiskBytes)).ToLowerInvariant(),
            ["types"] = md.GetTypes().Count(),
            ["methods"] = (long)md.Metadata.TablesStream.MethodTable.Rows,
            ["anomalies"] = Array(PeTables.Anomalies(m).Select(x => (JsonNode?)x)),
        };

        var entries = new JsonArray();
        if (md.ManagedEntryPoint is MethodDef ep) entries.Add(Member(m, ep, "entry_point"));
        if (md.GlobalType?.FindStaticConstructor() is { } init) entries.Add(Member(m, init, "module_initializer"));
        o["entry_points"] = entries;

        var protections = ProtectionTables.Detect(s, m).ToList();
        o["protections"] = Array(protections.Select(f => (JsonNode?)new JsonObject
        {
            ["name"] = f.Name, ["kind"] = f.Kind, ["confidence"] = f.Confidence, ["evidence"] = f.Evidence,
            ["handle"] = f.Handle,
        }));
        // only when untamper() would do something: bodies that do not decode, and the routine it interprets (one with the
        // VirtualProtect import and plain bodies has nothing to decrypt; in a module untamper() made, the routine would
        // decrypt the decrypted bodies again)
        if (protections.Any(f => f.Kind == "anti-tamper") && m.Origin != "untamper" && HexTables.Undecodable(m).Count > 0
            && CoreFunctions.AntiTamperInitializer(s, m) != null)
            next.Add($"SELECT untamper({m.Id})  -- anti-tamper: method bodies are encrypted in the file; analyze the module it returns");

        // a shell with no code: the first thing to do is to open what it carries
        if (protections.Any(f => f.Kind == "stub assembly"))
            next.Insert(0, $"SELECT open_bytes(data) FROM embedded_pes WHERE module = {m.Id} AND is_dotnet ORDER BY size DESC LIMIT 1  -- the code of this " +
                     "assembly: it has no method body of its own");
        foreach (var vm in ProtectionTables.Virtualization(m))
            next.Add($"SELECT caller_name FROM callers WHERE method = {m.H(vm.Dispatcher)}  -- the {vm.Stubs.Count} methods virtualized into " +
                     $"{OneLine(vm.Dispatcher.FullName)}: their code is VM bytecode, not IL");
        var carved = ProtectionTables.Carve(m).ToList();
        o["embedded_pes"] = Array(carved.Select(c =>
        {
            var bytes = c.Slice();
            bool dotnet = Workspace.NotDotNet(bytes[..Math.Min(bytes.Length, 4096)].ToArray()) == null;
            return (JsonNode?)new JsonObject
            {
                ["location"] = c.Location, ["size"] = c.Size, ["is_dotnet"] = dotnet,
                ["machine"] = Enum.GetName(typeof(dnlib.PE.Machine), c.Machine) ?? $"0x{c.Machine:X}",
                ["sha256"] = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),
                ["parent_offset"] = c.Parent,
            };
        }));
        if (o["embedded_pes"]!.AsArray().Any(x => x!["is_dotnet"]!.GetValue<bool>()))
            // no name: each stage gets one from its hash (a fixed name fails on the second row)
            next.Add($"SELECT open_bytes(data) AS module FROM embedded_pes WHERE module = {m.Id} AND is_dotnet  -- then triage each new module");

        var decryptors = ProtectionTables.Decryptors(s, m, 5).Where(d => !TriageTables.IsLibrary(d.Method) && ProtectionTables.ReturnsText(d.Method))
            .OrderByDescending(d => d.Score).ToList();
        o["string_decryptors"] = Counted(decryptors.Count, decryptors.Take(5).Select(d => (JsonNode?)new JsonObject
        {
            ["method"] = m.H(d.Method), ["name"] = d.Method.FullName, ["call_sites"] = d.Sites, ["constant_sites"] = d.ConstantSites, ["score"] = d.Score,
        }));

        // what the decryptors return is interpreted on request, not here: on a large sample that takes a while
        if (decryptors.Count > 0)
            next.Add($"SELECT caller_name, offset, plaintext, plaintext_kind, emulation FROM decryptor_calls WHERE module = {m.Id}  -- the strings " +
                     $"the {decryptors.Count} decryptor(s) return at each call site, interpreted (never run); plaintext_kind = 'ciphertext' is a second layer");

        var caps = TriageTables.Capabilities(s, m).Where(c => !TriageTables.IsLibrary(c.Site.From)).ToList();
        o["capabilities"] = Array(caps.GroupBy(c => c.Kind).OrderByDescending(g => g.Count()).Select(g => (JsonNode?)new JsonObject
        {
            ["kind"] = g.Key, ["count"] = g.Count(),
            ["examples"] = Array(g.DistinctBy(c => c.Api).Take(MaxExamples).Select(c => (JsonNode?)new JsonObject
            {
                ["api"] = c.Api, ["method"] = c.Site.FromHandle, ["method_name"] = c.Site.From.FullName, ["offset"] = c.Site.Offset,
            })),
        }));

        // Config candidates: what constructors store, grouped by type, the types with the most values first.
        var inits = TriageTables.Inits(s, m).Where(f => !IsDefault(f.Value) && f.Field.DeclaringType != null && !TriageTables.IsLibrary(f.SetIn)).ToList();
        var byType = inits.GroupBy(f => f.Field.DeclaringType!.FullName).OrderByDescending(g => g.Count()).ToList();
        o["config_candidates"] = Counted(inits.Count, byType.SelectMany(g => g).Take(MaxInits).Select(f => (JsonNode?)new JsonObject
        {
            ["type"] = f.Field.DeclaringType!.FullName, ["field"] = f.Field.Name.String, ["kind"] = f.Kind, ["value"] = Value(f.Value), ["source"] = f.Source,
        }));
        // settings types a decoder rewrites at startup (found from the IL): config_candidates has their ciphertext, and
        // decoded_fields what the program uses, interpreted on request
        var decoders = TriageTables.Decoders(s, m).ToList();
        o["settings_decoders"] = Counted(decoders.Count, decoders.Take(MaxShown).Select(d => (JsonNode?)new JsonObject
        {
            ["type"] = d.Settings.FullName, ["decoder"] = m.H(d.Decoder), ["decoder_name"] = d.Decoder.FullName, ["fields_written"] = d.Stored.Count,
        }));
        if (decoders.Count > 0)
            next.Add($"SELECT field_name, value, value_kind, error FROM decoded_fields WHERE module = {m.Id}  -- the settings as the " +
                     $"{decoders.Count} decoder(s) leave them at startup, interpreted (never run)");
        // by handle: a name can be in several open modules (an untamper() copy has all of them), and obfuscated ones are unreadable;
        // a store into a generic type's field names it as a TypeSpec (Gen`1<!0>), which decompile() refuses: its definition
        if (byType.Select(g => TypeDefOf(g.First().Field)).FirstOrDefault(t => t?.Module == md) is { } top)
            next.Add($"SELECT decompile('{Handle.Hex(m.H(top))}')  -- {OneLine(top.FullName)}: the type with the most stored constants");

        var resources = md.Resources.OfType<EmbeddedResource>().ToList();
        o["resources"] = Counted(resources.Count, resources.Take(MaxShown).Select(r =>
        {
            byte[]? head;
            try { head = r.CreateReader().ReadBytes((int)Math.Min(64 * 1024, r.Length)); }
            catch (Exception) { head = null; } // a resource whose data lies outside the file: listed, with no content type
            return (JsonNode?)new JsonObject { ["name"] = r.Name.String, ["size"] = (long)r.Length, ["content_type"] = head == null ? "unreadable" : ResourceTables.Content(head) };
        }));
        // every next item is a statement that runs as written; the advice goes in its comment. A compressed resource that
        // embedded_pes already inflated to a PE (Costura's DLLs) is decoded: the open_bytes() item above covers it.
        foreach (var r in o["resources"]!["items"]!.AsArray())
        {
            var name = r!["name"]!.GetValue<string>();
            if (r["content_type"]!.GetValue<string>() is not ("high entropy" or "gzip" or "zlib" or "deflate")
                || carved.Any(c => c.Location.StartsWith($"resource '{name}'", StringComparison.Ordinal))) continue;
            next.Add($"SELECT text FROM dnspysql_guides WHERE topic = 'unpack'  -- resource {Quote(OneLine(name))} is {r["content_type"]}: find its loader and decode it");
            break;
        }

        if (caps.Count > 0) next.Add($"SELECT kind, api, method_name, offset FROM capabilities WHERE module = {m.Id} AND NOT is_library  -- every capability site");
        // Nothing left to open or decrypt: the last step is to close the sample, or a long session keeps every module it
        // ever opened (memory is not released otherwise)
        var open = s.Ws.Modules.Select(x => x.Sha256).ToHashSet(StringComparer.Ordinal);
        bool pending = next.Any(n => n.StartsWith("SELECT untamper(", StringComparison.Ordinal))
                       || o["embedded_pes"]!.AsArray().Any(x => x!["is_dotnet"]!.GetValue<bool>() && !open.Contains(x["sha256"]!.GetValue<string>()));
        var family = new List<LoadedModule> { m };
        for (int i = 0; i < family.Count; i++) family.AddRange(s.Ws.Modules.Where(x => x.DerivedFrom == family[i].Id && !family.Contains(x)));
        if (!pending && family.All(s.Closable))
        {
            long mb = Math.Max(1, family.Sum(x => (long)x.DiskBytes.Length) >> 20);
            next.Add($"SELECT close({m.Id})  -- done with this sample{(family.Count > 1 ? $" and the {family.Count - 1} module(s) that came out of it" : "")}: " +
                     $"frees their memory ({mb:N0} MB of files)");
        }
        o["next"] = Array(next.Select(x => (JsonNode?)x));
        return o;
    }

    static TypeDef? TypeDefOf(IField f)
    {
        try { return f.DeclaringType?.ResolveTypeDef(); } catch (Exception) { return null; } // an unresolvable reference names no type here
    }

    static JsonObject Member(LoadedModule m, MethodDef md, string kind) => new() { ["kind"] = kind, ["method"] = m.H(md), ["name"] = md.FullName };

    static JsonArray Array(IEnumerable<JsonNode?> items) => new(items.ToArray());

    // A capped list with the number of entries it had.
    static JsonObject Counted(int total, IEnumerable<JsonNode?> items)
    {
        var arr = Array(items);
        return new JsonObject { ["total"] = total, ["shown"] = arr.Count, ["items"] = arr };
    }

    static JsonNode? Value(object? v) => v switch
    {
        null => null,
        string str => str.Length > 2000 ? str[..2000] + "..." : str,
        long l => l,
        int i => i,
        double d => double.IsFinite(d) ? d : d.ToString(System.Globalization.CultureInfo.InvariantCulture), // JSON has no Infinity or NaN
        bool b => b,
        byte[] bytes => $"x'{Convert.ToHexString(bytes.AsSpan(0, Math.Min(bytes.Length, 64)))}'{(bytes.Length > 64 ? $" ({bytes.Length} bytes)" : "")}",
        _ => Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture),
    };

    // as field_inits.is_default: what the compiler stores for an explicit initializer, not a setting
    static bool IsDefault(object? v) => v is null or 0L or 0 or false or "" || v is double d && d == 0;

    static string Quote(string s) => "'" + s.Replace("'", "''") + "'";

    // A name the sample chose, inside a suggested query: on one line, or a line break would end the -- comment and
    // what follows (the sample author's SQL) would run as a statement of its own.
    static readonly System.Text.RegularExpressions.Regex LineBreaks = new(@"[\x00-\x1F\x7F\u0085  ]");
    static string OneLine(string s) => LineBreaks.Replace(Output.Visible(s), m => $"\\u{(int)m.Value[0]:X4}");
}
