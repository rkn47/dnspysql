// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Sql;
using dnlib.DotNet;
using dnlib.DotNet.Resources;
using static DnSpySql.Tables.TableKit;

namespace DnSpySql.Tables;

public sealed record ResRow(LoadedModule M, Resource R, int Index) : IHasModule;
public sealed record ResElemRow(LoadedModule M, Resource R, int ResIndex, ResourceElement E, int Index) : IHasModule;

/// <summary>Manifest resources and .resources elements (dnSpy resource nodes + resource editor).</summary>
public static class ResourceTables
{
    // Codes from UserTypes (0x40) on index the file's list of user types: each is a serialized object, not a code of its own
    static string CodeName(ResourceTypeCode c) => c >= ResourceTypeCode.UserTypes ? nameof(ResourceTypeCode.UserTypes) : c.ToString();

    public static void Register(Session s)
    {
        var ws = s.Ws;
        var db = s.Db;

        var res = new Table<ResRow>("resources", "Manifest resources. data = embedded bytes. INSERT(name, data[, visibility, module]), UPDATE name/visibility/data, DELETE") { Domain = "resources" };
        res.Source(c => ws.Modules(c).SelectMany(m => m.Module.Resources.Select((r, i) => new ResRow(m, r, i)))
                .Where(r => c.Text("name") is not string n || r.R.Name == n))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Int("idx", r => r.Index)
            .Text("name", r => r.R.Name.String, s.Setter<ResRow>((r, v) => Journaled(s, r, "name", x => x.Name, (x, n) => x.Name = n, (UTF8String)Str(v, "name"))), pushdown: Pushdown.Eq)
            .Text("kind", r => r.R.ResourceType switch { ResourceType.Embedded => "embedded", ResourceType.Linked => "linked", _ => "assembly_linked" })
            .Text("visibility", r => r.R.IsPublic ? "public" : "private", s.Setter<ResRow>((r, v) => Journaled(s, r, "visibility", x => x.Attributes, (x, a) => x.Attributes = a,
                Str(v, "visibility").ToLowerInvariant() == "public" ? ManifestResourceAttributes.Public : ManifestResourceAttributes.Private)))
            .Int("size", r => (r.R as EmbeddedResource)?.Length)
            .Int("file_offset", r => r.R is EmbeddedResource er && !r.M.Dirty ? (long)er.CreateReader().StartOffset : null)
            .Blob("data", r => (r.R as EmbeddedResource)?.CreateReader().ToArray(), (r, v) => ReplaceData(s, r, Values.ToBytes(v) ?? Array.Empty<byte>()))
            .Text("sniffed_type", r => r.R is EmbeddedResource er ? Sniff(er.CreateReader().ReadBytes((int)Math.Min(SniffBytes, er.Length)), r.R.Name) : null)
            .Text("content_type", r => r.R is EmbeddedResource er ? Content(er.CreateReader().ReadBytes((int)Math.Min(EntropyBytes, er.Length))) : null,
                doc: "from the content alone (sniffed_type adds the name's extension): png, pe, gzip, zlib, deflate (bytes that inflate, also after a 4-byte length), text, ..., 'high entropy' (encrypted) or binary")
            .Bool("is_resource_set", r => r.R is EmbeddedResource er && ResourceReader.CouldBeResourcesFile(er.CreateReader()))
            .Text("linked_file", r => (r.R as LinkedResource)?.File?.Name.String)
            .Text("linked_assembly", r => (r.R as AssemblyLinkedResource)?.Assembly?.FullName)
            .Text("sha256", r => r.R is EmbeddedResource er ? Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(er.CreateReader().ToArray())).ToLowerInvariant() : null)
            .Text("text", r => r.R is EmbeddedResource er && Sniff(er.CreateReader().ReadBytes((int)Math.Min(SniffBytes, er.Length)), r.R.Name) is "text" or "xml" or "json"
                ? System.Text.Encoding.UTF8.GetString(er.CreateReader().ToArray()) : null);
        res.JournalUpdates = false;
        res.OnInsert(v =>
        {
            var lm = ws.ModuleArg(v.GetValueOrDefault("module"));
            var name = Str(v.GetValueOrDefault("name"), "name");
            var data = Values.ToBytes(v.GetValueOrDefault("data")) ?? Array.Empty<byte>();
            var attrs = (Values.ToText(v.GetValueOrDefault("visibility")) ?? "public").ToLowerInvariant() == "private" ? ManifestResourceAttributes.Private : ManifestResourceAttributes.Public;
            var er = new EmbeddedResource(name, data, attrs);
            lm.Module.Resources.Add(er);
            ws.Touch(lm);
            ws.Record("resources", "INSERT INTO resources", () => { lm.Module.Resources.Remove(er); ws.Touch(lm); }, () => { lm.Module.Resources.Add(er); ws.Touch(lm); });
            return (0, null, null);
        }).OnDelete(r =>
        {
            var list = r.M.Module.Resources;
            int idx = list.IndexOf(r.R);
            list.RemoveAt(idx);
            ws.Touch(r.M);
            ws.Record("resources", "DELETE FROM resources", () => { list.Insert(idx, r.R); ws.Touch(r.M); }, () => { list.Remove(r.R); ws.Touch(r.M); });
            return (null, null);
        });
        db.Register(res);

        var elems = new Table<ResElemRow>("resource_elements",
            "Entries of .resources files (strings, primitives, byte[]/streams, serialized objects). UPDATE value/name, INSERT(resource, name, value), DELETE") { Domain = "resources" };
        elems.Source(c => ws.Modules(c).SelectMany(m => m.Module.Resources.Select((r, i) => (r, i))
                .Where(x => c.Text("resource") is not string rn || x.r.Name == rn)
                .SelectMany(x => ReadSet(m, x.r) is { } set ? set.ResourceElements.Select((e, k) => new ResElemRow(m, x.r, x.i, e, k)) : Array.Empty<ResElemRow>())))
            .Int("module", r => r.M.Id, pushdown: Pushdown.Eq)
            .Text("resource", r => r.R.Name.String, pushdown: Pushdown.Eq)
            .Int("idx", r => r.Index)
            .Text("name", r => r.E.Name, (r, v) => EditSet(s, r, set => Find(set, r.E.Name).Name = Str(v, "name")))
            .Text("type", r => CodeName(r.E.ResourceData.Code), doc: "String, Int32, ByteArray, Stream, ... or UserTypes (a serialized object: type_name)")
            .Text("type_name", r => r.E.ResourceData is BinaryResourceData b ? b.TypeName : CodeName(r.E.ResourceData.Code))
            .Col("value", SqlType.Any, r => ElementValue(r.E), (r, v) => EditSet(s, r, set => Find(set, r.E.Name).ResourceData = MakeData(r.M.Module, r.E.ResourceData, v)))
            .Int("size", r => r.E.ResourceData is BuiltInResourceData { Data: byte[] b } ? b.Length : r.E.ResourceData is BinaryResourceData bd ? bd.Data.Length : (Values.ToText(ElementValue(r.E))?.Length ?? 0))
            .Text("sniffed_type", r => ElementValue(r.E) is byte[] b ? Sniff(b.Take(SniffBytes).ToArray(), r.E.Name) : null)
            .Text("content_type", r => ElementValue(r.E) is byte[] b ? Content(b.Take(EntropyBytes).ToArray()) : null,
                doc: "from the content alone (sniffed_type adds the name's extension): png, pe, gzip, text, ..., 'high entropy' (encrypted or compressed) or binary")
            .Bool("is_baml", r => ElementValue(r.E) is byte[] b && IsBaml(b));
        elems.JournalUpdates = false;
        elems.OnInsert(v =>
        {
            var lm = ws.ModuleArg(v.GetValueOrDefault("module"));
            var rname = Str(v.GetValueOrDefault("resource"), "resource");
            var idx = lm.Module.Resources.ToList().FindIndex(r => r.Name == rname);
            if (idx < 0) throw new SqlException($"no resource '{rname}' (create one with INSERT INTO resources(name, data) VALUES ('{rname}', resource_set_empty()))");
            var row = new ResElemRow(lm, lm.Module.Resources[idx], idx, null!, -1);
            EditSet(s, row, set =>
            {
                var factory = new ResourceDataFactory(lm.Module);
                var name = Str(v.GetValueOrDefault("name"), "name");
                if (set.ResourceElements.Any(e => e.Name == name)) throw new SqlException($"element '{name}' already exists");
                set.Add(new ResourceElement { Name = name, ResourceData = MakeData(lm.Module, null, v.GetValueOrDefault("value")) });
            });
            return (0, null, null);
        }).OnDelete(r =>
        {
            EditSet(s, r, set =>
            {
                var keep = set.ResourceElements.Where(e => e.Name != r.E.Name).ToList();
                var fresh = ResourceElementSet.CreateForResourceReader(r.M.Module);
                foreach (var e in keep) fresh.Add(e);
                Replace(set, fresh);
            });
            return (null, null);
        });
        db.Register(elems);
    }

    // Sets one property of a resource and journals it (the resources table journals its writes itself).
    static void Journaled<V>(Session s, ResRow r, string column, Func<Resource, V> get, Action<Resource, V> set, V value)
    {
        var (res, old) = (r.R, get(r.R));
        set(res, value);
        s.Ws.Record("resources", $"UPDATE resources SET {column}", () => { set(res, old); s.Ws.Touch(r.M); }, () => { set(res, value); s.Ws.Touch(r.M); });
    }

    public static ResourceElementSet? ReadSet(LoadedModule m, Resource r)
    {
        if (r is not EmbeddedResource er) return null;
        try
        {
            var rd = er.CreateReader();
            if (!ResourceReader.CouldBeResourcesFile(rd)) return null;
            return ResourceReader.Read(m.Module, er.CreateReader());
        }
        catch { return null; }
    }

    static ResourceElement Find(ResourceElementSet set, string name) =>
        set.ResourceElements.FirstOrDefault(e => e.Name == name) ?? throw new SqlException($"element '{name}' not found");

    [ThreadStatic] static ResourceElementSet? _replacement;
    static void Replace(ResourceElementSet _, ResourceElementSet fresh) => _replacement = fresh;

    /// <summary>Applies a mutation to a .resources set and regenerates the embedded resource (dnSpy RegenerateEmbeddedResource).</summary>
    static void EditSet(Session s, ResElemRow row, Action<ResourceElementSet> mutate)
    {
        var lm = row.M;
        var list = lm.Module.Resources;
        var old = row.R;
        int idx = list.IndexOf(old);
        if (idx < 0) throw new SqlException("resource no longer exists");
        var set = ReadSet(lm, old) ?? throw new SqlException($"'{old.Name}' is not a .resources file");
        _replacement = null;
        mutate(set);
        var final = _replacement ?? set;
        _replacement = null;
        using var ms = new MemoryStream();
        ResourceWriter.Write(lm.Module, ms, final);
        var fresh = new EmbeddedResource(old.Name, ms.ToArray(), old.Attributes);
        foreach (var ca in old.CustomAttributes) fresh.CustomAttributes.Add(ca);
        list[idx] = fresh;
        s.Ws.Touch(lm);
        s.Ws.Record("resource_elements", $"edit {old.Name}", () => { list[idx] = old; s.Ws.Touch(lm); }, () => { list[idx] = fresh; s.Ws.Touch(lm); });
    }

    static void ReplaceData(Session s, ResRow r, byte[] data)
    {
        if (r.R is not EmbeddedResource old) throw new SqlException("only embedded resources carry data");
        var list = r.M.Module.Resources;
        int idx = list.IndexOf(old);
        var fresh = new EmbeddedResource(old.Name, data, old.Attributes);
        foreach (var ca in old.CustomAttributes) fresh.CustomAttributes.Add(ca);
        list[idx] = fresh;
        s.Ws.Touch(r.M);
        s.Ws.Record("resources", $"replace data of {old.Name}", () => { list[idx] = old; s.Ws.Touch(r.M); }, () => { list[idx] = fresh; s.Ws.Touch(r.M); });
    }

    public static object? ElementValue(ResourceElement e) => e.ResourceData switch
    {
        BuiltInResourceData b => b.Data switch
        {
            null => null,
            string str => str,
            byte[] bytes => bytes,
            bool x => x ? 1L : 0L,
            char ch => ch.ToString(),
            DateTime dt => dt.ToString("O"),
            TimeSpan ts => ts.ToString(),
            decimal d => d.ToString(System.Globalization.CultureInfo.InvariantCulture),
            float f => (double)f,
            double d => d,
            ulong ul => unchecked((long)ul),
            var o => Convert.ToInt64(o),
        },
        BinaryResourceData bd => bd.Data,
        _ => null,
    };

    static IResourceData MakeData(ModuleDef module, IResourceData? like, object? v)
    {
        var f = new ResourceDataFactory(module);
        var code = (like as BuiltInResourceData)?.Code;
        if (v == null) return f.CreateNull();
        try
        {
            return code switch
            {
                ResourceTypeCode.String => f.Create(Values.ToText(v)!),
                ResourceTypeCode.Boolean => f.Create(Values.ToBool(v)),
                ResourceTypeCode.Char => f.Create((Values.ToText(v) ?? "\0")[0]),
                ResourceTypeCode.Byte => f.Create((byte)Values.ToLong(v)!.Value),
                ResourceTypeCode.SByte => f.Create((sbyte)Values.ToLong(v)!.Value),
                ResourceTypeCode.Int16 => f.Create((short)Values.ToLong(v)!.Value),
                ResourceTypeCode.UInt16 => f.Create((ushort)Values.ToLong(v)!.Value),
                ResourceTypeCode.Int32 => f.Create((int)Values.ToLong(v)!.Value),
                ResourceTypeCode.UInt32 => f.Create((uint)Values.ToLong(v)!.Value),
                ResourceTypeCode.Int64 => f.Create(Values.ToLong(v)!.Value),
                ResourceTypeCode.UInt64 => f.Create((ulong)Values.ToLong(v)!.Value),
                ResourceTypeCode.Single => f.Create(Convert.ToSingle(v)),
                ResourceTypeCode.Double => f.Create(Convert.ToDouble(v)),
                ResourceTypeCode.Decimal => f.Create(Convert.ToDecimal(v, System.Globalization.CultureInfo.InvariantCulture)),
                ResourceTypeCode.DateTime => f.Create(DateTime.Parse(Values.ToText(v)!, System.Globalization.CultureInfo.InvariantCulture)),
                ResourceTypeCode.TimeSpan => f.Create(TimeSpan.Parse(Values.ToText(v)!, System.Globalization.CultureInfo.InvariantCulture)),
                ResourceTypeCode.ByteArray => f.Create(Values.ToBytes(v)!),
                ResourceTypeCode.Stream => f.CreateStream(Values.ToBytes(v)!),
                null when like is BinaryResourceData bd => new BinaryResourceData(new UserResourceType(bd.TypeName, ResourceTypeCode.UserTypes), Values.ToBytes(v)!, bd.Format),
                _ => v switch
                {
                    byte[] bytes => f.Create(bytes),
                    long l => l is >= int.MinValue and <= int.MaxValue ? f.Create((int)l) : f.Create(l),
                    double d => f.Create(d),
                    _ => f.Create(Values.ToText(v)!),
                },
            };
        }
        catch (Exception e) when (e is FormatException or OverflowException or InvalidCastException)
        {
            throw new SqlException($"cannot store {Fmt(v)} as {code}");
        }
    }

    public static bool IsBaml(byte[] b) =>
        b.Length > 16 && b[4] == 'M' && b[5] == 0 && b[6] == 'S' && b[7] == 0 && b[8] == 'B' && b[9] == 0 && b[10] == 'A' && b[11] == 0;

    /// <summary>Prefix length Sniff looks at: long enough that a short text header on random data is not taken for text.</summary>
    const int SniffBytes = 1024, EntropyBytes = 64 * 1024;

    // What the bytes are, without the name: a payload named *.exe that is AES ciphertext is 'high entropy', not a PE.
    public static string Content(byte[] b)
    {
        var kind = Sniff(b.Length > SniffBytes ? b[..SniffBytes] : b, "");
        if (kind != "binary" || b.Length < 256 || Overlay.Entropy(b) <= 7.5) return kind;
        // compressed rather than encrypted when the bytes inflate: decompress() takes them (after a 4-byte length too)
        return ProtectionTables.Stream(b) ?? "high entropy";
    }

    public static string Sniff(byte[] b, string name)
    {
        bool Starts(params byte[] m) => b.Length >= m.Length && b.AsSpan(0, m.Length).SequenceEqual(m);
        if (Starts(0x89, 0x50, 0x4E, 0x47)) return "png";
        if (Starts(0x47, 0x49, 0x46, 0x38)) return "gif";
        if (Starts(0xFF, 0xD8, 0xFF)) return "jpeg";
        if (Starts(0x42, 0x4D)) return "bmp";
        if (Starts(0x00, 0x00, 0x01, 0x00)) return "ico";
        if (Starts(0x00, 0x00, 0x02, 0x00)) return "cur";
        if (Starts(0x4D, 0x5A)) return "pe";
        if (Starts(0x50, 0x4B, 0x03, 0x04)) return "zip";
        if (Starts(0x1F, 0x8B)) return "gzip";
        if (Starts(0xCE, 0xCA, 0xEF, 0xBE)) return "resources";
        if (Starts(0x7F, 0x45, 0x4C, 0x46)) return "elf";
        if (IsBaml(b)) return "baml";
        if (b.Length == 0) return "empty";
        var text = b.SkipWhile(x => x is 0xEF or 0xBB or 0xBF).ToArray();
        if (text.All(x => x is 9 or 10 or 13 || x >= 0x20 && x != 0x7F) && IsUtf8(text))
        {
            var t = System.Text.Encoding.UTF8.GetString(text).TrimStart();
            if (t.Length > 1 && t[0] == '<' && (char.IsLetter(t[1]) || t[1] is '?' or '!' or '/')) return "xml"; // not "<#" (a PowerShell comment)
            if (t.StartsWith('{') || t.StartsWith('[')) return "json";
            return "text";
        }
        var ext = Path.GetExtension(name).ToLowerInvariant();
        return ext.Length > 1 ? "binary" + ext : "binary";
    }

    /// <summary>Strict UTF-8 check of a prefix; a multi-byte sequence cut off at the end of the sample still counts.</summary>
    static bool IsUtf8(byte[] b)
    {
        for (int i = 0; i < b.Length;)
        {
            int c = b[i], n = c < 0x80 ? 0 : c is >= 0xC2 and <= 0xDF ? 1 : c is >= 0xE0 and <= 0xEF ? 2 : c is >= 0xF0 and <= 0xF4 ? 3 : -1;
            if (n < 0) return false;
            for (int k = 1; k <= n; k++)
                if (i + k < b.Length && (b[i + k] & 0xC0) != 0x80) return false;
            i += n + 1;
        }
        return true;
    }
}
