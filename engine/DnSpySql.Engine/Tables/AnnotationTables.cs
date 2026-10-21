// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Sql;
using dnlib.DotNet;
using static DnSpySql.Tables.TableKit;

namespace DnSpySql.Tables;

/// <summary>User annotations persisted in the project file: comments, bookmarks, tags, key/values.</summary>
public sealed record KvRow(string Key, string Value);

public static class AnnotationTables
{
    public static string ModuleKey(LoadedModule lm) => lm.Module.Mvid?.ToString() ?? lm.Sha256;

    public static AnnLocation Loc(Session s, object? handle, object? offset)
    {
        var h = s.Ws.HandleArg(handle) ?? throw new SqlException("handle is required");
        var lm = s.Ws.Get(Handle.Module(h));
        return new AnnLocation { Mvid = ModuleKey(lm), Token = Handle.Token(h), Offset = offset == null ? -1 : (int)Lng(offset, "offset") };
    }

    public static long? HandleOf(Session s, AnnLocation at)
    {
        var lm = s.Ws.Modules.FirstOrDefault(m => ModuleKey(m) == at.Mvid);
        return lm == null ? null : lm.H(at.Token);
    }

    public static string? NameOf(Session s, AnnLocation at)
    {
        if (HandleOf(s, at) is not long h) return null;
        try { return (s.Ws.Resolve(h).item as IFullName)?.FullName; } catch { return null; }
    }

    public static string? CommentAt(Session s, long methodHandle, int offset, int end)
    {
        var lm = s.Ws.Get(Handle.Module(methodHandle));
        var key = ModuleKey(lm);
        var tok = Handle.Token(methodHandle);
        var hits = s.Store.Comments.Where(c => c.At.Mvid == key && c.At.Token == tok && c.At.Offset >= offset && c.At.Offset < end).Select(c => c.Text).ToList();
        return hits.Count == 0 ? null : string.Join(" | ", hits);
    }

    public static void ListUndo<T>(Session s, string table, List<T> list, T item, bool added)
    {
        void Add() { list.Add(item); s.Store.Changed(); }
        void Remove() { list.Remove(item); s.Store.Changed(); }
        if (added) s.Ws.Record(table, $"INSERT INTO {table}", Remove, Add);
        else s.Ws.Record(table, $"DELETE FROM {table}", Add, Remove);
    }

    public static Action<T, object?> Set<T>(Session s, Action<T, object?> set) => (r, v) => { set(r, v); s.Store.Changed(); };

    public static void Register(Session s)
    {
        var db = s.Db;
        var st = () => s.Store;

        // ---- comments ----
        var comments = new Table<CommentRec>("comments", "Comments on entities (offset -1) or IL offsets inside methods. Persisted in the project file") { Domain = "annotations" };
        comments.Source(c => st().Comments.Where(x => c.Long("handle") is not long h || HandleOf(s, x.At) == s.Ws.Normalize(h)))
            .Keyed(x => x.Id, id => st().Comments.FirstOrDefault(x => x.Id == id))
            .Int("id", x => x.Id)
            .Int("handle", x => HandleOf(s, x.At), pushdown: Pushdown.Eq)
            .Int("offset", x => x.At.Offset, Set<CommentRec>(s, (x, v) => x.At.Offset = v == null ? -1 : (int)Lng(v, "offset")), doc: "IL offset, -1 = the entity itself")
            .Text("kind", x => x.Kind, Set<CommentRec>(s, (x, v) => x.Kind = Values.ToText(v) ?? "eol"), doc: "eol | pre | post | note (free-form)")
            .Text("comment", x => x.Text, Set<CommentRec>(s, (x, v) => { x.Text = Values.ToText(v) ?? ""; x.Updated = DateTime.UtcNow; }))
            .Text("name", x => NameOf(s, x.At))
            .Text("updated", x => x.Updated.ToString("O"));
        comments.OnInsert(v =>
        {
            var rec = new CommentRec { Id = st().NewId(), At = Loc(s, v.GetValueOrDefault("handle"), v.GetValueOrDefault("offset")),
                Kind = Values.ToText(v.GetValueOrDefault("kind")) ?? "eol", Text = Str(v.GetValueOrDefault("comment"), "comment") };
            st().Comments.Add(rec); st().Changed();
            ListUndo(s, "comments", st().Comments, rec, true);
            return (rec.Id, null, null);
        }).OnDelete(x => { st().Comments.Remove(x); st().Changed(); ListUndo(s, "comments", st().Comments, x, false); return (null, null); });
        db.Register(comments);

        // ---- bookmarks ----
        var bms = new Table<BookmarkRec>("bookmarks", "Bookmarks (dnSpy Bookmarks window). Persisted in the project file; bp_export() hands them to dnSpy") { Domain = "annotations" };
        bms.Source(_ => st().Bookmarks)
            .Keyed(x => x.Id, id => st().Bookmarks.FirstOrDefault(x => x.Id == id))
            .Int("id", x => x.Id)
            .Int("handle", x => HandleOf(s, x.At))
            .Int("offset", x => x.At.Offset)
            .Text("name", x => x.Name, Set<BookmarkRec>(s, (x, v) => x.Name = Values.ToText(v) ?? ""))
            .Text("category", x => x.Category, Set<BookmarkRec>(s, (x, v) => x.Category = Values.ToText(v) ?? ""))
            .Text("comment", x => x.Comment, Set<BookmarkRec>(s, (x, v) => x.Comment = Values.ToText(v) ?? ""))
            .Bool("enabled", x => x.Enabled, Set<BookmarkRec>(s, (x, v) => x.Enabled = Values.ToBool(v)))
            .Text("target", x => NameOf(s, x.At));
        bms.OnInsert(v =>
        {
            var rec = new BookmarkRec { Id = st().NewId(), At = Loc(s, v.GetValueOrDefault("handle"), v.GetValueOrDefault("offset")),
                Name = Values.ToText(v.GetValueOrDefault("name")) ?? "", Category = Values.ToText(v.GetValueOrDefault("category")) ?? "",
                Comment = Values.ToText(v.GetValueOrDefault("comment")) ?? "" };
            st().Bookmarks.Add(rec); st().Changed();
            ListUndo(s, "bookmarks", st().Bookmarks, rec, true);
            return (rec.Id, null, null);
        }).OnDelete(x => { st().Bookmarks.Remove(x); st().Changed(); ListUndo(s, "bookmarks", st().Bookmarks, x, false); return (null, null); });
        db.Register(bms);

        // ---- tags (progress tracking: 'progress:reviewed', 'role:crypto' ...) ----
        var tags = new Table<TagRec>("tags", "Tags on entities for triage/progress tracking") { Domain = "annotations" };
        tags.Source(c => st().Tags.Where(x => (c.Text("tag") is not string t || x.Tag == t) && (c.Long("handle") is not long h || HandleOf(s, x.At) == s.Ws.Normalize(h))))
            .Keyed(x => x.Id, id => st().Tags.FirstOrDefault(x => x.Id == id))
            .Int("id", x => x.Id)
            .Int("handle", x => HandleOf(s, x.At), pushdown: Pushdown.Eq)
            .Text("tag", x => x.Tag, Set<TagRec>(s, (x, v) => x.Tag = Str(v, "tag")), pushdown: Pushdown.Eq)
            .Text("comment", x => x.Comment, Set<TagRec>(s, (x, v) => x.Comment = Values.ToText(v) ?? ""))
            .Text("name", x => NameOf(s, x.At));
        tags.OnInsert(v =>
        {
            var at = Loc(s, v.GetValueOrDefault("handle"), null);
            var tag = Str(v.GetValueOrDefault("tag"), "tag");
            var existing = st().Tags.FirstOrDefault(x => x.Tag == tag && x.At.Mvid == at.Mvid && x.At.Token == at.Token);
            if (existing != null) return (existing.Id, null, null);
            var rec = new TagRec { Id = st().NewId(), At = at, Tag = tag, Comment = Values.ToText(v.GetValueOrDefault("comment")) ?? "" };
            st().Tags.Add(rec); st().Changed();
            ListUndo(s, "tags", st().Tags, rec, true);
            return (rec.Id, null, null);
        }).OnDelete(x => { st().Tags.Remove(x); st().Changed(); ListUndo(s, "tags", st().Tags, x, false); return (null, null); });
        db.Register(tags);

        // ---- kv (idasql netnode_kv analogue: agent memory / progress state) ----
        var kv = new Table<KvRow>("kv", "Persistent key/value store in the project file (agent notes, progress, settings)") { Domain = "annotations" };
        static long KvId(string k) => (long)(uint)StringComparer.Ordinal.GetHashCode(k);
        kv.Source(c => (c.Text("key") is string k ? st().Kv.Where(x => x.Key == k) : st().Kv).Select(x => new KvRow(x.Key, x.Value)).ToList())
            .Keyed(x => KvId(x.Key), id => st().Kv.Where(x => KvId(x.Key) == id).Select(x => new KvRow(x.Key, x.Value)).FirstOrDefault())
            .Text("key", x => x.Key, pushdown: Pushdown.Eq)
            .Text("value", x => x.Value, (x, v) => { st().Kv[x.Key] = Values.ToText(v) ?? ""; st().Changed(); });
        kv.OnInsert(v =>
        {
            var k = Str(v.GetValueOrDefault("key"), "key");
            var had = st().Kv.TryGetValue(k, out var old);
            var nv = Values.ToText(v.GetValueOrDefault("value")) ?? "";
            st().Kv[k] = nv; st().Changed();
            s.Ws.Record("kv", "INSERT INTO kv", () => { if (had) st().Kv[k] = old!; else st().Kv.Remove(k); st().Changed(); }, () => { st().Kv[k] = nv; st().Changed(); });
            return (KvId(k), null, null);
        }).OnDelete(x =>
        {
            st().Kv.Remove(x.Key); st().Changed();
            s.Ws.Record("kv", "DELETE FROM kv", () => { st().Kv[x.Key] = x.Value; st().Changed(); }, () => { st().Kv.Remove(x.Key); st().Changed(); });
            return (null, null);
        });
        db.Register(kv);
    }
}
