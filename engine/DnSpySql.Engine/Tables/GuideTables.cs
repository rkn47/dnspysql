// dnspysql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Sql;

namespace DnSpySql.Tables;

/// <summary>
/// How to use dnspysql, from inside it: the workflow guides (Guides/*.md, embedded in the engine) as rows, so any
/// front end can read them with SQL and the MCP server can offer them as prompts.
/// </summary>
public static class GuideTables
{
    public sealed record Guide(string Topic, string Title, string Description, string Text);

    // Order is the reading order: basics first.
    static readonly (string topic, string description)[] Topics =
    {
        ("basics", "Rules, sessions, handles and resolve(), schema discovery, required filters, writes and undo: read first"),
        ("explore", "Understand code: orientation, search, decompiled C# and IL, callers and the Analyzer, call graphs"),
        ("triage", "Statically triage a sample: protection, capabilities, indicators, config extraction, report"),
        ("unpack", "Protected and packed assemblies: anti-tamper, embedded PEs, decoding resources and payloads in SQL"),
        ("dnspy", "Hand results to dnSpy: comments, bookmarks, breakpoints, dnSpy.xml, annotated copies"),
    };

    static readonly Lazy<IReadOnlyList<Guide>> all = new(Load);

    public static IReadOnlyList<Guide> All => all.Value;

    static IReadOnlyList<Guide> Load()
    {
        var asm = typeof(GuideTables).Assembly;
        var list = new List<Guide>();
        foreach (var (topic, description) in Topics)
        {
            using var stream = asm.GetManifestResourceStream($"DnSpySql.Guides.{topic}.md")
                               ?? throw new InvalidOperationException($"guide '{topic}' is not embedded in the engine");
            var text = new StreamReader(stream).ReadToEnd().Replace("\r\n", "\n");
            var title = text.StartsWith("# ", StringComparison.Ordinal) ? text[2..text.IndexOf('\n')].Trim() : topic;
            list.Add(new Guide(topic, title, description, text));
        }
        return list;
    }

    public static void Register(Session s)
    {
        s.Db.Register(new Table<Guide>("dnspysql_guides",
                "How to use dnspysql, for people and agents: one guide per workflow (basics, explore, triage, unpack, dnspy). " +
                "SELECT text FROM dnspysql_guides WHERE topic = 'basics'; the MCP server offers the same guides as prompts") { Domain = "meta" }
            .Source(c => c.Text("topic") is string t ? All.Where(g => g.Topic == t) : All)
            .Text("topic", g => g.Topic, pushdown: Pushdown.Eq)
            .Text("title", g => g.Title)
            .Text("description", g => g.Description)
            .Text("text", g => g.Text, doc: "the guide, in Markdown"));
    }
}
