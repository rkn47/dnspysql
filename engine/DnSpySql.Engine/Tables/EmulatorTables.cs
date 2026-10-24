// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Sql;

namespace DnSpySql.Tables;

/// <summary>The IL interpreter's model of the world, as a table: what it answers, calls and refuses.</summary>
public static class EmulatorTables
{
    public sealed record ModelRow(string Area, string Name, string Kind, string Answer, string Why);

    public static void Register(Session s)
    {
        var rows = Emulator.Model().Select(m => new ModelRow(m.Area, m.Name, m.Kind, m.Answer, m.Why)).ToList();
        s.Db.Register(new Table<ModelRow>("emulator_model",
                "What the IL interpreter (emulate, decryptor_calls, decoded_fields, untamper) answers for the environment, which framework " +
                "types and members it calls, and what it refuses: why a plaintext says %TEMP%\\, or why an emulation stopped") { Domain = "triage" }
            .Source(c => c.Text("area") is string a ? rows.Where(r => r.Area == a) : rows)
            .Text("area", r => r.Area, pushdown: Pushdown.Eq, doc: "environment | allowlist | nondeterministic")
            .Text("name", r => r.Name, doc: "the API (full name, or P/Invoke entry point), type or member")
            .Text("kind", r => r.Kind, doc: "placeholder | no debugger | image | no-op | refused | allowed type | allowed member | blocked member")
            .Text("answer", r => r.Answer, doc: "what the code gets")
            .Text("why", r => r.Why)
            .Estimate(150, 1));
    }
}
