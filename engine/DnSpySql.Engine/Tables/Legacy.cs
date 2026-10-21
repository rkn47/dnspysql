// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using DnSpySql.Sql;
using dnlib.DotNet;

namespace DnSpySql.Tables;

/// <summary>
/// The schema of earlier DnSpySql versions, on top of the current one: older column names as extra
/// columns, the overlay and header-repair columns of `modules`, and `refs` / `attributes` as views. Queries written
/// for either tool run unchanged. One name could not be kept: `params.seq` is now the ECMA sequence number
/// (0 = return value), and the older 0-based argument position is `params.arg_index`.
/// </summary>
public static class Legacy
{
    public static void Register(Session s)
    {
        // ---- modules ----
        Alias(s, "modules", "module", "id");
        Alias(s, "modules", "version", "assembly_version");
        Alias(s, "modules", "runtime", "runtime_version");
        Alias(s, "modules", "il_only", "is_il_only");
        Alias(s, "modules", "types", "type_count");
        Col<LoadedModule>(s, "modules", "repair", SqlType.Text, m => m.Repair, "what was repaired to load the file (e.g. a corrupt CLI header), else NULL");
        Col<LoadedModule>(s, "modules", "overlay", SqlType.Text, m => m.Overlay?.Anomaly,
            "data appended after the PE image (payload, second PE, padding), summarized; NULL if none");
        Col<LoadedModule>(s, "modules", "overlay_offset", SqlType.Integer, m => m.Overlay?.Offset,
            "file offset of the appended data, past any Authenticode certificate table");
        Col<LoadedModule>(s, "modules", "overlay_size", SqlType.Integer, m => m.Overlay?.Size ?? 0, "bytes appended after the image, excluding the certificate table");
        Col<LoadedModule>(s, "modules", "overlay_entropy", SqlType.Real, m => m.Overlay?.Entropy,
            "Shannon entropy (bits/byte) of the appended data before any trailing zero padding");
        Col<LoadedModule>(s, "modules", "overlay_kind", SqlType.Text, m => m.Overlay?.Kind,
            "embedded PE | ZIP/7-Zip/RAR/CAB archive | gzip data | PDF document | zero padding | encrypted or compressed data | text | low-entropy filler | data");
        Col<LoadedModule>(s, "modules", "overlay_pe_offset", SqlType.Integer, m => m.Overlay?.EmbeddedPe, "file offset of the first embedded MZ/PE header in the appended data");
        Col<LoadedModule>(s, "modules", "overlay_padding", SqlType.Integer, m => m.Overlay?.Padding, "trailing zero bytes (file inflation)");

        // ---- members: tokens next to the handles ----
        Token(s, "types", "base_token", "base_type");
        Token(s, "types", "declaring_token", "declaring_type");
        Alias(s, "types", "generic_params", "generic_param_count");
        Alias(s, "types", "methods", "method_count");
        Alias(s, "types", "fields", "field_count");
        Col<Row<TypeDef>>(s, "types", "interfaces", SqlType.Text, r => string.Join(", ", r.Item.Interfaces.Select(i => i.Interface?.FullName)),
            "implemented interfaces, comma-separated (see the interfaces table)");
        Token(s, "methods", "type_token", "type");
        Col<Row<MethodDef>>(s, "methods", "param_types", SqlType.Text, r => string.Join(", ", r.Item.MethodSig?.Params.Select(p => p.FullName) ?? []));
        Alias(s, "methods", "il_size", "code_size");
        Alias(s, "methods", "instructions", "instr_count");
        Alias(s, "methods", "locals", "local_count");
        Alias(s, "methods", "handlers", "eh_count");
        Token(s, "fields", "type_token", "type");
        Token(s, "params", "method_token", "method");
        Token(s, "properties", "type_token", "type");
        Token(s, "properties", "getter_token", "getter");
        Token(s, "properties", "setter_token", "setter");
        Token(s, "events", "type_token", "type");
        Token(s, "events", "add_token", "adder");
        Token(s, "events", "remove_token", "remover");
        Token(s, "events", "invoke_token", "raiser");
        Token(s, "pinvokes", "method_token", "method");
        Col<ResRow>(s, "resources", "target", SqlType.Text, r => r.R switch
        {
            LinkedResource l => l.File?.Name.String,
            AssemblyLinkedResource a => a.Assembly?.FullName,
            _ => null,
        }, "linked file or assembly of a non-embedded resource");
        Token(s, "il", "method_token", "method");
        Col<InsRow>(s, "il", "operand_token", SqlType.Integer, r => r.Ins.Operand is IMDTokenProvider p ? (long)p.MDToken.Raw : null,
            "metadata token of the operand, when it is a metadata entity");
        Token(s, "breakpoints", "method_token", "method");
        Alias(s, "breakpoints", "il_offset", "offset");

        // ---- renamed tables ----
        s.Db.Exec("""
            CREATE VIEW refs AS
            SELECT module, from_method & 0xFFFFFFFF AS from_token, from_name AS from_method, offset, opcode,
                   CASE WHEN kind = 'string' THEN 'string'
                        WHEN kind IN ('call', 'callvirt', 'newobj', 'ldftn', 'ldvirtftn', 'jmp') OR to_kind = 'method' THEN 'method'
                        WHEN kind IN ('read', 'write', 'addr') OR to_kind = 'field' THEN 'field'
                        ELSE 'type' END AS kind,
                   to_token, CASE WHEN kind = 'string' THEN string_value ELSE to_name END AS target,
                   CASE WHEN to_def <> 0 THEN to_def >> 32 END AS to_def_module,
                   CASE WHEN to_def <> 0 THEN to_def & 0xFFFFFFFF END AS to_def_token
            FROM xrefs
            """);
        s.Db.Exec("""
            CREATE VIEW attributes AS
            SELECT module, owner & 0xFFFFFFFF AS owner_token, owner_name AS owner, attribute_type AS attribute,
                   ctor & 0xFFFFFFFF AS ctor_token, args
            FROM custom_attributes
            """);
    }

    static ColumnInfo Source(Session s, string table, string column) =>
        s.Db.Table(table).Columns.FirstOrDefault(c => c.Name == column)
        ?? throw new InvalidOperationException($"legacy column: {table}.{column} does not exist");

    // Same value as `source`, under its older name.
    static void Alias(Session s, string table, string alias, string source)
    {
        var src = Source(s, table, source);
        s.Db.Table(table).Columns.Add(new ColumnInfo { Name = alias, Type = src.Type, Get = src.Get, Doc = $"older name of {source}" });
    }

    // The metadata token part of a handle column.
    static void Token(Session s, string table, string alias, string handleColumn)
    {
        var src = Source(s, table, handleColumn);
        s.Db.Table(table).Columns.Add(new ColumnInfo
        {
            Name = alias, Type = SqlType.Integer, Doc = $"metadata token of {handleColumn} (older column)",
            Get = row => Values.ToLong(src.Get(row)) is long h && h != 0 ? h & 0xFFFFFFFF : null,
        });
    }

    static void Col<T>(Session s, string table, string name, SqlType type, Func<T, object?> get, string? doc = null) =>
        s.Db.Table(table).Columns.Add(new ColumnInfo { Name = name, Type = type, Get = row => get((T)row), Doc = doc });
}
