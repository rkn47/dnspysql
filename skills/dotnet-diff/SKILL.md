---
name: dotnet-diff
description: Compare two versions of a .NET assembly with DnSpySql — types and members added or removed, methods whose IL changed, references, resources and P/Invokes that differ, then read the changed methods side by side in decompiled C#. Use for patch diffing, "what changed between these builds", finding the fix for a vulnerability, or comparing two samples of one family.
---

# Diffing two .NET assemblies with DnSpySql

Open both versions in one session; every table has a `module` column, so a diff is a join of a table with itself.
Metadata tokens differ between builds, so match by **name** (`full_name` includes the signature), never by handle or
token. Read `SELECT text FROM dnspysql_guides WHERE topic = 'basics'` first.

## 1. Open both

```sql
SELECT open('C:/cases/diff/v1/App.dll');   -- module 1
SELECT open('C:/cases/diff/v2/App.dll');   -- module 2
SELECT id, file_name, assembly_version, mvid, sha256, type_count, method_count FROM modules;
```

Use one session (an MCP server, or one CLI process with `-f diff.sql`): the temporary table below lives as long as the
session. With the same names in both, `resolve(name, NULL, <module>)` picks the version.

## 2. What changed

```sql
-- one fingerprint per method: its instructions as text, in order (tokens differ between builds, names do not)
CREATE TEMP TABLE fp AS
  SELECT m.module, m.full_name, m.handle,
         (SELECT group_concat(t, char(10)) FROM (SELECT opcode || ' ' || coalesce(operand_text, '') AS t FROM il
            WHERE il.method = m.handle ORDER BY idx)) AS body
    FROM methods m WHERE m.module IN (1, 2);

SELECT 'added' AS change, b.full_name FROM fp b WHERE b.module = 2 AND b.full_name NOT IN (SELECT full_name FROM fp WHERE module = 1)
UNION ALL SELECT 'removed', a.full_name FROM fp a WHERE a.module = 1 AND a.full_name NOT IN (SELECT full_name FROM fp WHERE module = 2)
UNION ALL SELECT 'changed', a.full_name FROM fp a JOIN fp b ON b.module = 2 AND b.full_name = a.full_name
 WHERE a.module = 1 AND a.body IS NOT b.body;
```

Building `fp` reads every method body of both modules: seconds on a large assembly. For a quick first look, compare
`code_size` and `instr_count` instead (cheap, but it misses a change that keeps the size).

```sql
SELECT 'type added', full_name FROM types WHERE module = 2 AND full_name NOT IN (SELECT full_name FROM types WHERE module = 1)
UNION ALL SELECT 'type removed', full_name FROM types WHERE module = 1 AND full_name NOT IN (SELECT full_name FROM types WHERE module = 2);
SELECT 'field', b.full_name FROM fields b WHERE b.module = 2 AND b.full_name NOT IN (SELECT full_name FROM fields WHERE module = 1);
SELECT a.module, a.name, a.version FROM asmrefs a
 WHERE NOT EXISTS (SELECT 1 FROM asmrefs b WHERE b.module <> a.module AND b.name = a.name AND b.version = a.version);
SELECT a.module, a.dll, a.entry FROM pinvokes a
 WHERE NOT EXISTS (SELECT 1 FROM pinvokes b WHERE b.module <> a.module AND b.dll = a.dll AND b.entry = a.entry);
SELECT a.module, a.name, a.size, a.sha256 FROM resources a
 WHERE NOT EXISTS (SELECT 1 FROM resources b WHERE b.module <> a.module AND b.name = a.name AND b.sha256 = a.sha256);
SELECT a.module, a.value FROM string_refs a WHERE a.kind = 'il'
 AND NOT EXISTS (SELECT 1 FROM string_refs b WHERE b.module <> a.module AND b.kind = 'il' AND b.value = a.value);
```

Renamed members show up as one removed and one added with the same body: match `fp.body` across the two lists to pair
them. An obfuscated build renames everything, so a name-based diff is useless there; deobfuscate both first
(`dotnet-deobfuscate`) or compare by body alone.

## 3. Read a change

```sql
SELECT decompile(resolve('Ns.Type::Method', NULL, 1));
SELECT decompile(resolve('Ns.Type::Method', NULL, 2));
SELECT module, body FROM fp WHERE full_name = '<full name>';   -- the IL of both, instruction by instruction
SELECT caller_name FROM callers WHERE method = resolve('Ns.Type::Method', NULL, 2);  -- who reaches the changed code
```

Diff the two decompiled texts in your own tool (or `diff` on two files) to see the lines. For a security fix, look for
a new check (a bounds or null test, a path canonicalization, a type allowlist before deserialization) and follow the
callers of the changed method back to an entry point to see what input reaches it.

## Report

List what changed by category (added, removed, changed; references, P/Invokes, resources), the changed methods by full
name and `tok(handle)` in each version, and for each change that matters what it does, quoting only the lines that
show it. Close both when done: `SELECT close_all()`.
