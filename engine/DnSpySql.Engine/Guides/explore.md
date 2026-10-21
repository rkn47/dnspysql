# Understanding code

## Orient

```sql
SELECT key, value FROM binary;
SELECT id, file_name, assembly, kind, target_framework, is_mixed_mode, has_pdb FROM modules;
SELECT method, full_name, kind FROM entry_points;
SELECT full_name, kind, method_count FROM types WHERE NOT is_compiler_generated ORDER BY method_count DESC LIMIT 20;
SELECT dst_assembly, dst_name, call_count FROM external_calls ORDER BY call_count DESC LIMIT 30;
SELECT name, kind, size, content_type FROM resources;
SELECT name, call_in, call_out, hotness_score FROM method_metrics ORDER BY hotness_score DESC LIMIT 15;
```

If `protections` reports obfuscation, anti-tamper or string encryption, read the `unpack` guide first.

## Find

```sql
SELECT kind, full_name, handle FROM jump_entities WHERE name LIKE '%License%';
SELECT kind, full_name, handle, location, offset FROM search WHERE query = 'License';
SELECT * FROM search WHERE query = '/^Get.*Key$/' AND kind = 'method';
SELECT value, referrer_name, offset FROM string_refs WHERE value LIKE '%http%';
SELECT handle, signature FROM methods WHERE type = resolve('Ns.Type') AND name = 'Load';
```

## Read

```sql
SELECT decompile(resolve('Ns.Type::Method'));
SELECT il_text(resolve('Ns.Type::Method'));
SELECT decompile(resolve('Ns.Type::Method'), 'vb');   -- VB.NET, as dnSpy shows it (pseudocode* take language = 'vb')
SELECT line_num, il_offset, line FROM pseudocode_lines WHERE handle = resolve('Ns.Type::Method');
SELECT line_num, text, kind, target FROM pseudocode_refs WHERE handle = resolve('Ns.Type::Method') AND kind IN ('method','field','property');
SELECT summary FROM api_docs WHERE doc_id = 'M:System.Convert.FromBase64String(System.String)';
```

`pseudocode_lines.il_offset` maps a decompiled line to its IL statement; `pseudocode_refs.target` turns each name in
the decompiled text into a handle to follow. Decompile methods one at a time rather than `decompile_module()`.

## Relationships

| question | query |
|---|---|
| who calls M | `SELECT caller_name, call_site, via FROM callers WHERE method = resolve('N.T::M')` |
| what M calls | `SELECT callee_name, call_site, is_external FROM callees WHERE method = resolve('N.T::M')` |
| who reads or writes field F | `analyze WHERE target = resolve('N.T::F')` (`field.read_by`, `field.assigned_by`) |
| who uses or creates type T | `analyze WHERE target = resolve('N.T') AND relation IN ('type.used_by','type.instantiated_by')` |
| overrides and implementations | `analyze` relations `type.subtypes`, `method.overridden_by`, `method.implemented_by` |
| calls into an API | `SELECT from_name, offset FROM xrefs WHERE to_name LIKE '%WebClient::Download%'` |

Transitive callers:

```sql
WITH RECURSIVE up(m, depth) AS (
  SELECT resolve('Ns.Type::Method'), 0
  UNION
  SELECT c.caller, up.depth + 1 FROM up JOIN callers c ON c.method = up.m WHERE up.depth < 5)
SELECT depth, name_of(m) FROM up ORDER BY depth;
```

## Data and resources

```sql
SELECT field_name, type_name, kind, value FROM field_inits WHERE NOT is_default;
SELECT resource, name, type, value FROM resource_elements WHERE type = 'String';
SELECT resource, name, xaml FROM baml;
```

Record what you learn as you go (`set_comment`, `tag`, `INSERT INTO kv`), so the work can resume later.
