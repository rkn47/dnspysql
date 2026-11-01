# Understanding code

## Orient

```sql
SELECT key, value FROM binary;
SELECT id, file_name, assembly, kind, target_framework, is_mixed_mode, has_pdb FROM modules;
SELECT method, full_name, kind FROM entry_points;
SELECT name, type_count FROM namespaces ORDER BY type_count DESC;
SELECT full_name, kind, method_count FROM types WHERE NOT is_compiler_generated ORDER BY method_count DESC LIMIT 20;
SELECT name, version, resolved_path FROM asmrefs;
SELECT dst_assembly, dst_name, call_count FROM external_calls ORDER BY call_count DESC LIMIT 30;
SELECT dll, entry, methods FROM native_imports;
SELECT name, kind, size, content_type FROM resources;
SELECT name, call_in, call_out, hotness_score FROM method_metrics ORDER BY hotness_score DESC LIMIT 15;
```

Obfuscated names (non-printable, `a`/`b`/`#=q…`) mean you work by handle and by shape (`method_metrics`, call graphs,
`il`) rather than by name.

## Find

```sql
SELECT kind, full_name, handle FROM jump_entities WHERE name LIKE '%License%';
SELECT kind, full_name, handle, location, offset FROM search WHERE query = 'License';
SELECT * FROM search WHERE query = '/^Get.*Key$/' AND kind = 'method';
SELECT * FROM search WHERE query = 'password' AND kind = 'string';
SELECT value, referrer_name, offset FROM string_refs WHERE value LIKE '%http%';
SELECT method_name, offset, value FROM literals WHERE kind <> 'string' AND value = 0x5A4D;   -- magic numbers
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

`pseudocode_lines.il_offset` maps a decompiled line to its IL statement, and `method` is the real method (`MoveNext`
for async methods and iterators); breakpoints and comments use this mapping. `pseudocode_refs.target` turns each name
in the decompiled text into a handle to follow, which is more reliable than resolving names you read. A failure comes
back as `/* dnspysql: ... */`: fall back to `il_text()`. Decompile methods one at a time rather than
`decompile_module()`, which can be megabytes.

## Relationships

| question | query |
|---|---|
| who calls M | `SELECT caller_name, call_site, via FROM callers WHERE method = resolve('N.T::M')` |
| what M calls | `SELECT callee_name, call_site, is_external FROM callees WHERE method = resolve('N.T::M')` |
| who reads or writes field F | `analyze WHERE target = resolve('N.T::F')` (`field.read_by`, `field.assigned_by`) |
| who uses or creates type T | `analyze WHERE target = resolve('N.T') AND relation IN ('type.used_by','type.instantiated_by')` |
| overrides and implementations | `analyze` relations `type.subtypes`, `method.overridden_by`, `method.implemented_by` |
| calls into an API | `SELECT from_name, offset FROM xrefs WHERE to_name LIKE '%WebClient::Download%'` |
| what relations exist | `SELECT relation, count(*) FROM analyze WHERE target = <h> GROUP BY relation` |

Transitive callers:

```sql
WITH RECURSIVE up(m, depth) AS (
  SELECT resolve('Ns.Type::Method'), 0
  UNION
  SELECT c.caller, up.depth + 1 FROM up JOIN callers c ON c.method = up.m WHERE up.depth < 5)
SELECT depth, name_of(m) FROM up ORDER BY depth;
```

Swap in `callees`/`callee` to go downwards, and stop at `is_external`. Async methods and iterators link to their state
machine's `MoveNext` through `xrefs.kind = 'async'`.

## Constants and resources

```sql
SELECT value, referrer_name, offset FROM string_refs;                 -- every string literal and where it is used
SELECT f.full_name, i.operand_text FROM fields f JOIN il i ON i.operand_text LIKE '%' || f.name;  -- stores into a field
SELECT resource, name, type, value FROM resource_elements WHERE type = 'String';
SELECT name, size, content_type, hex(substr(data, 1, 16)) FROM resources;   -- data is the raw bytes; decode in your own code
SELECT resource, name, xaml FROM baml;
SELECT name, field_type, constant FROM fields WHERE has_default;          -- const / literal fields
SELECT owner_name, attribute_type, args FROM custom_attributes WHERE attribute_type LIKE '%Obfuscation%';
SELECT url, embedded_source IS NOT NULL FROM pdb_documents;                -- source files, if a PDB is there
```

Record what you learn as you go (`set_comment`, `tag`, `INSERT INTO kv`), so the work can resume later.
