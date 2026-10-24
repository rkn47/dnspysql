# DnSpySql basics

DnSpySql is one thing: an SQL interface to dnSpy's model of a .NET assembly (dnlib's metadata and dnSpyEx's
decompiler) — metadata, IL, cross-references, dnSpy's Analyzer, decompiled C# with its line-to-IL mapping, resources,
PE bytes, PDB data, and dnSpy's breakpoint configuration. It maps dnSpy to tables and does not analyse for you:
triage, config extraction and unpacking are the agent's own work, done with these tables plus your own code and tools.
Other guides: `SELECT topic, title FROM dnspysql_guides`.

## Rules

- Never execute the assembly or anything you decode from it. DnSpySql only parses the file; nothing here runs sample
  code. Never contact URLs or hosts found in a sample, and defang them in reports (`hxxps://evil[.]com`).
- Work on a copy. Annotations are saved to `<first input>.dnspysql.json`; `save()` writes to the path you give, so
  never give the original's.
- On Windows, breakpoints, bookmarks and other dnSpy state are merged into dnSpy's `dnSpy.xml` after each statement
  that changes them (runtime setting `dnspy_xml`, `off` disables it). Ask the user before changing their dnSpy setup.
- Read every `note:` after a result: files written, `dnSpy.xml` updated or blocked, ambiguous names.

## Sessions

- `SELECT open('C:/abs/path/app.dll')` loads an assembly and returns its module id. `open_bytes` (bytes you decoded
  yourself) and `open_bundle_entry` add modules too. Once several are loaded, filter on `module`.
- Memory is only released by closing: work sample by sample, open → query → close. `SELECT close(id)` takes a
  module out with every module that came out of it (`modules.derived_from`: stages opened from its bytes) when the
  statement ends; `close_all()` closes everything but the project file's module. A module with unsaved edits is
  refused (save it first; undoing the edits still leaves it marked as edited). Ids are never reused. For bulk work start
  the server with `--no-project`: otherwise the first module opened holds the project file and stays open.
- The CLI runs one session per process: undo and unsaved edits end with it. Put a multi-step job in one process
  (several `-c`, or `-f script.sql`), or use the MCP or HTTP server.

## Handles

- `handle = module << 32 | metadata token`. Columns such as `method`, `type`, `owner`, `caller` and `target` hold
  handles; output shows them as integers. `tok(h)` prints `0x1_06000014`, and that text, the integer, `'0x106000014'`
  and a bare token (`0x06000014`, current module: `use_module(id)`) are all accepted as input.
- `resolve('Ns.Type')`, `resolve('Ns.Outer/Nested')`, `resolve('Ns.Type::Method')`, `resolve('Ns.Type::.ctor')`,
  `resolve('Ns.Type::field')`. Name an overload by its parameter types: `resolve('Ns.Type::Load(System.String)')`.
  Without them the first overload is returned, with a note. With several modules it searches the current one first
  and notes a name found in more than one; `resolve(name, NULL, module)` searches one. `resolve()` returns NULL when nothing matches, and it uses
  current names, so after a rename only the new name works. A NULL matches nothing in `WHERE x = resolve(...)`: when
  a query returns 0 rows, check the `resolve()`.
- `name_of`, `kind_of`, `module_of`, `token_of` and `def_of` (a reference to its definition) go the other way. With
  obfuscated names, keep using handles once you have them.

## Discovery

```sql
SELECT table_name, domain, required_filter, description FROM dnspysql_tables ORDER BY domain;
SELECT column_name, type, writable, pushdown, description FROM dnspysql_columns WHERE table_name = 'methods';
SELECT signature, mutates, description FROM dnspysql_functions WHERE name LIKE 'bp_%';
```

## Rules of the SQL surface

- Tables computed from an argument need it and say so: `pseudocode`, `pseudocode_lines` and `pseudocode_refs`
  (`handle`), `analyze` (`target`), `search` (`query`), `md_rows` (`table_name`), `byte_search` (`pattern`),
  `api_docs` (`member` or `doc_id`), `split_text` (`text`).
- `il`, `locals`, `exception_handlers`, `blocks` and `cfg_edges` read every body without `WHERE method = <handle>`.
- Equality filters on `pushdown` columns are answered by the engine; other filters run after the scan. Add `LIMIT`
  while exploring.
- `callers` includes calls that reach a method through a base or interface method it overrides or implements
  (`via` = `virtual` or `interface`); `call_edges` and `xrefs` record the method the IL names.
- `decompile()`, `decompile_module()` and `il_text()` never fail a query: a failure comes back as text starting with
  `/* dnspysql:`.
- Blobs: `length()`, `hex(substr(x, 1, 16))`, `text_decode(x [, 'utf-16le'])`, `int_at(x, offset, size)`, and the
  `REGEXP` family. Decoding and crypto (base64, decompress, decrypt, hashes) are not here: export the bytes
  (`resources.data`, `read_bytes()`) and do those in your own code. SQL string literals have no backslash escapes.

## Writes

Writes are `UPDATE`/`INSERT`/`DELETE` and the functions marked `mutates`. Each statement is one undo group:
`undo(n)`, `redo(n)`, the `transactions` table. `--readonly` refuses them, and so does a session after
`SELECT set_setting('read_only', 1)` (one way: it cannot be switched off). An UPDATE that reports 0 changed rows
usually had a NULL `resolve()`. Model edits stay in memory until `save('new/path')` (`is_dirty()`). Annotations
(`comments`, `tags`, `bookmarks`, `breakpoints`, `kv`) persist at once in the project file; `kv` is a scratchpad for
notes that a later session can read.
