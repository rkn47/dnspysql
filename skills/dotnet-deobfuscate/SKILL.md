---
name: dotnet-deobfuscate
description: Make an obfuscated .NET assembly readable with DnSpySql — rename types, methods and fields by role, recover encrypted strings (find the decryptor, reimplement it in your own code, write the plaintext back as comments or into the IL), remove opaque predicates and proxy calls with IL edits, and save a readable copy for dnSpy. Use when names are garbage or invisible, strings go through a decryptor, or the decompiled code is unreadable. Decrypting is your own code; DnSpySql locates, edits and saves.
---

# Deobfuscating a .NET assembly with DnSpySql

DnSpySql gives you the structure (who calls what, which literals go where, every IL instruction) and journaled edits
on the live model; the decompiled view shows each edit at once. It does not decrypt or devirtualize: you read the
algorithm, reimplement it in your own code, and write the result back. Never run the sample or its decryptor.

Read `SELECT text FROM dnspysql_guides WHERE topic = 'basics'` first. Packed payloads and anti-tamper come before this:
the `dotnet-unpack` skill. Work on the module you will save (`WHERE module = <id>` once several are open).

## 1. What kind of obfuscation

```sql
SELECT value FROM binary WHERE key = 'anomalies';         -- invisible/bidi names, nonstandard streams, encrypted bodies
SELECT full_name, kind, method_count FROM types WHERE NOT is_compiler_generated ORDER BY method_count DESC LIMIT 30;
SELECT name, call_in, call_out, string_count, hotness_score FROM method_metrics ORDER BY hotness_score DESC LIMIT 20;
SELECT count(*) FROM string_refs WHERE kind = 'il';        -- few readable literals: strings are encrypted
```

| sign | technique | section |
|---|---|---|
| `a`, `#=q…`, invisible or bidi names | name obfuscation | §2 |
| one static method called from many sites with constant arguments, few readable literals | string encryption | §3 |
| tiny static methods that only forward to another call | proxy calls | §4 |
| a `switch` in a loop over a state variable, branches on constant expressions | control flow obfuscation | §4 |
| bodies that do not decode (`method_bodies.il_status`) | anti-tamper, not readability | `dotnet-unpack` |
| methods that hand an id to one dispatcher | IL virtualization: out of scope, say so | — |

## 2. Rename by role

Collect handles first: handles survive renames, names do not, and obfuscated names are often duplicated.

```sql
-- what a type is: its base, its interfaces, what its methods call
SELECT handle, full_name, base_type_name, interface_count FROM types WHERE NOT is_compiler_generated;
SELECT caller_name, call_site FROM callers WHERE method = <h>;
SELECT callee_name, is_external FROM callees WHERE method = <h>;
-- rename, and check the changed-row count
UPDATE types SET name = 'Settings' WHERE handle = <h>;
UPDATE methods SET name = 'DecryptString' WHERE handle = <h>;
UPDATE fields SET name = 'C2Host' WHERE handle = <h>;
UPDATE params SET name = 'cipherText' WHERE method = <h> AND seq = 1;
SELECT rename_namespace('<obfuscated namespace>', 'App.Core');   -- every top-level type of a namespace at once
```

Name what the code shows (`SendBeacon`, `ReadConfig`), not a guess; `tag(handle, 'renamed')` and
`INSERT INTO kv VALUES ('renames', '...')` keep track over several passes.

## 3. Encrypted strings

```sql
-- the decryptor: static, string-returning, many call sites with constant arguments
SELECT m.handle, m.full_name, count(*) AS sites
  FROM methods m JOIN call_edges c ON c.dst = m.handle
 WHERE m.is_static AND m.return_type = 'System.String' GROUP BY 1, 2 HAVING sites > 10 ORDER BY sites DESC;
SELECT decompile(<decryptor>);                               -- its algorithm, key and any static tables it reads
-- every call site, with the instructions that push its arguments
SELECT c.src, c.src_name, c.idx, c.call_site FROM call_edges c WHERE c.dst = <decryptor>;
SELECT idx, offset, opcode, operand_text FROM il WHERE method = <caller> AND idx BETWEEN <call idx> - 4 AND <call idx>;
```

Reimplement the decryptor in your own code (a scratch script), run it over the arguments, and check a few results
against what the code does with them. Then write the plaintexts back, in one of two ways:

- **As comments** (no change to the code): `SELECT set_comment(<caller>, <call offset>, 'decrypted: "..."')`. dnSpy shows
  them once the copy is saved.
- **Into the IL**, so the decompiled code reads the string itself: NOP the argument pushes and replace the call with
  the literal. Indexes are `il.idx`, not offsets; for a call at index `i` with one argument at `i - 1`:

  ```sql
  SELECT il_nop(<caller>, <i - 1>);
  SELECT il_set(<caller>, <i>, 'ldstr', '<plaintext>');
  SELECT decompile(<caller>);                                -- check it reads right
  ```

  Each statement is one undo group: `undo()` takes back a wrong one. Only do this when the call has no other effect
  (the decompiled decryptor shows whether it touches state).

## 4. Proxies and control flow

```sql
-- proxy methods: a body that is one call and a return
SELECT handle, full_name, instr_count FROM methods WHERE is_static AND instr_count <= 6 AND has_body;
SELECT idx, opcode, operand_text, operand_def FROM il WHERE method = <proxy>;
-- replace a call to the proxy with a call to what it forwards to (operand: the target's handle)
SELECT il_set(<caller>, <i>, 'call', <target handle>);
-- an opaque predicate: a branch whose outcome is fixed
SELECT il_skip_branch(<method>, <i>);        -- never taken
SELECT il_to_unconditional(<method>, <i>);   -- always taken
SELECT il_nop(<method>, <i>, <count>);       -- dead or junk instructions
```

`il_insert`, `il_remove`, `il_invert_branch` and `il_optimize` cover the rest; branches and handlers that pointed at
removed instructions are retargeted. Check every change with `decompile()` before the next. Unflattening a whole state
machine by hand is rarely worth it: comment the states instead (`set_comment` on the `switch` offset).

## 5. Save a readable copy

```sql
SELECT is_dirty();
SELECT save('C:/cases/x/sample.readable.dll');   -- + sample.readable.xml (comments as ///) and .dnspysql.json
```

Tokens and the MVID are kept, so breakpoints and bookmarks carry over to the copy (the `dnspy` guide). Say in the
report which strings were recovered and how, which edits changed the IL, and what was left as it was.
