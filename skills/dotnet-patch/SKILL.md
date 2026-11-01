---
name: dotnet-patch
description: Patch and rebuild a .NET assembly with DnSpySql — stub a method's return value, rewrite a method or a whole class in C#, add members, edit IL instruction by instruction, rewrite string literals or raw bytes, check each change in the decompiled code, undo mistakes, and save a patched copy that keeps its tokens. Use when asked to patch, fix, modify, stub out or rebuild a .NET binary the user is entitled to change (their own software, a CTF or crackme, a compatibility fix).
---

# Patching a .NET assembly with DnSpySql

These are dnSpy's editing commands as SQL functions on the live model: every edit shows at once in `decompile()`,
each statement is one undo group (`undo()`, `redo()`, the `transactions` table), and nothing is written until
`save()`. Patch only what the user is entitled to change, and say what the patch does. DnSpySql never runs the result;
whether and where to run the patched copy is the user's call, and never on a malware sample outside a sandbox.

Read `SELECT text FROM dnspysql_guides WHERE topic = 'basics'` first. Work on a copy and save to a new path.

## 1. Find the place

```sql
SELECT handle, full_name, signature FROM methods WHERE name LIKE '%License%' OR name LIKE '%Valid%';
SELECT decompile(resolve('App.License::IsValid'));
SELECT caller_name, call_site FROM callers WHERE method = resolve('App.License::IsValid');
SELECT line_num, il_offset, line FROM pseudocode_lines WHERE handle = resolve('App.License::IsValid');
```

## 2. Pick the smallest edit that does it

| goal | function |
|---|---|
| a method returns a constant | `set_body_stub(m, 1)` (dnSpy "Replace Method Body with Stub"; `stub_return` is the same) |
| rewrite one method in C# | `compile_method(m, 'public bool IsValid() { return Key.Length > 0; }')` (dnSpy "Edit Method (C#)") |
| rewrite a class in C# | `edit_type(t, '<the full class>')` (dnSpy "Edit Class (C#)"); closures, iterators and async are spliced |
| add fields, methods, nested types | `add_members(t, '<C# member declarations>')`, `add_type('<C# source>')` |
| change single instructions | `il_set`, `il_insert`, `il_remove`, `il_nop`, `il_invert_branch`, `il_skip_branch`, `il_to_unconditional` (by `il.idx`) |
| a string literal everywhere | `replace_string('old', 'new')` |
| metadata (names, flags, constants) | `UPDATE types/methods/fields/params/properties SET ...` |
| resources | `UPDATE resources ...`, `add_resource`, `set_resource_data`, `UPDATE resource_elements ...` |
| bytes, as a hex editor | `patch_bytes(offset, 'hex')`, `UPDATE file_bytes` or `UPDATE pe_fields`, saved with `save_raw()`: the original file plus these patches, without model edits |

```sql
SELECT set_body_stub(resolve('App.License::IsValid'), 1);
SELECT compile_preview(resolve('App.License::IsValid'), 'public bool IsValid() { return true; }');   -- when a compile fails
SELECT idx, offset, opcode, operand_text FROM il WHERE method = resolve('App.License::Check');
SELECT il_invert_branch(resolve('App.License::Check'), 7);
```

The C# compiler sees the type's private members and compiles against the SDK's reference pack, so the patch
references `System.Runtime` like the original build. A compile error comes back with the compiler's message; fix the
source, or read what `compile_preview` hands the compiler.

## 3. Check, undo, save

```sql
SELECT decompile(resolve('App.License::IsValid'));      -- after every edit
SELECT kind, group_id, table_name, description FROM transactions ORDER BY seq DESC LIMIT 10;
SELECT undo();                                           -- the last statement's edits
SELECT is_dirty();
SELECT strip_strong_name();                              -- a signed assembly no longer matches its signature once edited
SELECT save('C:/work/patched/App.dll');                  -- tokens and MVID kept (dnSpy "Preserve All")
```

`save()` also writes `App.xml` and `App.dll.dnspysql.json` beside the copy (comments and annotations); set
`save_sidecars` to 0 for the bare assembly. An edited ReadyToRun image is saved as IL-only
(`save_strip_ready_to_run`), since the runtime would otherwise keep running the precompiled code. Then reopen the copy
(`SELECT open('C:/work/patched/App.dll')`) and decompile the patched methods again to confirm the file says what the
model said.

## Tell the user

What was changed (method by full name and `tok(handle)`, before and after in a few decompiled lines), where the copy
is, whether the strong name was stripped, and that the original file is untouched.
