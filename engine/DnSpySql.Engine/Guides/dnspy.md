# Handing results to dnSpy

DnSpySql never runs or debugs anything: it prepares what dnSpy shows and where it stops.

| what | reaches dnSpy through |
|---|---|
| comments, tags | `save()` writes `<copy>.xml` beside the copy, shown by dnSpyEx as `///` comments |
| renames | the saved copy |
| breakpoints, bookmarks, module breakpoints, exception settings, Watch, debugger options | `dnSpy.xml`, merged after each statement that changes them (Windows, runtime setting `dnspy_xml`), or `bp_export(path)` |

dnSpy reads `dnSpy.xml` at startup and overwrites it on exit: when a note says dnSpy is running, the user closes it,
then `SELECT dnspy_sync()`.

## Annotate

```sql
SELECT set_comment(resolve('Ns.Crypto::Decrypt'), 'config decryptor: AES-ECB, key = md5(mutex)');
SELECT set_comment(resolve('Ns.Program::Main'), 184, 'settings are plaintext after this');   -- an IL offset
SELECT tag(resolve('Ns.Settings'), 'config');
INSERT INTO bookmarks (handle, offset, name, category, comment) VALUES (resolve('Ns.Program::Main'), 184, 'config', 'config', 'decrypted here');
UPDATE methods SET name = 'DecryptString' WHERE handle = <h>;     -- collect handles first: they survive renames
```

Offsets are IL offsets (`il.offset`, `pseudocode_lines.il_offset`), not instruction indexes: to comment a decompiled
line, take its `il_offset`; `pseudocode_lines.comment` shows the comments back on their lines. An UPDATE reports the
rows it changed: check it.

## Breakpoints

```sql
SELECT line_num, il_offset, line FROM pseudocode_lines WHERE handle = resolve('Ns.Program::Main');
SELECT bp_set_decompiled(resolve('Ns.Program::Main'), 21);
SELECT bp_set(resolve('Ns.Crypto::Decrypt'));
SELECT bp_set_decompiled(resolve('Ns.Crypto::Decrypt'), 9, 'input.Length > 20');   -- names as pseudocode_refs shows them
SELECT bp_trace(resolve('Ns.Crypto::Decrypt'), 0, 'Decrypt({input}) from $CALLER', 1);
SELECT bp_module('stage2*.dll'), break_on_exception('System.Security.Cryptography.CryptographicException');
INSERT INTO dnspy_watch (window, expression) VALUES (0, 'Settings.Host');
SELECT id, method_name, offset, condition, status FROM breakpoints;   -- status must be ok
UPDATE breakpoints SET hit_count = 3, hit_count_kind = 'MultipleOf', labels = 'crypto' WHERE id = 1;
SELECT exception_type, method_name, offset FROM throw_sites;          -- where exceptions are thrown
SELECT name, value, description FROM dnspy_debugger_settings;         -- includes anti-anti-debug options
```

A `status` other than `ok` (`method changed`, `not an instruction boundary`, ...) does not bind in dnSpy.
`bp_enable(0, 'crypto')`, `bp_clear('crypto')` and `bp_toggle(m, offset)` work in bulk by label. Breakpoints that pay
off on a sample: the return of a string decryptor, the call that receives the config, and a loader just before
`Assembly.Load`. For a debugger other than dnSpy, `bp_patch()` writes each plain breakpoint into the IL as
`if (Debugger.IsAttached) Debugger.Break();` (then `save()` a copy); conditions, hit counts and tracepoints are refused.

## Save

`SELECT save('C:/cases/x/sample.annotated.exe')` writes the copy (tokens and MVID kept), its `.xml` documentation and
`.dnspysql.json`; later exports name the saved file, which joins the files dnSpy opens at startup.

Why something does not show in dnSpy: breakpoints and bookmarks are left out while the module has unsaved edits (save
first, and open the saved copy); dnSpy matches modules by full path (`bp_export(path, NULL, '<dir dnSpy opens it
from>')`); dnSpy overwrote the file on exit (`dnspy_sync()` after closing it). `bp_export('<new file>')` writes a file
to import from dnSpy's Breakpoints window instead of touching `dnSpy.xml`. `export_project(dir)` is dnSpy's Export to
Project (`export_project(dir, NULL, 1)` for SDK-style projects).

Tell the user what you wrote and where (the copy, its `.xml`, the project file, whether `dnSpy.xml` was updated), what
to open in dnSpy, which breakpoints exist and what each should show, and whether dnSpy must be restarted.
