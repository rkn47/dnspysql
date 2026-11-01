---
name: dotnet-debug-prep
description: Prepare a dnSpy debugging session for a .NET sample with DnSpySql — choose where to stop (decryptor returns, the config consumer, Assembly.Load and other stage loaders, anti-debug checks, exceptions), set breakpoints, tracepoints, module breakpoints, exception settings, Watch expressions and dnSpy's anti-anti-debug options, and hand an annotated copy to dnSpy. Use when static analysis runs out (runtime-computed values, a stage decrypted in memory) and the user will debug the sample in dnSpy themselves.
---

# Preparing a dnSpy debugging session with DnSpySql

DnSpySql never runs or debugs anything: it decides where dnSpy stops and what it shows. **Debugging runs the sample.**
That is the user's decision, in an isolated VM without network access to anything real; never start it yourself, and
say so in the hand-off. The mechanics of breakpoints, `dnSpy.xml` and saving are in the engine's guide:
`SELECT text FROM dnspysql_guides WHERE topic = 'dnspy'`. Ask the user before changing their `dnSpy.xml`
(the `dnspy_xml` setting); `bp_export('<new file>')` hands over a file to import instead.

## 1. Where to stop

```sql
-- the return of each string decryptor: the plaintext is on the stack
SELECT bp_set(method, offset) FROM il WHERE method = <decryptor> AND opcode = 'ret';
-- stage loaders: just before the bytes become an assembly
SELECT bp_set(from_method, offset) FROM xrefs
 WHERE to_name LIKE '%Assembly::Load(System.Byte[]%' OR to_name LIKE '%AppDomain::Load%' OR to_name LIKE '%Activator::CreateInstance%';
-- the consumer of the config: the first use of a settings field after the decoder
SELECT from_name, offset, kind FROM xrefs WHERE to_def = resolve('Ns.Settings::Host');
-- anti-debug checks, to see them fire and step past them
SELECT from_name, offset, to_name FROM xrefs
 WHERE to_name LIKE '%Debugger::get_IsAttached%' OR to_name LIKE '%Debugger::IsLogging%';
SELECT method_name, dll, entry FROM pinvokes
 WHERE entry IN ('IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess', 'OutputDebugStringA', 'OutputDebugStringW');
```

A tracepoint logs and keeps running, which suits a decryptor called thousands of times:
`SELECT bp_trace(<decryptor>, 0, 'Decrypt({input}) from $CALLER', 1)` (`{expression}` with the parameter names
`pseudocode_refs` shows; also `$FUNCTION`, `$CALLSTACK`, `$TID`). On a decompiled line use
`bp_set_decompiled(<method>, <line>, '<condition>')` with the names `pseudocode_refs` shows; a hit count
(`UPDATE breakpoints SET hit_count = 1, hit_count_kind = 'Equals' WHERE id = ...`) stops only the first time.

## 2. Around the code

```sql
SELECT bp_module('stage2*.dll');                       -- a stage loaded at runtime (module_breakpoints.is_in_memory)
SELECT break_on_exception('System.Security.Cryptography.CryptographicException');   -- a wrong key
SELECT exception_type, method_name, offset FROM throw_sites;   -- what the code throws itself
INSERT INTO dnspy_watch (window, expression) VALUES (0, 'Settings.Host');
SELECT name, value, description FROM dnspy_debugger_settings
 WHERE name IN ('PreventManagedDebuggerDetection', 'AntiIsDebuggerPresent', 'AntiCheckRemoteDebuggerPresent');
UPDATE dnspy_debugger_settings SET value = 1 WHERE name = 'PreventManagedDebuggerDetection';
```

dnSpy's anti-anti-debug options hide the debugger from the common checks; the breakpoints from §1 show whether the
sample has others.

## 3. Hand off

```sql
SELECT id, method_name, offset, instruction, condition, is_tracepoint, status FROM breakpoints;   -- every status ok
SELECT set_comment(<decryptor>, 'breakpoint on each ret: the plaintext');
SELECT save('C:/cases/x/sample.debug.exe');            -- breakpoints and bookmarks now point at this copy
```

Breakpoints are left out of `dnSpy.xml` while the module has unsaved edits, and dnSpy matches the file by full path:
the user must open the saved copy, from where it was saved (`bp_export(path, NULL, '<dir in the VM>')` when the VM
sees another path). dnSpy must be closed while `dnSpy.xml` changes.

Tell the user: which file to open in dnSpy, each breakpoint and what it should show when it hits, the debugger options
set, that running it executes the sample (VM, no network), and whether they must restart dnSpy.
