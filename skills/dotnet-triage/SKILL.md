---
name: dotnet-triage
description: Statically triage a .NET assembly (often malware) with DnSpySql — identify it, map what it references and does, pull out literals and config candidates, name a family only on evidence, and write a defanged report. Use when asked to triage, reverse, analyze or extract the config of a .NET sample. DnSpySql gives the dnSpy model as SQL tables; the judgement and any decoding are yours.
---

# Triaging a .NET assembly with DnSpySql

DnSpySql is an SQL interface to dnSpy's model of an assembly. It maps metadata, IL, decompiled code and the PE file to
tables; it does not decide what is malicious or decode anything for you. You do the triage with these tables plus your
own code. Packed or protected samples: the `dotnet-unpack` skill continues where step 1 shows protection. No
DnSpySql tools at all: follow `INSTALL.md` in the DnSpySql repository (https://github.com/rkn47/dnspysql).

Read the engine's own guides first: `SELECT text FROM dnspysql_guides WHERE topic = 'basics'`, then `'explore'`.

## Rules

- **Never run the sample** or anything decoded from it, and never fetch, resolve or ping what you find in it.
- **Defang** every indicator you write: `hxxps://evil[.]com/gate[.]php`, `10.1.2[.]3`, `user@mail[.]com`.
- Work on a **copy** in a case folder (`cases/<sha256[:12]>/`): annotating writes `<copy>.dnspysql.json` beside it.
  One server process (or CLI script) per sample keeps annotations apart.
- Report evidence, not guesses: each finding cites the method and IL offset (or resource) it comes from, and what
  cannot be determined statically is listed as such.

## 1. Identify

```sql
SELECT open('C:/cases/ab12cd34ef56/sample.bin');      -- the module id (1 for the first)
SELECT key, value FROM binary;                       -- hashes, target framework, anomalies the loader noticed
SELECT id, file_name, assembly, kind, target_framework, is_mixed_mode, repair, overlay FROM modules;
SELECT method, full_name, kind FROM entry_points;
SELECT name, version FROM asmrefs;
SELECT name, size, content_type FROM resources ORDER BY size DESC;
SELECT format, il_status, count(*) FROM method_bodies GROUP BY 1, 2;
```

`binary`'s `anomalies`, `modules.repair` / `overlay` and bodies that do not decode (`il_status` other than `ok` or
`native`) are signs of packing: read them, and switch to `dotnet-unpack` when they show it. Obfuscated names
(non-printable, `a`/`b`/`#=q…`) mean you work by handle and by shape, not by name.

## 2. What it references and does

The tables give you the facts; you decide what they mean.

```sql
-- every string literal, longest first: URLs, paths, keys, registry keys, mutex names are yours to spot
SELECT value, referrer_name, offset FROM string_refs WHERE kind = 'il' ORDER BY length(value) DESC;
SELECT DISTINCT value FROM string_refs WHERE value REGEXP '(?i)(https?://|\.onion|pastebin|discord|t\.me|api\.telegram)';
-- external calls by target, and the call sites of the APIs that matter
SELECT dst_assembly, dst_name, call_count FROM external_calls ORDER BY call_count DESC LIMIT 50;
SELECT from_name, offset, to_name FROM xrefs WHERE to_name LIKE '%Process::Start%' OR to_name LIKE '%WebClient::Download%'
   OR to_name LIKE '%Assembly::Load%' OR to_name LIKE '%Registry%::SetValue%';
SELECT dll, entry, methods FROM native_imports;   -- P/Invoke entry points: injection, hooks, crypto APIs
SELECT resource, name, value FROM resource_elements WHERE type = 'String';
```

Match the APIs and strings against behaviour yourself (injection or hollowing, persistence, download-and-run, in-memory
loading, keylogging, capture, credential theft, defense tampering, spreading, self-deletion, network). To confirm one,
read the method around the call: `SELECT decompile(<method>)`, or `pseudocode_lines` near its IL offset, and follow names
with `pseudocode_refs.target`.

## 3. Config and encoded data

Malware settings usually sit in a static class filled by its `.cctor`, often encrypted and decrypted by one method.
What the IL stores as a constant is in the tables; a value the code computes or decrypts is not — decode it yourself.

```sql
-- constants a settings type's fields are set to: the storing instructions
SELECT i.offset, i.opcode, i.operand_text FROM il i WHERE i.method = resolve('Ns.Settings::.cctor') ORDER BY i.idx;
SELECT decompile(resolve('Ns.Settings'));
-- a resource that is high entropy or not text is likely packed or encrypted: export its bytes
SELECT name, content_type, hex(data) FROM resources WHERE name = '<name>';
```

Settings decrypted by a string decryptor: find it and recover the strings as in the `dotnet-deobfuscate` skill (§3).
DnSpySql deliberately has no base64/xor/decrypt/decompress functions. Steps:

1. Read the decryptor or decoder with `decompile()` to learn the algorithm, key, IV and encoding.
2. Export the ciphertext: `resources.data`, a field's bytes, or a literal from `string_refs`.
3. Decode it in your own code (your language's base64/zlib/AES, or a scratch script). Never execute the sample's code.
4. If the result is itself a .NET assembly, bring it back in: `SELECT open_bytes(x'<hex>', 'stage2.dll', 0, 1)` (the last
   argument names the module it came from), then triage that module (`WHERE module = <id>`).

`text_decode(blob, 'utf-16le')`, `text_encode(text, 'utf-16le')` (a key the code builds with `Encoding.Unicode`),
`int_at(blob, offset, size)` and the `REGEXP` functions help read bytes inside SQL. SQL string literals have no
backslash escapes: `'\.'` reaches `REGEXP` as `\.`.

## 4. Family

Name a family only with evidence: config layout (field names, separators, order), distinctive strings, the mutex format,
C2 protocol strings, the mix of behaviour, resources. Write "consistent with X (evidence: ...)" rather than asserting
it, and "unknown" when nothing is distinctive.

## 5. Annotate and hand off

Record findings so the work survives and so dnSpy shows them: `set_comment(handle [, il_offset], text)`,
`tag(handle, tag)`, `INSERT INTO bookmarks(...)`, and rename obfuscated members with
`UPDATE types/methods/fields SET name = ...` (collect handles first: they survive renames). `INSERT INTO kv` keeps notes
a later session can read. `save('copy.dll')` writes an annotated copy for dnSpy (see the `dnspy` guide).

## 6. Report and close

Write the report from [references/report-template.md](references/report-template.md): verdict and confidence, hashes,
how it is protected, the config with its source, defanged indicators, behaviour with method and offset, what remains
unknown, and what to open in dnSpy (full name and `tok(handle)`).

Memory is only released by closing: `SELECT close(id)` frees a sample and its stages once it is saved (if edited).
With several samples, go one at a time: open, triage, report, close.
