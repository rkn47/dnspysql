---
name: dotnet-triage
description: Statically triage a .NET assembly (often malware) with DnSpySql — identify it, map what it references and does, pull out literals and config candidates, and write a report. Use when asked to triage, reverse, analyze or extract the config of a .NET sample. DnSpySql gives the dnSpy model as SQL tables; the judgement and any decoding are yours.
---

# Triaging a .NET assembly with DnSpySql

DnSpySql is an SQL interface to dnSpy's model of an assembly. It maps metadata, IL, decompiled code and the PE file to
tables; it does not decide what is malicious or decode anything for you. You do the triage with these tables plus your
own code. Never run the sample or anything you decode from it; defang indicators in reports (`hxxps://evil[.]com`).

Read the engine's own guides first: `SELECT text FROM dnspysql_guides WHERE topic = 'basics'`, then `'explore'`.

## 1. Identify

```sql
SELECT key, value FROM binary;                       -- hashes, target framework, anomalies the loader noticed
SELECT id, file_name, assembly, kind, target_framework, is_mixed_mode FROM modules;
SELECT method, full_name FROM entry_points;
SELECT name, size, content_type FROM resources ORDER BY size DESC;
```

`binary`'s `anomalies` lists wiped headers, high-entropy sections, overlays and bodies that do not decode — read them,
they hint at packing or obfuscation. Obfuscated names (non-printable, `a`/`b`/`#=q…`) mean you work by handle and by
shape, not by name.

## 2. What it references and does

The tables give you the facts; you decide what they mean.

```sql
-- every string literal, longest first: URLs, paths, keys, registry keys, mutex names are yours to spot
SELECT value, referrer_name, offset FROM string_refs WHERE kind = 'il' ORDER BY length(value) DESC;
-- external calls, and the literals each is given (a mutex's name, a path, a URL)
SELECT dst_assembly, dst_name, count(*) FROM call_edges WHERE is_external GROUP BY 1, 2 ORDER BY 3 DESC;
SELECT from_name, offset FROM xrefs WHERE to_name LIKE '%Process::Start%' OR to_name LIKE '%WebClient::Download%'
   OR to_name LIKE '%Assembly::Load%';
SELECT dll, entry, methods FROM native_imports;   -- P/Invoke entry points: injection, hooks, crypto APIs
SELECT resource, name, value FROM resource_elements WHERE type = 'String';
```

Match the APIs and strings against behaviour yourself (injection, persistence, download-and-run, keylogging, ...). To
read a method, `SELECT decompile(resolve('Ns.Type::Method'))` and follow names with `pseudocode_refs`.

## 3. Config and encoded data

What the IL stores as a constant is in the tables; a value the code computes or decrypts is not — decode it yourself.

```sql
-- constants a type's fields are set to (settings classes): read the storing instructions
SELECT i.offset, i.opcode, i.operand_text FROM il i WHERE i.method = resolve('Ns.Settings::.cctor') ORDER BY i.idx;
-- a resource that is high entropy or not text is likely packed/encrypted: export its bytes
SELECT name, content_type, hex(data) FROM resources WHERE name = '<name>';
```

Decoding and decryption are your job, in your own code or sandbox — DnSpySql deliberately has no base64/xor/decrypt/
decompress functions. Steps:

1. Read the decryptor or decoder with `decompile()` to learn the algorithm, key and encoding.
2. Export the ciphertext: `resources.data`, a field's bytes, or a literal from `string_refs`.
3. Decode it in your own code (your language's base64/zlib/AES, or a scratch script). Never execute the sample's code.
4. If the result is itself a .NET assembly, bring it back in: `SELECT open_bytes(x'<hex>', 'stage2.dll')`, then triage
   that module (`WHERE module = <id>`).

`text_decode(blob, 'utf-16le')`, `int_at(blob, offset, size)` and the `REGEXP` functions help read bytes inside SQL.

## 4. Annotate and report

Record findings so the work survives and so dnSpy shows them: `set_comment(handle [, il_offset], text)`,
`tag(handle, tag)`, `INSERT INTO bookmarks(...)`, and rename obfuscated members with
`UPDATE types/methods/fields SET name = ...`. `save('copy.dll')` writes an annotated copy for dnSpy (see the `dnspy`
guide). The report is yours: verdict and confidence, hashes, how it is protected, the config you recovered with its
source, defanged indicators, behaviour with method/offset locations, and what you could not determine statically.

## 5. Close

`SELECT close(id)` frees a sample and its stages; with several samples, close each when done.
