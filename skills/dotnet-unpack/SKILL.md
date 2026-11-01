---
name: dotnet-unpack
description: Unpack a protected .NET assembly with DnSpySql — read the signs of packing, find embedded or packed payloads (resources, overlays, gaps, images, single-file bundles), find the loader, decode in your own code and open each stage as a module, stage by stage. Use when a .NET sample is obfuscated, packed, decompiles to garbage, has a high-entropy resource, or carries another PE. DnSpySql exposes the dnSpy model as SQL; locating a payload or decryptor is a query, decoding it is your own code.
---

# Unpacking a protected .NET assembly with DnSpySql

DnSpySql maps dnSpy's model to SQL tables. It finds structure for you (bodies that do not decode, byte ranges, string
literals, call graphs); it does not decode, decrypt or devirtualize — you do that in your own code, then bring the
result back in with `open_bytes`, which only parses. Never run the sample or a payload you extract, and never write a
decoded payload where it could be launched unless the user asks for the file.

Read `SELECT text FROM dnspysql_guides WHERE topic = 'basics'` first; the `dotnet-triage` skill covers the rest of
the analysis. No DnSpySql tools at all: follow `INSTALL.md` in the DnSpySql repository (https://github.com/rkn47/dnspysql).

## 1. What is there

```sql
SELECT value FROM binary WHERE key = 'anomalies';                -- wiped headers, high-entropy sections, overlays
SELECT format, il_status, count(*) FROM method_bodies GROUP BY 1, 2;   -- many non-decoding bodies: encrypted until runtime
SELECT file_name, repair, overlay, overlay_size, overlay_kind, overlay_entropy FROM modules;
SELECT name, size, content_type, sha256 FROM resources ORDER BY size DESC;
SELECT resource, name, type, size, content_type FROM resource_elements WHERE size > 1000 ORDER BY size DESC;
SELECT name, raw_size, entropy FROM pe_sections;
SELECT path, size, entropy FROM file_map WHERE kind = 'gap' AND NOT all_zero ORDER BY size DESC LIMIT 10;
SELECT heap, count(*), sum(length) FROM heap_entries WHERE kind = 'slack' OR NOT referenced GROUP BY heap;
SELECT path, kind, size, compressed_size FROM bundle_entries;
```

| signal | meaning | go to |
|---|---|---|
| many bodies with `il_status` other than `ok`/`native`, `<Module>` P/Invokes `VirtualProtect` (`anomalies`) | anti-tamper: bodies decrypted in memory at startup | §4 |
| resource `content_type` `pe`, `high entropy`, `gzip`, `zlib`, `deflate` | an embedded, encrypted or compressed payload | §2 |
| `resource_images` rows a loader reads pixel by pixel | a payload in pixels | §2 |
| `modules.overlay`, `file_map` gaps with entropy > 7, `heap_entries` slack | appended or hidden data | §2 |
| `bundle_entries` rows | a single-file app: the real assemblies are inside | §2 |
| one static method called from many sites with constants | string encryption | `dotnet-deobfuscate` |
| invisible or bidi names, proxy calls, flattened control flow | readability, not packing | `dotnet-deobfuscate` |

## 2. Find the payload

```sql
SELECT hex(substr(data, 1, 16)), length(data) FROM resources WHERE name = '<name>';   -- 4D5A = MZ
SELECT hex(read_bytes(overlay_offset, 16)), overlay_kind FROM modules WHERE overlay_size > 0;
SELECT offset, rva, section FROM byte_search WHERE pattern = '4D 5A 90 00';          -- MZ inside the file bytes
SELECT resource, element, format, width, height, length(data) FROM resource_images;  -- the image file in data
SELECT open_bundle_entry('Payload.dll');                                              -- an assembly inside a bundle
```

`resources.data`, `resource_elements.value`, `read_bytes(offset, size)` and `resource_images.data` hand out the bytes
as they are. A wiped CLI header or metadata signature is repaired when the file loads (`modules.repair` says what was
done).

## 3. Find the loader, decode, open

Find who reads the payload and what it does with the bytes:

```sql
SELECT from_name, offset FROM xrefs WHERE kind = 'string' AND string_value = '<resource name>';
SELECT from_name, offset, to_name FROM xrefs
 WHERE to_name LIKE '%GetManifestResourceStream%' OR to_name LIKE '%ResourceManager::Get%' OR to_name LIKE '%Assembly::Load%';
SELECT decompile(<loader method>);
```

Rebuild its pipeline (base64, xor, AES/DES/RC4, gzip/zlib/LZMA, pixel order, a split across numbered resources) in your
own code over the exported bytes. Check every intermediate step before going further: its length, its first bytes, its
entropy (it drops after decryption). For pixels, read the loader's loop (channel order, rows or columns first, where a
length sits) and decode the image file the same way. Then open what comes out:

```sql
SELECT open_bytes(x'<decoded hex>', 'stage2.dll', 0, 1);   -- a new module id; parent = the module it came from
SELECT open_bytes(x'<dump hex>', 'dumped.dll', 1);         -- memory_layout = 1: an image dumped from memory
```

`open_bytes()` returns NULL with a note for a native PE (report its machine and SHA-256 instead), and the module already
open when the bytes are the same.

## 4. Anti-tamper and virtualization

- **Bodies encrypted until runtime**: the startup routine (usually called from `<Module>::.cctor`) decrypts them in
  memory. Read it with `decompile()`, reproduce the decryption in your own code over the file bytes (`read_bytes`), and
  `open_bytes` the rebuilt image. DnSpySql will not run the routine for you.
- **IL virtualization** (methods hand an id and their arguments to one dispatcher): devirtualizing is specific to each
  VM and out of scope for the SQL interface — say so in the report, or use a dedicated tool.

## 5. After each stage

A new module is a new sample: run the `dotnet-triage` steps on it with `WHERE module = <id>`, and `dotnet-deobfuscate`
when it is obfuscated. Record the chain (`INSERT INTO kv VALUES ('stages', '1 -> res x.bin aes+gzip -> 2')`) and report
each stage's SHA-256 (`SELECT sha256 FROM modules WHERE id = <id>`). When a value only exists at runtime (a stage
decrypted in memory, a key from the machine), the `dotnet-debug-prep` skill prepares a dnSpy session for the user.
Close modules you are done with: `SELECT close(id)`.
