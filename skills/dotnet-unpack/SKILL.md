---
name: dotnet-unpack
description: Unpack and deobfuscate a protected .NET assembly with DnSpySql — find embedded or packed payloads, recover decrypted strings, and get a readable module for dnSpy. Use when a .NET sample is obfuscated, packed, or carries another PE. DnSpySql exposes the dnSpy model as SQL; locating a payload or decryptor is a query, decoding it is your own code.
---

# Unpacking a protected .NET assembly with DnSpySql

DnSpySql maps dnSpy's model to SQL tables. It finds structure for you (bodies that do not decode, byte ranges, string
literals, call graphs); it does not decode, decrypt or devirtualize — you do that in your own code, then bring the
result back in with `open_bytes`. Never run the sample or a payload you extract.

Read `SELECT text FROM dnspysql_guides WHERE topic = 'basics'` first.

## Spot the protection

```sql
SELECT key, value FROM binary WHERE key = 'anomalies';          -- wiped headers, high-entropy sections, overlays
SELECT format, il_status, count(*) FROM method_bodies GROUP BY 1, 2;   -- many non-decoding bodies: encrypted until runtime
SELECT path, size, entropy FROM file_map WHERE kind = 'gap' AND NOT all_zero ORDER BY size DESC;
```

Decompiled code of a protected method reads as garbage or empty; `decompile()` adds a `/* dnspysql: */` note when a
body does not decode.

## Find an embedded or packed payload

```sql
-- a PE carried in a resource (MZ header), as bytes or base64
SELECT name, size, content_type FROM resources WHERE content_type IN ('pe', 'high entropy', 'gzip', 'zlib');
-- a PE appended after the image (overlay) or elsewhere in the file
SELECT overlay_offset, overlay_size, overlay_kind FROM modules WHERE overlay_size > 0;
SELECT offset FROM byte_search WHERE pattern = '4D 5A 90 00';   -- MZ, inside the file bytes
```

Export the bytes (`resources.data`, `read_bytes(offset, size)`), decode them in your own code if they are compressed
or encrypted (read the loader with `decompile()` to learn how), and open the result:

```sql
SELECT open_bytes(x'<decoded hex>', 'stage2.dll');   -- a new module id; then analyse it with WHERE module = <id>
```

A payload split across several resources, or encoded (base64, xor, gzip, a custom scheme), is reassembled and decoded
in your own code — join the pieces, decode, then `open_bytes`.

## Recover encrypted strings

Protected samples route strings through a decryptor: a static method called from many sites with constant arguments,
returning a string.

```sql
-- candidates by shape: static, string-returning, many call sites with constant (ldc/ldstr) arguments before them
SELECT m.handle, m.full_name, count(*) AS sites
FROM methods m JOIN call_edges c ON c.dst = m.handle
WHERE m.is_static AND m.return_type = 'System.String'
GROUP BY 1, 2 HAVING sites > 10 ORDER BY sites DESC;
SELECT text FROM pseudocode WHERE handle = <the decryptor>;   -- read its algorithm
SELECT i.offset, i.opcode, i.operand_text FROM il i WHERE i.method = <a caller> ORDER BY i.idx;  -- the arguments
```

Reimplement the decryptor in your own code from what `decompile()` shows, run it over the arguments there (never run
the sample's own code), and write the plaintexts back as comments so the decompiled view and a saved copy show them:
`SELECT set_comment(<caller handle>, <offset>, 'decrypted: "..."')`. To rename or restructure, use the `UPDATE` and
`il_*` edit functions; all edits are journaled (`undo`/`redo`) and written out with `save()`.

## Anti-tamper and virtualization

- **Bodies encrypted until runtime** (many `method_bodies` with `il_status` other than `ok`/`native`): the startup
  routine decrypts them in memory. Read it with `decompile()`, reproduce the decryption in your own code over the
  file bytes (`read_bytes`), and `open_bytes` the rebuilt image. DnSpySql will not run the routine for you.
- **IL virtualization** (a method hands an id and its arguments to one dispatcher): devirtualizing is specific to each
  VM and is out of scope for the SQL interface — handle it with a dedicated tool.

## Hand off

`save('readable.dll')` writes the edited, renamed, commented module plus its sidecars for dnSpy (see the `dnspy`
guide). Close modules you are done with: `SELECT close(id)`.
