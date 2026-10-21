# Protected and packed assemblies

Nothing here runs the sample: `untamper()`, `emulate()` and `decryptor_calls` interpret IL, and `open_bytes()` only
parses. A decoded stage is a new module; analyze it with `WHERE module = <id>`. `modules.origin` and `derived_from`
say where each one came from. An `untamper()` copy has every name of its original, so follow handles, or
`use_module(<id>)` first: `resolve()` searches the current module first.

## Signals

```sql
SELECT name, kind, confidence, evidence FROM protections;
SELECT value FROM binary WHERE key = 'anomalies';
SELECT format, il_status, count(*) FROM method_bodies GROUP BY 1, 2;
SELECT file_name, repair, overlay_kind, overlay_size, overlay_entropy FROM modules;
SELECT name, size, content_type FROM resources ORDER BY size DESC;
SELECT location, size, is_dotnet, machine FROM embedded_pes;
SELECT path, size, entropy FROM file_map WHERE kind = 'gap' AND NOT all_zero ORDER BY size DESC LIMIT 10;
```

| signal | next |
|---|---|
| anti-tamper, many invalid bodies | `SELECT untamper()`: returns the decrypted module's id |
| anti-tamper, every body decodes | nothing to decrypt: the protection's code is there, its effect is not |
| `embedded_pes` rows | `SELECT open_bytes(data) FROM embedded_pes WHERE is_dotnet`: one module per stage, named from its hash |
| resource with content_type high entropy, gzip, zlib | find the loader, then rebuild its decode chain in SQL |
| images a loader reads pixel by pixel | `image_pixels()` |
| `bundle_entries` rows | `open_bundle_entry('Name.dll')` |

## Decode chains

Find the loader (`xrefs WHERE to_name LIKE '%GetManifestResourceStream%'`, or the resource name in `string_refs`),
decompile it, and rebuild its steps innermost first. Check each step: `length()`, `hex(substr(x, 1, 16))` (`4D5A` is
MZ), `entropy()`.

```sql
SELECT open_bytes(decompress(data), 'payload.dll') FROM resources WHERE name = 'x.bin';
SELECT open_bytes(decompress(decrypt(substr(b, 17), 'aes', unhex(sha256('pass')), substr(b, 1, 16))), 'stage2.dll')
  FROM (SELECT base64_decode(text) AS b FROM resources WHERE name = 'cfg');
SELECT hex(substr(xor(data, 'k3y'), 1, 2)) FROM resources WHERE name = 'enc';
SELECT decrypt(data, 'aes', substr(k, 1, 32), substr(k, 33, 16)) FROM resources,
       (SELECT pbkdf2('password', unhex('0102030405060708'), 1000, 48) AS k) WHERE name = 'enc';
SELECT open_bytes(substr(px, 5, int_at(px, 0, 4)), 'stage2.dll')
  FROM (SELECT image_pixels(data, 'rgb') AS px FROM resource_images WHERE element = 'logo');
```

`decrypt` returns NULL when the padding check fails (wrong key, iv or mode). When the decoder is too involved to
rebuild, interpret it: `emulate(resolve('Ns.Loader::Decode'), <literal args>)`; what it cannot interpret (P/Invoke,
files, network) stops it with the reason.

Record the chain in `kv` and report each stage's `sha256` from `modules`.
