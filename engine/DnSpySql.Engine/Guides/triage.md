# Triage of a sample

Never run the sample; defang every indicator you report; cite the method and IL offset (or resource) of each finding;
list what cannot be determined statically. `SELECT triage()` returns the overview below as one JSON object.

## 1. Identify

```sql
SELECT key, value FROM binary WHERE key IN ('summary','sha256','md5','target_framework','anomalies');
SELECT file_name, assembly, kind, target_framework, repair, overlay FROM modules;
SELECT method, full_name, kind FROM entry_points;
SELECT name, size, content_type FROM resources ORDER BY size DESC;
```

## 2. Protection

```sql
SELECT name, kind, confidence, evidence FROM protections;
SELECT method_name, call_sites, constant_sites, score, sample_args FROM string_decryptors ORDER BY score DESC LIMIT 5;
SELECT location, size, is_dotnet, machine, sha256 FROM embedded_pes;
```

Decoy markers (`confidence = 'decoy'`) name no protector. Anti-tamper, embedded payloads and encrypted resources:
read the `unpack` guide, then triage each new module with `WHERE module = <id>`.

## 3. Behaviour and indicators

```sql
SELECT kind, api, method_name, offset, evidence FROM capabilities WHERE NOT is_library ORDER BY kind;
SELECT kind, value, source, method_name, resource FROM iocs WHERE NOT is_library ORDER BY kind;
```

`iocs.source`: literal, base64, decrypted (a decryptor's result, interpreted), computed (a value handed to an API),
resource.

## 4. Config

```sql
SELECT type_name, field_name, kind, value, source FROM field_inits WHERE NOT is_default ORDER BY type_name, offset;
SELECT caller_name, offset, args, plaintext FROM decryptor_calls WHERE emulation = 'ok';
SELECT emulation, count(*) FROM decryptor_calls GROUP BY 1;
SELECT caller_name, args, plaintext FROM decryptor_calls WHERE decryptor = resolve('a.b::c');   -- any method
SELECT emulate(resolve('Ns.Crypto::Decrypt'), 'base64ciphertext==');
SELECT text_decode(decrypt(base64_decode('<ct>'), 'aes', unhex(md5('<passphrase>'))));   -- no iv = ECB
SELECT field_name, text_decode(try_decrypt(base64_decode(value), 'aes', <key>)) FROM field_inits WHERE type_name = '<settings type>';
                                                     -- try_decrypt: NULL, not an error, for a value that is not ciphertext
SELECT idx, value FROM split_text WHERE text = '<decrypted>' AND separator = '|';
SELECT kind, value FROM text_iocs WHERE text = '<decrypted>';
```

## 5. Family and report

Name a family only with evidence (config layout, distinctive strings, mutex format, protocol strings) and say
"consistent with", or "unknown". The report has: verdict and confidence, hashes, protection, a config table with
sources, defanged indicators, capabilities with locations, what remains unknown, and what to open in dnSpy (full names
and `tok()` tokens).

## 6. Close the sample

```sql
SELECT close(<id>);          -- the module and every stage or untamper() copy that came out of it
SELECT value FROM binary WHERE key = 'session_memory_mb';
```

A session keeps every module it opened until it is closed, so with many samples go one at a time: open, triage,
report, close. `triage()` ends its `next` list with the `close()` once nothing is left to open or decrypt.
