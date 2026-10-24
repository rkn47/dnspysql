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
SELECT value, count(*) FROM string_refs WHERE kind = 'il' GROUP BY value ORDER BY length(value) DESC;  -- every literal
SELECT src_name, dst_name, string_args FROM call_edges
  WHERE string_args IS NOT NULL AND is_external;      -- what each framework call is given: a mutex name, a key, a URL
SELECT name, content_type, text FROM resources WHERE text IS NOT NULL;
SELECT resource, name, value FROM resource_elements WHERE type = 'String';
```

Indicators are yours to judge: read the literals, what the calls are given, the resources and (step 4) what the code
decrypts, and decide what is a host, a URL, a key or a name. Literal only: a value the code computes is in step 4.

## 4. Config

What the IL holds as it is, first:

```sql
SELECT type_name, field_name, kind, value, source FROM field_inits WHERE NOT is_default ORDER BY type_name, offset;
SELECT method_name, call_sites, constant_sites, score, sample_args FROM string_decryptors ORDER BY score DESC;
```

Then what the code computes, interpreted (the IL is read and computed instruction by instruction, never run; with the
`emulation` setting off these say so):

```sql
SELECT caller_name, offset, args, plaintext, plaintext_kind FROM decryptor_calls WHERE emulation = 'ok';
SELECT caller_name, args, plaintext FROM decryptor_calls WHERE args_from = 'field';   -- Decrypt(Settings.Host)
SELECT emulation, count(*) FROM decryptor_calls GROUP BY 1;
SELECT caller_name, args, plaintext FROM decryptor_calls WHERE decryptor = resolve('a.b::c');   -- any method
SELECT type_name, field_name, value, value_kind, decoder_name, error FROM decoded_fields;   -- settings decrypted at startup
SELECT emulate(resolve('Ns.Crypto::Decrypt'), 'base64ciphertext==');
```

A config is often a settings class whose fields hold ciphertext, decrypted in place at startup with a key derived from
another field: `decoded_fields` has the values the program uses. A plaintext with `plaintext_kind = 'ciphertext'` is a
first layer: look for the method that decrypts it in turn (`decoded_fields`, or `decryptor_calls WHERE args_from = 'field'`).

Or decode by hand with the data functions, from what the decompiled decryptor shows:

```sql
SELECT text_decode(decrypt(base64_decode('<ct>'), 'aes', unhex(md5('<passphrase>'))));   -- no iv = ECB
SELECT field_name, text_decode(try_decrypt(base64_decode(value), 'aes', <key>)) FROM field_inits WHERE type_name = '<settings type>';
                                                     -- try_decrypt: NULL, not an error, for a value that is not ciphertext
SELECT decompress(data, 'lzma') FROM resources WHERE name = '<packed>';
SELECT idx, value FROM split_text WHERE text = '<decrypted>' AND separator = '|';
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

`triage()` itself is static: it reads the file and the IL, and its `next` list names the interpreting queries
(`decryptor_calls`, `decoded_fields`) when it finds decryptors or settings decoders.
