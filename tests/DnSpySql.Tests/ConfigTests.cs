// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DnSpySql.Tests;

/// <summary>
/// Settings the program decrypts at startup (decoded_fields), field arguments of a decryptor, values that are still
/// ciphertext, the literals calls are given. The fixtures are written for the tests (reserved .example names, keys made here).
/// </summary>
public sealed class ConfigTests : SampleTest
{
    static readonly byte[] Salt = Encoding.ASCII.GetBytes("sample-salt-16by");

    // what the fixture's decoder undoes: AES-CBC under a PBKDF2 key, the IV in front, base64
    static string Seal(string plain)
    {
        var key = Rfc2898DeriveBytes.Pbkdf2("sample-secret", Salt, 1000, HashAlgorithmName.SHA1, 32);
        using var aes = Aes.Create();
        aes.Key = key;
        var iv = SHA256.HashData(Encoding.UTF8.GetBytes(plain))[..16]; // fixed per value, so the test is the same every run
        return Convert.ToBase64String([.. iv, .. aes.EncryptCbc(Encoding.UTF8.GetBytes(plain), iv)]);
    }

    // A settings class decrypted in place by Load(): the key from Secret and Salt (Salt computed by the framework in the
    // static constructor). Profile2's key comes from the machine name, which the interpreter refuses.
    static string Settings(string name, string keySource) =>
        $"public static class {name} {{ public static string Host = \"{Seal("library.example,backup.example")}\"; " +
        $"public static string Port = \"{Seal("8443,9443")}\"; public static string Mutex = \"{Seal("sample-mutex-1")}\"; " +
        "public static string Secret = \"c2FtcGxlLXNlY3JldA==\"; " +
        "public static readonly byte[] Salt = System.Text.Encoding.ASCII.GetBytes(\"sample-salt-16by\"); " +
        $"public static bool Load() {{ var key = new System.Security.Cryptography.Rfc2898DeriveBytes({keySource}, Salt, 1000, " +
        "System.Security.Cryptography.HashAlgorithmName.SHA1).GetBytes(32); Host = Open(key, Host); Port = Open(key, Port); Mutex = Open(key, Mutex); return true; } " +
        "static string Open(byte[] key, string b64) { var data = System.Convert.FromBase64String(b64); var iv = new byte[16]; " +
        "System.Buffer.BlockCopy(data, 0, iv, 0, 16); var aes = System.Security.Cryptography.Aes.Create(); " +
        "return System.Text.Encoding.UTF8.GetString(aes.CreateDecryptor(key, iv).TransformFinalBlock(data, 16, data.Length - 16)); } } " +
        $"public static class Start{name} {{ public static void Run() {{ if ({name}.Load()) new System.Threading.Mutex(false, {name}.Mutex); }} }}";

    [Fact]
    public void Settings_decrypted_at_startup_are_decoded_when_asked()
    {
        var r = Run($"select add_type('{Settings("Profile", "System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(Secret))")}')",
            $"select add_type('{Settings("Profile2", "System.Environment.MachineName")}')",
            "select field_name, value, value_kind, decoder_name, error from decoded_fields where type_name = 'Profile' order by field_name",
            "select count(*), max(error) from decoded_fields where type_name = 'Profile2' and field is null",
            "select count(*) from field_inits where field_name like '%Profile::Salt'",
            "select triage()",
            // off: nothing is interpreted, and each table says so
            "select set_setting('emulation', 0)",
            "select count(*), max(error) from decoded_fields where type_name = 'Profile' and field is null",
            "select set_setting('emulation', 1)",
            "select value from decoded_fields where field_name like '%Profile::Host'");
        var decoded = r.Rows(2).ToDictionary(x => x.GetProperty("field_name").GetString()!.Split("::")[1], x => x);
        Assert.Equal("library.example,backup.example", decoded["Host"].GetProperty("value").GetString());
        Assert.Equal("8443,9443", decoded["Port"].GetProperty("value").GetString());
        Assert.Equal("sample-mutex-1", decoded["Mutex"].GetProperty("value").GetString());
        Assert.All(decoded.Values, d => Assert.Equal("text", d.GetProperty("value_kind").GetString()));
        Assert.All(decoded.Values, d => Assert.Contains("Profile::Load", d.GetProperty("decoder_name").GetString()));
        Assert.All(decoded.Values, d => Assert.Equal(JsonValueKind.Null, d.GetProperty("error").ValueKind));
        // the decoder whose key comes from the machine (not this one's) changes nothing and says why
        Assert.Equal(1, r.Values(3)[0].GetInt64());
        Assert.False(string.IsNullOrEmpty(r.Values(3)[1].GetString()));
        // the salt, computed by Encoding.ASCII.GetBytes in the static constructor: no constant in the IL, so not a field_inits row
        Assert.Equal(0, r.Long(4));
        // triage() interprets nothing: it names both settings decoders and the query that interprets them
        var t = JsonDocument.Parse(r.Text(5)).RootElement;
        Assert.Equal(["Profile", "Profile2"], t.GetProperty("settings_decoders").GetProperty("items").EnumerateArray()
            .Select(d => d.GetProperty("type").GetString()!).Order().ToArray());
        Assert.Contains(t.GetProperty("next").EnumerateArray(), n => n.GetString()!.StartsWith("SELECT field_name, value, value_kind, error FROM decoded_fields"));
        Assert.False(t.TryGetProperty("decoded_fields", out _));
        Assert.Equal(1, r.Values(7)[0].GetInt64());
        Assert.StartsWith("emulation is off", r.Values(7)[1].GetString());
        Assert.Equal("library.example,backup.example", r.Text(9)); // on again: interpreted again, not the refusal kept
    }

    [Fact]
    public void Values_that_are_not_what_they_look_like_are_left_alone()
    {
        var r = Run(
            // a field the program reassigns has no one value: its decryptor calls are not folded
            "select add_type('public static class K { public static string Key = \"default\"; public static void Init(string s) { Key = s; } " +
            "public static string Dec(string a) { return a + \"!\"; } } public static class UseK { public static string Go() { " +
            "return K.Dec(K.Key) + K.Dec(K.Key) + K.Dec(K.Key) + K.Dec(K.Key) + K.Dec(K.Key) + K.Dec(K.Key); } }')",
            // the literals each call is given, per string parameter; a value that is not a literal is null
            "select add_type('public static class Lit { public static void Run(string p) { new System.Threading.Mutex(false, \"sample-mutex-2\"); " +
            "System.IO.File.WriteAllText(\"a.txt\", p); new System.Threading.Mutex(false, p); } }')",
            // a constant behind a getter is still the IL's constant
            "select add_type('public static class M { public static string Name = Get(); static string Get() { return \"9dd4e461268c8034f5c8564e155c67a6\"; } " +
            "public static void Run() { new System.Threading.Mutex(false, Name); } }')",
            "select count(*) from decryptor_calls where decryptor = resolve('K::Dec')",
            "select dst_name, string_args from call_edges where src = resolve('Lit::Run') and string_args is not null",
            "select source, value from field_inits where field_name like '%M::Name'",
            "select try_decrypt(x'00000000000000000000000000000000', '3des', zeroblob(16))");
        Assert.Equal(0, r.Long(3));
        var args = r.Rows(4).Select(x => $"{x.GetProperty("dst_name").GetString()} {x.GetProperty("string_args").GetString()}").ToList();
        Assert.Contains(args, a => a.Contains("Mutex::.ctor") && a.EndsWith("[\"sample-mutex-2\"]"));
        Assert.Contains(args, a => a.Contains("Mutex::.ctor") && a.EndsWith("[null]"));
        Assert.Contains(args, a => a.Contains("File::WriteAllText") && a.EndsWith("[\"a.txt\",null]"));
        Assert.Equal(["getter", "9dd4e461268c8034f5c8564e155c67a6"], r.Values(5).Select(v => v.GetString()!).ToArray());
        Assert.Equal(System.Text.Json.JsonValueKind.Null, r.Scalar(6).ValueKind); // a weak 3DES key: NULL, not an error
    }

    [Fact]
    public void A_decryptor_given_a_settings_field_is_interpreted_and_ciphertext_is_named()
    {
        // Cfg's static constructor decrypts a first layer (One, literal arguments) to base64 ciphertext; Two decrypts that,
        // given the fields
        var key = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();
        string Layer2(string plain) { using var aes = Aes.Create(); aes.Key = key; return Convert.ToBase64String(aes.EncryptEcb(Encoding.UTF8.GetBytes(plain), PaddingMode.PKCS7)); }
        var names = new[] { "alpha", "bravo", "charlie", "delta", "echo" }.Select(n => n + ".example").ToArray();
        string Reversed(string s) => new(s.Reverse().ToArray());
        var cfg = string.Join(" ", names.Select((n, i) => $"public static string F{i} = Layer.One(\"{Reversed(Layer2(n))}\");"));
        var r = Run("select add_type('public static class Layer { static readonly byte[] Key = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }; " +
                    "public static string One(string s) { var c = s.ToCharArray(); System.Array.Reverse(c); return new string(c); } " +
                    "public static string Two(string s) { var aes = System.Security.Cryptography.Aes.Create(); aes.Mode = System.Security.Cryptography.CipherMode.ECB; " +
                    "var d = System.Convert.FromBase64String(s); return System.Text.Encoding.UTF8.GetString(aes.CreateDecryptor(Key, new byte[16]).TransformFinalBlock(d, 0, d.Length)); } } " +
                    $"public static class Cfg {{ {cfg} }} " +
                    "public static class App { public static string Go() => Layer.Two(Cfg.F0) + Layer.Two(Cfg.F1) + Layer.Two(Cfg.F2) + Layer.Two(Cfg.F3) + Layer.Two(Cfg.F4); }')",
            "select plaintext, args_from, plaintext_kind, emulation from decryptor_calls where decryptor = resolve('Layer::Two') order by offset",
            "select distinct plaintext_kind from decryptor_calls where decryptor = resolve('Layer::One')",
            "select count(*) from decryptor_calls where args_from = 'field' and decryptor = resolve('Layer::Two')",
            "select triage()");
        var two = r.Rows(1);
        Assert.Equal(names, two.Select(x => x.GetProperty("plaintext").GetString()));
        Assert.All(two, x => Assert.Equal("field", x.GetProperty("args_from").GetString()));
        Assert.All(two, x => Assert.Equal("text", x.GetProperty("plaintext_kind").GetString()));
        Assert.Equal(new[] { "ciphertext" }, r.Rows(2).Select(x => x.GetProperty("plaintext_kind").GetString()));
        Assert.Equal(5, r.Long(3)); // Two's five sites have known arguments once Cfg's fields are interpreted
        var next = JsonDocument.Parse(r.Text(4)).RootElement.GetProperty("next").EnumerateArray().Select(x => x.GetString()!).ToList();
        Assert.Contains(next, n => n.Contains("FROM decryptor_calls") && n.Contains("plaintext_kind = 'ciphertext' is a second layer"));
    }
}
