// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DnSpySql.Tests;

/// <summary>
/// Settings the program decrypts at startup (decoded_fields), field arguments of a decryptor, values that are still
/// ciphertext, host and port pairs. The fixtures are written for the tests (reserved .example names, keys made here).
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
    public void Settings_decrypted_at_startup_are_decoded_and_feed_the_indicators()
    {
        var r = Run($"select add_type('{Settings("Profile", "System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(Secret))")}')",
            $"select add_type('{Settings("Profile2", "System.Environment.MachineName")}')",
            "select field_name, value, value_kind, decoder_name, error from decoded_fields where type_name = 'Profile' order by field_name",
            "select count(*), max(error) from decoded_fields where type_name = 'Profile2' and field is null",
            "select kind, value, source from field_inits where field_name like '%Profile::Salt'",
            "select kind, value, source, fields from iocs where source in ('decoded', 'encrypted') order by kind, value");
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
        // the salt, computed by Encoding.ASCII.GetBytes in the static constructor
        var salt = r.Values(4);
        Assert.Equal(new[] { "bytes", "cctor" }, new[] { salt[0].GetString(), salt[2].GetString() });

        var iocs = r.Rows(5).Select(x => $"{x.GetProperty("kind").GetString()} {x.GetProperty("value").GetString()} {x.GetProperty("source").GetString()}").ToList();
        Assert.Contains("domain library.example decoded", iocs);
        Assert.Contains("domain backup.example decoded", iocs);
        Assert.Contains("host:port library.example:8443 decoded", iocs);
        Assert.Contains("host:port backup.example:9443 decoded", iocs);
        Assert.Contains("mutex sample-mutex-1 decoded", iocs);
        // Profile2's mutex is still ciphertext: reported as encrypted, not as the mutex's name
        Assert.Contains($"mutex {Seal("sample-mutex-1")} encrypted", iocs);
        Assert.Contains(r.Rows(5), x => x.GetProperty("kind").GetString() == "host:port" && x.GetProperty("fields").GetString() == "System.String Profile::Host + System.String Profile::Port");
        Assert.DoesNotContain(iocs, i => i.StartsWith("mutex ") && i.EndsWith(" computed"));
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
        Assert.Equal(5, r.Long(3)); // Two ranks as a decryptor too: its five sites have known arguments
        var next = JsonDocument.Parse(r.Text(4)).RootElement.GetProperty("next").EnumerateArray().Select(x => x.GetString()!).ToList();
        Assert.Contains(next, n => n.Contains("plaintext_kind = 'ciphertext'") && n.Contains("a second layer"));
    }
}
