// DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
namespace DnSpySql.Tests;

/// <summary>Runtime settings: each validates and applies its own value.</summary>
public sealed class SettingsTests : SampleTest
{
    [Fact]
    public void Bool_settings_take_their_words_and_keep_1_or_0()
    {
        var r = Run("select set_setting('decompiler_show_tokens', 'yes')", "select value from runtime_settings where key = 'decompiler_show_tokens'",
                    "select set_setting('max_modules', '0x10')", "select value from runtime_settings where key = 'max_modules'");
        Assert.Equal("1", r.Text(1));
        Assert.Equal("16", r.Text(3));
        Assert.Contains("needs 1 or 0", Cli.Run(Sample, "select set_setting('save_sidecars', 'maybe')").Error);
    }
}
