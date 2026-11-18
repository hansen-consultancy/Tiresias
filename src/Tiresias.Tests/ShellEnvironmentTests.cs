using System.Text.Json.Nodes;
using Tiresias.EnvironmentVariables;

namespace Tiresias.Tests;

/// <summary>Folder sets, consent once per terminal, and the script the PowerShell hook runs.</summary>
public class ShellEnvironmentTests
{
    static readonly SealedEnvironment Sample = SealedEnvironment.Empty
        .WithGlobal([new("OPENAI_API_KEY", "global"), new("HF_TOKEN", "hf")])
        .WithFolder(@"C:\src\shop", [new("OPENAI_API_KEY", "shop"), new("SHOP_DB", "db")])
        .WithFolder(@"C:\src\shop\admin", [new("SHOP_DB", "admin-db")]);

    [TestCase(@"C:\elsewhere", "OPENAI_API_KEY=global HF_TOKEN=hf")]
    [TestCase(@"C:\src\shop", "OPENAI_API_KEY=shop HF_TOKEN=hf SHOP_DB=db")]
    [TestCase(@"c:\SRC\Shop\", "OPENAI_API_KEY=shop HF_TOKEN=hf SHOP_DB=db")]
    [TestCase(@"C:\src\shop\web\pages", "OPENAI_API_KEY=shop HF_TOKEN=hf SHOP_DB=db")]
    [TestCase(@"C:\src\shop\admin", "OPENAI_API_KEY=shop HF_TOKEN=hf SHOP_DB=admin-db")]
    [TestCase("C:/src/shop/admin/x", "OPENAI_API_KEY=shop HF_TOKEN=hf SHOP_DB=admin-db")]
    [TestCase(@"C:\src\shopfront", "OPENAI_API_KEY=global HF_TOKEN=hf")]
    public void A_directory_gets_the_global_set_overlaid_by_each_folder_down_to_it_nearest_winning(string directory, string expected) =>
        Assert.That(string.Join(' ', Sample.Resolve(directory).Select(v => $"{v.Name}={v.Value}")), Is.EqualTo(expected));

    [Test]
    public void A_drive_root_set_covers_the_whole_drive() =>
        Assert.That(SealedEnvironment.Empty.WithFolder(@"D:\", [new("A_KEY", "d")]).Resolve(@"D:\work").Select(v => v.Name), Is.EqualTo(new[] { "A_KEY" }));

    [Test]
    public void Everything_sealed_survives_the_document()
    {
        var back = SealedEnvironment.FromDocument(Sample.ToDocument());

        Assert.That(back.Global, Is.EqualTo(Sample.Global));
        Assert.That(back.Folders.Select(f => (f.Folder, string.Join(',', f.Variables))),
            Is.EqualTo(Sample.Folders.Select(f => (f.Folder, string.Join(',', f.Variables)))));
    }

    [Test]
    public void A_document_from_before_folder_sets_reads_as_the_global_set()
    {
        var phaseOne = (JsonObject)JsonNode.Parse("""{"variables":{"A_TOKEN":"one"},"expandable":["A_TOKEN"]}""")!;

        var environment = SealedEnvironment.FromDocument(phaseOne);

        Assert.That(environment.Global, Is.EqualTo(new[] { new SealedVariable("A_TOKEN", "one", Expandable: true) }));
        Assert.That(environment.Folders, Is.Empty);
    }

    [Test]
    public void A_folder_set_left_empty_is_dropped_and_others_are_untouched()
    {
        var removed = Sample.WithoutFolder(@"c:\src\shop\admin\", ["shop_db"]);

        Assert.That(removed.Folders.Select(f => f.Folder), Is.EqualTo(new[] { @"C:\src\shop" }));
        Assert.That(removed.Global, Is.EqualTo(Sample.Global));
    }

    [Test]
    public void Adding_to_a_folder_matches_it_however_it_is_spelled()
    {
        var added = Sample.WithFolder(@"c:\SRC\shop\", [new("NEW_KEY", "n")]);

        Assert.That(added.Folders, Has.Count.EqualTo(2));
        Assert.That(added.Find(@"C:\src\shop")!.Variables.Select(v => v.Name), Is.EqualTo(new[] { "OPENAI_API_KEY", "SHOP_DB", "NEW_KEY" }));
    }

    static readonly ShellIdentity Terminal = new(4242, new DateTime(2026, 11, 18, 9, 0, 0, DateTimeKind.Utc), @"C:\Program Files\PowerShell\7\pwsh.exe");

    [Test]
    public void A_terminal_is_asked_once_then_only_about_names_a_folder_adds()
    {
        var consent = new ShellConsent();

        var first = consent.Check(Terminal, ["A_KEY", "B_KEY"]);
        Assert.That(first.Answer, Is.EqualTo(ShellAnswer.Ask));
        Assert.That(first.New, Is.EqualTo(new[] { "A_KEY", "B_KEY" }));
        consent.Allow(Terminal, ["A_KEY", "B_KEY"]);

        Assert.That(consent.Check(Terminal, ["a_key"]).Answer, Is.EqualTo(ShellAnswer.Give));
        Assert.That(consent.Check(Terminal, ["A_KEY", "SHOP_DB"]).New, Is.EqualTo(new[] { "SHOP_DB" }));
    }

    [Test]
    public void After_a_no_the_terminal_keeps_what_it_had_and_is_not_asked_until_it_says_so()
    {
        var consent = new ShellConsent();
        consent.Allow(Terminal, ["A_KEY"]);
        consent.Refuse(Terminal);

        Assert.That(consent.Check(Terminal, ["A_KEY"]).Answer, Is.EqualTo(ShellAnswer.Give));
        var refused = consent.Check(Terminal, ["A_KEY", "SHOP_DB"]);
        Assert.That(refused.Answer, Is.EqualTo(ShellAnswer.Refused));
        Assert.That(refused.New, Is.EqualTo(new[] { "SHOP_DB" }));
        Assert.That(consent.Check(Terminal, ["A_KEY", "SHOP_DB"], askAgain: true).Answer, Is.EqualTo(ShellAnswer.Ask));
    }

    [Test]
    public void A_later_process_with_the_same_id_is_a_new_terminal()
    {
        var consent = new ShellConsent();
        consent.Allow(Terminal, ["A_KEY"]);

        Assert.That(consent.Check(Terminal with { Started = Terminal.Started.AddMinutes(5) }, ["A_KEY"]).Answer, Is.EqualTo(ShellAnswer.Ask));
    }

    [Test]
    public void Locking_and_closed_terminals_forget_what_was_allowed()
    {
        var consent = new ShellConsent();
        consent.Allow(Terminal, ["A_KEY"]);
        consent.Allow(Terminal with { ProcessId = 7 }, ["A_KEY"]);

        consent.Prune((id, _) => id == 7);
        Assert.That(consent.Count, Is.EqualTo(1));

        consent.Clear();
        Assert.That(consent.Count, Is.Zero);
    }

    [Test]
    public void The_script_removes_what_the_last_folder_added_and_sets_the_rest()
    {
        var script = ShellScript.PowerShell(["A_KEY", "SHOP_DB"], [new("A_KEY", "a")]);

        Assert.That(script, Is.EqualTo("""
            [Environment]::SetEnvironmentVariable('SHOP_DB', $null, 'Process')
            [Environment]::SetEnvironmentVariable('A_KEY', [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('YQ==')), 'Process')
            [Environment]::SetEnvironmentVariable('TIRESIAS_ENV_NAMES', 'A_KEY', 'Process')

            """.ReplaceLineEndings("\n")));
    }

    [Test]
    public void Nothing_left_clears_the_list_too() =>
        Assert.That(ShellScript.PowerShell(["A_KEY"], []), Does.EndWith("('TIRESIAS_ENV_NAMES', $null, 'Process')\n"));

    [TestCase("it's")]
    [TestCase("caf\u00e9 \u2019 \U0001F511")]
    [TestCase("$(Remove-Item C:\\) `n \"x\"")]
    public void Values_cross_the_console_as_base64_so_neither_its_code_page_nor_PowerShell_touches_them(string value)
    {
        var line = ShellScript.PowerShell([], [new("V", value)]).Split('\n')[0];
        var encoded = line.Split("FromBase64String('")[1].Split('\'')[0];

        Assert.That(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(encoded)), Is.EqualTo(value));
        Assert.That(line, Does.Not.Contain(value));
    }

    [Test]
    public void Names_are_single_quoted_doubling_every_quote_PowerShell_ends_one_at() =>
        Assert.That(ShellScript.PowerShell(["it's", "a\u2019b"], []), Does.Contain("('it''s', $null").And.Contain("('a\u2019\u2019b', $null"));

    [Test]
    public void The_names_list_reads_back_ignoring_blanks() =>
        Assert.That(ShellScript.Names(" A_KEY;;B_KEY "), Is.EqualTo(new[] { "A_KEY", "B_KEY" }));

}
