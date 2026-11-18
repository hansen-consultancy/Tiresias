using Tiresias.EnvironmentVariables;

namespace Tiresias.Tests;

/// <summary>Which user environment variables are offered for sealing, and the document they are sealed as.</summary>
public class SealedVariablesTests
{
    [TestCase("OPENAI_API_KEY", "sk-abc", true)]
    [TestCase("HF_TOKEN", "hf_abc", true)]
    [TestCase("DB_PASSWORD", "hunter2", true)]
    [TestCase("MyApp__ConnectionStrings__Db", "Server=x;Password=y", false)]
    [TestCase("Shop__ConnectionString", "Server=x", true)]
    [TestCase("NUGET_FEED_USER", "alice", false)]
    [TestCase("JAVA_HOME", @"C:\Program Files\Java", false)]
    [TestCase("SSH_KEY_PATH", @"C:\Users\alice\.ssh\id_ed25519", false)]
    [TestCase("Path", "C:\\bin;C:\\tools", false)]
    [TestCase("TEMP_TOKEN_DIR", "%LOCALAPPDATA%\\tokens", false)]
    [TestCase("EMPTY_TOKEN", "", false)]
    public void Names_that_say_secret_are_offered_unless_the_value_is_a_path(string name, string value, bool offered) =>
        Assert.That(SealedVariables.LooksSecret(name, value.Length, SealedVariables.IsPath(value)), Is.EqualTo(offered));

    [Test]
    public void A_sealed_set_survives_the_document_with_its_registry_kind()
    {
        SealedVariable[] variables = [new("A_TOKEN", "one"), new("B_KEY", "%HOME%\\x", Expandable: true)];

        var back = SealedVariables.FromDocument(SealedVariables.ToDocument(variables));

        Assert.That(back, Is.EqualTo(variables));
    }

    [Test]
    public void Names_match_as_Windows_does_ignoring_case()
    {
        IReadOnlyList<SealedVariable> set = [new("A_TOKEN", "old"), new("B_KEY", "b")];

        var replaced = SealedVariables.With(set, [new("a_token", "new")]);
        var removed = SealedVariables.Without(replaced, ["b_key"]);

        Assert.That(replaced, Has.Count.EqualTo(2));
        Assert.That(replaced[0].Value, Is.EqualTo("new"));
        Assert.That(removed.Select(v => v.Name), Is.EqualTo(new[] { "a_token" }));
    }

    [Test]
    public void Nothing_sealed_yet_is_an_empty_set() =>
        Assert.That(SealedVariables.FromDocument([]), Is.Empty);
}
