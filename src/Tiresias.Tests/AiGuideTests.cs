using System.Text.RegularExpressions;
using Tiresias.Keyring;

namespace Tiresias.Tests;

/// <summary>
/// <c>tir ai</c> tells agents which commands to run, so a renamed or removed command must fail here
/// rather than send an agent to one that doesn't exist: guide against usage, usage against the
/// dispatch in Program.cs.
/// </summary>
public class AiGuideTests
{
    /// <summary>The words naming each command in the usage, e.g. <c>env nuget add</c>.</summary>
    static readonly string[][] Commands = [.. Regex.Matches(CliUsage.Text, @"^[ \t]*tir ([^\r\n]+)", RegexOptions.Multiline)
        .Select(m => Regex.Split(m.Groups[1].Value, @"\s{2,}")[0].Split(' ').TakeWhile(IsWord).ToArray())];

    static bool IsWord(string token) => Regex.IsMatch(token, "^[a-z][a-z-]*$");

    /// <summary>Each <c>tir word...</c> in the text whose words neither start with a command nor are the start of one.</summary>
    static IEnumerable<string> Unknown(string text) =>
        Regex.Matches(text, @"\btir((?: [a-z][a-z-]*)+)")
            .Select(m => m.Groups[1].Value.Trim().Split(' '))
            .Where(words => !Commands.Any(c => c.SequenceEqual(words.Take(c.Length)) || words.SequenceEqual(c.Take(words.Length))))
            .Select(words => "tir " + string.Join(' ', words));

    [TestCase(AiGuide.Instructions)]
    [TestCase(AiGuide.Snippet)]
    public void Every_command_it_names_exists(string text) =>
        Assert.That(Unknown(text), Is.Empty);

    [TestCase("run `tir vault list` first", ExpectedResult = new[] { "tir vault list" })]
    [TestCase("run `tir exec github -- gh` or `tir env`", ExpectedResult = new string[0])]
    public string[] Unknown_commands_are_caught(string text) => [.. Unknown(text)];

    [TestCase(AiGuide.Instructions)]
    [TestCase(AiGuide.Snippet)]
    public void Every_flag_it_names_exists(string text)
    {
        foreach (Match flag in Regex.Matches(text, @"(?<![\w-])--[a-z][a-z-]*"))
            Assert.That(CliUsage.Text, Does.Contain(flag.Value), $"{flag.Value} is not in the usage.");
    }

    [Test]
    public void Every_command_in_the_usage_is_dispatched()
    {
        var program = File.ReadAllText(Path.Combine(RepoRoot(), "src", "Tiresias.Keyring", "Program.cs"));
        Assert.That(Commands, Is.Not.Empty);
        foreach (var command in Commands)
            Assert.That(program, Does.Contain($"(\"{command[0]}\", "), $"tir {command[0]} is in the usage but not dispatched.");
    }

    [Test]
    public void The_snippet_points_at_the_guide() =>
        Assert.That(AiGuide.Snippet, Does.Contain("`tir ai`"));

    static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(TestContext.CurrentContext.TestDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "Tiresias.slnx")))
                return dir.FullName;
        throw new DirectoryNotFoundException("Tiresias.slnx not found above the test directory.");
    }
}
