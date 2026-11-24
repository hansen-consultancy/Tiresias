using Tiresias.App.Logic;

namespace Tiresias.Tests;

public class PromptWhyTests
{
    [Test]
    public void The_heading_names_the_prompt_windows_shows()
    {
        Assert.That(PromptWhy.Describe(PromptReason.Unlock, PromptKind.Hello).Heading.Key, Is.EqualTo("Prompt_HeadingHello"));
        Assert.That(PromptWhy.Describe(PromptWhy.ForAdminStep("install", null), PromptKind.Uac).Heading.Key, Is.EqualTo("Prompt_HeadingUac"));
    }

    [Test]
    public void Every_purpose_has_its_own_words()
    {
        var keys = Enum.GetValues<PromptPurpose>()
            .Select(p => PromptWhy.Describe(new(p, "app.exe"), PromptKind.Hello).Reason.Key)
            .ToArray();

        Assert.That(keys, Is.Unique);
        Assert.That(keys.Where(k => k == "Prompt_Unnamed"), Has.Exactly(1).Items);
    }

    [TestCase(@"C:\Tools\app.exe", "app.exe")]
    [TestCase("/usr/bin/dotnet", "dotnet")]
    [TestCase("tir.exe", "tir.exe")]
    public void A_program_that_asked_is_named_by_its_file_name(string image, string shown)
    {
        var reason = PromptWhy.Describe(PromptReason.ProgramAsked(image), PromptKind.Hello).Reason;

        Assert.That(reason.Key, Is.EqualTo("Prompt_ProgramAsked"));
        Assert.That(reason.Args, Is.EqualTo(new object[] { shown }));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase(@"C:\Tools\")]
    public void An_unknown_program_still_gets_a_reason(string? image) =>
        Assert.That(PromptWhy.Describe(PromptReason.ProgramAsked(image), PromptKind.Hello).Reason.Key, Is.EqualTo("Prompt_ProgramAskedUnknown"));

    [TestCase("install", null, "Prompt_AdminInstall")]
    [TestCase("remove", null, "Prompt_AdminRemove")]
    [TestCase("release-decoys", null, "Prompt_AdminReleaseDecoys")]
    [TestCase("adopt-decoys", null, "Prompt_AdminAdoptDecoys")]
    [TestCase("review-incidents", "42", "Prompt_AdminReviewIncidents")]
    [TestCase("unblock-program", @"C:\Tools\app.exe", "Prompt_AdminUnblock")]
    [TestCase("unblock-program", null, "Prompt_AdminUnblockUnknown")]
    [TestCase("something-new", null, "Prompt_Unnamed")]
    public void Each_admin_tier_step_says_what_it_is_for(string verb, string? argument, string key) =>
        Assert.That(PromptWhy.Describe(PromptWhy.ForAdminStep(verb, argument), PromptKind.Uac).Reason.Key, Is.EqualTo(key));

    [Test]
    public void Unblocking_names_the_program()
    {
        var reason = PromptWhy.Describe(PromptWhy.ForAdminStep("unblock-program", @"C:\Tools\app.exe"), PromptKind.Uac).Reason;

        Assert.That(reason.Args, Is.EqualTo(new object[] { "app.exe" }));
    }
}
