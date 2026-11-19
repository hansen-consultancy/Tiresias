using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

public class KeysAsValuesTests
{
    static DoctorCheck[] Checks(string[] asValues, params DoctorService[] services) =>
        [.. Doctor.KeysAsValues(new(asValues, services))];

    [Test]
    public void A_known_bearer_key_without_a_service_suggests_one_at_its_address()
    {
        var check = Checks(["OPENAI_API_KEY"]).Single();

        Assert.That(check.Name, Is.EqualTo("sealed key OPENAI_API_KEY"));
        Assert.That(check.Fix, Is.EqualTo(new UsePlaceholder("OPENAI_API_KEY", "", "https://api.openai.com/v1")));
        Assert.That(check.Fix!.Instruction, Does.StartWith("tir service add <service> --upstream https://api.openai.com/v1"));
        Assert.That(FindingView.Moves(check), Is.EqualTo("E4/C1 → E3/C1"));
        Assert.That(FindingView.Button(check.Fix)?.Action, Is.EqualTo(FixAction.UsePlaceholder));
    }

    [TestCase("openai")]
    [TestCase("openai-prod")]
    public void A_matching_vault_service_is_named_in_the_fix(string slug) =>
        Assert.That(Checks(["OPENAI_API_KEY"], new DoctorService(slug, "api.openai.com")).Single().Fix!.Instruction,
            Is.EqualTo($"tir env placeholder add OPENAI_API_KEY {slug}"));

    [Test]
    public void An_unknown_prefix_is_a_finding_only_with_a_vault_service_for_it()
    {
        Assert.That(Checks(["ACME_TOKEN"]).Single().IsFinding, Is.False);

        var check = Checks(["ACME_TOKEN"], new DoctorService("billing", "api.acme.example")).Single();

        Assert.That(check.Fix, Is.EqualTo(new UsePlaceholder("ACME_TOKEN", "billing")));
    }

    [TestCase("ANTHROPIC_API_KEY")]
    [TestCase("GITHUB_TOKEN")]
    [TestCase("GH_TOKEN")]
    [TestCase("AZURE_OPENAI_API_KEY")]
    [TestCase("DATABASE_PASSWORD")]
    public void Keys_that_dont_take_a_bearer_placeholder_are_not_reported(string name) =>
        Assert.That(Checks([name], new DoctorService("anthropic", "api.anthropic.com"), new DoctorService("github", "api.github.com")).Where(c => c.IsFinding), Is.Empty);

    [Test]
    public void Without_findings_there_is_one_passing_line() =>
        Assert.That(Checks([]).Single(), Is.EqualTo(new DoctorCheck(Doctor.KeysAsValuesCheck, DoctorStatus.Ok, "none of the sealed keys would work as a placeholder instead")));

    [Test]
    public void Locked_skips_the_check_without_a_finding()
    {
        var check = Doctor.KeysAsValues(null).Single();

        Assert.That(check.Detail, Does.StartWith("skipped: locked"));
        Assert.That(check.IsFinding, Is.False);
    }
}
