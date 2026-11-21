using Tiresias.EnvironmentVariables;
using Tiresias.AdminTier;
using Tiresias.Protocol;
using Tiresias.UserSecrets;

namespace Tiresias.Tests;

public class ReleasePolicyTests
{
    static readonly ReleasePolicy Before = new(new ReleaseScope(0));
    static readonly ReleasePolicy After = new(new ReleaseScope(8));
    static readonly ReleasePolicy Blocked = new(new ReleaseScope(8), "The program is blocked.");

    [Test]
    public async Task The_blocklist_follows_the_service_cursor_through_the_last_page()
    {
        var first = new AdminBlockedProgram(@"C:\one.exe", null, DateTimeOffset.UnixEpoch);
        var second = first with { Path = @"C:\two.exe" };
        var cursors = new List<string?>();
        var result = await AdminBlocks.ReadAllAsync(after =>
        {
            cursors.Add(after);
            return Task.FromResult<AdminBlocks?>(after is null ? new([first], first.Path) : new([second]));
        });
        Assert.That(cursors, Is.EqualTo(new[] { null, first.Path }));
        Assert.That(result, Is.EqualTo(new[] { first, second }));
    }

    [TestCase(true)]
    [TestCase(false)]
    public async Task A_failed_or_repeated_page_makes_the_entire_blocklist_unavailable(bool interrupted)
    {
        var first = new AdminBlockedProgram(@"C:\one.exe", null, DateTimeOffset.UnixEpoch);
        var repeated = first with { Path = first.Path.ToUpperInvariant() };
        var result = await AdminBlocks.ReadAllAsync(after => Task.FromResult<AdminBlocks?>(after is null
            ? new([first], first.Path) : interrupted ? null : new([repeated], repeated.Path)));
        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task Only_a_confirmed_absence_allows_release_without_a_service_reply()
    {
        async Task<ReleasePolicy> Check(bool? installed, AdminReply? reply) =>
            await AdminBlockCheck.ReadAsync(installed, "program", _ => Task.FromResult(reply), _ => null);

        Assert.That((await Check(false, null)).Refusal, Is.Null);
        Assert.That((await Check(null, null)).Refusal, Is.EqualTo(ReleasePolicy.Unavailable));
        Assert.That((await Check(true, null)).Refusal, Is.EqualTo(ReleasePolicy.Unavailable));
        Assert.That((await Check(true, AdminReply.Refused("unknown operation"))).Refusal, Is.EqualTo(ReleasePolicy.Unavailable));
        Assert.That((await Check(true, AdminReply.Ok(new { blocked = false }))).Refusal, Is.EqualTo(ReleasePolicy.Unavailable));
        Assert.That((await Check(true, AdminReply.Ok(new AdminBlockStatus(false, 0)))).Refusal, Is.Null);
    }

    [Test]
    public async Task An_unreadable_image_cannot_clear_a_possible_hash_match()
    {
        Task<AdminReply?> Query(string? hash) => Task.FromResult<AdminReply?>(AdminReply.Ok(new AdminBlockStatus(hash is null, hash is null ? 3 : 0)));
        Assert.That((await AdminBlockCheck.ReadAsync(true, "program", Query, _ => null)).Refusal, Is.Not.Null);
        Assert.That((await AdminBlockCheck.ReadAsync(true, "program", Query, _ => "different digest")).Refusal, Is.Null);
    }

    [Test]
    public void Shell_session_consent_tracks_both_the_terminal_and_its_pipe_client()
    {
        var shell = new ShellIdentity(41, DateTime.UnixEpoch, @"C:\shell.exe");
        var consent = new ShellConsent();
        var first = Before.WithPeer(@"C:\tir.exe", Before);
        consent.Allow(shell, ["TOKEN"], first.Scope);

        Assert.That(consent.Check(shell, ["TOKEN"], scope: first.Scope).Answer, Is.EqualTo(ShellAnswer.Give));
        Assert.That(After.WithPeer(@"C:\tir.exe", Before).RefusalSince(first), Is.EqualTo(ReleasePolicy.Changed));
        Assert.That(Before.WithPeer(@"C:\tir.exe", Blocked).RefusalSince(first), Is.EqualTo(Blocked.Refusal));
        Assert.That(consent.Check(shell, ["TOKEN"], scope: Before.WithPeer(@"C:\tir.exe", After).Scope).Answer, Is.EqualTo(ShellAnswer.Ask));
        Assert.That(consent.Check(shell, ["TOKEN"], scope: Before.WithPeer(@"C:\another.exe", Before).Scope).Answer, Is.EqualTo(ShellAnswer.Ask));
    }

    [Test]
    public async Task NuGet_rechecks_cached_and_interactive_answers_and_reprompts_after_unblock()
    {
        var consent = new NuGetConsent();
        int prompts = 0;
        Task<ConsentAnswer> Allow()
        {
            prompts++;
            return Task.FromResult(ConsentAnswer.AllowForSession);
        }
        Task<(NuGetOutcome Outcome, string? PolicyRefusal)> Ask(ReleasePolicy before, ReleasePolicy final) =>
            consent.DecideAsync("dotnet", "TOKEN", before, Allow, () => Task.FromResult(final));

        Assert.That((await Ask(Before, Blocked)).PolicyRefusal, Is.EqualTo(Blocked.Refusal));
        Assert.That((await Ask(Before, Before)).Outcome, Is.EqualTo(NuGetOutcome.AllowedForSession));
        Assert.That((await Ask(Before, Before)).Outcome, Is.EqualTo(NuGetOutcome.CoveredBySession));
        Assert.That((await Ask(Before, Blocked)).PolicyRefusal, Is.EqualTo(Blocked.Refusal));
        Assert.That((await Ask(Blocked, Blocked)).Outcome, Is.EqualTo(NuGetOutcome.Denied));
        Assert.That((await Ask(After, After)).Outcome, Is.EqualTo(NuGetOutcome.AllowedForSession));
        Assert.That(prompts, Is.EqualTo(3));
    }

    [Test]
    public async Task Shell_withholds_every_value_when_blocked_before_or_during_delivery()
    {
        int prepared = 0;
        var policy = Blocked;
        Task<Delivery> Prepare()
        {
            prepared++;
            policy = Blocked;
            return Task.FromResult(new Delivery(new Dictionary<string, string> { ["TOKEN"] = "test-value" }, []));
        }
        var before = await ShellConsent.ReleaseAsync(Before, () => Task.FromResult(policy), Prepare);
        Assert.That(before.Delivery, Is.Null);
        Assert.That(before.Refusal, Is.EqualTo(Blocked.Refusal));
        Assert.That(prepared, Is.Zero);
        policy = Before;
        var during = await ShellConsent.ReleaseAsync(Before, () => Task.FromResult(policy), Prepare);
        Assert.That(during.Delivery, Is.Null);
        Assert.That(during.Refusal, Is.EqualTo(Blocked.Refusal));
        Assert.That(prepared, Is.EqualTo(1));
    }
}
