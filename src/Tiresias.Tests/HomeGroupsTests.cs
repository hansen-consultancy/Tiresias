using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

/// <summary>Home's two groups: how credentials are held, and what can reach them (docs/attack-surface.md#ranking).</summary>
public class HomeGroupsTests
{
    static readonly DoctorCheck Variables = new("environment variables", DoctorStatus.Warn, "1 looks like a secret",
        new ProtectVariables(["API_KEY"]), Position.Plaintext, Position.SealedApproved);

    static readonly DoctorCheck Blocked = new(@"blocked C:\bad.exe", DoctorStatus.Fail, "still here",
        new RevealFile(@"C:\bad.exe"), Kind: Doctor.BlockedKind) { Surface = true };

    static DoctorCheck Unsigned(string name) => new($"unsigned {name}", DoctorStatus.Warn, "no signature",
        new RevealFile($@"C:\{name}.exe"), Kind: Doctor.UnsignedStartupKind) { Surface = true };

    [Test]
    public void Surface_findings_rank_apart_from_how_credentials_are_held()
    {
        var split = FindingView.Of([Unsigned("a"), Variables, Blocked, Unsigned("b")], Dismissals.Empty);

        Assert.That(split.Held.Select(g => g.Single()), Is.EqualTo(new[] { Variables }));
        Assert.That(split.Reach.Select(FindingView.Title), Is.EqualTo(new[] { Blocked.Name, $"2 {Doctor.UnsignedStartupKind}" }));
    }

    [Test]
    public void Home_numbers_how_credentials_are_held_first_even_against_a_failing_surface_finding()
    {
        var split = FindingView.Of([Blocked, Variables], Dismissals.Empty);

        Assert.That(split.Open.Select(g => g[0]), Is.EqualTo(new[] { Variables, Blocked }));
    }

    [Test]
    public void A_group_with_nothing_open_is_empty()
    {
        var split = FindingView.Of([Variables], Dismissals.Empty.Dismiss(Variables, "test machine", DateTimeOffset.UnixEpoch));

        Assert.That(split.Held, Is.Empty);
        Assert.That(split.Reach, Is.Empty);
    }

    [Test]
    public async Task The_doctor_marks_programs_and_blocks_as_surface_and_variables_as_held()
    {
        var checks = await Doctor.RunAsync(new Probe());

        Assert.That(checks.Single(c => c.Name == Doctor.VariablesCheck).Surface, Is.False);
        Assert.That(checks.Where(c => c.Kind is Doctor.BlockedKind or Doctor.UnsignedStartupKind).Select(c => c.Surface), Is.Not.Empty.And.All.True);
    }

    sealed class Probe : IDoctorProbe
    {
        public bool Enrolled => true;
        public bool HasDeviceKey => true;
        public bool RecoveryKeySet => true;
        public IReadOnlyList<string> ExposedVariables => ["API_KEY"];
        public Task<int?> BrokerStatusAsync() => Task.FromResult<int?>(401);
        public Task<bool> ForwarderListeningAsync() => Task.FromResult(true);
        public IEnumerable<DoctorFile> UserSecretsFiles() => [];
        public IEnumerable<DoctorFile> Projects() => [];
        public IEnumerable<DoctorFile> ConfigFiles() => [];
        public IEnumerable<string> KeyFiles() => [];
        public DoctorVault? Vault => new(2, [], []);
        public IEnumerable<StartupEntry> StartupEntries() => [new("Mine", StartupEntry.RunKey, @"C:\Users\alice\mine.exe", Signed: false)];
        public IEnumerable<string> BlockedPrograms() => [@"C:\Program Files\Bad\bad.exe"];
    }
}
