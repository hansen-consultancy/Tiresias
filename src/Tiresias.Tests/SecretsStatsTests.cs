using Tiresias.App.Logic;
using Tiresias.Protocol;
using Tiresias.UserSecrets;

namespace Tiresias.Tests;

public class SecretsStatsTests
{
    [TestCase(SecretsFileKind.Sealed, SecretsContent.Secrets, ProjectState.Sealed)]
    [TestCase(SecretsFileKind.Plain, SecretsContent.Secrets, ProjectState.NotSealed)]
    [TestCase(SecretsFileKind.Plain, SecretsContent.Settings, ProjectState.Settings)]
    [TestCase(SecretsFileKind.Plain, SecretsContent.Empty, ProjectState.Empty)]
    [TestCase(SecretsFileKind.None, SecretsContent.Empty, ProjectState.Empty)]
    [TestCase(SecretsFileKind.Invalid, SecretsContent.Invalid, ProjectState.Invalid)]
    public void A_folder_s_state_comes_from_its_file(SecretsFileKind kind, SecretsContent content, ProjectState state) =>
        Assert.That(SecretsStats.StateOf(kind, content), Is.EqualTo(state));

    [TestCase(SecretsFileKind.Sealed, 2, ProjectState.PlainAdded)]
    [TestCase(SecretsFileKind.Sealed, 0, ProjectState.Sealed)]
    [TestCase(SecretsFileKind.Plain, 2, ProjectState.NotSealed)]
    public void Plain_keys_beside_a_sealed_envelope_stand_out_until_sealed(SecretsFileKind kind, int additions, ProjectState state) =>
        Assert.That(SecretsStats.StateOf(kind, SecretsContent.Secrets, additions), Is.EqualTo(state));

    [Test]
    public void The_counts_add_up_to_the_side_bar_s_number()
    {
        var stats = SecretsStats.Of([ProjectState.Sealed, ProjectState.Sealed, ProjectState.PlainAdded, ProjectState.NotSealed, ProjectState.Settings, ProjectState.Empty, ProjectState.Empty, ProjectState.Empty]);

        Assert.That(stats, Is.EqualTo(new SecretsStats(Sealed: 2, PlainAdded: 1, NotSealed: 1, Settings: 1, Empty: 3, Invalid: 0)));
        Assert.That(stats.Total, Is.EqualTo(8));
    }
}
