using System.Text.Json.Nodes;
using NSec.Cryptography;
using NUnit.Framework;
using Tiresias.Agent;
using Tiresias.EnvironmentVariables;
using Tiresias.UserSecrets;
using Tiresias.Vault;

namespace Tiresias.App.Tests;

public class RecoveryEnvelopeTests
{
    [Test]
    public void Each_paper_key_recovers_the_vault_project_and_environment_versions_sealed_to_it()
    {
        using var first = Key.Create(KeyAgreementAlgorithm.X25519);
        using var second = Key.Create(KeyAgreementAlgorithm.X25519);
        var current = Binding(first);
        var before = Seal(1);
        current = Binding(second);
        var after = Seal(2);

        Check(before, first, opens: true);
        Check(before, second, opens: false);
        Check(after, second, opens: true);
        Check(after, first, opens: false);

        (SealedSecret Vault, string Project, string Environment) Seal(int version)
        {
            var recipient = RecoveryKey.Wrapper(() => current, () => throw new AssertionException("Unexpected legacy lookup"))!;
            return (SecretEnvelope.Seal("example", version, "example value"u8, [recipient]),
                UserSecretsVault.Seal("project", version, new JsonObject { ["key"] = "example" }, [recipient]),
                UserSecretsVault.Seal(EnvironmentFile.Id, version, SealedEnvironment.Empty.ToDocument(), [recipient]));
        }
    }

    static RecoveryBinding Binding(Key key) =>
        new(Guid.NewGuid(), Convert.ToBase64String(key.PublicKey.Export(KeyBlobFormat.RawPublicKey)));

    static void Check((SealedSecret Vault, string Project, string Environment) snapshot, Key key, bool opens)
    {
        var paper = X25519KeyWrapper.ForKey(RecoveryKey.WrapperId, key);
        var dek = SecretEnvelope.UnwrapDek(snapshot.Vault, paper);
        try
        {
            Assert.That(dek is not null && SecretEnvelope.Open(snapshot.Vault, dek) is not null, Is.EqualTo(opens));
            Assert.That(UserSecretsVault.Opens("project", snapshot.Project, paper), Is.EqualTo(opens));
            Assert.That(UserSecretsVault.Opens(EnvironmentFile.Id, snapshot.Environment, paper), Is.EqualTo(opens));
        }
        finally
        {
            if (dek is not null)
                Array.Clear(dek);
        }
    }
}
