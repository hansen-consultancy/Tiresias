using System.IO;
using System.Security.Cryptography;
using NSec.Cryptography;
using NUnit.Framework;
using Tiresias.Agent;
using Tiresias.Client;
using Tiresias.Trust;
using Tiresias.UserSecrets;
using Tiresias.Vault;

namespace Tiresias.App.Tests;

public class RecoveryKeyTests
{
    [Test]
    public void A_legacy_recipient_requires_migration_but_a_new_profile_has_no_wrapper()
    {
        Assert.That(() => RecoveryKey.Wrapper(() => null, () => true), Throws.InvalidOperationException.With.Message.Contains("tir recovery restore"));
        Assert.That(RecoveryKey.Wrapper(() => null, () => false), Is.Null);
    }

    [Test]
    public void A_queued_wrap_requires_the_same_protected_revision()
    {
        using var key = Key.Create(KeyAgreementAlgorithm.X25519);
        var original = Binding(key);
        RecoveryBinding? current = original;
        var wrapper = RecoveryKey.Wrapper(() => current, () => throw new AssertionException("Unexpected legacy lookup"))!;
        Assert.That(wrapper.Wrap(new byte[32], "test"), Is.Not.Empty);
        current = original with { Revision = Guid.NewGuid() };
        Assert.That(() => wrapper.Wrap(new byte[32], "test"), Throws.InvalidOperationException);
        current = null;
        Assert.That(() => wrapper.Wrap(new byte[32], "test"), Throws.InvalidOperationException);
    }

    [TestCase("device")]
    [TestCase("tenant")]
    [TestCase("project")]
    [TestCase("environment")]
    [TestCase("invalid project")]
    public void A_profile_without_enrollment_or_a_hint_still_recognizes_existing_sealed_data(string store)
    {
        var folder = Directory.CreateTempSubdirectory();
        var project = new UserSecretsFolder("example", folder.FullName);
        var env = Path.Combine(folder.FullName, "environment.json");
        var vaults = new[] { "device", "tenant" }.Select(name => Path.Combine(folder.FullName, name + ".json")).ToArray();
        using var key = Key.Create(KeyAgreementAlgorithm.X25519);
        var wrap = X25519KeyWrapper.ForKey("recovery", key);
        try
        {
            foreach (var vault in vaults)
                VaultFile.Save(vault, new([], []));
            Assert.That(HasData(), Is.False);
            if (store == "invalid project")
                File.WriteAllText(project.FilePath, "{");
            else if (store == "project" || store == "environment")
                File.WriteAllText(store == "project" ? project.FilePath : env, UserSecretsVault.Seal("example", 1, new(), [wrap]));
            else
                VaultFile.Save(store == "device" ? vaults[0] : vaults[1], new([SecretEnvelope.Seal("demo", 1, "example"u8, [wrap])], []));
            Assert.That(HasData(), Is.True);
            Assert.That(() => RecoveryKey.Wrapper(() => null, HasData), Throws.InvalidOperationException);
        }
        finally
        {
            foreach (var path in vaults.Append(project.FilePath).Append(env))
                File.Delete(path);
            folder.Delete();
        }

        bool HasData() => RecoveryRestore.AnythingSealed(vaults, [project], env);
    }

    [Test]
    public void An_unreadable_vault_is_never_reported_as_unused()
    {
        var path = Path.GetTempFileName();
        try
        {
            using var held = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            Assert.That(() => RecoveryRestore.AnythingSealed([path], [], path), Throws.InstanceOf<IOException>());
        }
        finally { File.Delete(path); }
    }

    [Test]
    public void Rotation_requires_the_current_paper_and_defers_the_change_until_backup()
    {
        using var key = Key.Create(KeyAgreementAlgorithm.X25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var original = Binding(key);
        var oldPaper = key.Export(KeyBlobFormat.RawPrivateKey);
        var current = original;
        void Change(RecoveryBinding? expected, string recipient)
        {
            if (expected != current)
                throw new InvalidOperationException("Stale enrollment");
            current = new(Guid.NewGuid(), recipient);
        }

        PendingRecoveryKey? first = null, second = null;
        try
        {
            Assert.That(() => RecoveryKey.Rotate(new byte[32], original, Change), Throws.InvalidOperationException);
            Assert.That(() => RecoveryKey.Rotate(oldPaper, null, Change), Throws.InvalidOperationException);
            first = RecoveryKey.Rotate(oldPaper, original, Change);
            second = RecoveryKey.Rotate(oldPaper, original, Change);
            Assert.That(current, Is.EqualTo(original));
            first.Enroll();
            Assert.That(PaperKey.Matches(first.Paper, Convert.FromBase64String(current.PublicKey)), Is.True);
            Assert.That(current.PublicKey, Is.Not.EqualTo(original.PublicKey));
            var enrolled = current;
            Assert.That(second.Enroll, Throws.InvalidOperationException);
            Assert.That(current, Is.EqualTo(enrolled));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(oldPaper);
            if (first is not null) CryptographicOperations.ZeroMemory(first.Paper);
            if (second is not null) CryptographicOperations.ZeroMemory(second.Paper);
        }
    }

    [Test]
    public void A_first_run_replacement_rechecks_eligibility_after_the_paper_was_shown()
    {
        bool eligible = true, changed = false;
        var pending = RecoveryKey.Prepare(null, () =>
        {
            if (!eligible)
                throw new InvalidOperationException();
        }, (_, _) => changed = true);
        try
        {
            Assert.That(changed, Is.False);
            eligible = false;
            Assert.That(pending.Enroll, Throws.InvalidOperationException);
            Assert.That(changed, Is.False);
            eligible = true;
            pending.Paper[0] ^= 1;
            Assert.That(pending.Enroll, Throws.InvalidOperationException);
            Assert.That(changed, Is.False);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pending.Paper);
        }
    }

    [TestCase(false, "paper", "paper", 0, 0, true, false)]
    [TestCase(false, "paper", "paper", 2, 1, true, false)]
    [TestCase(false, "older", "paper", 2, 1, false, true)]
    [TestCase(false, "older", "paper", 2, 2, true, false)]
    [TestCase(false, "<malformed>", "paper", 1, 1, true, false)]
    [TestCase(false, null, "paper", 2, 1, true, false)]
    [TestCase(false, null, "paper", 0, 0, true, false)]
    [TestCase(true, "wrong hint", "paper", 2, 1, false, false)]
    [TestCase(true, "older", "older", 1, 1, false, true)]
    public void Restore_preserves_protected_enrollment_and_honors_proven_legacy_paper(bool enrolled, string? legacy,
        string offered, int items, int opens, bool expectEnroll, bool expectKept)
    {
        var protectedKey = enrolled ? new RecoveryBinding(Guid.NewGuid(), "paper") : null;
        Assert.That(RecoveryRestore.PlanEnrollment(protectedKey, legacy, offered, items, opens, SoloPaperProof.NoSolo), Is.EqualTo((expectEnroll, expectKept)));
    }

    [TestCase(null, 2, 0)]
    [TestCase("older", 2, 0)]
    [TestCase("older", 0, 0)]
    [TestCase("<malformed>", 0, 0)]
    public void Mismatched_paper_without_evidence_cannot_migrate_a_legacy_recipient(string? legacy, int items, int opens)
    {
        Assert.That(() => RecoveryRestore.PlanEnrollment(null, legacy, "offered", items, opens, SoloPaperProof.NoSolo), Throws.InvalidOperationException);
    }

    [Test]
    public void A_matching_legacy_hint_cannot_displace_the_known_solo_signer_without_independent_evidence()
    {
        var trustedPaper = RandomNumberGenerator.GetBytes(32);
        var offeredPaper = RandomNumberGenerator.GetBytes(32);
        try
        {
            using var signing = PaperKey.SigningKey(trustedPaper);
            using var device = Key.Create(SignatureAlgorithm.Ed25519);
            using var offered = Key.Import(KeyAgreementAlgorithm.X25519, offeredPaper, KeyBlobFormat.RawPrivateKey);
            var recipient = Convert.ToBase64String(offered.PublicKey.Export(KeyBlobFormat.RawPublicKey));
            var genesis = TrustChain.Start("solo", "owner", new("device", device), new("paper", signing), new(), DateTimeOffset.UtcNow);
            var pin = TrustChain.Hash(genesis);
            Assert.That(RecoveryKey.MatchesSolo(trustedPaper, [genesis], pin), Is.True);
            Assert.That(RecoveryKey.MatchesSolo(trustedPaper, [genesis], TrustChain.ZeroHash), Is.False);
            Assert.That(RecoveryKey.MatchesSolo(offeredPaper, [genesis], pin), Is.False);
            Assert.That(() => RecoveryRestore.PlanEnrollment(null, recipient, recipient, 0, 0, SoloPaperProof.Mismatch),
                Throws.InvalidOperationException.With.Message.Contains("solo trust chain"));
            Assert.That(RecoveryRestore.PlanEnrollment(null, recipient, recipient, 1, 1, SoloPaperProof.Mismatch), Is.EqualTo((true, false)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(trustedPaper);
            CryptographicOperations.ZeroMemory(offeredPaper);
        }
    }

    [Test]
    public void A_legacy_hint_cannot_enroll_a_paper_that_opens_none_of_the_existing_data()
    {
        using var original = Key.Create(KeyAgreementAlgorithm.X25519);
        using var proposed = Key.Create(KeyAgreementAlgorithm.X25519);
        using var hello = Key.Create(KeyAgreementAlgorithm.X25519);
        var unlocked = X25519KeyWrapper.ForKey("hello", hello);
        var item = SecretEnvelope.Seal("demo", 1, "example"u8, [X25519KeyWrapper.ForKey("recovery", original), unlocked]);
        var (outcome, _, opens) = RecoveryRewrap.Secret(item, unlocked, X25519KeyWrapper.ForKey("recovery", proposed));
        Assert.That(outcome, Is.EqualTo(RewrapOutcome.AlreadyOpens));
        Assert.That(opens, Is.False);
        var recipient = Binding(proposed).PublicKey;
        foreach (var solo in new[] { SoloPaperProof.NoSolo, SoloPaperProof.MatchesProfilePin, SoloPaperProof.Mismatch })
            Assert.That(() => RecoveryRestore.PlanEnrollment(null, recipient, recipient, 1, opens ? 1 : 0, solo),
                Throws.InvalidOperationException.With.Message.Contains("opens none"));
        Assert.That(RecoveryRestore.PlanEnrollment(null, recipient, recipient, 1, 0, SoloPaperProof.MatchesServicePin), Is.EqualTo((true, false)));
        Assert.That(RecoveryRestore.PlanEnrollment(null, recipient, recipient, 0, 0, SoloPaperProof.NoSolo), Is.EqualTo((true, false)));
    }

    [TestCase(null, 0)]
    [TestCase(null, 3)]
    [TestCase("stale", 0)]
    [TestCase("stale", 3)]
    public void The_verified_service_paper_still_migrates_with_a_missing_or_stale_hint(string? legacy, int items)
    {
        Assert.That(RecoveryRestore.PlanEnrollment(null, legacy, "verified", items, 0, SoloPaperProof.MatchesServicePin),
            Is.EqualTo((true, false)));
        var current = new RecoveryBinding(Guid.NewGuid(), "enrolled");
        Assert.That(() => RecoveryRestore.PlanEnrollment(current, legacy, "verified", items, 0, SoloPaperProof.MatchesServicePin),
            Throws.InvalidOperationException);
        Assert.That(RecoveryRestore.PlanEnrollment(current, legacy, "verified", 1, 1, SoloPaperProof.MatchesServicePin),
            Is.EqualTo((false, true)));
    }

    [Test]
    public void A_declined_enrollment_or_a_concurrent_edit_aborts_all_restore_writes()
    {
        var paths = new[] { Path.GetTempFileName(), Path.GetTempFileName() };
        try
        {
            var changes = paths.Select(path =>
                (path, SHA256.HashData(File.ReadAllBytes(path)), (Action)(() => File.WriteAllText(path, "restored")))).ToArray();
            Assert.That(() => RecoveryRestore.Apply(() => throw new OperationCanceledException(), changes), Throws.TypeOf<OperationCanceledException>());
            Assert.That(paths.Select(File.ReadAllText), Is.All.Empty);
            Assert.That(() => RecoveryRestore.Apply(() => File.WriteAllText(paths[1], "updated"), changes), Throws.InvalidOperationException);
            Assert.That(paths.Select(File.ReadAllText), Is.EqualTo(new[] { "", "updated" }));
        }
        finally
        {
            foreach (var path in paths)
                File.Delete(path);
        }
    }

    static RecoveryBinding Binding(Key key) =>
        new(Guid.NewGuid(), Convert.ToBase64String(key.PublicKey.Export(KeyBlobFormat.RawPublicKey)));
}
