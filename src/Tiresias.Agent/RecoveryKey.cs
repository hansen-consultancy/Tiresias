using System.Security.Cryptography;
using NSec.Cryptography;
using Tiresias.Client;
using Tiresias.Trust;
using Tiresias.Vault;

namespace Tiresias.Agent;

internal enum SoloPaperProof { NoSolo, Mismatch, MatchesProfilePin, MatchesServicePin }

/// <summary>A new paper key awaiting backup and enrollment. Its caller owns and clears <see cref="Paper"/>.</summary>
public sealed class PendingRecoveryKey
{
    readonly byte[] digest;
    readonly Action<string> enroll;
    public byte[] Paper { get; }

    internal PendingRecoveryKey(Action<string> enroll)
    {
        using var key = Key.Create(KeyAgreementAlgorithm.X25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        Paper = key.Export(KeyBlobFormat.RawPrivateKey);
        digest = SHA256.HashData(Paper);
        this.enroll = enroll;
    }

    public void Enroll()
    {
        using var key = Key.Import(KeyAgreementAlgorithm.X25519, Paper, KeyBlobFormat.RawPrivateKey);
        if (!CryptographicOperations.FixedTimeEquals(digest, SHA256.HashData(Paper)))
            throw new InvalidOperationException("The prepared paper recovery key has changed.");
        enroll(Convert.ToBase64String(key.PublicKey.Export(KeyBlobFormat.RawPublicKey)));
    }
}

/// <summary>The paper recovery key. Only the enrolled public recipient may wrap new data keys.</summary>
public static class RecoveryKey
{
    public const string WrapperId = "recovery";

    public static string? PublicKey => RecoveryEnrollment.Current()?.PublicKey;

    public static IReadOnlyList<DateTimeOffset> EnrollmentApprovalTimes() => RecoveryEnrollment.ApprovalTimes();

    public static bool IsEnrolled => RecoveryEnrollment.Current() is not null;

    public static bool NeedsVerification => !IsEnrolled && HasUnverifiedSetup;

    static bool HasUnverifiedSetup => KeyringStore.Settings.RecoveryPublicKey is not null || HasTrust;

    static bool HasTrust => BrokerService.EnrollmentForCurrentUser() is not null || RecoveryRestore.Exists(SoloBroker.TrustChainPath)
        || KeyringStore.Tenants.Any(t => t.Solo && t.GenesisHash is not null);

    public static bool CanReplaceUnused => !HasTrust && !RecoveryRestore.AnythingSealed();

    /// <summary>Prepares a first paper without changing the recipient until its backup has been confirmed.</summary>
    public static PendingRecoveryKey Create(bool keepImportedSecretsLocked = false)
        => Prepare(null, () => RequireFresh(keepImportedSecretsLocked),
            keepImportedSecretsLocked ? RecoveryEnrollment.Change : RecoveryEnrollment.ChangeUnused);

    static void RequireFresh(bool keepImportedSecretsLocked)
    {
        if (RecoveryEnrollment.Current() is not null)
            throw new InvalidOperationException("A recovery key is already enrolled. Use tir recovery rotate to change it.");
        if (HasUnverifiedSetup)
            throw new InvalidOperationException("Verify the existing paper recovery key with tir recovery restore before sealing new secrets.");
        if (!keepImportedSecretsLocked && RecoveryRestore.AnythingSealed())
            throw new InvalidOperationException("This PC already has sealed secrets. Restore them with their paper key, or choose a new recovery key in the setup wizard.");
    }

    /// <summary>An interrupted first run can replace a lost key only while nothing relies on it.</summary>
    public static PendingRecoveryKey ReplaceUnused() => Prepare(RecoveryEnrollment.Current(), () =>
    {
        if (!CanReplaceUnused)
            throw new InvalidOperationException("Sealed data or an enrolled trust chain still needs the original recovery key.");
    }, RecoveryEnrollment.ChangeUnused);

    /// <summary>Changes the recipient of future wraps. Existing envelopes and trust chains keep their original paper keys.</summary>
    public static PendingRecoveryKey Rotate(byte[] currentPaper) => Rotate(currentPaper, RecoveryEnrollment.Current(), RecoveryEnrollment.Change);

    internal static PendingRecoveryKey Rotate(ReadOnlySpan<byte> currentPaper, RecoveryBinding? current, Action<RecoveryBinding?, string> change)
    {
        if (current is null)
            throw new InvalidOperationException("No recovery key is enrolled. Verify the original paper with tir recovery restore first.");
        if (!PaperKey.Matches(currentPaper, Convert.FromBase64String(current.PublicKey)))
            throw new InvalidOperationException("That paper does not match the enrolled recovery key.");
        return new(recipient => change(current, recipient));
    }

    internal static PendingRecoveryKey Prepare(RecoveryBinding? expected, Action requireEligible, Action<RecoveryBinding?, string> change)
    {
        requireEligible();
        return new(recipient =>
        {
            requireEligible();
            change(expected, recipient);
        });
    }

    public static IKeyWrapper? Wrapper() => Wrapper(RecoveryEnrollment.Current, () => HasUnverifiedSetup || RecoveryRestore.AnythingSealed());

    // Even if its old profile field disappeared, a configured solo installation already has a paper signer.
    internal static SoloPaperProof VerifySoloPaper(ReadOnlySpan<byte> paper)
    {
        if (!HasTrust)
            return SoloPaperProof.NoSolo;
        var servicePin = BrokerService.EnrollmentForCurrentUser()?.GenesisHash;
        var genesis = servicePin ?? KeyringStore.Tenants.FirstOrDefault(t => t.Solo)?.GenesisHash;
        if (genesis is null || !RecoveryRestore.Exists(SoloBroker.TrustChainPath))
            return SoloPaperProof.Mismatch;
        if (!MatchesSolo(paper, TrustLinkJson.ParseChain(File.ReadAllBytes(SoloBroker.TrustChainPath)), genesis))
            return SoloPaperProof.Mismatch;
        return servicePin is null ? SoloPaperProof.MatchesProfilePin : SoloPaperProof.MatchesServicePin;
    }

    internal static bool MatchesSolo(ReadOnlySpan<byte> paper, TrustLink[]? chain, string pinnedGenesis)
    {
        if (chain is not [{ Body: Genesis first }, ..] || !TrustChainVerifier.Verify(chain, pinnedGenesis).IsValid)
            return false;
        using var signing = PaperKey.SigningKey(paper);
        return CryptographicOperations.FixedTimeEquals(first.PaperKey.PublicKey, signing.PublicKey.Export(KeyBlobFormat.RawPublicKey));
    }

    internal static IKeyWrapper? Wrapper(Func<RecoveryBinding?> read, Func<bool> needsVerification)
    {
        if (read() is { } binding)
            return new EnrolledWrapper(binding, read);
        if (needsVerification())
            throw new InvalidOperationException("The recovery key in this profile needs verification. Run tir recovery restore with the original paper before sealing new secrets.");
        return null;
    }

    // A pending consent may outlive a rotation. Recheck the captured revision at the actual wrap.
    sealed class EnrolledWrapper(RecoveryBinding binding, Func<RecoveryBinding?> read) : IKeyWrapper
    {
        readonly IKeyWrapper recipient = X25519KeyWrapper.ForPublicKey(WrapperId, Convert.FromBase64String(binding.PublicKey));
        public string Id => WrapperId;
        public byte[] Wrap(ReadOnlySpan<byte> dek, string context) =>
            read() == binding ? recipient.Wrap(dek, context) : throw new InvalidOperationException("The enrolled recovery key changed. Request sealing again.");
        public byte[]? Unwrap(ReadOnlySpan<byte> wrapped, string context) => null;
    }
}
