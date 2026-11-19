using Tiresias.Policy;
using Tiresias.Vault;

namespace Tiresias.Agent;

/// <summary>
/// Changes to the selected tenant's vault file, for <c>tir</c> and the app alike. Secrets are
/// sealed to Windows Hello and the recovery key before they touch the disk; services change only
/// through <see cref="Approve"/>. In solo mode the running broker notices the file changed and uses
/// it from its next request.
/// </summary>
public static class VaultEditor
{
    public static string Path => KeyringStore.Settings.VaultPath;

    /// <summary>The vault, or an empty one when the file doesn't exist yet.</summary>
    public static VaultDocument Load() => File.Exists(Path) ? VaultFile.Load(Path) : new VaultDocument([], []);

    /// <summary>
    /// Seals <paramref name="value"/> as the next version of <paramref name="slug"/>, replacing the
    /// previous one. A new value approves no policy: it keeps the policy approved for the previous
    /// version, and a new secret gets the empty one, so services using it need <see cref="Approve"/>.
    /// </summary>
    /// <param name="hello">The agent's open wrapper; <c>null</c> opens one here, which may show the Hello prompt.</param>
    /// <returns>The version written.</returns>
    /// <exception cref="InvalidOperationException">No recovery key yet, an empty value, or the services using the secret changed without approval.</exception>
    public static int SealSecret(string slug, ReadOnlySpan<byte> value, HelloKeyWrapper? hello = null)
    {
        if (value.IsEmpty)
            throw new InvalidOperationException("Empty value.");
        var recovery = RecoveryKey.Wrapper()
            ?? throw new InvalidOperationException("No recovery key yet. Run tir recovery init first, so no secret depends on the TPM alone.");
        var vault = Load();
        var previous = vault.FindSecret(slug);
        byte[]? policy;
        if (previous is null)
            policy = PolicyBinding.Hash(new VaultDocument([], []), slug);
        else if (previous.PolicyHash is null)
            policy = null;
        else if (PolicyBinding.Allows(vault, previous))
            policy = previous.PolicyHash;
        else
            throw new InvalidOperationException($"The services using {slug} changed without your approval. Approve them in the app's Services window, or undo the change in {Path}.");
        var version = (previous?.Version ?? 0) + 1;
        SealedSecret secret;
        if (hello is not null)
            secret = SecretEnvelope.Seal(slug, version, value, [hello, recovery], policy);
        else
        {
            using var opened = HelloKeyWrapper.Open(create: true);
            secret = SecretEnvelope.Seal(slug, version, value, [opened, recovery], policy);
        }
        VaultFile.Save(Path, vault with { Secrets = [.. vault.Secrets.Where(s => s.Slug != slug), secret] });
        return version;
    }

    /// <summary>What setting <paramref name="set"/> and removing <paramref name="remove"/> would change, for the user to approve.</summary>
    /// <exception cref="InvalidOperationException">A service set uses a secret that isn't in the vault.</exception>
    public static PolicyChange Plan(IReadOnlyList<Service> set, IReadOnlyList<string> remove) => PolicyChangePlanner.Plan(Load(), set, remove);

    /// <summary>
    /// Writes a change the user approved, rebinding each secret it touches to its new policy. The
    /// DEKs are opened with <paramref name="fresh"/>, so approving costs a Windows Hello prompt
    /// even while the agent is unlocked: its held wrapper opens secrets, not policy changes.
    /// </summary>
    /// <param name="fresh">A wrapper opened for this approval alone (<see cref="HelloKeyWrapper.Open"/>), never the agent's.</param>
    /// <exception cref="InvalidOperationException">The vault changed since <paramref name="change"/> was planned, a secret didn't open, or no recovery key yet.</exception>
    public static void Approve(PolicyChange change, HelloKeyWrapper fresh)
    {
        var vault = Load();
        var again = PolicyChangePlanner.Plan(vault, change.Set, change.Remove);
        if (!again.Lines.SequenceEqual(change.Lines) || !again.Rebind.SequenceEqual(change.Rebind))
            throw new InvalidOperationException("The vault changed while you were deciding. Look at the change again.");
        if (again.Rebind.Count == 0)
        {
            VaultFile.Save(Path, again.Next);
            return;
        }
        var recovery = RecoveryKey.Wrapper()
            ?? throw new InvalidOperationException("No recovery key yet. Run tir recovery init first, so no secret depends on the TPM alone.");
        var secrets = again.Next.Secrets.ToList();
        foreach (var slug in again.Rebind)
        {
            var index = secrets.FindIndex(s => s.Slug == slug);
            var dek = SecretEnvelope.UnwrapDek(secrets[index], fresh)
                ?? throw new InvalidOperationException($"Windows Hello can't open {slug}. Re-wrap the vault from the recovery key, then approve again.");
            try
            {
                secrets[index] = SecretEnvelope.Rebind(secrets[index], dek, PolicyBinding.Hash(again.Next, slug), [fresh, recovery])
                    ?? throw new InvalidOperationException($"{slug} doesn't open. Seal its value again, then approve.");
            }
            finally
            {
                Array.Clear(dek);
            }
        }
        VaultFile.Save(Path, again.Next with { Secrets = secrets });
    }
}
