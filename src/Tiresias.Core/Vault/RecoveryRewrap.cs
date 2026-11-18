namespace Tiresias.Vault;

/// <summary>What restoring did to one sealed item.</summary>
public enum RewrapOutcome
{
    /// <summary>This Windows Hello key opens it already; nothing changed.</summary>
    AlreadyOpens,
    /// <summary>The recovery key opened it, and a copy of its DEK for this Hello key was added.</summary>
    Rewrapped,
    /// <summary>Neither key opens it: sealed to another recovery key, or tampered with.</summary>
    DoesNotOpen,
}

/// <summary>
/// Gives a sealed item back to Windows Hello after the Hello key it was sealed with is gone (another
/// PC, a reset TPM, a removed Hello credential). The recovery key opens the item's DEK, which is then
/// wrapped again for the current Hello key. The value, its ciphertext, its version and its recovery
/// copy stay as they were, so nothing is decrypted and nothing is lost if this is interrupted.
/// </summary>
public static class RecoveryRewrap
{
    /// <param name="recoveryOpens">Whether the recovery key opens the item, checked even when Hello already does.</param>
    public static (RewrapOutcome Outcome, SealedSecret Secret, bool RecoveryOpens) Secret(SealedSecret secret, IKeyWrapper hello, IKeyWrapper recovery)
    {
        var byRecovery = SecretEnvelope.UnwrapDek(secret, recovery);
        try
        {
            var byHello = SecretEnvelope.UnwrapDek(secret, hello);
            if (byHello is not null)
            {
                Array.Clear(byHello);
                return (RewrapOutcome.AlreadyOpens, secret, byRecovery is not null);
            }
            return byRecovery is null
                ? (RewrapOutcome.DoesNotOpen, secret, false)
                : (RewrapOutcome.Rewrapped, SecretEnvelope.Rewrap(secret, byRecovery, hello), true);
        }
        finally
        {
            if (byRecovery is not null)
                Array.Clear(byRecovery);
        }
    }

    /// <summary>
    /// Whether the device should store the typed recovery key as its own after a restore. A device
    /// with none takes it when it opened something here (or nothing is sealed yet). A device with a
    /// different one swaps only when the typed key opens every sealed item, so the swap loses
    /// nothing; a stored key some items still need is kept, since only its paper opens them.
    /// </summary>
    public static bool ShouldAdopt(bool hasStoredKey, bool storedMatches, int items, int recoveryOpens) =>
        !storedMatches && (hasStoredKey ? items > 0 && recoveryOpens == items : items == 0 || recoveryOpens > 0);
}
