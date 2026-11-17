using NSec.Cryptography;
using Tiresias.Vault;

namespace Tiresias.Agent;

/// <summary>
/// The paper recovery key: an X25519 key whose private half exists only on paper and whose public
/// half wraps every secret's DEK beside Hello, so no secret depends on the TPM alone.
/// </summary>
public static class RecoveryKey
{
    public const string WrapperId = "recovery";

    /// <summary>
    /// Creates the key and stores its public half. The caller shows the returned private half once
    /// and zeroes it.
    /// </summary>
    /// <exception cref="InvalidOperationException">One is already configured: secrets sealed so far open only with that one.</exception>
    public static byte[] Create()
    {
        var settings = KeyringStore.Settings;
        if (settings.RecoveryPublicKey is not null)
            throw new InvalidOperationException("A recovery key is already configured. Secrets sealed so far open only with that one; refusing to replace it.");

        using var key = Key.Create(KeyAgreementAlgorithm.X25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var raw = key.Export(KeyBlobFormat.RawPrivateKey);
        KeyringStore.Settings = settings with { RecoveryPublicKey = Convert.ToBase64String(key.PublicKey.Export(KeyBlobFormat.RawPublicKey)) };
        return raw;
    }

    /// <summary>The wrapper that seals to the recovery key, or <c>null</c> when none is set.</summary>
    public static IKeyWrapper? Wrapper() =>
        KeyringStore.Settings.RecoveryPublicKey is { } key ? X25519KeyWrapper.ForPublicKey(WrapperId, Convert.FromBase64String(key)) : null;
}
