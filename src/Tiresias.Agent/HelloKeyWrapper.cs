using System.Text;
using Tiresias.Vault;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;

namespace Tiresias.Agent;

/// <summary>
/// The day-to-day vault key: a Windows Hello credential (<see cref="KeyCredentialManager"/>, named
/// <see cref="CredentialName"/>). Its private key is created in the TPM and is non-exportable, and
/// Windows asks for the Hello gesture on every signature, so nothing on this machine can use it
/// without the user present.
/// </summary>
/// <remarks>
/// Hello keys can only sign, so the wrap key is derived from a signature over a fixed challenge
/// (<see cref="SignatureDerivedWrapper"/>). That rests on one assumption, stated plainly: Hello keys
/// are RSA and sign with PKCS#1 v1.5, which is deterministic, so the same key always yields the
/// same signature and thus the same wrap key. If Windows ever switched these credentials to a
/// randomised scheme (PSS, ECDSA), unwrap would fail closed (return <c>null</c>) and the vault
/// would need re-wrapping from the recovery key. The signature itself is as secret as the wrap key
/// and is zeroed after derivation; it exists in this process's memory for that moment.
/// One instance costs one Hello prompt, on first use.
/// </remarks>
public sealed class HelloKeyWrapper : IKeyWrapper, IDisposable
{
    public const string CredentialName = "Tiresias";

    readonly SignatureDerivedWrapper inner;

    HelloKeyWrapper(KeyCredential credential) =>
        inner = new SignatureDerivedWrapper("hello", challenge => Sign(credential, challenge));

    public string Id => inner.Id;

    /// <param name="create">Create the credential when it doesn't exist yet. Only when sealing: a new credential can't open what an old one wrapped.</param>
    public static HelloKeyWrapper Open(bool create) => new(OpenCredential(create));

    /// <summary>A fresh Hello prompt that proves the user is present, for step-up actions such as elevation.</summary>
    public static void ConfirmPresence(string purpose)
    {
        var challenge = Encoding.UTF8.GetBytes($"tiresias/v1/presence\n{purpose}\n{Guid.NewGuid():N}");
        Array.Clear(Sign(OpenCredential(create: false), challenge));
    }

    public byte[] Wrap(ReadOnlySpan<byte> dek, string context) => inner.Wrap(dek, context);

    public byte[]? Unwrap(ReadOnlySpan<byte> wrapped, string context) => inner.Unwrap(wrapped, context);

    public void Dispose() => inner.Dispose();

    static KeyCredential OpenCredential(bool create)
    {
        if (!KeyCredentialManager.IsSupportedAsync().AsTask().GetAwaiter().GetResult())
            throw new InvalidOperationException("Windows Hello is not set up on this machine.");

        var opened = KeyCredentialManager.OpenAsync(CredentialName).AsTask().GetAwaiter().GetResult();
        if (opened.Status == KeyCredentialStatus.Success)
            return opened.Credential;
        if (opened.Status != KeyCredentialStatus.NotFound || !create)
            throw new InvalidOperationException(opened.Status == KeyCredentialStatus.NotFound
                ? $"No Windows Hello credential '{CredentialName}' on this machine. Re-wrap the vault from the recovery key."
                : $"Windows Hello credential unavailable: {opened.Status}.");

        var created = KeyCredentialManager.RequestCreateAsync(CredentialName, KeyCredentialCreationOption.FailIfExists).AsTask().GetAwaiter().GetResult();
        return created.Status == KeyCredentialStatus.Success
            ? created.Credential
            : throw new InvalidOperationException($"Could not create the Windows Hello credential: {created.Status}.");
    }

    static byte[] Sign(KeyCredential credential, byte[] data)
    {
        var result = credential.RequestSignAsync(CryptographicBuffer.CreateFromByteArray(data)).AsTask().GetAwaiter().GetResult();
        if (result.Status != KeyCredentialStatus.Success)
            throw new InvalidOperationException($"Windows Hello did not sign: {result.Status}.");
        CryptographicBuffer.CopyToByteArray(result.Result, out var signature);
        return signature;
    }
}
