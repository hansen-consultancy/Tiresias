using System.Runtime.InteropServices;
using Tiresias.Vault;
using Windows.Foundation;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Tiresias.Trust;

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
public sealed partial class HelloKeyWrapper : IKeyWrapper, IDisposable
{
    /// <summary>Whether the Tiresias Hello credential exists. Asks Windows without a prompt.</summary>
    public static bool Exists() =>
#if DEBUG
        DemoMode.On ? DemoMode.HelloExists :
#endif
        KeyCredentialManager.IsSupportedAsync().AsTask().GetAwaiter().GetResult()
        && KeyCredentialManager.OpenAsync(CredentialName).AsTask().GetAwaiter().GetResult().Status == KeyCredentialStatus.Success;

    public const string CredentialName = "Tiresias";

    readonly SignatureDerivedWrapper inner;

    HelloKeyWrapper(Func<byte[], byte[]> sign) =>
        inner = new SignatureDerivedWrapper("hello", sign);

    public string Id => inner.Id;

    /// <param name="create">Create the credential when it doesn't exist yet. Only when sealing: a new credential can't open what an old one wrapped.</param>
    public static HelloKeyWrapper Open(bool create)
    {
#if DEBUG
        if (DemoMode.On)
            return OpenDemo(create);
#endif
        var credential = OpenCredential(create);
        return new(challenge => Sign(credential, challenge));
    }

#if DEBUG
    /// <summary>Demo mode's stand-in: a fixed key that "signs" without a prompt, so the real credential is never opened or created.</summary>
    static HelloKeyWrapper OpenDemo(bool create)
    {
        if (!DemoMode.HelloExists && !create)
            throw new HelloException(HelloProblem.CredentialMissing, $"No Windows Hello credential '{CredentialName}' on this machine. Re-wrap the vault from the recovery key.");
        DemoMode.HelloExists = true;
        return new(challenge =>
        {
            // No prompt, but the reason card shows as it would, for a moment, so a demo can be looked at and captured.
            using var why = HelloPrompts.Showing();
            if (why is not null)
                Thread.Sleep(DemoMode.PromptPause);
            return System.Security.Cryptography.HMACSHA256.HashData(DemoMode.HelloKey, challenge);
        });
    }
#endif

    /// <summary>The lease's approval key; no extra prompt once this wrapper has derived its wrap key.</summary>
    public NSec.Cryptography.Key ApprovalKey(string leaseId) => inner.ApprovalKey(leaseId);

    /// <summary>The vault revision signer enrolled with this user's broker service.</summary>
    public NSec.Cryptography.Key RevisionKey() => inner.RevisionKey();

    /// <summary>
    /// The same credential as a trust-chain link key (docs/trust-links.md): its public key, and a
    /// signer that shows a Hello prompt for every link it signs.
    /// </summary>
    public static HelloKey LinkKey(bool create)
    {
        var credential = OpenCredential(create);
        CryptographicBuffer.CopyToByteArray(credential.RetrievePublicKey(CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo), out var spki);
        return new(spki, data => Sign(credential, data));
    }

    public byte[] Wrap(ReadOnlySpan<byte> dek, string context) => inner.Wrap(dek, context);

    public byte[]? Unwrap(ReadOnlySpan<byte> wrapped, string context) => inner.Unwrap(wrapped, context);

    public void Dispose() => inner.Dispose();

    static KeyCredential OpenCredential(bool create)
    {
        if (!KeyCredentialManager.IsSupportedAsync().AsTask().GetAwaiter().GetResult())
            throw new HelloException(HelloProblem.NotSetUp, "Windows Hello is not set up on this machine.");

        var opened = KeyCredentialManager.OpenAsync(CredentialName).AsTask().GetAwaiter().GetResult();
        if (opened.Status == KeyCredentialStatus.Success)
            return opened.Credential;
        if (opened.Status != KeyCredentialStatus.NotFound || !create)
            throw opened.Status == KeyCredentialStatus.NotFound
                ? new HelloException(HelloProblem.CredentialMissing, $"No Windows Hello credential '{CredentialName}' on this machine. Re-wrap the vault from the recovery key.")
                : new HelloException(Problem(opened.Status), $"Windows Hello credential unavailable: {opened.Status}.");

        var created = Prompt(() => KeyCredentialManager.RequestCreateAsync(CredentialName, KeyCredentialCreationOption.FailIfExists));
        if (created.Status == KeyCredentialStatus.CredentialAlreadyExists)
            created = KeyCredentialManager.OpenAsync(CredentialName).AsTask().GetAwaiter().GetResult();
        return created.Status == KeyCredentialStatus.Success
            ? created.Credential
            : throw new HelloException(Problem(created.Status), $"Could not create the Windows Hello credential: {created.Status}.");
    }

    static byte[] Sign(KeyCredential credential, byte[] data)
    {
        var result = Prompt(() => credential.RequestSignAsync(CryptographicBuffer.CreateFromByteArray(data)));
        if (result.Status != KeyCredentialStatus.Success)
            throw new HelloException(Problem(result.Status), $"Windows Hello did not sign: {result.Status}.");
        CryptographicBuffer.CopyToByteArray(result.Result, out var signature);
        return signature;
    }

    /// <summary>
    /// Runs a call that shows the Hello prompt. Windows opens that prompt behind or beside a desktop
    /// app's windows (a known Windows bug, also worked around by Chromium and KeePassXC), so this
    /// brings it to the front while the call runs, or flashes it in the taskbar when Windows won't
    /// let this process take the foreground (see <see cref="Foreground"/>). Windows sometimes fails
    /// the call with a bare HRESULT instead of a status; that becomes a <see cref="HelloException"/>
    /// the app can explain.
    /// </summary>
    static T Prompt<T>(Func<IAsyncOperation<T>> start)
    {
        // The host's reason goes up first: Windows' prompt says only that a sign-in is needed.
        using var why = HelloPrompts.Showing();
        using var done = new CancellationTokenSource();
        var front = Task.Run(() => KeepPromptInFront(done.Token));
        try
        {
            return start().AsTask().GetAwaiter().GetResult();
        }
        catch (COMException e) when (e.HResult == InvalidTicket)
        {
            throw new HelloException(HelloProblem.Expired, "The Windows Hello prompt expired before it was answered.", e);
        }
        catch (COMException e)
        {
            throw new HelloException(HelloProblem.Unavailable, $"Windows Hello failed (0x{e.HResult:X8}).", e);
        }
        finally
        {
            done.Cancel();
            front.Wait();
        }
    }

    /// <summary>
    /// <c>WINBIO_E_INVALID_TICKET</c>: the gesture's ticket expired before the key used it, which is
    /// what happens when a prompt waits out of sight for minutes and is answered late.
    /// </summary>
    const int InvalidTicket = unchecked((int)0x80098044);

    static void KeepPromptInFront(CancellationToken done)
    {
        // Poll fast until the prompt first appears (up to 4 s), then slowly: a wrong PIN re-shows it.
        // Each prompt window is brought forward once; one Windows keeps back flashes until it is looked at.
        nint shown = 0;
        for (var i = 0; !done.IsCancellationRequested && (shown != 0 || i < 40); i++)
        {
            var hwnd = FindWindowW("Credential Dialog Xaml Host", null);
            if (hwnd != 0 && hwnd != shown)
            {
                Foreground.Bring(hwnd);
                shown = hwnd;
            }
            done.WaitHandle.WaitOne(shown != 0 ? 500 : 100);
        }
    }

    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint FindWindowW(string className, string? windowName);

    static HelloProblem Problem(KeyCredentialStatus status) => status switch
    {
        KeyCredentialStatus.UserCanceled => HelloProblem.Cancelled,
        KeyCredentialStatus.NotFound => HelloProblem.CredentialMissing,
        KeyCredentialStatus.UserPrefersPassword => HelloProblem.Cancelled,
        _ => HelloProblem.Unavailable,
    };
}
