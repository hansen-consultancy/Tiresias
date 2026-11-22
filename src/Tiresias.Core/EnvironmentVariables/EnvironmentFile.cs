using System.Text.Json;
using Tiresias.Protocol;
using Tiresias.UserSecrets;
using Tiresias.Vault;

namespace Tiresias.EnvironmentVariables;

public sealed class EnvironmentIntegrityException : InvalidOperationException
{
    public EnvironmentIntegrityException() : base("The sealed environment could not be authenticated.") { }

    EnvironmentIntegrityException(string reason) : base(reason) { }

    internal static EnvironmentIntegrityException Changed() => new("The sealed environment changed during this request. Request access again.");

    internal static EnvironmentIntegrityException SessionChanged() => new("The unlock session changed during this request. Request access again.");
}

/// <summary>The environment's authenticated on-disk policy. Only an absent file represents a new environment.</summary>
public sealed class EnvironmentFile(string path)
{
    // A colon cannot occur in a Windows project-secrets directory name.
    public const string Id = "tiresias:environment";

    public bool Exists => ReadIfPresent(() => { _ = File.GetAttributes(path); return true; });

    public (SealedEnvironment Environment, int Version) Open(IKeyWrapper hello) => Open(ReadText(), hello);

    public EnvironmentSnapshot ReadForDelivery(IKeyWrapper hello)
    {
        var text = ReadText();
        return new(Open(text, hello).Environment, () =>
        {
            if (ReadText() != text)
                throw EnvironmentIntegrityException.Changed();
        });
    }

    public bool Opens(IKeyWrapper hello)
    {
        try
        {
            return Open(hello).Version > 0;
        }
        catch (EnvironmentIntegrityException)
        {
            return false;
        }
    }

    public (RewrapOutcome Outcome, string FileText, bool RecoveryOpens) Rewrap(IKeyWrapper hello, IKeyWrapper recovery)
    {
        var text = ReadText() ?? throw new EnvironmentIntegrityException();
        var secret = ReadEnvelope(text);
        var (outcome, restored, recoveryOpens) = RecoveryRewrap.Secret(secret, hello, recovery);
        if (outcome != RewrapOutcome.DoesNotOpen)
            Open(restored, hello);
        return (outcome, outcome == RewrapOutcome.Rewrapped ? SecretsFile.Write(UserSecretsVault.ToBlob(restored)) : text, recoveryOpens);
    }

    static (SealedEnvironment Environment, int Version) Open(string? text, IKeyWrapper hello)
    {
        if (text is null)
            return (SealedEnvironment.Empty, 0);
        var secret = ReadEnvelope(text);
        return (Open(secret, hello), secret.Version);
    }

    static SealedSecret ReadEnvelope(string text) => ReadData(() =>
    {
        var secret = UserSecretsVault.ToSecret(Id, SecretsFile.ReadSealedOnly(text));
        if (secret.Version < 1)
            throw new EnvironmentIntegrityException();
        return secret;
    });

    static SealedEnvironment Open(SealedSecret secret, IKeyWrapper hello)
    {
        // A Windows Hello cancellation or timeout is a user-presence outcome and must reach the caller.
        var dek = SecretEnvelope.UnwrapDek(secret, hello) ?? throw new EnvironmentIntegrityException();
        try
        {
            return ReadData(() => SealedEnvironment.FromDocument(UserSecretsVault.OpenDocument(secret, dek)));
        }
        finally
        {
            Array.Clear(dek);
        }
    }

    static T ReadData<T>(Func<T> read)
    {
        try
        {
            return read();
        }
        catch (Exception e) when (e is JsonException or InvalidDataException or FormatException or InvalidOperationException or ArgumentException or OverflowException)
        {
            throw new EnvironmentIntegrityException();
        }
    }

    string? ReadText() => ReadIfPresent(() => File.ReadAllText(path));

    static T? ReadIfPresent<T>(Func<T> read)
    {
        try
        {
            return read();
        }
        catch (Exception e) when (e is FileNotFoundException or DirectoryNotFoundException)
        {
            return default;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new EnvironmentIntegrityException();
        }
    }
}
