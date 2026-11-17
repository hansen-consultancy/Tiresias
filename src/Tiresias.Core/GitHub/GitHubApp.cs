using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Tiresias.GitHub;

/// <summary>
/// A GitHub App installation as a vault secret: the JSON <c>{ appId, installationId, privateKeyPem }</c>.
/// The private key never leaves the broker; what a device gets is an installation token, scoped to
/// the installation's repositories and permissions and dead within the hour.
/// </summary>
public sealed record GitHubAppSecret(string AppId, long InstallationId, string PrivateKeyPem)
{
    public const string ApiHost = "api.github.com";

    /// <returns><c>null</c> when the bytes aren't that JSON.</returns>
    public static GitHubAppSecret? Parse(ReadOnlySpan<byte> utf8)
    {
        try
        {
            var secret = JsonSerializer.Deserialize<GitHubAppSecret>(utf8, JsonSerializerOptions.Web);
            return secret is { AppId.Length: > 0, InstallationId: > 0, PrivateKeyPem.Length: > 0 } ? secret : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

/// <summary>The app JWT GitHub wants before it issues an installation token (RS256, at most 10 minutes).</summary>
public static class GitHubAppJwt
{
    /// <summary>
    /// <c>iat</c> is 60 s in the past and <c>exp</c> 9 minutes ahead, GitHub's advice for clock drift
    /// against its 10-minute ceiling.
    /// </summary>
    public static string Create(string appId, string privateKeyPem, DateTimeOffset now)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        var header = Base64Url("""{"alg":"RS256","typ":"JWT"}"""u8);
        var payload = Base64Url(JsonSerializer.SerializeToUtf8Bytes(new
        {
            iat = now.AddSeconds(-60).ToUnixTimeSeconds(),
            exp = now.AddMinutes(9).ToUnixTimeSeconds(),
            iss = appId,
        }));
        var signingInput = $"{header}.{payload}";
        var signature = rsa.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return $"{signingInput}.{Base64Url(signature)}";
    }

    static string Base64Url(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
