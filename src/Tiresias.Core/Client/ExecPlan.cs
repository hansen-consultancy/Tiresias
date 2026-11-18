using System.Text;
using Tiresias.GitHub;
using Tiresias.Policy;

namespace Tiresias.Client;

/// <summary>A credential <c>tir exec</c> obtained for one service: a placeholder, or for a GitHub App an installation token.</summary>
public sealed record ExecCredential(Service Service, string Value);

/// <summary>
/// The environment <c>tir exec</c> gives its child. The child sees placeholders and loopback URLs,
/// never a vault secret; the one exception is a GitHub installation token, which <c>gh</c> and
/// <c>git</c> must hold themselves and which expires within the hour.
/// </summary>
public static class ExecPlan
{
    /// <summary>
    /// GitHub (upstream <c>api.github.com</c>): <c>GH_TOKEN</c> and <c>GITHUB_TOKEN</c>. SQL Server
    /// (<c>mssql://</c>): <c>{SLUG}_TOKEN</c> and <c>{SLUG}_SQL_URL</c> (the forwarder's <c>/sql/{slug}</c>).
    /// Anything else: <c>{SLUG}_TOKEN</c> and <c>{SLUG}_BASE_URL</c> (the forwarder's <c>/svc/{slug}</c>).
    /// </summary>
    public static IReadOnlyDictionary<string, string> Environment(IEnumerable<ExecCredential> credentials, Uri forwarder)
    {
        var origin = forwarder.GetLeftPart(UriPartial.Authority);
        var env = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var (service, value) in credentials)
        {
            if (IsGitHubApp(service))
            {
                env["GH_TOKEN"] = value;
                env["GITHUB_TOKEN"] = value;
                continue;
            }
            var name = EnvName(service.Slug);
            env[$"{name}_TOKEN"] = value;
            if (service.Upstream.Scheme == "mssql")
                env[$"{name}_SQL_URL"] = $"{origin}/sql/{service.Slug}";
            else
                env[$"{name}_BASE_URL"] = ServiceUrl(service.Slug, forwarder);
        }
        return env;
    }

    /// <summary>Where a placeholder for an HTTP service is sent: the forwarder's <c>/svc/{slug}</c>.</summary>
    public static string ServiceUrl(string slug, Uri forwarder) => $"{forwarder.GetLeftPart(UriPartial.Authority)}/svc/{slug}";

    public static bool IsGitHubApp(Service service) =>
        service.Upstream.Host.Equals(GitHubAppSecret.ApiHost, StringComparison.OrdinalIgnoreCase);

    /// <summary><c>llm-prod</c> → <c>LLM_PROD</c>: upper case, anything but letters and digits as <c>_</c>.</summary>
    public static string EnvName(string slug)
    {
        var sb = new StringBuilder(slug.Length);
        foreach (var c in slug)
            sb.Append(char.IsAsciiLetterOrDigit(c) ? char.ToUpperInvariant(c) : '_');
        return sb.ToString();
    }
}
