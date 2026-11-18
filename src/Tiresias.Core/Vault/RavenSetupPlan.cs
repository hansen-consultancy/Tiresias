using Tiresias.Policy;

namespace Tiresias.Vault;

/// <summary>What someone typed into the app's "Set up a RavenDB" form.</summary>
/// <param name="Server">The server's https URL, e.g. <c>https://a.raven.example.com</c>.</param>
/// <param name="Database">The database the app uses: checked before saving, and named in the snippet.</param>
/// <param name="AllowChanges">The grant also opens WebSockets, so the app can use the Changes API.</param>
public sealed record RavenSetupInput(string Slug, string Server, string Database, bool AllowChanges);

public enum RavenSetupField { Slug, Server, Database }

public sealed record RavenSetupProblem(RavenSetupField Field, string Message);

/// <param name="Service">The service to save, or <c>null</c> when there are <see cref="Problems"/>.</param>
/// <param name="Replaces">The vault already has this service for the same server: saving again replaces its certificate.</param>
public sealed record RavenSetupPlan(Service? Service, IReadOnlyList<RavenSetupProblem> Problems, bool Replaces)
{
    /// <summary>The client certificate, a base64 passwordless PFX.</summary>
    public string CertificateSecret => $"{Service?.Slug}-certificate";

    public string Database { get; init; } = "";
}

/// <summary>
/// The decision behind the app's RavenDB setup: validation and the service it saves, the server's
/// https URL with one grant, <c>app</c>, that presents the client certificate on any request. What
/// the app may read or write is the certificate's own clearance on the server, not a second policy
/// here that would have to know RavenDB's endpoints. Checking the certificate and sealing it is the
/// caller's.
/// </summary>
public static class RavenSetupPlanner
{
    public const string GrantName = "app";

    static readonly string[] Methods = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];

    /// <summary>
    /// The form for a service this setup saved, to edit it: <c>null</c> for any other service. The
    /// database is left empty, because the service doesn't name one (any database the certificate
    /// may use goes through it).
    /// </summary>
    public static RavenSetupInput? Recognize(Service service) =>
        service is { Upstream.Scheme: "https", Grants: [{ Name: GrantName, IssuesLogins: false } grant] }
            && grant.SecretSlug == $"{service.Slug}-certificate"
            ? new(service.Slug, service.Upstream.GetLeftPart(UriPartial.Authority), "", grant.Rule.Methods.Contains("WEBSOCKET"))
            : null;

    public static RavenSetupPlan Plan(RavenSetupInput input, VaultDocument vault)
    {
        var problems = new List<RavenSetupProblem>();
        var slug = input.Slug.Trim();
        var server = input.Server.Trim().TrimEnd('/');
        var database = input.Database.Trim();

        Uri? url = null;
        if (server.Length == 0)
            problems.Add(new(RavenSetupField.Server, "Type the server's address, e.g. https://a.raven.example.com."));
        else if (!Uri.TryCreate(server, UriKind.Absolute, out url) || url.Scheme != Uri.UriSchemeHttps
            || url.AbsolutePath != "/" || url.Query.Length > 0 || url.UserInfo.Length > 0)
        {
            problems.Add(new(RavenSetupField.Server, url?.Scheme == Uri.UriSchemeHttp
                ? "Use the https address: an http server is unsecured and never asks for a certificate, so there is nothing for Tiresias to keep."
                : $"'{server}' isn't a server address: https://host or https://host:port, with no path."));
            url = null;
        }

        if (database.Length == 0)
            problems.Add(new(RavenSetupField.Database, "Type the database the app uses. Tiresias checks the certificate can reach it."));
        else if (database.Any(c => char.IsControl(c) || c is '/' or '\\' or '?' or '#'))
            problems.Add(new(RavenSetupField.Database, $"'{database}' isn't a RavenDB database name."));

        var replaces = false;
        if (!ServicePlanner.IsSlug(slug))
            problems.Add(new(RavenSetupField.Slug, $"'{slug}' can't be a service name: use lower-case letters, digits and dashes, e.g. orders."));
        else if (vault.FindService(slug) is { } existing)
        {
            replaces = url is not null && Uri.Compare(existing.Upstream, url, UriComponents.SchemeAndServer, UriFormat.Unescaped, StringComparison.OrdinalIgnoreCase) == 0;
            if (!replaces)
                problems.Add(new(RavenSetupField.Slug, $"A service named {slug} exists already for {existing.Upstream}. Pick another name."));
        }

        if (problems.Count > 0)
            return new(null, problems, false) { Database = database };

        HashSet<string> methods = [.. Methods];
        if (input.AllowChanges)
            methods.Add("WEBSOCKET");
        var service = new Service(slug, new Uri(url!.GetLeftPart(UriPartial.Authority) + "/"),
            [new Grant(GrantName, $"{slug}-certificate", new RequestRule(methods, [VaultFile.Compile("^/")]))]);
        return new(service, [], replaces) { Database = database };
    }
}
