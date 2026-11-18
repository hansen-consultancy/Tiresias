using System.Text.RegularExpressions;
using Tiresias.Policy;

namespace Tiresias.Vault;

/// <summary>What someone asked for when adding a service, as typed: <c>tir service add</c>'s options or the app's form.</summary>
/// <param name="Secret">The vault secret the grant injects; defaults to <see cref="Slug"/>.</param>
/// <param name="Methods">HTTP methods, any case, each possibly comma-separated; defaults to GET.</param>
/// <param name="Allow">Regexes over path and query; none means every path.</param>
/// <param name="Grant">The grant's name; defaults to <c>default</c>.</param>
public sealed record ServiceInput(
    string Slug,
    string Upstream,
    string? Secret = null,
    IReadOnlyList<string>? Methods = null,
    IReadOnlyList<string>? Allow = null,
    IReadOnlyList<string>? Deny = null,
    string? Grant = null,
    bool RequiresElevation = false);

public enum ServiceField { Slug, Upstream, Secret, Grant, Methods, Allow, Deny }

public enum ServiceProblemKind
{
    SlugInvalid,
    SlugTaken,
    UpstreamInvalid,
    UpstreamNotHttps,
    SecretInvalid,
    GrantInvalid,
    MethodInvalid,
    AllowInvalid,
    DenyInvalid,
}

/// <summary>One thing wrong with a <see cref="ServiceInput"/>.</summary>
/// <param name="Message">For the terminal: what is wrong and what to type instead, in <c>tir</c>'s option names.</param>
/// <param name="Value">The offending text, for a front end that words it differently.</param>
/// <param name="Detail">Why a regex doesn't compile.</param>
public sealed record ServiceProblem(ServiceField Field, ServiceProblemKind Kind, string Message, string? Value = null, string? Detail = null);

/// <param name="Service">The service to add, or <c>null</c> when there are <see cref="Problems"/>.</param>
/// <param name="AllowsEveryPath">No allow pattern was given, so the grant covers every path: say so.</param>
/// <param name="NeedsSecret">The secret isn't in the vault yet; its value must be asked for and sealed before the service is saved.</param>
public sealed record ServicePlan(Service? Service, IReadOnlyList<ServiceProblem> Problems, bool AllowsEveryPath, bool NeedsSecret)
{
    public string SecretSlug => Service?.Grants[0].SecretSlug ?? "";
}

/// <summary>
/// The decision behind adding a service with one grant: defaults, validation and the entry itself.
/// <c>tir service add</c> and the app's Services window both call it, so they refuse the same
/// things for the same reasons. It never overwrites, except the one service being edited: any
/// other slug already in the vault is a problem.
/// </summary>
public static class ServicePlanner
{
    public const string DefaultGrant = "default";
    public const string EveryPath = "^/.*";

    static readonly Regex SlugPattern = new("^[a-z0-9][a-z0-9-]{0,62}$", RegexOptions.CultureInvariant);
    static readonly Regex MethodPattern = new("^[A-Z]+$", RegexOptions.CultureInvariant);

    /// <summary>Lower-case letters, digits and dashes, starting with a letter or digit: secret, service and grant names.</summary>
    public static bool IsSlug(string text) => SlugPattern.IsMatch(text);

    /// <summary>
    /// The input that plans back to <paramref name="service"/>, to edit it in the same form; <c>null</c>
    /// for a service that form can't show faithfully: several grants, a body limit, or logins.
    /// </summary>
    public static ServiceInput? Describe(Service service) =>
        service.Grants is [{ IssuesLogins: false, Rule.MaxBodyBytes: null } grant]
            ? new(service.Slug, service.Upstream.ToString(), grant.SecretSlug,
                [.. grant.Rule.Methods.Order(StringComparer.Ordinal)],
                grant.Rule.Allow is [{ } only] && only.ToString() == EveryPath ? [] : [.. grant.Rule.Allow.Select(r => r.ToString())],
                [.. (grant.Rule.Deny ?? []).Select(r => r.ToString())],
                grant.Name, grant.RequiresElevation)
            : null;

    /// <param name="replacing">The slug of the service being edited: planning it again isn't "exists already".</param>
    public static ServicePlan Plan(ServiceInput input, VaultDocument vault, string? replacing = null)
    {
        var problems = new List<ServiceProblem>();
        var slug = input.Slug.Trim();
        if (!IsSlug(slug))
            problems.Add(new(ServiceField.Slug, ServiceProblemKind.SlugInvalid,
                $"'{slug}' can't be a service name: use lower-case letters, digits and dashes, e.g. httpbin or github-api.", slug));
        else if (slug != replacing && vault.FindService(slug) is not null)
            problems.Add(new(ServiceField.Slug, ServiceProblemKind.SlugTaken,
                $"A service named {slug} exists already. Pick another name, or remove it first: tir service remove {slug}", slug));

        var upstream = ParseUpstream(input.Upstream.Trim(), problems);

        var secret = string.IsNullOrWhiteSpace(input.Secret) ? slug : input.Secret.Trim();
        // A secret named after a bad slug is the slug's problem, reported once.
        if (secret != slug && !IsSlug(secret))
            problems.Add(new(ServiceField.Secret, ServiceProblemKind.SecretInvalid,
                $"'{secret}' can't be a secret name: use lower-case letters, digits and dashes, e.g. --secret httpbin-token.", secret));

        var grant = string.IsNullOrWhiteSpace(input.Grant) ? DefaultGrant : input.Grant.Trim();
        if (!IsSlug(grant))
            problems.Add(new(ServiceField.Grant, ServiceProblemKind.GrantInvalid,
                $"'{grant}' can't be a grant name: use lower-case letters, digits and dashes, e.g. --grant read.", grant));

        var methods = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var method in Split(input.Methods))
        {
            var upper = method.ToUpperInvariant();
            if (MethodPattern.IsMatch(upper))
                methods.Add(upper);
            else
                problems.Add(new(ServiceField.Methods, ServiceProblemKind.MethodInvalid,
                    $"'{method}' isn't an HTTP method. Type one per --method, e.g. --method GET --method POST.", method));
        }
        if (methods.Count == 0)
            methods.Add("GET");

        var allowsEveryPath = !Split(input.Allow, comma: false).Any();
        var allow = Compile(allowsEveryPath ? [EveryPath] : Split(input.Allow, comma: false), ServiceField.Allow, problems);
        var deny = Compile(Split(input.Deny, comma: false), ServiceField.Deny, problems);

        if (problems.Count > 0)
            return new(null, problems, allowsEveryPath, false);
        var service = new Service(slug, upstream!,
            [new Grant(grant, secret, new RequestRule(methods, allow, deny), input.RequiresElevation)]);
        return new(service, [], allowsEveryPath, vault.FindSecret(secret) is null);
    }

    static Uri? ParseUpstream(string text, List<ServiceProblem> problems)
    {
        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http") || uri.Host.Length == 0)
        {
            var hint = text.Length > 0 && !text.Contains("://", StringComparison.Ordinal) ? $"https://{text}" : "https://api.example.com";
            problems.Add(new(ServiceField.Upstream, ServiceProblemKind.UpstreamInvalid,
                $"'{text}' isn't a web address. Type the full address, e.g. --upstream {hint}", text, hint));
            return null;
        }
        if (uri.Scheme == "http" && !uri.IsLoopback)
        {
            var https = new UriBuilder(uri) { Scheme = "https", Port = uri.IsDefaultPort ? -1 : uri.Port }.Uri.ToString();
            problems.Add(new(ServiceField.Upstream, ServiceProblemKind.UpstreamNotHttps,
                $"{text} is plain http, which would send the secret unencrypted. Use https, e.g. --upstream {https} (http is only for localhost).", text, https));
            return null;
        }
        return uri;
    }

    static Regex[] Compile(IEnumerable<string> patterns, ServiceField field, List<ServiceProblem> problems)
    {
        var compiled = new List<Regex>();
        foreach (var pattern in patterns)
        {
            try
            {
                compiled.Add(VaultFile.Compile(pattern));
            }
            catch (ArgumentException e)
            {
                var option = field == ServiceField.Allow ? "--allow" : "--deny";
                problems.Add(new(field, field == ServiceField.Allow ? ServiceProblemKind.AllowInvalid : ServiceProblemKind.DenyInvalid,
                    $"{option} '{pattern}' isn't a valid regular expression ({e.Message}). Quote it and anchor it, e.g. {option} '^/v1/models$'.",
                    pattern, e.Message));
            }
        }
        return compiled.ToArray();
    }

    static IEnumerable<string> Split(IReadOnlyList<string>? values, bool comma = true) =>
        (values ?? []).SelectMany(v => comma ? v.Split(',') : [v]).Select(v => v.Trim()).Where(v => v.Length > 0);
}
