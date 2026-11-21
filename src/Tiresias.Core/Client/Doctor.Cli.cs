using System.Text.Json;
using System.Text.RegularExpressions;

namespace Tiresias.Client;

/// <summary>
/// The config files of the CLIs that sign in as the user: the GitHub CLI's <c>hosts.yml</c> and the
/// Azure CLI's <c>azureProfile.json</c>; either <c>null</c> when missing. Neither holds the Azure
/// CLI's tokens; <c>hosts.yml</c> may hold the GitHub CLI's, which are never read past their key.
/// </summary>
public sealed record DoctorCliConfigs(DoctorFile? GitHubHosts, DoctorFile? AzureProfile);

public static partial class Doctor
{
    /// <summary>
    /// Findings for a CLI signed in as the user: any program running as them can use its sign-in,
    /// unasked and unrecorded (E5/C3). Read from each tool's own config, offline: no process is
    /// started and no host is called. Names the accounts, never a token.
    /// </summary>
    /// <param name="gitHubApp">The slug of a vault GitHub App service <c>tir exec</c> can mint tokens from; <c>null</c> when there is none.</param>
    public static IEnumerable<DoctorCheck> CliSignIns(DoctorCliConfigs configs, string? gitHubApp)
    {
        if (configs.GitHubHosts?.Text is { } hosts && GitHubCliHosts.Accounts(hosts) is { Count: > 0 } github)
        {
            var plain = github.Any(a => a.PlainToken);
            yield return new("gh signed in", DoctorStatus.Warn,
                $"the GitHub CLI is signed in as {string.Join(", ", github.Select(a => $"{a.User} on {a.Host}"))} with a token "
                + (plain ? $"in plain text in {configs.GitHubHosts.Path}" : "in Windows Credential Manager")
                + ": any program running as you can use it, unasked and unrecorded. Run scripts and agents through tir exec, which mints a token per run after you allow it; "
                + "keep gh's own sign-in for your own use, or sign it out with gh auth logout",
                new RunThroughExec("gh", gitHubApp), Position.Plaintext, new(Exposure.ShortLived, Control.Approved));
        }
        if (configs.AzureProfile?.Text is { } profile && AzureCliProfile.Accounts(profile) is { Count: > 0 } azure)
            yield return new("az signed in", DoctorStatus.Warn,
                $"the Azure CLI is signed in as {string.Join(", ", azure)}, and its cached Entra session is as reusable as a stored token: any program running as you can use it, unasked and unrecorded. "
                + "Tiresias has no broker-held Entra identity to offer instead yet; sign it out with az logout when you're done",
                Now: Position.Plaintext);
    }
}

/// <summary>Run a CLI through <c>tir exec</c>, with a token minted per run after consent, instead of its own sign-in.</summary>
/// <param name="Service">The GitHub App service to mint from; <c>null</c> when it has to be added first.</param>
public sealed record RunThroughExec(string Tool, string? Service) : DoctorFix
{
    /// <summary>The service to add first, when there is none.</summary>
    public AddService? Setup => Service is null ? new(ServiceKind.Http, NeedCatalog.GitHubApi) : null;

    public override string Instruction => Service is null
        ? $"add a GitHub App service (tir service add <slug> --upstream {NeedCatalog.GitHubApi} with the app's JSON), then tir exec <slug> --purpose \"<why>\" -- {Tool} <args>"
        : $"tir exec {Service} --purpose \"<why>\" -- {Tool} <args>";
}

/// <summary>Reads the GitHub CLI's <c>hosts.yml</c> for its hosts and signed-in users. A token's value is never read.</summary>
static partial class GitHubCliHosts
{
    /// <param name="PlainToken">Whether the file holds a token for the host, rather than Windows Credential Manager.</param>
    public sealed record Account(string Host, string User, bool PlainToken);

    /// <summary>Each host with an active <c>user:</c>; a host without one isn't signed in.</summary>
    public static IReadOnlyList<Account> Accounts(string text)
    {
        var accounts = new List<Account>();
        string? host = null, user = null;
        var plain = false;
        foreach (var line in text.Split('\n'))
        {
            if (TopLevelKey().Match(line) is { Success: true } top)
            {
                Flush();
                host = top.Groups["key"].Value;
            }
            else if (host is not null && ActiveUser().Match(line) is { Success: true } active)
                user = active.Groups["user"].Value;
            else if (host is not null && TokenKey().IsMatch(line))
                plain = true;
        }
        Flush();
        return accounts;

        void Flush()
        {
            if (host is not null && !string.IsNullOrEmpty(user))
                accounts.Add(new(host, user, plain));
            (host, user, plain) = (null, null, false);
        }
    }

    [GeneratedRegex(@"^(?<key>[^\s#][^:]*):\s*\r?$")]
    private static partial Regex TopLevelKey();

    // The host's own user: key, one indent deep; a users: map's entries are deeper.
    [GeneratedRegex(@"^ {1,4}user:\s*""?(?<user>[^""\s#]+)""?\s*\r?$")]
    private static partial Regex ActiveUser();

    [GeneratedRegex(@"^\s+oauth_token:")]
    private static partial Regex TokenKey();
}

/// <summary>Reads the Azure CLI's <c>azureProfile.json</c> for the accounts it has subscriptions for; <c>az logout</c> empties it.</summary>
static class AzureCliProfile
{
    /// <summary>The distinct <c>user.name</c> of its subscriptions; empty when unreadable.</summary>
    public static IReadOnlyList<string> Accounts(string text)
    {
        try
        {
            using var json = JsonDocument.Parse(text.TrimStart('﻿'));
            if (json.RootElement.ValueKind != JsonValueKind.Object || !json.RootElement.TryGetProperty("subscriptions", out var subscriptions) || subscriptions.ValueKind != JsonValueKind.Array)
                return [];
            return [.. subscriptions.EnumerateArray()
                .Select(s => s.ValueKind == JsonValueKind.Object && s.TryGetProperty("user", out var user) && user.ValueKind == JsonValueKind.Object
                    && user.TryGetProperty("name", out var name) && name.ValueKind == JsonValueKind.String ? name.GetString() : null)
                .OfType<string>().Where(n => n.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase)];
        }
        catch (JsonException)
        {
            return [];
        }
    }
}
