using System.Text.RegularExpressions;

namespace Tiresias.Client;

/// <summary>
/// What the user's git setup says about stored tokens, without a token: the <c>credential.helper</c>
/// in <c>~/.gitconfig</c>, and the hosts <c>~/.git-credentials</c> holds entries for (one per entry).
/// </summary>
public sealed record DoctorGitCredentials(string? Helper, IReadOnlyList<string> StoredHosts)
{
    /// <summary>From the texts of <c>~/.gitconfig</c> and <c>~/.git-credentials</c> (<c>null</c> when missing); of the second only hosts are kept.</summary>
    public static DoctorGitCredentials From(string? gitconfig, string? credentials) =>
        new(gitconfig is null ? null : Doctor.GitConfigEntries(gitconfig).LastOrDefault(e => e is { Section: "credential", Subsection: null, Key: "helper" }).Value,
            credentials is null ? [] : GitCredentialsFile.Hosts(credentials));
}

public static partial class Doctor
{
    /// <summary>
    /// Findings for git tokens: in a repository's remote URL, where <c>git remote -v</c>, logs and
    /// every copy of the folder show it too, and in <c>.git-credentials</c>, in plain text. URLs
    /// are printed without their user info.
    /// </summary>
    /// <param name="repositories">Each repository's <c>.git/config</c>.</param>
    public static IEnumerable<DoctorCheck> GitTokens(IEnumerable<DoctorFile> repositories, DoctorGitCredentials? credentials)
    {
        foreach (var file in repositories)
        {
            if (file.Text is null)
                continue;
            var repository = Path.GetDirectoryName(Path.GetDirectoryName(file.Path)) ?? file.Path;
            foreach (var (section, subsection, key, value) in GitConfigEntries(file.Text))
            {
                // A [url "<base>"] section rewrites to its name, so the token is there, not in insteadOf.
                var url = section == "url" ? subsection : value;
                if (url is null || WithoutToken(url) is not { } bare)
                    continue;
                if (section == "remote" && key is "url" or "pushurl" && subsection is { } remote)
                    yield return new($"git remote {remote} in {repository}", DoctorStatus.Warn,
                        $"its URL holds a token for {bare.Host} in plain text, which any program running as you can read, and which git remote -v, logs and every copy of the folder show. "
                        + "Take it out of the URL: the token then lives wherever your credential helper keeps it, which stops it spreading but doesn't make it safer",
                        RemoveTokenFromRemote.For(repository, remote, bare.Url, key == "pushurl"), Position.Plaintext, Kind: "git remotes with a token in their URL");
                else if (section == "url" && key is "insteadof" or "pushinsteadof")
                    yield return new($"git URL rewrite to {bare.Url} in {repository}", DoctorStatus.Warn,
                        $"a [url] section's name holds a token for {bare.Host} in plain text, which any program running as you can read. Remove the user info from the section name in {file.Path}",
                        Now: Position.Plaintext, Kind: "git remotes with a token in their URL");
            }
        }

        if (credentials is { StoredHosts.Count: > 0 } stored)
        {
            var hosts = string.Join(", ", stored.StoredHosts.Distinct(StringComparer.OrdinalIgnoreCase));
            yield return new("git credentials file", DoctorStatus.Warn,
                $"{stored.StoredHosts.Count} {(stored.StoredHosts.Count == 1 ? "token" : "tokens")} in plain text in .git-credentials for {hosts}, which any program running as you can read"
                + (IsStore(stored.Helper) ? "" : ", though git's credential.helper is no longer store") + ". Git Credential Manager keeps them out of a plain file; delete the file once they are there",
                Now: Position.Plaintext);
        }
        else if (credentials?.Helper is { } helper && helper.StartsWith("manager", StringComparison.OrdinalIgnoreCase))
            yield return new("git credentials", DoctorStatus.Ok,
                "Git Credential Manager keeps tokens in Windows Credential Manager, which any program running as you can read; Tiresias has nothing better to offer yet");
    }

    static bool IsStore(string? helper) => helper is not null && (helper == "store" || helper.StartsWith("store ", StringComparison.Ordinal));

    /// <summary>The URL without user info and its host, when it has a password (<c>https://user:token@host</c>); <c>null</c> otherwise.</summary>
    static (string Url, string Host)? WithoutToken(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http") || !uri.UserInfo.Contains(':', StringComparison.Ordinal))
            return null;
        return (new UriBuilder(uri) { UserName = "", Password = "" }.Uri.ToString(), uri.Host);
    }

    /// <summary>Every <c>key = value</c> of a git config file with its section (lower case) and subsection; values unquoted.</summary>
    internal static IEnumerable<(string Section, string? Subsection, string Key, string Value)> GitConfigEntries(string text)
    {
        string section = "";
        string? subsection = null;
        foreach (var line in text.Split('\n'))
        {
            if (GitSection().Match(line) is { Success: true } header)
            {
                section = header.Groups["section"].Value.ToLowerInvariant();
                subsection = header.Groups["sub"].Success ? header.Groups["sub"].Value.Replace("\\\"", "\"", StringComparison.Ordinal).Replace("\\\\", "\\", StringComparison.Ordinal) : null;
                // A section header may carry an entry on the same line: [remote "x"] url = ...
                if (GitEntry().Match(line[header.Length..]) is { Success: true } inline)
                    yield return (section, subsection, inline.Groups["key"].Value.ToLowerInvariant(), Unquote(inline.Groups["value"].Value));
            }
            else if (GitEntry().Match(line) is { Success: true } entry)
                yield return (section, subsection, entry.Groups["key"].Value.ToLowerInvariant(), Unquote(entry.Groups["value"].Value));
        }

        static string Unquote(string value) => value.Length >= 2 && value[0] == '"' && value[^1] == '"' ? value[1..^1] : value;
    }

    [GeneratedRegex(@"^\s*\[\s*(?<section>[A-Za-z0-9.-]+)(?:\s+""(?<sub>(?:[^""\\]|\\.)*)"")?\s*\]")]
    private static partial Regex GitSection();

    [GeneratedRegex(@"^\s*(?<key>[A-Za-z][A-Za-z0-9-]*)\s*=\s*(?<value>[^\r\n#;]*?)\s*(?:[#;].*)?\r?$")]
    private static partial Regex GitEntry();
}

/// <summary>Take the token out of a remote's URL; git then asks its credential helper.</summary>
/// <param name="Url">The URL without its user info.</param>
public sealed record RemoveTokenFromRemote(string Repository, string Remote, string Url, bool Push = false) : DoctorFix
{
    public override string Instruction => $"git -C \"{Repository}\" remote set-url {(Push ? "--push " : "")}\"{Remote}\" \"{Url}\"";

    /// <summary>
    /// The fix, or none unless every value is made of characters no shell treats specially: the
    /// command is pasted into cmd, PowerShell or bash, and a .git/config is anyone's to write. Only
    /// the repository's path may hold a backslash (not as its last character, where it would escape
    /// bash's closing quote) and a space, which its quotes keep.
    /// </summary>
    internal static RemoveTokenFromRemote? For(string repository, string remote, string url, bool push) =>
        Plain(repository, path: true) && Plain(remote) && Plain(url) ? new(repository, remote, url, push) : null;

    static bool Plain(string value, bool path = false) =>
        value.Length > 0 && !value.EndsWith('\\') && value.All(c => char.IsAsciiLetterOrDigit(c) || "/:._@+-".Contains(c) || (path && c is '\\' or ' '));
}

/// <summary>Reads <c>.git-credentials</c>, git's <c>store</c> helper file, for its hosts alone.</summary>
static class GitCredentialsFile
{
    /// <summary>The host of every entry (one URL per line); the rest of each line is dropped.</summary>
    internal static IReadOnlyList<string> Hosts(string text) =>
        [.. text.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0)
            .Select(l => Uri.TryCreate(l, UriKind.Absolute, out var uri) ? uri.Host : null).OfType<string>().Where(h => h.Length > 0)];
}
