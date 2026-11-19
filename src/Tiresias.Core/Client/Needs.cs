namespace Tiresias.Client;

/// <summary>One way to meet a need, and where it puts the credential on the two axes (docs/what-do-you-need.md).</summary>
/// <param name="Id">Unique within its need; a known service preselects an option by it.</param>
/// <param name="Summary">What the option does, in one line.</param>
/// <param name="GivesUp">What it gives up against the strongest option of its need; <c>null</c> on that strongest one.</param>
/// <param name="Action">Where the option leads: a window filled in, or a guide.</param>
/// <param name="NeedsBroker">The option stores a vault service, which needs a broker (solo or remote).</param>
public sealed record NeedOption(string Id, string Title, string Summary, Position Position, DoctorFix Action, string? GivesUp = null, bool NeedsBroker = false);

/// <summary>Something a user needs ("An app needs a database"): the phrases it answers to and the ways to meet it.</summary>
public sealed record Need(string Id, string Title, IReadOnlyList<string> Phrases, IReadOnlyList<NeedOption> Options);

/// <summary>A product people name when they search ("Azure SQL", "OpenAI"), and the option it points at.</summary>
public sealed record KnownService(string Name, IReadOnlyList<string> Aliases, string NeedId, string OptionId);

/// <summary>What the planner knows about this machine when it ranks options. Read without unlocking.</summary>
/// <param name="HasBroker">Set up with a broker, solo or remote: vault services can be stored.</param>
public sealed record NeedFacts(bool HasBroker);

/// <summary>An option in its ranked place.</summary>
/// <param name="Recommended">The first option this machine can use.</param>
/// <param name="Unavailable">Why it can't be used here; <c>null</c> when it can. It keeps its place either way.</param>
public sealed record RankedOption(NeedOption Option, bool Recommended, string? Unavailable);

/// <summary>
/// The catalogue behind <i>What do you need?</i>: a static table, versioned with the code, read by the
/// app and <c>tir advise</c> alike so both give the same advice. Options are ranked from their
/// positions, never by their order here.
/// </summary>
public static class NeedCatalog
{
    const string GitHubApi = "https://api.github.com";
    const string NoBroker = "Needs a broker: finish setting up Tiresias, or run tir solo init.";

    public static IReadOnlyList<Need> Needs { get; } =
    [
        new("database", "An app needs a database",
            ["database", "db", "connection string"],
            [
                new("sql-lease", "SQL Server: a login per lease",
                    "The broker creates a SQL login for each lease and drops it when the lease ends; the connection string holds a tiresias:sql reference.",
                    new(Exposure.ShortLived, Control.Approved), new AddService(ServiceKind.SqlServer), NeedsBroker: true),
                new("raven", "RavenDB: the broker presents the certificate",
                    "The broker holds the client certificate and presents it for the app; the app never gets the file.",
                    new(Exposure.BrokerOnly, Control.Approved), new AddService(ServiceKind.RavenDb),
                    "A certificate exists that outlives the lease, though only the broker holds it.", NeedsBroker: true),
                new("sql-integrated", "SQL Server: Windows or Entra sign-in",
                    "Where the server accepts it for this app, the connection string holds no secret at all.",
                    new(Exposure.NothingToCopy, Control.Silent), new FollowGuide("Integrated / Entra ID authentication"),
                    "Any program running as you can connect as you, unasked and unrecorded."),
            ]),
        new("api-key", "A program needs an API key",
            ["api key", "api", "key", "token", "bearer"],
            [
                new("placeholder", "A placeholder for the service",
                    "Tiresias holds the key and adds it to each request through the broker; the program gets a placeholder that works only through this PC.",
                    new(Exposure.BrokerOnly, Control.Approved), new AddService(ServiceKind.Http), NeedsBroker: true),
                new("sealed", "The sealed key, handed to the program",
                    "Sealed in Tiresias and given to the program as an environment variable after you allow it.",
                    Position.SealedApproved, new SealVariable(),
                    "The program holds the real key and can send it anywhere."),
                new("identity", "The service's own identity",
                    "A managed identity or OIDC, where the service offers one: no key exists.",
                    new(Exposure.NothingToCopy, Control.Silent), new FollowGuide("Managed identity"),
                    "Anything running as that identity can use it, unasked and unrecorded."),
            ]),
        new("cli-key", "A command-line tool needs a key",
            ["command line", "terminal", "script", "shell", "powershell", "environment variable"],
            [
                new("terminal-placeholder", "A placeholder in the terminal",
                    "tir run or the terminal hook gives the tool a placeholder for a vault service; the real key stays with the broker.",
                    new(Exposure.BrokerOnly, Control.Approved), new SealVariable(), NeedsBroker: true),
                new("terminal-sealed", "The sealed value, for that tool only",
                    "tir run --only NAME gives the tool the real value after you allow it.",
                    Position.SealedApproved, new SealVariable(),
                    "The tool holds the real key and can send it anywhere."),
            ]),
        new("cli-sign-in", "A command-line tool that signs in as me",
            ["signs in as me", "sign in as me", "signed in", "cli", "azure cli", "az"],
            [
                new("exec-token", "A token per run through tir exec",
                    "A GitHub App held by the broker mints a token for each run of gh, after you allow it; it expires within the hour.",
                    new(Exposure.ShortLived, Control.Approved), new AddService(ServiceKind.Http, GitHubApi), NeedsBroker: true),
                new("own-sign-in", "The tool's own sign-in",
                    "gh auth login or az login, kept for your own interactive use.",
                    Position.Plaintext, new FollowGuide("Its own sign-in for interactive use only"),
                    "Any program running as you can read the tool's token and use it, unasked and unrecorded."),
            ]),
        new("project-secrets", "Protect this project's secrets",
            ["user secrets", "secrets json", "appsettings", "project", "protect", "secrets"],
            [
                new("seal-user-secrets", "Seal its user secrets",
                    "The values are sealed with Windows Hello; the app reads them through Tiresias after you allow it, with no code change.",
                    Position.SealedApproved, new SealUserSecrets()),
            ]),
        new("publish", "Publish packages from CI",
            ["publish", "publishing", "package", "packages", "release", "ci", "github actions", "pipeline"],
            [
                // C1: the trusted-publishing policy names the one repository and workflow allowed, and the registry records each key it issues.
                new("trusted-publishing", "Trusted publishing",
                    "The workflow's OIDC token is exchanged for a key valid about an hour; nothing is stored.",
                    new(Exposure.NothingToCopy, Control.Approved), new FollowGuide("Trusted publishing")),
                new("local-key", "A short-lived key sealed for local pushes",
                    "Sealed in Tiresias; tir run gives it to the push command after you allow it.",
                    Position.SealedApproved, new SealVariable(),
                    "A key exists that works from anywhere until it expires."),
            ]),
        new("git", "Sign in to git",
            ["git", "push", "clone", "personal access token", "pat", "ssh", "repository", "repo"],
            [
                new("app-token", "A GitHub App token per run",
                    "tir exec mints a token for git and gh after you allow it; it expires within the hour.",
                    new(Exposure.ShortLived, Control.Approved), new AddService(ServiceKind.Http, GitHubApi), NeedsBroker: true),
                new("ssh-agent", "An SSH key held by an agent",
                    "Windows Hello or a hardware key holds the key; nothing reusable sits in a file.",
                    new(Exposure.NothingToCopy, Control.Silent), new FollowGuide("Git Credential Manager"),
                    "Any program running as you can use the agent's key, unrecorded."),
                new("credential-manager", "Git Credential Manager",
                    "Browser sign-in; the token is kept in Windows Credential Manager.",
                    Position.Plaintext, new FollowGuide("Git Credential Manager"),
                    "The token is readable by anything running as you, and used unrecorded."),
            ]),
    ];

    public static IReadOnlyList<KnownService> Services { get; } =
    [
        new("SQL Server", ["sql server", "azure sql", "mssql", "sql", "ef core", "entity framework", "sqlclient"], "database", "sql-lease"),
        new("RavenDB", ["ravendb", "raven"], "database", "raven"),
        new("OpenAI", ["openai", "gpt", "chatgpt"], "api-key", "placeholder"),
        new("Anthropic", ["anthropic", "claude"], "api-key", "placeholder"),
        new("GitHub CLI", ["gh", "github cli"], "cli-sign-in", "exec-token"),
        new("GitHub", ["github"], "git", "app-token"),
        new("NuGet", ["nuget"], "publish", "trusted-publishing"),
        new("npm", ["npm"], "publish", "trusted-publishing"),
        new("PyPI", ["pypi"], "publish", "trusted-publishing"),
    ];

    public static Need Find(string id) => Needs.Single(n => n.Id == id);

    /// <summary>
    /// The need's options, strongest first: control before exposure (C1 before C3; within a control,
    /// E1 before E5), ties in catalogue order. The first one this machine can use is recommended;
    /// one it can't keeps its place and says why.
    /// </summary>
    public static IReadOnlyList<RankedOption> Rank(Need need, NeedFacts facts)
    {
        var recommended = false;
        return
        [
            .. need.Options
                .OrderBy(o => o.Position.Control)
                .ThenBy(o => o.Position.Exposure)
                .Select(o =>
                {
                    var unavailable = o.NeedsBroker && !facts.HasBroker ? NoBroker : null;
                    var first = unavailable is null && !recommended;
                    recommended |= first;
                    return new RankedOption(o, first, unavailable);
                }),
        ];
    }
}

/// <summary>A need the typed words found, and the option a named service points at.</summary>
/// <param name="Score">0 when nothing matched and the whole catalogue is shown.</param>
/// <param name="Preselect">The option to open expanded; <c>null</c> when no known service was named.</param>
public sealed record NeedMatch(Need Need, int Score, string? Preselect);

/// <summary>
/// The search box: words typed are scored against each need's phrases and the known services'
/// aliases, on this machine, the same way every time. No language model, nothing sent anywhere.
/// </summary>
public static class NeedMatcher
{
    const int Exact = 3;
    const int Partial = 1;
    const int MinPartial = 3;

    static readonly HashSet<string> StopWords = new(StringComparer.Ordinal)
    {
        "a", "an", "the", "my", "me", "i", "we", "our", "for", "to", "of", "in", "on", "at", "with", "and", "or",
        "is", "are", "it", "its", "this", "that", "from", "by", "as", "be", "can", "how", "do", "does",
        "need", "needs", "want", "wants", "use", "uses", "using", "talk", "talks", "app", "apps",
    };

    /// <summary>
    /// Needs with a score, highest first, ties in catalogue order; with nothing matched, the whole
    /// catalogue. A token equal to a phrase's word scores more than one that starts it, and a
    /// phrase of several words scores only when all of them are there.
    /// </summary>
    public static IReadOnlyList<NeedMatch> Match(string? text)
    {
        var tokens = Tokens(text ?? "");
        var matches = NeedCatalog.Needs
            .Select(need =>
            {
                var score = need.Phrases.Sum(p => Score(p, tokens));
                var services = NeedCatalog.Services.Where(s => s.NeedId == need.Id)
                    .Select(s => (s.OptionId, Score: s.Aliases.Sum(a => Score(a, tokens))))
                    .Where(s => s.Score > 0)
                    .ToArray();
                var best = services.Length == 0 ? null : services.MaxBy(s => s.Score).OptionId;
                return new NeedMatch(need, score + services.Sum(s => s.Score), best);
            })
            .Where(m => m.Score > 0)
            .OrderByDescending(m => m.Score)
            .ToArray();
        return matches.Length > 0 ? matches : [.. NeedCatalog.Needs.Select(n => new NeedMatch(n, 0, null))];
    }

    /// <summary>Lowercase words, split on anything that isn't a letter or digit, stop words dropped.</summary>
    public static IReadOnlyList<string> Tokens(string text)
    {
        var tokens = new List<string>();
        var start = -1;
        for (var i = 0; i <= text.Length; i++)
        {
            var inWord = i < text.Length && char.IsLetterOrDigit(text[i]);
            if (inWord && start < 0)
                start = i;
            else if (!inWord && start >= 0)
            {
                var word = text[start..i].ToLowerInvariant();
                if (!StopWords.Contains(word))
                    tokens.Add(word);
                start = -1;
            }
        }
        return tokens;
    }

    static int Score(string phrase, IReadOnlyList<string> tokens)
    {
        var total = 0;
        foreach (var word in Tokens(phrase))
        {
            var best = 0;
            foreach (var token in tokens)
            {
                if (token == word)
                    best = Exact;
                else if (best == 0 && token.Length >= MinPartial && word.StartsWith(token, StringComparison.Ordinal))
                    best = Partial;
            }
            if (best == 0)
                return 0;
            total += best;
        }
        return total;
    }
}
