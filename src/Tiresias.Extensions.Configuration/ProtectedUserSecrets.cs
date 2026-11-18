using Tiresias.Protocol;
using System.Reflection;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Json;
using Microsoft.Extensions.Configuration.UserSecrets;
using Microsoft.Extensions.FileProviders;

namespace Tiresias.Extensions.Configuration;

public static class ProtectedUserSecretsExtensions
{
    /// <summary>
    /// <c>AddUserSecrets&lt;T&gt;()</c> with the plaintext file replaced by one the tir agent seals.
    /// Same <see cref="UserSecretsIdAttribute"/>, same folder. When the builder already holds the
    /// plain user-secrets source (<c>WebApplication.CreateBuilder</c> adds it in Development), that
    /// source is replaced where it stands, so precedence against appsettings and environment
    /// variables does not change. Without a tir agent and with a plaintext file, behaves exactly like
    /// <c>AddUserSecrets</c>. Projects referencing the generator never call this by name: their
    /// <c>AddUserSecrets</c> calls are intercepted into it.
    /// </summary>
    public static IConfigurationBuilder AddProtectedUserSecrets<T>(this IConfigurationBuilder builder, bool optional = false) where T : class =>
        builder.AddProtectedUserSecrets(typeof(T).Assembly, optional);

    public static IConfigurationBuilder AddProtectedUserSecrets(this IConfigurationBuilder builder, Assembly assembly, bool optional = false)
    {
        var id = assembly.GetCustomAttribute<UserSecretsIdAttribute>()?.UserSecretsId;
        if (id is null)
        {
            return optional
                ? builder
                : throw new InvalidOperationException(
                    $"Could not find a UserSecretsIdAttribute on assembly '{assembly.GetName().Name}'. Set <UserSecretsId> in the project file.");
        }
        return builder.AddProtectedUserSecrets(id);
    }

    public static IConfigurationBuilder AddProtectedUserSecrets(this IConfigurationBuilder builder, string userSecretsId) =>
        builder.AddProtectedUserSecrets(userSecretsId, DirectoryOf(userSecretsId), optional: true, new NamedPipeUserSecretsAgent());

    /// <summary>
    /// Swaps the stock user-secrets source a host builder added for itself (Development only) for the
    /// protected one, in place. A no-op when there is none. Interceptors call this right after
    /// <c>WebApplication.CreateBuilder</c> and its host equivalents, the one place user secrets are
    /// added by framework code an interceptor cannot reach.
    /// </summary>
    public static void ProtectUserSecrets(this IConfigurationBuilder builder)
    {
        for (var i = 0; i < builder.Sources.Count; i++)
        {
            if (PlainUserSecretsDirectory(builder.Sources[i]) is { } directory)
            {
                builder.Sources[i] = new ProtectedUserSecretsSource(Path.GetFileName(directory), directory, optional: true, new NamedPipeUserSecretsAgent());
                return;
            }
        }
    }

    internal static IConfigurationBuilder AddProtectedUserSecrets(this IConfigurationBuilder builder, string userSecretsId, string directory, bool optional, IUserSecretsAgent agent)
    {
        var source = new ProtectedUserSecretsSource(userSecretsId, directory, optional, agent);
        var want = Normalize(directory);
        for (var i = 0; i < builder.Sources.Count; i++)
        {
            if (PlainUserSecretsDirectory(builder.Sources[i]) is { } existing && string.Equals(Normalize(existing), want, StringComparison.OrdinalIgnoreCase))
            {
                builder.Sources[i] = source;
                return builder;
            }
        }
        builder.Add(source);
        return builder;
    }

    static string DirectoryOf(string userSecretsId) => Path.GetDirectoryName(PathHelper.GetSecretsPathFromSecretsId(userSecretsId))!;

    static string Normalize(string directory) => Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));

    /// <summary>
    /// The secrets folder of a source <c>AddUserSecrets</c> added, or <c>null</c>. It adds one of two
    /// shapes: <c>secrets.json</c> under a physical provider rooted at the folder when the folder
    /// exists, else the file's full path (no secrets yet).
    /// </summary>
    static string? PlainUserSecretsDirectory(IConfigurationSource source)
    {
        if (source is not JsonConfigurationSource { Path: { } path } json)
            return null;
        var full = Path.IsPathRooted(path)
            ? path
            : json.FileProvider is PhysicalFileProvider provider ? Path.Combine(provider.Root, path) : null;
        if (full is null || !string.Equals(Path.GetFileName(full), SecretsFile.FileName, StringComparison.OrdinalIgnoreCase))
            return null;
        var directory = Normalize(Path.GetDirectoryName(full)!);
        return string.Equals(Path.GetFileName(Path.GetDirectoryName(directory)), "UserSecrets", StringComparison.OrdinalIgnoreCase)
            ? directory
            : null;
    }
}

sealed class ProtectedUserSecretsSource(string userSecretsId, string directory, bool optional, IUserSecretsAgent agent) : IConfigurationSource
{
    public IConfigurationProvider Build(IConfigurationBuilder builder) =>
        new ProtectedUserSecretsProvider(userSecretsId, directory, optional, agent);
}

/// <summary>
/// Gets the secrets document from the agent when one listens, else from the plain file, and parses
/// it with the stock JSON configuration parser so keys come out exactly as <c>AddUserSecrets</c>
/// would produce them. When the document holds values that expire (a temporary SQL login), it loads
/// again before they do and raises the reload token, so <c>IOptionsMonitor</c> and connection
/// factories that read configuration per use pick up the new login.
/// </summary>
sealed class ProtectedUserSecretsProvider(string userSecretsId, string directory, bool optional, IUserSecretsAgent agent)
    : JsonStreamConfigurationProvider(new JsonStreamConfigurationSource()), IDisposable
{
    /// <summary>How long a failed renewal waits before trying again, while the old values still work.</summary>
    internal static TimeSpan RenewalRetry { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Where the one-line notice goes when Tiresias provided the secrets: stderr, so it never mixes
    /// into an app's own output. Configuration loads before logging exists, so there is no ILogger.
    /// </summary>
    internal static TextWriter Notices { get; set; } = Console.Error;

    /// <summary>Short: an absent agent is the normal case on a colleague's machine and must not slow startup.</summary>
    internal static readonly TimeSpan Glance = TimeSpan.FromMilliseconds(300);

    /// <summary>
    /// Sealed secrets are useless without the agent, so an absent one is waited for: an app that
    /// starts at sign-in usually races the Tiresias app starting at the same moment.
    /// </summary>
    internal static readonly TimeSpan AgentStartWait = TimeSpan.FromSeconds(60);

    bool fromAgent;

    /// <summary>The last load was refused (consent screen or policy), not merely failed.</summary>
    bool denied;
    DateTimeOffset? refreshAt;
    Timer? renewal;

    public override void Load()
    {
        var json = Fetch();
        if (string.IsNullOrWhiteSpace(json))
        {
            Data = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
            return;
        }
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));
        Load(stream);
        if (fromAgent)
            Notices.WriteLine($"Tiresias: user secrets '{userSecretsId}' provided ({(Data.Count == 1 ? "1 key" : $"{Data.Count} keys")}).");
        if (refreshAt is { } at)
            Schedule(at - DateTimeOffset.UtcNow);
    }

    void Schedule(TimeSpan due)
    {
        due = due < TimeSpan.FromSeconds(1) ? TimeSpan.FromSeconds(1) : due;
        renewal ??= new Timer(_ => Renew());
        renewal.Change(due, Timeout.InfiniteTimeSpan);
    }

    /// <summary>
    /// A timer callback: an exception escaping it would end the app, so every failure is caught.
    /// A refusal on the consent screen stops renewing (asking again every minute would only train
    /// people to dismiss it); anything else keeps the old values and tries again shortly.
    /// </summary>
    void Renew()
    {
        try
        {
            Load();
            OnReload();
        }
        catch (InvalidOperationException e) when (denied)
        {
            Notices.WriteLine($"Tiresias: not renewing user secrets '{userSecretsId}' ({e.Message}). The current values work until they expire; restart the app to ask again.");
        }
#pragma warning disable CA1031 // The process boundary: see above.
        catch (Exception e)
#pragma warning restore CA1031
        {
            Notices.WriteLine($"Tiresias: could not renew user secrets '{userSecretsId}' ({e.Message}); trying again in {RenewalRetry.TotalSeconds:0} seconds.");
            Schedule(RenewalRetry);
        }
    }

    public void Dispose() => renewal?.Dispose();

    string? Fetch()
    {
        var path = Path.Combine(directory, SecretsFile.FileName);
        var text = File.Exists(path) ? File.ReadAllText(path) : null;
        var kind = SecretsFile.Classify(text);
        if (kind == SecretsFileKind.None)
            return null; // Nothing to protect and nothing to ask anyone for.

        denied = false;
        var request = new AgentRequest(AgentRequest.LoadUserSecrets, userSecretsId, directory);
        var reply = agent.TryLoad(request, Glance);
        // A file naming tiresias: values needs the app as much as a sealed one does.
        var needsAgent = kind == SecretsFileKind.Sealed || (kind == SecretsFileKind.Plain && SecretsFile.NamesReferences(text!));
        if (reply is null && needsAgent)
        {
            Notices.WriteLine($"Tiresias: user secrets '{userSecretsId}' need the Tiresias app; waiting up to {AgentStartWait.TotalSeconds:0} seconds for the Tiresias app to start.");
            reply = agent.TryLoad(request, AgentStartWait);
        }
        switch (reply?.Status)
        {
            case AgentStatus.Ok:
                fromAgent = true;
                refreshAt = reply.RefreshAt is { } at ? DateTimeOffset.FromUnixTimeSeconds(at) : null;
                return reply.Json;
            case AgentStatus.Denied:
                denied = true;
                throw new InvalidOperationException($"Access to user secrets '{userSecretsId}' was denied by Tiresias: "
                    + (reply.Message ?? "declined on the consent screen."));
            case AgentStatus.Error:
                throw new InvalidOperationException($"The tir agent could not load user secrets '{userSecretsId}': {reply.Message}");
        }

        // No agent: a colleague without tir gets stock behaviour; sealed secrets fail loudly, because
        // carrying on without them only surfaces later as a confusing connection error.
        return kind switch
        {
            SecretsFileKind.Plain when SecretsFile.NamesReferences(text!) => throw new InvalidOperationException(
                $"User secrets '{userSecretsId}' name tiresias: values, which only the Tiresias app can fetch, and it did not start within {AgentStartWait.TotalSeconds:0} seconds. Start it (or run 'tir agent'), then start this app again."),
            SecretsFileKind.Plain => text,
            SecretsFileKind.Sealed => throw new InvalidOperationException(
                $"User secrets '{userSecretsId}' are protected by tir and the Tiresias agent did not start within {AgentStartWait.TotalSeconds:0} seconds. Start the Tiresias app (or run 'tir agent'), then start this app again."),
            _ when optional => null,
            _ => throw new InvalidDataException($"'{path}' is not valid JSON."),
        };
    }

    public override string ToString() => $"ProtectedUserSecrets '{userSecretsId}'";
}
