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
/// would produce them.
/// </summary>
sealed class ProtectedUserSecretsProvider(string userSecretsId, string directory, bool optional, IUserSecretsAgent agent)
    : JsonStreamConfigurationProvider(new JsonStreamConfigurationSource())
{
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
    }

    string? Fetch()
    {
        var path = Path.Combine(directory, SecretsFile.FileName);
        var text = File.Exists(path) ? File.ReadAllText(path) : null;
        var kind = SecretsFile.Classify(text);
        if (kind == SecretsFileKind.None)
            return null; // Nothing to protect and nothing to ask anyone for.

        var reply = agent.TryLoad(new AgentRequest(AgentRequest.LoadUserSecrets, userSecretsId, directory));
        switch (reply?.Status)
        {
            case AgentStatus.Ok:
                return reply.Json;
            case AgentStatus.Denied:
                throw new InvalidOperationException($"Access to user secrets '{userSecretsId}' was denied on the tir consent screen.");
            case AgentStatus.Error:
                throw new InvalidOperationException($"The tir agent could not load user secrets '{userSecretsId}': {reply.Message}");
        }

        // No agent: a colleague without tir gets stock behaviour; sealed secrets fail loudly, because
        // carrying on without them only surfaces later as a confusing connection error.
        return kind switch
        {
            SecretsFileKind.Plain => text,
            SecretsFileKind.Sealed => throw new InvalidOperationException(
                $"User secrets '{userSecretsId}' are protected by tir and no tir agent is running. Start it with 'tir agent'."),
            _ when optional => null,
            _ => throw new InvalidDataException($"'{path}' is not valid JSON."),
        };
    }

    public override string ToString() => $"ProtectedUserSecrets '{userSecretsId}'";
}
