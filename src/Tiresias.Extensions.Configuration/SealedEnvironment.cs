using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.EnvironmentVariables;
using Tiresias.Protocol;

namespace Tiresias.Extensions.Configuration;

public static class SealedEnvironmentExtensions
{
    /// <summary>
    /// Asks the Tiresias app, once per process, for the sealed environment variables marked for .NET
    /// apps, and puts the ones allowed into this process's environment just before the host's
    /// environment-variables source reads it. Each then reaches configuration exactly as it did from
    /// the Windows user environment: same key, same precedence. A builder that reads no environment
    /// variables gets nothing, as before. Without the app, or after a no, the app starts without them.
    /// The interceptor calls this through <c>ProtectUserSecrets</c> and <c>AddProtectedUserSecrets</c>.
    /// </summary>
    public static IConfigurationBuilder AddSealedEnvironment(this IConfigurationBuilder builder) =>
        builder.AddSealedEnvironment(new NamedPipeUserSecretsAgent());

    internal static IConfigurationBuilder AddSealedEnvironment(this IConfigurationBuilder builder, IUserSecretsAgent agent)
    {
        var at = -1;
        for (var i = 0; i < builder.Sources.Count; i++)
        {
            if (builder.Sources[i] is SealedEnvironmentSource)
                return builder;
            if (at < 0 && builder.Sources[i] is EnvironmentVariablesConfigurationSource { Prefix: null or "" })
                at = i;
        }
        if (at >= 0)
            builder.Sources.Insert(at, new SealedEnvironmentSource(agent));
        return builder;
    }
}

sealed class SealedEnvironmentSource(IUserSecretsAgent agent) : IConfigurationSource
{
    public IConfigurationProvider Build(IConfigurationBuilder builder) => new SealedEnvironmentProvider(agent);
}

/// <summary>
/// Holds no keys itself: it sets the allowed variables in the process environment, which the
/// environment-variables source after it then reads. That keeps the stock name mapping
/// (<c>__</c>, connection-string prefixes) rather than a copy of it, and children the app starts get
/// the variables too, as they would have from Windows.
/// </summary>
sealed class SealedEnvironmentProvider(IUserSecretsAgent agent) : ConfigurationProvider
{
    /// <summary>Where the one-line notices go; stderr, as for user secrets.</summary>
    internal static TextWriter Notices { get; set; } = Console.Error;

    /// <summary>The folder sent to the agent, which picks folder sets; tests set their own.</summary>
    internal static Func<string> Folder { get; set; } = () => Environment.CurrentDirectory;

    static readonly Lock Gate = new();
    static bool asked;

    /// <summary>For tests: the next load asks again.</summary>
    internal static void Reset()
    {
        lock (Gate)
            asked = false;
    }

    /// <summary>
    /// Asks once per process: a host rebuilds its sources several times while it starts, and a no
    /// must not bring the dialog back each time.
    /// </summary>
    public override void Load()
    {
        lock (Gate)
        {
            if (asked)
                return;
            asked = true;
            Deliver();
        }
    }

    void Deliver()
    {
        var present = Environment.GetEnvironmentVariables().Keys.Cast<object>().Select(k => k.ToString()!).ToArray();
        // An app on a machine without Tiresias must not wait: there are no sealed variables to need.
        var reply = agent.TryLoad(AgentRequest.ForEnvironment(Folder(), present), ProtectedUserSecretsProvider.Glance);
        switch (reply)
        {
            case null:
                return;
            case { Status: AgentStatus.Ok, Json: { } json }:
                var given = JsonSerializer.Deserialize<Dictionary<string, string>>(json) ?? [];
                foreach (var (name, value) in given)
                    Environment.SetEnvironmentVariable(name, value);
                if (given.Count > 0)
                    Notices.WriteLine($"Tiresias: environment variables provided ({string.Join(", ", given.Keys.Order(StringComparer.OrdinalIgnoreCase))}).");
                return;
            default:
                // Refused, or an agent that predates the request: the app starts without them, as it would elsewhere.
                Notices.WriteLine($"Tiresias: no sealed environment variables for this app ({reply.Message ?? reply.Status.ToString()}).");
                return;
        }
    }

    public override string ToString() => "SealedEnvironment";
}
