using Tiresias.EnvironmentVariables;

namespace Tiresias.Client;

/// <summary>A vault service a placeholder can stand in for: an https API, by slug and host.</summary>
public sealed record DoctorService(string Slug, string Host);

/// <summary>
/// What the sealed environment delivers, without a value: the global variables handed out as their
/// value, and the vault's services a placeholder could stand in for.
/// </summary>
public sealed record DoctorEnvironment(IReadOnlyList<string> AsValues, IReadOnlyList<DoctorService> Services);

public static partial class Doctor
{
    /// <summary>The name of the sealed-keys check, for its line when there is no finding.</summary>
    public const string KeysAsValuesCheck = "sealed keys handed out as values";

    /// <summary>APIs that take <c>Authorization: Bearer</c> and whose SDKs read the base-URL variable, by variable prefix, with their address.</summary>
    static readonly Dictionary<string, string> BearerApis = new(StringComparer.OrdinalIgnoreCase)
    {
        ["OPENAI"] = "https://api.openai.com/v1",
        ["GROQ"] = "https://api.groq.com/openai/v1",
        ["MISTRAL"] = "https://api.mistral.ai/v1",
        ["DEEPSEEK"] = "https://api.deepseek.com",
        ["OPENROUTER"] = "https://openrouter.ai/api/v1",
        ["TOGETHER"] = "https://api.together.xyz/v1",
        ["FIREWORKS"] = "https://api.fireworks.ai/inference/v1",
        ["XAI"] = "https://api.x.ai/v1",
    };

    /// <summary>Keys known not to work as a placeholder: another header (Anthropic's <c>x-api-key</c>, Azure's <c>api-key</c>), or GitHub's, whose answer is <c>tir exec</c>.</summary>
    static readonly string[] NotBearer = ["ANTHROPIC", "CLAUDE", "AZURE", "GITHUB", "GH"];

    /// <summary>
    /// Findings for sealed API keys handed out as their value where a placeholder would do: the
    /// program would stop holding the key (E4/C1 → E3/C1). Judged by names alone.
    /// </summary>
    /// <param name="environment"><c>null</c> while locked: the names are sealed too, and the doctor never asks for Hello.</param>
    public static IEnumerable<DoctorCheck> KeysAsValues(DoctorEnvironment? environment)
    {
        if (environment is null)
        {
            yield return new(KeysAsValuesCheck, DoctorStatus.Ok, "skipped: locked. Unlock Tiresias to check which sealed keys could be placeholders");
            yield break;
        }
        var found = false;
        foreach (var name in environment.AsValues)
        {
            if (SealedEnvironment.BaseUrlVariableFor(name) is not { } baseUrl)
                continue;
            var prefix = baseUrl[..^"_BASE_URL".Length];
            if (NotBearer.Any(p => prefix.Equals(p, StringComparison.OrdinalIgnoreCase) || prefix.StartsWith(p + "_", StringComparison.OrdinalIgnoreCase)))
                continue;
            var service = environment.Services.FirstOrDefault(s => Matches(s, prefix));
            var known = BearerApis.TryGetValue(prefix, out var upstream);
            if (service is null && !known)
                continue;
            found = true;
            var detail = $"is handed out as its value, so every program given it holds the key. A placeholder for {(service is null ? "a vault service" : service.Slug)} keeps the key with the broker, with {baseUrl} pointing the tool at it. "
                + "Tools that ignore " + baseUrl + " get nothing useful from a placeholder: try it, and Hand out the value undoes it";
            yield return new($"sealed key {name}", DoctorStatus.Warn, detail,
                new UsePlaceholder(name, service?.Slug ?? "", service is null ? upstream : null),
                Position.SealedApproved, new(Exposure.BrokerOnly, Control.Approved), "sealed keys handed out as values where a placeholder would do");
        }
        if (!found)
            yield return new(KeysAsValuesCheck, DoctorStatus.Ok, "none of the sealed keys would work as a placeholder instead");
    }

    /// <summary>A service for <c>OPENAI</c>: slug <c>openai</c>, <c>openai-prod</c>, or an upstream at <c>api.openai.com</c>.</summary>
    static bool Matches(DoctorService service, string prefix)
    {
        var word = prefix.Replace('_', '-');
        return service.Slug.Equals(word, StringComparison.OrdinalIgnoreCase)
            || service.Slug.StartsWith(word + "-", StringComparison.OrdinalIgnoreCase)
            || service.Host.Split('.').Contains(word, StringComparer.OrdinalIgnoreCase);
    }
}

/// <summary>Hand a sealed variable out as a placeholder for <paramref name="Service"/>, with a new service at <paramref name="Upstream"/> first when <paramref name="Service"/> is empty.</summary>
public sealed record UsePlaceholder(string Variable, string Service, string? Upstream = null) : DoctorFix
{
    public override string Instruction => Service.Length > 0
        ? $"tir env placeholder add {Variable} {Service}"
        : $"tir service add <service> --upstream {Upstream ?? "https://<api>"}, with the key as its secret (\"Bearer <key>\"); then tir env placeholder add {Variable} <service>";
}
