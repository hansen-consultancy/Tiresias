using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Tiresias.App.Logic;

/// <summary>
/// A demo scenario (<c>src/Tiresias.App/Demo/&lt;name&gt;.json</c>): the made-up machine a Debug
/// build's demo mode starts from. Values are plain text; seeding seals what the real app would have
/// sealed. Every section may be left out.
/// </summary>
/// <param name="Description">What the scenario shows, for whoever picks one.</param>
/// <param name="SetUp">The first run is done: the Hello credential and a recovery key exist. Sealing anything needs it.</param>
/// <param name="Unlocked">The app starts unlocked.</param>
/// <param name="Files">Files under the made-up user's profile, by relative path (<c>AppData/Local/Tiresias/projects.json</c>), with <see cref="Expand"/>'s tokens.</param>
/// <param name="Secrets">The vault's secrets, by slug, sealed into <c>AppData/Local/Tiresias/vault.json</c> (whose services come from <paramref name="Files"/>).</param>
/// <param name="UserSecrets">Sealed <c>secrets.json</c> documents, by user-secrets id. A plain one is a file like any other.</param>
/// <param name="Variables">The user's Windows environment variables.</param>
/// <param name="SealedVariables">The sealed environment's global variables.</param>
public sealed partial record DemoScenario(
    string Description,
    bool SetUp,
    bool Unlocked,
    IReadOnlyDictionary<string, string> Files,
    IReadOnlyDictionary<string, string> Secrets,
    IReadOnlyDictionary<string, JsonObject> UserSecrets,
    IReadOnlyDictionary<string, string> Variables,
    IReadOnlyDictionary<string, string> SealedVariables)
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    /// <exception cref="JsonException">Not a scenario.</exception>
    public static DemoScenario Parse(string json)
    {
        var dto = JsonSerializer.Deserialize<Dto>(json, Json) ?? throw new JsonException("The scenario is empty.");
        if (dto.UserSecrets?.Keys.FirstOrDefault(id => !UserSecretsId().IsMatch(id) || id.Trim('.').Length == 0) is { } bad)
            throw new JsonException($"'{bad}' is not a user-secrets id: it names a folder, so it takes letters, digits, '.', '_' and '-' only.");
        return new(dto.Description ?? "", dto.SetUp ?? true, dto.Unlocked ?? false,
            dto.Files ?? [], dto.Secrets ?? [], dto.UserSecrets ?? [], dto.Variables ?? [], dto.SealedVariables ?? []);
    }

    /// <summary>
    /// The full path of <paramref name="relative"/> under <paramref name="profile"/>. A scenario
    /// writes only inside the made-up profile: a rooted path or one climbing out with <c>..</c> is refused.
    /// </summary>
    /// <exception cref="ArgumentException">The path leaves the profile.</exception>
    public static string Target(string profile, string relative)
    {
        var parts = relative.Split('/', '\\');
        if (relative.Length == 0 || Path.IsPathRooted(relative) || relative.Contains(':', StringComparison.Ordinal)
            || parts.Any(p => p is "" or "." or ".."))
            throw new ArgumentException($"'{relative}' is not a path inside the profile.", nameof(relative));
        return Path.Combine([profile, .. parts]);
    }

    /// <summary>
    /// Whether <paramref name="path"/> is inside <paramref name="profile"/>, so demo mode may delete
    /// it for good: anything else is on the real machine, even while the demo runs.
    /// </summary>
    public static bool Inside(string profile, string path)
    {
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(profile)) + Path.DirectorySeparatorChar;
        return Path.GetFullPath(path).StartsWith(root, StringComparison.OrdinalIgnoreCase);
    }

    [GeneratedRegex(@"^[A-Za-z0-9._-]+$")]
    private static partial Regex UserSecretsId();

    static readonly Regex Token = new(@"\{\{(?:profile|now(?:-(?<n>\d+)(?<unit>[mhd]))?)\}\}", RegexOptions.CultureInvariant);

    /// <summary>
    /// A file's content with its tokens filled in: <c>{{profile}}</c> is the made-up profile's path,
    /// and <c>{{now}}</c>, <c>{{now-90m}}</c>, <c>{{now-2h}}</c>, <c>{{now-3d}}</c> are times before
    /// <paramref name="now"/> (round-trip format), so activity is always recent. In a <c>.json</c> or
    /// <c>.jsonl</c> file the path is escaped as a JSON string's content.
    /// </summary>
    public static string Expand(string content, string fileName, string profile, DateTimeOffset now)
    {
        var json = fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase) || fileName.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase);
        var path = json ? JsonEncodedText.Encode(profile).ToString() : profile;
        return Token.Replace(content, m =>
        {
            if (m.Value == "{{profile}}")
                return path;
            if (!m.Groups["n"].Success)
                return now.ToString("o", CultureInfo.InvariantCulture);
            var n = int.Parse(m.Groups["n"].Value, CultureInfo.InvariantCulture);
            var ago = m.Groups["unit"].Value switch
            {
                "m" => TimeSpan.FromMinutes(n),
                "h" => TimeSpan.FromHours(n),
                _ => TimeSpan.FromDays(n),
            };
            return (now - ago).ToString("o", CultureInfo.InvariantCulture);
        });
    }

    sealed record Dto(
        string? Description,
        bool? SetUp,
        bool? Unlocked,
        Dictionary<string, string>? Files,
        Dictionary<string, string>? Secrets,
        Dictionary<string, JsonObject>? UserSecrets,
        Dictionary<string, string>? Variables,
        Dictionary<string, string>? SealedVariables);
}
