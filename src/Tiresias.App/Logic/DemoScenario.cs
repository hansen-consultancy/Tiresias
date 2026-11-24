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
/// <param name="Registry">Keys under the made-up <c>HKCU</c>, by path (<c>Software\Microsoft\...\Uninstall\app</c>), with their values: text (with <see cref="Expand"/>'s tokens) or a whole number.</param>
/// <param name="ProgramRuns">When each program was last opened from Explorer, the Start menu or the taskbar, by path; both with <see cref="Expand"/>'s tokens.</param>
public sealed partial record DemoScenario(
    string Description,
    bool SetUp,
    bool Unlocked,
    IReadOnlyDictionary<string, string> Files,
    IReadOnlyDictionary<string, string> Secrets,
    IReadOnlyDictionary<string, JsonObject> UserSecrets,
    IReadOnlyDictionary<string, string> Variables,
    IReadOnlyDictionary<string, string> SealedVariables,
    IReadOnlyDictionary<string, IReadOnlyDictionary<string, object>> Registry,
    IReadOnlyDictionary<string, string> ProgramRuns)
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    /// <exception cref="JsonException">Not a scenario.</exception>
    public static DemoScenario Parse(string json)
    {
        var dto = JsonSerializer.Deserialize<Dto>(json, Json) ?? throw new JsonException("The scenario is empty.");
        if (dto.UserSecrets?.Keys.FirstOrDefault(id => !UserSecretsId().IsMatch(id) || id.Trim('.').Length == 0) is { } bad)
            throw new JsonException($"'{bad}' is not a user-secrets id: it names a folder, so it takes letters, digits, '.', '_' and '-' only.");
        var registry = (dto.Registry ?? []).ToDictionary(k => k.Key,
            k => (IReadOnlyDictionary<string, object>)k.Value.ToDictionary(v => v.Key, v => RegistryValue(k.Key, v.Key, v.Value)));
        return new(dto.Description ?? "", dto.SetUp ?? true, dto.Unlocked ?? false,
            dto.Files ?? [], dto.Secrets ?? [], dto.UserSecrets ?? [], dto.Variables ?? [], dto.SealedVariables ?? [],
            registry, dto.ProgramRuns ?? []);
    }

    static object RegistryValue(string key, string name, JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString()!,
        JsonValueKind.Number when value.TryGetInt32(out var number) => number,
        _ => throw new JsonException($"{key}\\{name}: a registry value is text or a whole number."),
    };

    /// <summary>Where Windows records the programs started from Explorer, the Start menu or the taskbar, under <c>HKCU</c>.</summary>
    public const string UserAssistKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count";

    /// <summary>A program's UserAssist value name: its path in ROT13, as Windows writes it.</summary>
    public static string UserAssistName(string path) => string.Create(path.Length, path, (span, source) =>
    {
        for (var i = 0; i < source.Length; i++)
            span[i] = source[i] switch
            {
                >= 'a' and <= 'z' and var c => (char)('a' + (c - 'a' + 13) % 26),
                >= 'A' and <= 'Z' and var c => (char)('A' + (c - 'A' + 13) % 26),
                var c => c,
            };
    });

    /// <summary>A UserAssist value saying the program was last opened at <paramref name="lastRun"/>: 72 bytes, the time a FILETIME at 60.</summary>
    public static byte[] UserAssistValue(DateTimeOffset lastRun)
    {
        var value = new byte[72];
        BitConverter.GetBytes(1).CopyTo(value, 4);
        BitConverter.GetBytes(lastRun.ToFileTime()).CopyTo(value, 60);
        return value;
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

    static readonly Regex Token = new(@"\{\{(?:profile|(?<kind>now|date)(?:-(?<n>\d+)(?<unit>[mhd]))?)\}\}", RegexOptions.CultureInvariant);

    /// <summary>
    /// A file's content with its tokens filled in: <c>{{profile}}</c> is the made-up profile's path,
    /// and <c>{{now}}</c>, <c>{{now-90m}}</c>, <c>{{now-2h}}</c>, <c>{{now-3d}}</c> are times before
    /// <paramref name="now"/> (round-trip format), so activity is always recent. In a <c>.json</c> or
    /// <c>.jsonl</c> file the path is escaped as a JSON string's content. <c>{{date-3d}}</c> is the
    /// day alone, as an uninstall entry's <c>InstallDate</c> (<c>yyyyMMdd</c>).
    /// </summary>
    public static string Expand(string content, string fileName, string profile, DateTimeOffset now)
    {
        var json = fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase) || fileName.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase);
        var path = json ? JsonEncodedText.Encode(profile).ToString() : profile;
        return Token.Replace(content, m =>
        {
            if (m.Value == "{{profile}}")
                return path;
            var format = m.Groups["kind"].Value == "date" ? "yyyyMMdd" : "o";
            if (!m.Groups["n"].Success)
                return now.ToString(format, CultureInfo.InvariantCulture);
            var n = int.Parse(m.Groups["n"].Value, CultureInfo.InvariantCulture);
            var ago = m.Groups["unit"].Value switch
            {
                "m" => TimeSpan.FromMinutes(n),
                "h" => TimeSpan.FromHours(n),
                _ => TimeSpan.FromDays(n),
            };
            return (now - ago).ToString(format, CultureInfo.InvariantCulture);
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
        Dictionary<string, string>? SealedVariables,
        Dictionary<string, Dictionary<string, JsonElement>>? Registry,
        Dictionary<string, string>? ProgramRuns);
}
