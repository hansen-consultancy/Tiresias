using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Tiresias.Decoys;

namespace Tiresias.AdminTier;

/// <summary>What <c>decoys.status</c> answers: the kinds placed (one per decoy) and how many files, never a place, port or value.</summary>
/// <param name="Listening">The service has the set's ports bound now.</param>
public sealed record AdminDecoysStatus(bool Held, bool Listening, IReadOnlyList<DecoyKind> Kinds, int Files, bool NeedsVerification = false,
    bool Verified = false)
{
    /// <summary>Older services report a held set without any placement confirmation.</summary>
    public AdminDecoysStatus ConfirmedStatus() => Held && !Verified ? new(false, false, [], 0, NeedsVerification: true) : this;
}

/// <summary>What <c>decoys.release</c> answers: the set, handed back, and the user it is whose (the session's, for an over-the-shoulder caller).</summary>
public sealed record AdminDecoysRelease(string UserSid, DecoySet? Set, string? Receipt = null);

/// <summary>A service-recorded decoy use and the processes that started its program, nearest first.</summary>
public sealed record AdminEvent(long Id, DecoyHit Hit, IReadOnlyList<string> Parents);

/// <summary>One page, oldest first. The protected review position advances only on explicit review.</summary>
public sealed record AdminEvents(IReadOnlyList<AdminEvent> Events, long ReviewedThrough = 0, long LastId = 0);

/// <summary>The most recent matching incident is retained even after the program is unblocked.</summary>
public sealed record AdminBlockStatus(bool Blocked, long Generation);

public sealed record AdminBlockedProgram(string Path, string? Sha256, DateTimeOffset Since);

public sealed partial record AdminBlocks(IReadOnlyList<AdminBlockedProgram> Programs, string? NextAfter = null);

/// <summary>
/// The arguments of the decoy ops and <c>events.wait</c>, as <see cref="AdminCallerPolicy"/> checks
/// them: by shape and size, before the service reads them. A check never says which value failed.
/// </summary>
public static partial class AdminArgs
{
    public const int MaxPlaced = 16;
    public const int MaxFiles = 16;
    public const int MaxPath = 1024;
    public const int MaxValue = 512;
    public const int MaxWaitSeconds = Protocol.AdminWire.MaxWaitSeconds;

    /// <summary><c>decoys.adopt</c>'s arguments for a set: its fields (not the values it derives) and the paths of its files.</summary>
    public static JsonObject Adopt(DecoySet set, string ownerSid) => new()
    {
        ["owner"] = ownerSid,
        ["set"] = Protocol.AdminWire.ToNode(new WireSet(set.HttpPort, set.SqlPort, set.Values, [.. set.Placed])),
        ["files"] = Protocol.AdminWire.ToNode(AdminHeldDecoys.FilesFor(set)),
    };

    sealed record WireSet(int HttpPort, int SqlPort, DecoyValues Values, PlacedDecoy[] Placed);

    static readonly string[] KindNames = [.. Enum.GetNames<DecoyKind>().Select(JsonNamingPolicy.CamelCase.ConvertName)];

    /// <summary><c>decoys.adopt</c>'s <c>set</c>: a <see cref="DecoySet"/> as the wire has it, exactly its fields.</summary>
    public static bool Set(JsonNode? node)
    {
        if (node is not JsonObject set || !Exactly(set, "httpPort", "sqlPort", "values", "placed"))
            return false;
        if (!Int(set["httpPort"], DecoySet.MinPort, DecoySet.MaxPort, out var http) ||
            !Int(set["sqlPort"], DecoySet.MinPort, DecoySet.MaxPort, out var sql) || http == sql)
            return false;
        if (set["values"] is not JsonObject values || !Exactly(values, "sqlUser", "sqlPassword", "adminToken", "apiKey")
            || values.Any(v => !Text(v.Value, MaxValue)))
            return false;
        return set["placed"] is JsonArray placed && placed.Count is > 0 and <= MaxPlaced && placed.All(Placed);
    }

    static bool Placed(JsonNode? node) =>
        node is JsonObject placed && Exactly(placed, "kind", "where", "placed")
        && placed["kind"] is JsonValue kind && kind.TryGetValue<string>(out var name) && KindNames.Contains(name, StringComparer.Ordinal)
        && Text(placed["where"], MaxPath)
        && placed["placed"] is JsonValue at && at.TryGetValue<string>(out var time)
        && DateTimeOffset.TryParse(time, CultureInfo.InvariantCulture, DateTimeStyles.None, out _);

    /// <summary><c>decoys.adopt</c>'s <c>files</c>: the decoy files' full paths, a few at most.</summary>
    public static bool Files(JsonNode? node) =>
        node is JsonArray files && files.Count <= MaxFiles && files.All(f => Text(f, MaxPath) && FullPath((string)f!));

    public static bool Cursor(JsonNode? node) => Long(node, out var id) && id >= 0;

    public static bool Program(JsonNode? node) => Text(node, MaxPath) && ImagePath((string)node!);

    // These names are only compared with recorded images. The service never opens a request's path.
    internal static bool ImagePath(string? path) => path is { Length: > 2 } &&
        ((char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\') || path.StartsWith(@"\\", StringComparison.Ordinal));

    public static bool Digest(JsonNode? node) => node is JsonValue value && value.TryGetValue<string>(out var text)
        && text.Length == 64 && text.All(char.IsAsciiHexDigit);

    /// <summary><c>events.wait</c>'s <c>wait</c>: seconds to wait for an event when none is queued.</summary>
    public static bool Wait(JsonNode? node) => Int(node, 0, MaxWaitSeconds, out _);

    /// <summary>A drive-rooted Windows path, without a <c>..</c> segment: the decoys are the user's files, never a device or a share.</summary>
    public static bool FullPath(string path) =>
        DrivePath().IsMatch(path) && !path.Contains('/', StringComparison.Ordinal) && path.Split('\\').Skip(1).All(segment =>
            segment.Length > 0 && segment[^1] is not ('.' or ' ') && !DeviceName().IsMatch(segment));

    /// <summary>A local, domain or Entra ID user's SID: the only thing the service names a file after.</summary>
    public static bool UserSid(string? sid) => sid is not null && SidPattern().IsMatch(sid);

    public static bool Owner(JsonNode? node) => node is JsonValue v && v.TryGetValue<string>(out var sid) && UserSid(sid);

    static bool Exactly(JsonObject node, params string[] names) =>
        node.Count == names.Length && names.All(node.ContainsKey);

    static bool Text(JsonNode? node, int max) =>
        node is JsonValue value && value.TryGetValue<string>(out var text) && text.Length is > 0 && text.Length <= max && !text.Any(char.IsControl);

    static bool Int(JsonNode? node, int min, int max, out int value)
    {
        value = 0;
        return node is JsonValue v && v.GetValueKind() == JsonValueKind.Number && v.TryGetValue(out value) && value >= min && value <= max;
    }

    static bool Long(JsonNode? node, out long value)
    {
        value = 0;
        return node is JsonValue v && v.GetValueKind() == JsonValueKind.Number && v.TryGetValue(out value);
    }

    [GeneratedRegex(@"^[A-Za-z]:\\[^<>""|?*:]*$")]
    private static partial Regex DrivePath();

    [GeneratedRegex(@"^(CON|NUL|PRN|AUX|COM[1-9]|LPT[1-9])(?:\.|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DeviceName();

    [GeneratedRegex(@"^S-1-(5-21|12-1)(-[0-9]{1,10}){4}$", RegexOptions.IgnoreCase)]
    private static partial Regex SidPattern();
}

/// <summary>
/// A user's decoys as the service holds them, in its state folder (<c>decoys\&lt;sid&gt;.json</c>):
/// the set and the paths of its files. A damaged file, or one from a newer service, reads as none.
/// </summary>
public sealed record AdminHeldDecoys(DecoySet Set, IReadOnlyList<string> Files, bool Verified = true)
{
    public const int Version = 2;

    public string ReleaseReceipt() => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(ToJson())));

    public AdminDecoysStatus Status(bool listening) => Verified
        ? new(true, listening, [.. Set.Placed.Select(p => p.Kind)], Files.Count, Verified: true)
        : new(false, false, [], 0, NeedsVerification: true);

    public bool MatchesManifest()
    {
        if (Set.HttpPort is < DecoySet.MinPort or > DecoySet.MaxPort || Set.SqlPort is < DecoySet.MinPort or > DecoySet.MaxPort ||
            Set.HttpPort == Set.SqlPort || Set.Placed.Count is 0 or > AdminArgs.MaxPlaced || Set.Placed.Any(p =>
            p.Kind == DecoyKind.Variables ? p.Where != "user environment" : !AdminArgs.FullPath(p.Where)))
            return false;
        var expected = FilesFor(Set);
        return expected.Count == Files.Count && expected.Count <= AdminArgs.MaxFiles &&
            expected.All(AdminArgs.FullPath) && expected.Distinct(StringComparer.OrdinalIgnoreCase).Count() == expected.Count &&
            expected.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(Files) &&
            Set.Placed.Count(p => p.Kind == DecoyKind.Variables) <= 1;
    }

    public static IReadOnlyList<string> FilesFor(DecoySet set) =>
        [.. DecoyPlan.Files(set).Select(path => path.Replace('/', '\\'))];

    public bool IsPlaced(Func<DecoyStep, bool> matches) => MatchesManifest() &&
        Set.Placed.SelectMany(p => DecoyPlan.Steps(Set, p.Kind, p.Where, _ => false)).All(matches);

    public string ToJson() => new JsonObject
    {
        ["v"] = Verified ? Version : 1,
        ["set"] = JsonNode.Parse(Set.ToJson()),
        ["files"] = new JsonArray([.. Files.Select(f => (JsonNode)f)]),
    }.ToJsonString();

    public static AdminHeldDecoys? Parse(string? json)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(json) || JsonNode.Parse(json) is not JsonObject file || file["v"]?.GetValue<int>() is not (1 or Version))
                return null;
            if (DecoySet.Parse(file["set"]?.ToJsonString()) is not { Placed.Count: > 0 } set || file["files"] is not JsonArray files)
                return null;
            var held = new AdminHeldDecoys(set, [.. files.Select(f => f?.GetValue<string>()).OfType<string>()], file["v"]!.GetValue<int>() == Version);
            return held.Verified && !held.MatchesManifest() ? null : held;
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or FormatException)
        {
            return null;
        }
    }
}


/// <summary>
/// Where an elevated process hands a held set back: <c>decoys.json</c> in the user's keyring folder,
/// written only as a new file whose final path, read from its open handle, is the path asked for. A
/// link anywhere on the way (the user can make one in their own profile) would otherwise steer an
/// administrator's write; such a file is deleted again and the set stays held.
/// </summary>
public static class AdminHandBack
{
    /// <summary>The keyring folder in a profile, as <c>%LOCALAPPDATA%\Tiresias</c> is for its own user.</summary>
    public static string KeyringFolder(string profile) => profile.TrimEnd('\\') + @"\AppData\Local\Tiresias";

    /// <param name="finalPath">The created file's final path (<c>GetFinalPathNameByHandle</c>), with or without <c>\\?\</c>.</param>
    public static bool IsWhereAsked(string asked, string finalPath) =>
        string.Equals(AdminCopySource.Normal(asked), AdminCopySource.Normal(finalPath), StringComparison.OrdinalIgnoreCase);
}
