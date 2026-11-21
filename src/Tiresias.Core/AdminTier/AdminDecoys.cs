using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Tiresias.Decoys;

namespace Tiresias.AdminTier;

/// <summary>What <c>decoys.status</c> answers: the kinds placed (one per decoy) and how many files, never a place, port or value.</summary>
/// <param name="Listening">The service has the set's ports bound now.</param>
public sealed record AdminDecoysStatus(bool Held, bool Listening, IReadOnlyList<DecoyKind> Kinds, int Files);

/// <summary>What <c>decoys.release</c> answers: the set, handed back, and the user it is whose (the session's, for an over-the-shoulder caller).</summary>
public sealed record AdminDecoysRelease(string UserSid, DecoySet? Set);

/// <summary>A decoy used, queued for its user until the app acknowledges it: <see cref="DecoyHit"/> and the processes that started the program, nearest first.</summary>
public sealed record AdminEvent(long Id, DecoyHit Hit, IReadOnlyList<string> Parents);

/// <summary>What <c>events.wait</c> answers: the caller's events not yet acknowledged, oldest first.</summary>
public sealed record AdminEvents(IReadOnlyList<AdminEvent> Events);

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
    public const int MaxAck = 256;
    public const int MaxWaitSeconds = Protocol.AdminWire.MaxWaitSeconds;

    /// <summary>Ports a decoy may name: none of the well-known ones.</summary>
    public const int MinPort = 1024;

    /// <summary><c>decoys.adopt</c>'s arguments for a set: its fields (not the values it derives) and the paths of its files.</summary>
    public static JsonObject Adopt(DecoySet set) => new()
    {
        ["set"] = Protocol.AdminWire.ToNode(new WireSet(set.HttpPort, set.SqlPort, set.Values, [.. set.Placed])),
        ["files"] = Protocol.AdminWire.ToNode(set.Placed
            .SelectMany(p => DecoyPlan.Steps(set, p.Kind, p.Where, _ => false)).OfType<WriteDecoyFile>().Select(f => f.Path).ToArray()),
    };

    sealed record WireSet(int HttpPort, int SqlPort, DecoyValues Values, PlacedDecoy[] Placed);

    static readonly string[] KindNames = [.. Enum.GetNames<DecoyKind>().Select(JsonNamingPolicy.CamelCase.ConvertName)];

    /// <summary><c>decoys.adopt</c>'s <c>set</c>: a <see cref="DecoySet"/> as the wire has it, exactly its fields.</summary>
    public static bool Set(JsonNode? node)
    {
        if (node is not JsonObject set || !Exactly(set, "httpPort", "sqlPort", "values", "placed"))
            return false;
        if (!Int(set["httpPort"], MinPort, 65535, out var http) || !Int(set["sqlPort"], MinPort, 65535, out var sql) || http == sql)
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

    /// <summary><c>events.wait</c>'s <c>ack</c>: ids of events the app has handled.</summary>
    public static bool Ack(JsonNode? node) =>
        node is JsonArray ids && ids.Count <= MaxAck && ids.All(id => Long(id, out var value) && value > 0);

    /// <summary><c>events.wait</c>'s <c>wait</c>: seconds to wait for an event when none is queued.</summary>
    public static bool Wait(JsonNode? node) => Int(node, 0, MaxWaitSeconds, out _);

    /// <summary>A drive-rooted Windows path, without a <c>..</c> segment: the decoys are the user's files, never a device or a share.</summary>
    public static bool FullPath(string path) =>
        DrivePath().IsMatch(path) && !path.Split('\\').Any(segment => segment is ".." or ".");

    /// <summary>A local, domain or Entra ID user's SID: the only thing the service names a file after.</summary>
    public static bool UserSid(string? sid) => sid is not null && SidPattern().IsMatch(sid);

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

    [GeneratedRegex(@"^S-1-(5-21|12-1)(-[0-9]{1,10}){4}$", RegexOptions.IgnoreCase)]
    private static partial Regex SidPattern();
}

/// <summary>
/// A user's decoys as the service holds them, in its state folder (<c>decoys\&lt;sid&gt;.json</c>):
/// the set and the paths of its files. A damaged file, or one from a newer service, reads as none.
/// </summary>
public sealed record AdminHeldDecoys(DecoySet Set, IReadOnlyList<string> Files)
{
    public const int Version = 1;

    public AdminDecoysStatus Status(bool listening) => new(true, listening, [.. Set.Placed.Select(p => p.Kind)], Files.Count);

    public string ToJson() => new JsonObject
    {
        ["v"] = Version,
        ["set"] = JsonNode.Parse(Set.ToJson()),
        ["files"] = new JsonArray([.. Files.Select(f => (JsonNode)f)]),
    }.ToJsonString();

    public static AdminHeldDecoys? Parse(string? json)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(json) || JsonNode.Parse(json) is not JsonObject file || file["v"]?.GetValue<int>() != Version)
                return null;
            if (DecoySet.Parse(file["set"]?.ToJsonString()) is not { Placed.Count: > 0 } set || file["files"] is not JsonArray files)
                return null;
            return new(set, [.. files.Select(f => f?.GetValue<string>()).OfType<string>()]);
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or FormatException)
        {
            return null;
        }
    }
}

/// <summary>
/// One user's queue of decoy uses, kept by the service until the app acknowledges each by id, so a
/// use while the app is closed (or the machine restarts) is still told. Bounded: past
/// <see cref="Capacity"/> the oldest go. Immutable.
/// </summary>
public sealed record AdminEventQueue(long NextId, IReadOnlyList<AdminEvent> Pending)
{
    public const int Version = 1;
    public const int Capacity = 100;

    public static readonly AdminEventQueue Empty = new(1, []);

    public (AdminEventQueue Queue, AdminEvent Added) Add(DecoyHit hit, IReadOnlyList<string> parents)
    {
        var added = new AdminEvent(NextId, hit, parents);
        return (new(NextId + 1, [.. Pending.Append(added).TakeLast(Capacity)]), added);
    }

    public AdminEventQueue Ack(IEnumerable<long> ids)
    {
        var done = ids.ToHashSet();
        return this with { Pending = [.. Pending.Where(e => !done.Contains(e.Id))] };
    }

    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public string ToJson() => JsonSerializer.Serialize(new File(Version, NextId, [.. Pending]), Json);

    /// <returns><see cref="Empty"/> for no file, a damaged one, or one from a newer service.</returns>
    public static AdminEventQueue Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return Empty;
        try
        {
            return JsonSerializer.Deserialize<File>(json, Json) is { V: Version, NextId: > 0 } file
                ? new(file.NextId, [.. (file.Pending ?? []).Where(e => e is { Hit: not null } && e.Id < file.NextId)])
                : Empty;
        }
        catch (JsonException)
        {
            return Empty;
        }
    }

    sealed record File(int V, long NextId, AdminEvent[]? Pending);
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