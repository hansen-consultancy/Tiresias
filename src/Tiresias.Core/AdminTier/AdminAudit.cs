using System.Globalization;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using Tiresias.Decoys;

namespace Tiresias.AdminTier;

/// <summary>An object access the Security log recorded (event 4663): which file, opened for what, by which process.</summary>
/// <param name="ProcessName">The opener's full image path, as Windows recorded it.</param>
public sealed record AuditedAccess(long RecordId, DateTimeOffset At, string ObjectName, uint AccessMask, int ProcessId, string ProcessName);

/// <summary>
/// The admin tier's read auditing (docs/admin-tier.md, <i>Every read named</i>): an audit rule on
/// each held decoy file, event 4663 read back from the Security log, and each read of a held file
/// turned into a <see cref="DecoyHit"/> for the file's user. Which files may carry a rule, and what
/// an event says, are decided here; setting the rule and reading the log are the service's.
/// </summary>
public static class AdminAudit
{
    public const int ObjectAccessEvent = 4663;

    /// <summary><c>FILE_READ_DATA</c>: the only access the rule audits, and the only one that is a read.</summary>
    public const uint ReadData = 0x1;

    /// <summary>The <i>File System</i> audit subcategory, which must audit success for the rules to log anything.</summary>
    public static readonly Guid FileSystemSubcategory = new("0cce921d-69ae-11d9-bed3-505054503030");

    const string SecurityAuditing = "Microsoft-Windows-Security-Auditing";

    /// <summary>The Security log query: object accesses after the last one handled, so reads while the service was stopped are still read.</summary>
    public static string Query(long afterRecordId) =>
        string.Create(CultureInfo.InvariantCulture, $"*[System[(EventID={ObjectAccessEvent}) and (EventRecordID>{afterRecordId})]]");

    /// <summary>
    /// Whether a decoy file may carry an audit rule: opened without following a link, it is a regular
    /// file with one name, owned by the user whose set it is. Anything else may be a file the user
    /// swapped in to have SYSTEM change a rule on.
    /// </summary>
    /// <returns>Why not, or <c>null</c> when it may.</returns>
    public static string? RuleRefusal(FileAttributes attributes, uint links, string? ownerSid, string userSid)
    {
        if (attributes.HasFlag(FileAttributes.ReparsePoint))
            return "is a link";
        if (attributes.HasFlag(FileAttributes.Directory))
            return "is a folder";
        if (links != 1)
            return $"has {links} hard links";
        return string.Equals(ownerSid, userSid, StringComparison.OrdinalIgnoreCase) ? null : "isn't owned by the user whose decoy it is";
    }

    /// <summary>An event 4663 as its XML has it (<c>EventRecord.ToXml()</c>); <c>null</c> for anything else or a damaged one.</summary>
    public static AuditedAccess? Parse(string xml)
    {
        try
        {
            var root = XDocument.Parse(xml).Root;
            if (root is null)
                return null;
            var ns = root.Name.Namespace;
            var system = root.Element(ns + "System");
            if (system?.Element(ns + "Provider")?.Attribute("Name")?.Value != SecurityAuditing
                || system.Element(ns + "EventID")?.Value != ObjectAccessEvent.ToString(CultureInfo.InvariantCulture))
                return null;
            var data = root.Element(ns + "EventData")?.Elements(ns + "Data")
                .Where(d => d.Attribute("Name") is not null)
                .GroupBy(d => d.Attribute("Name")!.Value)
                .ToDictionary(g => g.Key, g => g.First().Value) ?? [];
            if (!long.TryParse(system.Element(ns + "EventRecordID")?.Value, NumberStyles.None, CultureInfo.InvariantCulture, out var record)
                || !DateTimeOffset.TryParse(system.Element(ns + "TimeCreated")?.Attribute("SystemTime")?.Value, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal, out var at)
                || !data.TryGetValue("ObjectName", out var file) || file.Length == 0
                || !Hex(data.GetValueOrDefault("AccessMask"), out var mask)
                || !Hex(data.GetValueOrDefault("ProcessId"), out var pid) || pid > int.MaxValue)
                return null;
            return new(record, at, file, mask, (int)pid, data.GetValueOrDefault("ProcessName") ?? "");
        }
        catch (XmlException)
        {
            return null;
        }
    }

    static bool Hex(string? text, out uint value)
    {
        value = 0;
        return text is not null && text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            && uint.TryParse(text.AsSpan(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out value);
    }

    /// <summary>
    /// A read of a held decoy file, for the user whose file it is; <c>null</c> when the access isn't a
    /// read of one. A file held for two users (it can't be: each is placed new) goes to the first.
    /// </summary>
    /// <param name="files">Each held decoy file and the SID of its user.</param>
    public static (string UserSid, DecoyHit Hit)? Read(AuditedAccess access, IReadOnlyDictionary<string, string> files)
    {
        if ((access.AccessMask & ReadData) == 0 || !files.TryGetValue(Normal(access.ObjectName), out var sid))
            return null;
        // Windows writes "-" or nothing when the image is unknown; it is a path otherwise.
        var image = access.ProcessName.Contains('\\', StringComparison.Ordinal) ? access.ProcessName : null;
        return (sid, new DecoyHit(DecoyUse.Read, access.ObjectName, access.ProcessId == 0 ? null : access.ProcessId, image, access.At));
    }

    /// <summary>A held file's path as <see cref="Read"/> looks it up: the event names it as <c>C:\…</c>, sometimes as <c>\??\C:\…</c>.</summary>
    public static string Normal(string path) =>
        (path.StartsWith(@"\??\", StringComparison.Ordinal) ? path[4..] : AdminCopySource.Normal(path)).ToUpperInvariant();

    /// <summary>
    /// The processes that started the opener, only when the process now under its id is the one that
    /// opened: started no later than the event. A later process under a reused id gets none.
    /// </summary>
    public static bool SameProcess(DateTime started, DateTimeOffset openedAt) => started <= openedAt.UtcDateTime.AddSeconds(1);

    /// <summary>The routine openers' folders for a user's reads, as the agent has them: Tiresias's is that user's own (<c>%LOCALAPPDATA%\Tiresias</c>, where the app installs).</summary>
    public static RoutineFolders Routine(string windows, IReadOnlyList<string> programFiles, string programData, string? profile) =>
        new(windows, programFiles, programData, profile is null ? null : AdminHandBack.KeyringFolder(profile));
}

/// <summary>
/// What the service changed to audit, so it can put it back (<c>audit.json</c> in its state folder):
/// whether it turned on success auditing of the File System subcategory, and the last Security log
/// record it handled. Immutable.
/// </summary>
/// <param name="EnabledPolicy">The service turned success auditing on, and turns it off again when no set is held.</param>
public sealed record AdminAuditState(bool EnabledPolicy, long LastRecordId)
{
    public const int Version = 1;

    public static readonly AdminAuditState Initial = new(false, 0);

    /// <summary>Before setting rules: whether to turn success auditing on, which is then the service's to turn off.</summary>
    public (bool TurnOn, AdminAuditState State) Enable(bool successOn) =>
        successOn ? (false, this) : (true, this with { EnabledPolicy = true });

    /// <summary>After a set is released: when none is left, the policy goes back to off, if the service turned it on.</summary>
    public (bool TurnOff, AdminAuditState State) Release(int setsLeft) =>
        setsLeft == 0 && EnabledPolicy ? (true, this with { EnabledPolicy = false }) : (false, this);

    /// <summary>Records only forward: an event handled twice is not an event read twice.</summary>
    public AdminAuditState Handled(long recordId) => recordId > LastRecordId ? this with { LastRecordId = recordId } : this;

    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public string ToJson() => JsonSerializer.Serialize(new File(Version, EnabledPolicy, LastRecordId), Json);

    /// <returns><see cref="Initial"/> for no file or a damaged one; a newer one too, so nothing is turned off that this version didn't turn on.</returns>
    public static AdminAuditState Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return Initial;
        try
        {
            return JsonSerializer.Deserialize<File>(json, Json) is { V: Version, LastRecordId: >= 0 } file ? new(file.EnabledPolicy, file.LastRecordId) : Initial;
        }
        catch (JsonException)
        {
            return Initial;
        }
    }

    sealed record File(int V, bool EnabledPolicy, long LastRecordId);
}
