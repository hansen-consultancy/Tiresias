using System.Text.Json;
using System.Runtime.InteropServices;
using Tiresias.Decoys;

namespace Tiresias.AdminTier;

/// <summary>
/// One user's service-owned incidents and decisions, in commit order. Reading has no effect on other
/// readers. A review or unblock is a separate entry, so either can be reconstructed after a restart
/// without erasing evidence. The service serializes access to each journal.
/// </summary>
public sealed class AdminIncidentJournal
{
    // Service image and ancestry names are bounded at collection. This page fits the admin wire frame.
    public const int PageSize = 12;
    public const int BlockPageSize = 64;
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    readonly string path;
    readonly List<AdminEvent> events = [];
    readonly List<Block> blocks = [];
    long lastId;
    long reviewed;
    bool writeFailed;

    sealed record Block(AdminBlockedProgram Program, long Generation, bool Active);
    sealed record Row(int V, string Kind, DateTimeOffset At, AdminEvent? Event = null,
        string? Sha256 = null, long? Through = null, string? Program = null);
    sealed record PreviousQueue(int V, long NextId, AdminEvent[]? Pending);

    public AdminIncidentJournal(string folder, string sid)
    {
        if (!AdminArgs.UserSid(sid))
            throw new ArgumentException("Invalid user SID.", nameof(sid));
        path = Path.Combine(folder, sid + ".jsonl");
        // Keep the protected v1 snapshot as the immutable base. Its next id also covers old events
        // acknowledged before the upgrade, whose contents are no longer available.
        try
        {
            var old = JsonSerializer.Deserialize<PreviousQueue>(File.ReadAllText(Path.Combine(folder, sid + ".json")), Json);
            if (old is not { V: 1, NextId: > 0, Pending: not null })
                throw InvalidJournal();
            foreach (var e in old.Pending)
            {
                if (e is null || e.Id <= lastId || e.Id >= old.NextId)
                    throw InvalidJournal();
                Add(e, null);
            }
            lastId = old.NextId - 1;
        }
        catch (FileNotFoundException) { }
        try
        {
            using var file = File.OpenRead(path);
            // A torn last write requires recovery before granting access or appending another row.
            if (file.Length == 0)
                throw InvalidJournal();
            file.Seek(-1, SeekOrigin.End);
            if (file.ReadByte() != '\n')
                throw InvalidJournal();
            file.Position = 0;
            using var reader = new StreamReader(file);
            while (reader.ReadLine() is { } line)
                Apply(JsonSerializer.Deserialize<Row>(line, Json) ?? throw InvalidJournal());
        }
        catch (FileNotFoundException) { }
    }

    public AdminEvent Record(DecoyHit hit, IReadOnlyList<string> parents, string? sha256)
    {
        var e = new AdminEvent(checked(lastId + 1), hit, parents);
        Append(new(1, "incident", hit.At, Event: e, Sha256: sha256));
        return e;
    }

    public AdminEvents Read(long after, bool pendingOnly)
    {
        EnsureAvailable();
        var from = pendingOnly ? Math.Max(after, reviewed) : after;
        // Ids can have gaps in upgraded v1 histories.
        var at = CollectionsMarshal.AsSpan(events).BinarySearch(new EventId(from));
        var start = at >= 0 ? at + 1 : ~at;
        return new(events.GetRange(start, Math.Min(PageSize, events.Count - start)), reviewed, lastId);
    }

    readonly record struct EventId(long Value) : IComparable<AdminEvent>
    {
        public int CompareTo(AdminEvent? other) => Value.CompareTo(other!.Id);
    }

    public AdminEvents Review(long through)
    {
        EnsureAvailable();
        var target = Math.Min(through, lastId);
        if (target > reviewed)
            Append(new(1, "review", DateTimeOffset.UtcNow, Through: target));
        return new([], reviewed, lastId);
    }

    public AdminBlockStatus Check(string? program, string? sha256)
    {
        EnsureAvailable();
        var blocked = false;
        long generation = 0;
        foreach (var b in blocks)
        {
            // If the caller cannot identify an image or hash, include every mark this could be.
            if (program is not null && !Same(program, b.Program.Path)
                && (b.Program.Sha256 is null || (sha256 is not null && !Same(sha256, b.Program.Sha256))))
                continue;
            blocked |= b.Active;
            generation = Math.Max(generation, b.Generation);
        }
        return new(blocked, generation);
    }

    public AdminBlocks List(string? after = null)
    {
        EnsureAvailable();
        var names = StringComparer.OrdinalIgnoreCase;
        var page = blocks.Where(b => b.Active && names.Compare(b.Program.Path, after) > 0)
            .GroupBy(b => b.Program.Path, names).Select(group => group.MaxBy(b => b.Generation)!.Program)
            .OrderBy(p => p.Path, names).Take(BlockPageSize + 1).ToArray();
        return page.Length <= BlockPageSize ? new(page) : new(page[..BlockPageSize], page[BlockPageSize - 1].Path);
    }

    public AdminBlockStatus Unblock(string program)
    {
        EnsureAvailable();
        var matches = blocks.Where(b => Same(b.Program.Path, program)).ToArray();
        if (matches.Any(b => b.Active))
            Append(new(1, "unblock", DateTimeOffset.UtcNow, Program: program));
        return new(false, matches.Select(b => b.Generation).DefaultIfEmpty().Max());
    }

    void Append(Row row)
    {
        EnsureAvailable();
        var bytes = JsonSerializer.SerializeToUtf8Bytes(row, Json);
        try
        {
            using var file = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
            file.Write(bytes);
            file.WriteByte((byte)'\n');
            file.Flush(flushToDisk: true);
            Apply(row);
        }
        catch
        {
            writeFailed = true;
            throw;
        }
    }

    void Apply(Row row)
    {
        if (row.V != 1)
            throw InvalidJournal();
        switch (row.Kind)
        {
            case "incident" when row.Event is { } e && e.Id == checked(lastId + 1):
                Add(e, row.Sha256);
                break;
            case "review" when row.Through is { } id && id > reviewed && id <= lastId:
                reviewed = id;
                break;
            case "unblock" when row.Program is { } program && AdminArgs.ImagePath(program):
                for (var i = 0; i < blocks.Count; i++)
                    if (Same(blocks[i].Program.Path, program))
                        blocks[i] = blocks[i] with { Active = false };
                break;
            default:
                throw InvalidJournal();
        }
    }

    void Add(AdminEvent e, string? sha256)
    {
        if (e.Hit is null || e.Parents is null || !Enum.IsDefined(e.Hit.Use))
            throw InvalidJournal();
        events.Add(e);
        lastId = e.Id;
        if (e.Hit.Use == DecoyUse.Read || e.Hit.Program is not { } program || !AdminArgs.ImagePath(program))
            return;
        var block = new Block(new(program, sha256, e.Hit.At), e.Id, true);
        var previous = blocks.FindIndex(b => Same(b.Program.Path, program) && Same(b.Program.Sha256, sha256));
        if (previous < 0)
            blocks.Add(block);
        else
            blocks[previous] = block;
    }

    static bool Same(string? a, string? b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    void EnsureAvailable()
    {
        if (writeFailed)
            throw new IOException("The incident journal needs recovery.");
    }

    static InvalidDataException InvalidJournal() => new("Invalid incident journal.");
}
