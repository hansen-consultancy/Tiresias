using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Tiresias.Access;
using Tiresias.Protocol;

namespace Tiresias.EnvironmentVariables;

/// <summary>A ticket's devcontainer: the project folder it was minted for, and when it ends.</summary>
public sealed record DevcontainerTicket(string Folder, DateTimeOffset ExpiresAt);

/// <summary>
/// The tickets that let a devcontainer ask for sealed variables (docs/devcontainers.md). One per
/// folder, minted by <c>tir run</c> and held in memory only; each ends after
/// <see cref="Consent.MaxDuration"/>, and all end when the agent locks. A ticket also carries what
/// was allowed for its container and the placeholders handed to it, so both end with it.
/// </summary>
public sealed class DevcontainerTickets(TimeProvider time)
{
    sealed class Entry(string ticket, DevcontainerTicket about)
    {
        public string Ticket { get; } = ticket;
        public DevcontainerTicket About { get; } = about;
        public List<EnvironmentVariableAccess> Allowed { get; } = [];
        public List<string> Placeholders { get; } = [];
    }

    /// <summary>By the ticket's hash, so finding one doesn't compare the ticket itself byte by byte.</summary>
    readonly Dictionary<string, Entry> byHash = new(StringComparer.Ordinal);
    readonly Lock gate = new();

    /// <summary>The folder's ticket: the one it has while that lasts, otherwise a new one of 256 random bits.</summary>
    public string Mint(string folder)
    {
        var normalized = SealedEnvironment.Normalize(folder);
        lock (gate)
        {
            if (Live().FirstOrDefault(e => SealedEnvironment.Normalize(e.About.Folder) == normalized) is { } held)
                return held.Ticket;
            var ticket = Base64Url(RandomNumberGenerator.GetBytes(32));
            byHash[Hash(ticket)] = new(ticket, new(folder, time.GetUtcNow() + Consent.MaxDuration));
            return ticket;
        }
    }

    /// <summary>The devcontainer a ticket belongs to; <c>null</c> for a missing, unknown or ended one.</summary>
    public DevcontainerTicket? Find(string? ticket) => Get(ticket)?.About;

    /// <summary>Whether every one of <paramref name="wanted"/> was allowed for this container, with the same delivery.</summary>
    public bool AllAllowed(string ticket, IEnumerable<EnvironmentVariableAccess> wanted)
    {
        lock (gate)
            return Get(ticket) is { } entry && wanted.All(w => entry.Allowed.Any(a => a.SameDelivery(w)));
    }

    /// <summary>"Allow for this container": asked again only once the ticket ends.</summary>
    public void Allow(string ticket, IEnumerable<EnvironmentVariableAccess> accesses)
    {
        lock (gate)
            Get(ticket)?.Allowed.AddRange(accesses);
    }

    /// <summary>Placeholders handed to the container, revoked when its ticket ends. <c>false</c> when it ended meanwhile: revoke them now.</summary>
    public bool Hold(string ticket, IEnumerable<string> placeholders)
    {
        lock (gate)
        {
            if (Get(ticket) is not { } entry)
                return false;
            entry.Placeholders.AddRange(placeholders);
            return true;
        }
    }

    /// <summary>Ends the tickets that are past their time, and hands back their placeholders to revoke.</summary>
    public IReadOnlyList<string> Prune()
    {
        lock (gate)
            return End(byHash.Where(p => p.Value.About.ExpiresAt <= time.GetUtcNow()).Select(p => p.Key).ToArray());
    }

    /// <summary>Ends every ticket (the agent locked), and hands back their placeholders to revoke.</summary>
    public IReadOnlyList<string> Clear()
    {
        lock (gate)
            return End([.. byHash.Keys]);
    }

    List<string> End(IEnumerable<string> hashes)
    {
        List<string> placeholders = [];
        foreach (var hash in hashes)
            if (byHash.Remove(hash, out var entry))
                placeholders.AddRange(entry.Placeholders);
        return placeholders;
    }

    Entry? Get(string? ticket)
    {
        if (string.IsNullOrEmpty(ticket))
            return null;
        lock (gate)
            return byHash.TryGetValue(Hash(ticket), out var entry) && entry.About.ExpiresAt > time.GetUtcNow() ? entry : null;
    }

    IEnumerable<Entry> Live() => byHash.Values.Where(e => e.About.ExpiresAt > time.GetUtcNow());

    static string Hash(string ticket) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(ticket)));

    static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>
    /// Whether a <c>devcontainer.json</c> asks for a ticket: its <c>remoteEnv</c> hands
    /// <see cref="DevcontainerWire.TicketVariable"/> in from the host's environment. Malformed JSON doesn't.
    /// </summary>
    public static bool Asks(ReadOnlySpan<byte> devcontainerJson)
    {
        try
        {
            var reader = new Utf8JsonReader(devcontainerJson, new JsonReaderOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
                return false;
            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                var property = reader.GetString();
                reader.Read();
                if (property != "remoteEnv" || reader.TokenType != JsonTokenType.StartObject)
                {
                    reader.Skip();
                    continue;
                }
                while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
                {
                    var name = reader.GetString();
                    reader.Read();
                    if (name == DevcontainerWire.TicketVariable && reader.TokenType == JsonTokenType.String
                        && reader.GetString() == $"${{localEnv:{DevcontainerWire.TicketVariable}}}")
                        return true;
                    reader.Skip();
                }
            }
        }
        catch (JsonException)
        {
        }
        return false;
    }

    /// <summary>
    /// The folder a <c>tir run</c> command opens: its first argument that is an existing folder, as
    /// in <c>code C:\src\shop</c>, otherwise the folder it runs in.
    /// </summary>
    public static string FolderFor(IReadOnlyList<string> commandLine, string directory, Func<string, bool> isFolder)
    {
        foreach (var argument in commandLine.Skip(1).Where(a => a.Length > 0 && !a.StartsWith('-', StringComparison.Ordinal)))
        {
            try
            {
                if (Path.GetFullPath(argument, directory) is var full && isFolder(full))
                    return full;
            }
            catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException)
            {
            }
        }
        return directory;
    }

    /// <summary>Where a placeholder's base URL points from inside a container: the same port on the host, through the relay.</summary>
    public static Uri ForContainer(Uri endpoint) => new UriBuilder(endpoint) { Host = DevcontainerWire.Host }.Uri;
}
