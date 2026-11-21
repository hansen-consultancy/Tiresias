using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Tiresias.Audit;

public enum AuditKind
{
    LeaseBegin,
    LeaseEnd,
    Mint,
    Allow,
    Deny,
    Elevate,
    /// <summary>A trust-chain link this broker accepted for the first time.</summary>
    TrustLink,
    /// <summary>A trust chain that failed verification; a rollback or fork here means someone tried to rewrite history.</summary>
    TrustRejected,
    /// <summary>A newly accepted link was authorized by a paper key.</summary>
    BreakGlass,
    /// <summary>A short-lived token was issued to a device from a vault secret (a GitHub App installation token).</summary>
    Token,
    /// <summary>A placeholder was revoked before its expiry, e.g. when <c>tir exec</c>'s child exited.</summary>
    PlaceholderRevoked,
    /// <summary>An RFC 3161 timestamp over the log's head, in <c>Evidence</c>; see <see cref="AuditAnchors"/>.</summary>
    Anchor,
}

/// <summary>
/// One broker decision. Deliberately has no field for a body, a secret value or a placeholder
/// token: <paramref name="Token"/> is a short prefix of the token's hash, enough to correlate
/// records, useless to an attacker.
/// </summary>
/// <param name="Path">Path only, never the query string, which may carry a credential of its own.</param>
/// <param name="Process">The local process the requester was, as the consent request or the forwarder reported it.</param>
/// <param name="Evidence">Base64 of third-party proof about the log itself (an <see cref="AuditKind.Anchor"/>'s timestamp token), never of a request.</param>
public sealed record AuditRecord(
    AuditKind Kind,
    string? LeaseId = null,
    string? Consumer = null,
    string? Service = null,
    string? Grant = null,
    string? Method = null,
    string? Path = null,
    int? Status = null,
    string? Reason = null,
    string? Token = null,
    string? Process = null,
    string? Evidence = null);

/// <summary>
/// Append-only JSON-lines audit log. Each line carries <c>prevHash</c>, the SHA-256 of the previous
/// line's exact bytes (64 zero hex digits for the first), so editing, deleting or reordering any
/// line breaks the chain at that point. Truncating the tail is not detectable from the file alone;
/// the copy pushed to the control plane covers that.
/// </summary>
/// <remarks>
/// The file is opened per line, so readers (the control-plane push, <see cref="Verify"/>) never contend with a
/// held handle. <see cref="Dispose"/> waits for a line being written and refuses later ones, so once
/// it returns this process holds no handle on the file: the host's shutdown, not timing, decides
/// when the file is free.
/// </remarks>
public sealed class AuditLog : IDisposable
{
    public static readonly string Genesis = new('0', 64);

    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    readonly string path;
    readonly TimeProvider time;
    readonly Lock gate = new();
    string lastHash;
    bool disposed;

    public AuditLog(string path, TimeProvider time)
    {
        this.path = path;
        this.time = time;
        var last = File.Exists(path) ? File.ReadLines(path).LastOrDefault(l => l.Length > 0) : null;
        lastHash = last is null ? Genesis : Hash(last);
    }

    /// <summary>The hash of the last line written, which the next line will carry as <c>prevHash</c>.</summary>
    public string Head
    {
        get
        {
            lock (gate)
                return lastHash;
        }
    }

    /// <summary>Short reference to a placeholder for audit records: the first 8 hex digits of its hash.</summary>
    public static string TokenRef(byte[] tokenHash) => Convert.ToHexStringLower(tokenHash)[..8];

    /// <summary>Raised after a record is written, outside the log's lock, on the writer's thread. The app alerts on some (docs/alerts.md).</summary>
    public event Action<AuditRecord, DateTimeOffset>? Appended;

    public void Append(AuditRecord record)
    {
        DateTimeOffset at;
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            at = time.GetUtcNow();
            var line = JsonSerializer.Serialize(new Line(lastHash, at, record.Kind, record.LeaseId, record.Consumer,
                record.Service, record.Grant, record.Method, record.Path, record.Status, record.Reason, record.Token, record.Process, record.Evidence), Json);
            File.AppendAllText(path, line + "\n");
            lastHash = Hash(line);
        }
        Appended?.Invoke(record, at);
    }

    /// <summary>Waits for a line in progress; every later <see cref="Append"/> throws.</summary>
    public void Dispose()
    {
        lock (gate)
            disposed = true;
    }

    /// <returns>The 1-based number of the first line whose chain is broken, or <c>null</c> when the whole file verifies.</returns>
    public static int? Verify(string path)
    {
        var expected = Genesis;
        var number = 0;
        foreach (var line in File.ReadLines(path))
        {
            number++;
            try
            {
                using var doc = JsonDocument.Parse(line);
                if (!doc.RootElement.TryGetProperty("prevHash", out var prev) || prev.GetString() != expected)
                    return number;
            }
            catch (JsonException)
            {
                return number;
            }
            expected = Hash(line);
        }
        return null;
    }

    internal static string Hash(string line) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(line)));

    sealed record Line(
        string PrevHash,
        DateTimeOffset Time,
        AuditKind Kind,
        string? LeaseId,
        string? Consumer,
        string? Service,
        string? Grant,
        string? Method,
        string? Path,
        int? Status,
        string? Reason,
        string? Token,
        string? Process,
        string? Evidence);
}
