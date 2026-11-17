using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text.Json;

namespace Tiresias.Audit;

/// <param name="Line">The 1-based line of the <see cref="AuditKind.Anchor"/> record.</param>
/// <param name="AnchoredLine">The last line the token covers: it and every line before it existed no later than <paramref name="Time"/>. 0 is the empty log.</param>
/// <param name="Signer">The TSA certificate's subject. Whether that TSA is one to believe is the reader's call.</param>
public sealed record AnchorCheck(int Line, int? AnchoredLine, DateTimeOffset? Time, string? Signer, string? Error)
{
    public bool IsValid => Error is null;
}

/// <summary>
/// RFC 3161 anchors over the audit log's head. The hash chain proves order; a token from a public
/// TSA over a head proves that head, and so every line up to it, existed no later than the token's
/// time. The TSA is sent only the head hash itself as the message imprint (SHA-256 already), never
/// a line.
/// </summary>
/// <remarks>
/// <see cref="Check"/> verifies the token's CMS signature against the certificate it carries; it
/// does not decide whether that TSA is trusted. That is a policy over <see cref="AnchorCheck.Signer"/>.
/// </remarks>
public static class AuditAnchors
{
    const string Sha256Oid = "2.16.840.1.101.3.4.2.1";

    /// <summary>What to ask the TSA to timestamp for <paramref name="head"/>, as a SHA-256 hash.</summary>
    public static byte[] Imprint(string head) => Convert.FromHexString(head);

    /// <summary>Whether <paramref name="token"/> is a validly signed RFC 3161 token over <paramref name="head"/>.</summary>
    public static (DateTimeOffset? Time, string? Signer, string? Error) Check(byte[] token, string head)
    {
        if (!Rfc3161TimestampToken.TryDecode(token, out var decoded, out _))
            return (null, null, "not an RFC 3161 timestamp token");
        var info = decoded.TokenInfo;
        if (info.HashAlgorithmId.Value != Sha256Oid)
            return (null, null, $"imprint uses {info.HashAlgorithmId.Value}, not SHA-256");
        var imprint = Imprint(head);
        if (!info.GetMessageHash().Span.SequenceEqual(imprint))
            return (null, null, "the token is for another head");
        if (!decoded.VerifySignatureForHash(imprint, HashAlgorithmName.SHA256, out var signer, extraCandidates: null))
            return (null, null, "the token's signature does not verify");
        using (signer)
            return (info.Timestamp, signer?.Subject, null);
    }

    /// <summary>Checks every anchor in the log at <paramref name="path"/> against the lines before it.</summary>
    public static IReadOnlyList<AnchorCheck> Verify(string path)
    {
        var heads = new Dictionary<string, int> { [AuditLog.Genesis] = 0 };
        var checks = new List<AnchorCheck>();
        var number = 0;
        foreach (var line in File.ReadLines(path))
        {
            number++;
            if (Anchor(line) is { } evidence)
                checks.Add(VerifyOne(number, evidence, heads));
            heads.TryAdd(AuditLog.Hash(line), number);
        }
        return checks;
    }

    static AnchorCheck VerifyOne(int number, string evidence, Dictionary<string, int> heads)
    {
        byte[] token;
        try
        {
            token = Convert.FromBase64String(evidence);
        }
        catch (FormatException)
        {
            return new(number, null, null, null, "evidence is not base64");
        }
        if (!Rfc3161TimestampToken.TryDecode(token, out var decoded, out _))
            return new(number, null, null, null, "not an RFC 3161 timestamp token");

        var head = Convert.ToHexStringLower(decoded.TokenInfo.GetMessageHash().Span);
        if (!heads.TryGetValue(head, out var anchored))
            return new(number, null, null, null, "the token covers no earlier head of this log");
        var (time, signer, error) = Check(token, head);
        return new(number, anchored, time, signer, error);
    }

    static string? Anchor(string line)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            return root.TryGetProperty("kind", out var kind) && kind.GetString() == nameof(AuditKind.Anchor)
                ? root.TryGetProperty("evidence", out var e) ? e.GetString() ?? "" : ""
                : null;
        }
        catch (JsonException)
        {
            return null; // AuditLog.Verify reports the broken line.
        }
    }
}
