using System.Security.Cryptography;
using AsicSharp.Services;
using Tiresias.Audit;

namespace Tiresias.Broker;

/// <summary>
/// Timestamps the audit log's head with an RFC 3161 TSA and appends the token as an
/// <see cref="AuditKind.Anchor"/> record: every <see cref="Interval"/> and at every lease end,
/// whenever something was logged since the last anchor. Truncation after the last anchor is
/// therefore bounded by the interval.
/// </summary>
/// <remarks>
/// Evidence is best effort: an unreachable TSA, or one answering with a token that doesn't verify,
/// is logged and retried next time and never blocks access. After an hour of failures the warning
/// becomes an error, once.
/// </remarks>
sealed class AuditAnchoring(AuditLog audit, ITsaClient tsa, TimeProvider time, ILogger<AuditAnchoring> logger) : BackgroundService
{
    public static readonly TimeSpan Interval = TimeSpan.FromMinutes(15);
    static readonly TimeSpan AlertAfter = TimeSpan.FromHours(1);

    readonly SemaphoreSlim gate = new(1, 1);
    string? anchoredThrough;
    DateTimeOffset? failingSince;
    bool alerted;

    public async Task AnchorAsync(CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try
        {
            var head = audit.Head;
            if (head == anchoredThrough || head == AuditLog.Genesis)
                return;

            string? error;
            byte[]? token = null;
            try
            {
                token = (await tsa.RequestTimestampAsync(AuditAnchors.Imprint(head), HashAlgorithmName.SHA256, ct)).TokenBytes;
                error = AuditAnchors.Check(token, head).Error;
            }
            catch (Exception ex) when (!ct.IsCancellationRequested) // Whatever the TSA or its client throws, access must not depend on it.
            {
                error = ex.Message;
            }

            if (error is null)
            {
                audit.Append(new(AuditKind.Anchor, Reason: $"head {head}", Evidence: Convert.ToBase64String(token!)));
                anchoredThrough = audit.Head;
                failingSince = null;
                alerted = false;
                return;
            }

            var now = time.GetUtcNow();
            failingSince ??= now;
            if (now - failingSince >= AlertAfter && !alerted)
            {
                alerted = true;
                logger.LogError("Audit anchoring has failed since {Since:u}: {Error}", failingSince, error);
            }
            else
                logger.LogWarning("Audit anchor not obtained, retrying later: {Error}", error);
        }
        finally
        {
            gate.Release();
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval, time);
        while (await timer.WaitForNextTickAsync(stoppingToken))
            await AnchorAsync(stoppingToken);
    }

    public override void Dispose()
    {
        gate.Dispose();
        base.Dispose();
    }
}
