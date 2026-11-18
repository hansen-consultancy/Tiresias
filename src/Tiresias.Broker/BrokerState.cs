using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Tiresias.Access;
using Tiresias.Audit;
using Tiresias.Crypto;
using Tiresias.Leases;
using Tiresias.Policy;
using Tiresias.Sql;
using Tiresias.Transport;
using Tiresias.Vault;
using NSec.Cryptography;

namespace Tiresias.Broker;

/// <summary>Why the broker said no, in the shape the HTTP layer returns it.</summary>
public sealed record Refusal(int Status, string Reason, string? ElevationNeeded = null, IReadOnlyList<string>? Problems = null);

public sealed record SignedLeaseOffer(LeaseOffer Offer, byte[] Signature);

public sealed record SealResult(IReadOnlyList<string> Accepted, IReadOnlyList<string> Rejected);

public sealed record MintedPlaceholder(string Token, DateTimeOffset ExpiresAt);

/// <summary>
/// A SQL Server service is one whose upstream is <c>mssql://host/database</c> (shown, never dialled:
/// the grant's connection string says where to connect). Its grants must be named <c>read</c> and
/// <c>write</c>, which map to the database roles <c>tir_read</c> and <c>tir_write</c>.
/// </summary>
public static class SqlGrants
{
    public const string UpstreamScheme = "mssql";

    public const string Read = "read";
    public const string Write = "write";
}

/// <summary>
/// Everything the broker knows that matters for security, behind one lock: the current lease, its
/// ephemeral X25519 key, the DEKs delivered for it, the placeholders minted under it, and the vault.
/// Key material exists only while a lease is open; every entry point first checks the lease is
/// still valid and, when it isn't, ends it (zeroes the DEKs, drops the lease key, revokes the
/// placeholders, audits) before answering. Callers therefore never see a stale lease, even between
/// <see cref="Tick"/>s.
/// </summary>
public sealed class BrokerState : IDisposable
{
    VaultDocument vault;
    readonly LeaseTerms terms;
    readonly AuditLog audit;
    readonly Key identity;
    readonly TimeProvider time;
    readonly PlaceholderRegistry placeholders;
    readonly Lock gate = new();
    readonly Dictionary<string, byte[]> deks = [];

    Lease? lease;
    Key? leaseKey;
    string? leaseDevice;

    public BrokerState(VaultDocument vault, LeaseTerms terms, AuditLog audit, Key identity, TimeProvider time)
    {
        this.vault = vault;
        this.terms = terms;
        this.audit = audit;
        this.identity = identity;
        this.time = time;
        placeholders = new(time);
    }

    /// <summary>
    /// Raised with the lease id after a lease ended, for whatever holds per-lease resources outside
    /// this class (temporary SQL logins, client certificates). Handlers run on the thread pool, never
    /// under the state lock, so they may call back in.
    /// </summary>
    public event Action<string>? LeaseEnded;

    /// <summary>Opens a new lease, ending any current one. The offer is signed by the broker identity.</summary>
    public SignedLeaseOffer BeginLease(string device)
    {
        lock (gate)
        {
            var now = time.GetUtcNow();
            if (CurrentLease(now) is { } previous)
            {
                previous.Revoke();
                EndLease("superseded");
            }

            var id = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
            lease = Lease.Begin(id, now, terms);
            leaseKey = Key.Create(KeyAgreementAlgorithm.X25519);
            leaseDevice = device;
            audit.Append(new(AuditKind.LeaseBegin, id, device));

            var offer = new LeaseOffer(id, leaseKey.PublicKey.Export(KeyBlobFormat.RawPublicKey),
                DateTimeOffset.FromUnixTimeSeconds(lease.HardCapAt.ToUnixTimeSeconds()));
            return new(offer, offer.Sign(identity));
        }
    }

    /// <summary>
    /// Accepts DEKs sealed to the lease key. Each must open under its lease/slug context and must
    /// actually open its vault secret, so garbage is refused here rather than at the first request.
    /// </summary>
    public (SealResult? Result, Refusal? Refusal) Seal(string leaseId, IReadOnlyDictionary<string, byte[]> sealedDeks)
    {
        lock (gate)
        {
            if (Check(leaseId) is { } refusal)
                return (null, refusal);

            var accepted = new List<string>();
            var rejected = new List<string>();
            foreach (var (slug, box) in sealedDeks)
            {
                var secret = vault.FindSecret(slug);
                var dek = secret is null ? null : SealedBox.Open(leaseKey!, box, LeaseOffer.DekContext(leaseId, slug));
                if (dek is null || !Opens(secret!, dek))
                {
                    if (dek is not null)
                        Array.Clear(dek);
                    rejected.Add(slug);
                    continue;
                }

                if (deks.Remove(slug, out var old))
                    Array.Clear(old);
                deks[slug] = dek;
                accepted.Add(slug);
            }
            return (new(accepted.ToArray(), rejected.ToArray()), null);
        }
    }

    public Refusal? Heartbeat(string leaseId)
    {
        lock (gate)
            return Check(leaseId) ?? (lease!.Heartbeat(time.GetUtcNow()) ? null : new Refusal(503, "no-lease"));
    }

    /// <summary>
    /// Swaps in a vault that changed on disk, keeping the lease. A leased DEK stays only while it
    /// still opens its secret: a removed or re-sealed secret loses it (zeroed) until the Keyring
    /// seals the new one. Placeholders keep working for services that are still there.
    /// </summary>
    /// <returns>The secrets of the open lease that have no DEK now, for the Keyring to seal; empty without a lease.</returns>
    public IReadOnlyList<string> ReplaceVault(VaultDocument next)
    {
        lock (gate)
        {
            foreach (var (slug, dek) in deks.ToArray())
            {
                if (next.FindSecret(slug) is { } secret && Opens(secret, dek))
                    continue;
                Array.Clear(dek);
                deks.Remove(slug);
            }
            vault = next;
            return CurrentLease(time.GetUtcNow()) is null ? [] : next.Secrets.Where(s => !deks.ContainsKey(s.Slug)).Select(s => s.Slug).ToArray();
        }
    }

    /// <summary>Revokes the current lease, if any. Idempotent.</summary>
    public void End()
    {
        lock (gate)
        {
            if (lease is null)
                return;
            lease.Revoke();
            EndLease("revoked");
        }
    }

    /// <summary>
    /// Ends the lease when the device that opened it is no longer trusted, e.g. just revoked in the
    /// trust chain. Its placeholders die with it; whoever holds that device's key must not keep a
    /// working lease.
    /// </summary>
    /// <returns><c>true</c> when a lease was ended.</returns>
    public bool EndLeaseOfUntrustedDevice(Func<string, bool> isTrusted)
    {
        lock (gate)
        {
            if (CurrentLease(time.GetUtcNow()) is not { } current || isTrusted(leaseDevice!))
                return false;
            current.Revoke();
            EndLease("device-revoked");
            return true;
        }
    }

    /// <summary>Ends the lease if its hard cap passed or its heartbeat was lost. Run on a timer.</summary>
    public void Tick()
    {
        lock (gate)
            CurrentLease(time.GetUtcNow());
    }

    public (MintedPlaceholder? Minted, Refusal? Refusal) Mint(AccessRequest request)
    {
        lock (gate)
        {
            var now = time.GetUtcNow();
            if (CurrentLease(now) is not { } current)
                return (null, new(503, "no-lease"));
            if (vault.FindService(request.ServiceSlug) is not { } service)
                return (null, new(404, "unknown-service"));
            var problems = Consent.Validate(request, service);
            if (problems.Count > 0)
                return (null, new(400, "invalid-request", Problems: problems));

            var token = placeholders.Mint(current.Id, request, current.HardCapAt);
            var placeholder = placeholders.Resolve(token, current.Id).Placeholder!;
            audit.Append(new(AuditKind.Mint, current.Id, request.Consumer, service.Slug, request.Ceiling,
                Reason: request.Purpose, Token: AuditLog.TokenRef(placeholder.TokenHash), Process: request.ObservedProcess));
            return (new(token, placeholder.ExpiresAt), null);
        }
    }

    /// <summary>Revokes one placeholder of the current lease. Idempotent: an unknown token is not an error.</summary>
    public void RevokePlaceholder(string token)
    {
        lock (gate)
        {
            if (placeholders.Revoke(token) is { } revoked)
                audit.Append(new(AuditKind.PlaceholderRevoked, revoked.LeaseId, revoked.Request.Consumer, revoked.Request.ServiceSlug,
                    Token: AuditLog.TokenRef(revoked.TokenHash)));
        }
    }

    /// <summary>
    /// Opens a GitHub App service's secret for <c>/token</c>, on behalf of a signed device. Uses the
    /// service's least privileged grant; one that needs elevation is refused unless elevated.
    /// </summary>
    public (AllowedRequest? Allowed, Refusal? Refusal) AuthorizeToken(string serviceSlug, string device)
    {
        var record = new AuditRecord(AuditKind.Deny, Consumer: device, Service: serviceSlug, Method: "TOKEN");
        lock (gate)
        {
            var now = time.GetUtcNow();
            if (CurrentLease(now) is not { } current)
                return (null, Refuse(record, 503, "no-lease"));
            record = record with { LeaseId = current.Id };
            if (vault.FindService(serviceSlug) is not { } service)
                return (null, Refuse(record, 404, "unknown-service"));
            if (!service.Upstream.Host.Equals(GitHub.GitHubAppSecret.ApiHost, StringComparison.OrdinalIgnoreCase) || service.Grants.Count == 0)
                return (null, Refuse(record, 400, "not-a-token-service"));
            var grant = service.Grants[0];
            record = record with { Grant = grant.Name };
            if (grant.RequiresElevation && !current.ActiveElevations(serviceSlug, now).Contains(grant.Name))
                return (null, Refuse(record, 403, "elevation-required", grant.Name));
            var secret = vault.FindSecret(grant.SecretSlug);
            if (secret is null || !deks.TryGetValue(grant.SecretSlug, out var dek))
                return (null, Refuse(record, 503, "secret-not-leased"));
            if (SecretEnvelope.Open(secret, dek) is not { } value)
                return (null, Refuse(record, 500, "secret-unreadable"));
            return (new AllowedRequest(audit, record with { Kind = AuditKind.Token }, service, grant, value, current.HardCapAt), null);
        }
    }

    /// <summary>Records an elevation the Keyring approved (after its own Hello prompt). Never outlives the lease.</summary>
    public (DateTimeOffset? ExpiresAt, Refusal? Refusal) Elevate(string serviceSlug, string grantName, TimeSpan duration)
    {
        lock (gate)
        {
            var now = time.GetUtcNow();
            if (CurrentLease(now) is not { } current)
                return (null, new(503, "no-lease"));
            var grant = vault.FindService(serviceSlug)?.Grants.FirstOrDefault(g => g.Name == grantName);
            if (grant is not { RequiresElevation: true })
                return (null, new(400, "not-elevatable"));
            if (duration <= TimeSpan.Zero)
                return (null, new(400, "invalid-duration"));

            var expires = current.Elevate(serviceSlug, grantName, duration, now);
            audit.Append(new(AuditKind.Elevate, current.Id, leaseDevice, serviceSlug, grantName,
                Reason: $"until {expires:O}"));
            return (expires, null);
        }
    }

    /// <summary>
    /// The whole decision for one <c>/svc</c> request. On allow, the grant's secret is decrypted for
    /// this request only and handed over in an <see cref="AllowedRequest"/>, which zeroes it and
    /// writes the Allow record. Every deny is audited here. Nothing here contacts the upstream.
    /// </summary>
    /// <param name="authorization">The request's <c>Authorization</c> header, expected <c>Bearer tirph_…</c>.</param>
    /// <param name="observedProcess">What the forwarder reported in <see cref="ForwarderHeaders.ObservedProcess"/>; recorded, never decided on.</param>
    public (AllowedRequest? Allowed, Refusal? Refusal) Authorize(string? authorization, string serviceSlug, BrokeredRequest request, string? observedProcess = null)
    {
        var token = ParseBearer(authorization);
        var record = new AuditRecord(AuditKind.Deny, Service: serviceSlug, Method: request.Method, Path: PathOnly(request.PathAndQuery),
            Token: token is null ? null : AuditLog.TokenRef(PlaceholderToken.Hash(token)), Process: observedProcess);

        lock (gate)
        {
            var now = time.GetUtcNow();
            var (admitted, refusal) = Admit(token, serviceSlug, now, ref record);
            if (admitted is not var (current, placeholder, service))
                return (null, refusal);

            GrantDecision decision;
            try
            {
                decision = GrantSelector.Select(service, request, placeholder.Request.Ceiling, current.ActiveElevations(serviceSlug, now));
            }
            catch (RegexMatchTimeoutException)
            {
                return Deny(403, "policy-timeout");
            }
            if (decision.Grant is not { } grant)
                return Deny(403, decision.Reason switch
                {
                    DenyReason.SuspiciousPath => "suspicious-path",
                    DenyReason.ElevationRequired => "elevation-required",
                    _ => "not-covered",
                }, decision.ElevationNeeded);

            record = record with { Grant = grant.Name };
            var secret = vault.FindSecret(grant.SecretSlug);
            if (secret is null || !deks.TryGetValue(grant.SecretSlug, out var dek))
                return Deny(503, "secret-not-leased");
            if (SecretEnvelope.Open(secret, dek) is not { } value)
                return Deny(500, "secret-unreadable");

            return (new AllowedRequest(audit, record with { Kind = AuditKind.Allow }, service, grant, value, current.HardCapAt), null);
        }

        (AllowedRequest?, Refusal?) Deny(int status, string reason, string? elevationNeeded = null) =>
            (null, Refuse(record, status, reason, elevationNeeded));
    }

    /// <summary>
    /// The decision for one <c>/sql</c> statement: the placeholder checks of <see cref="Authorize"/>,
    /// then the named grant must be reachable under the placeholder's ceiling (and elevated when it
    /// says so), and a <c>read</c> grant only runs what <see cref="SqlReadClassifier"/> can prove is
    /// one SELECT. The SQL text is never audited; only its verdict is.
    /// </summary>
    /// <param name="instance">The vault service slug of the SQL Server database.</param>
    /// <param name="grantName"><c>read</c> or <c>write</c>; the grant's secret is the provisioner connection string.</param>
    public (AllowedRequest? Allowed, Refusal? Refusal) AuthorizeSql(string? authorization, string instance, string grantName, string sql, string? observedProcess = null) =>
        AuthorizeSqlAccess(authorization, instance, grantName, sql, observedProcess);

    /// <summary>
    /// The decision for <c>/sql/{instance}/{grant}/login</c>: the checks of <see cref="AuthorizeSql"/>
    /// without a statement to classify, and the grant must issue logins. Audited as <c>LOGIN</c>.
    /// </summary>
    public (AllowedRequest? Allowed, Refusal? Refusal) AuthorizeSqlLogin(string? authorization, string instance, string grantName, string? observedProcess = null) =>
        AuthorizeSqlAccess(authorization, instance, grantName, sql: null, observedProcess);

    /// <param name="sql">The statement, or <c>null</c> for a login hand-out.</param>
    (AllowedRequest? Allowed, Refusal? Refusal) AuthorizeSqlAccess(string? authorization, string instance, string grantName, string? sql, string? observedProcess)
    {
        var token = ParseBearer(authorization);
        var classification = sql is null ? null : SqlReadClassifier.Classify(sql);
        var record = new AuditRecord(AuditKind.Deny, Service: instance, Grant: grantName, Method: sql is null ? "LOGIN" : "SQL",
            Token: token is null ? null : AuditLog.TokenRef(PlaceholderToken.Hash(token)), Process: observedProcess);

        lock (gate)
        {
            var now = time.GetUtcNow();
            var (admitted, refusal) = Admit(token, instance, now, ref record);
            if (admitted is not var (current, placeholder, service))
                return (null, refusal);

            if (service.Upstream.Scheme != SqlGrants.UpstreamScheme)
                return Deny(404, "not-sql");
            if (grantName is not (SqlGrants.Read or SqlGrants.Write)
                || Consent.Reachable(service, placeholder.Request.Ceiling).FirstOrDefault(g => g.Name == grantName) is not { } grant)
                return Deny(403, "not-covered");
            if (grant.RequiresElevation && !current.ActiveElevations(instance, now).Contains(grant.Name))
                return Deny(403, "elevation-required", grant.Name);
            if (classification is null && !grant.IssuesLogins)
                return Deny(403, "no-logins");
            if (classification is not null && grantName == SqlGrants.Read && !classification.IsRead)
                return Deny(403, "not-read-only", detail: classification.Reason);

            var secret = vault.FindSecret(grant.SecretSlug);
            if (secret is null || !deks.TryGetValue(grant.SecretSlug, out var dek))
                return Deny(503, "secret-not-leased");
            if (SecretEnvelope.Open(secret, dek) is not { } value)
                return Deny(500, "secret-unreadable");

            var allow = record with { Kind = AuditKind.Allow, Reason = classification is null ? "login" : classification.IsRead ? "select" : "statement" };
            return (new AllowedRequest(audit, allow, service, grant, value, current.HardCapAt), null);
        }

        (AllowedRequest?, Refusal?) Deny(int status, string reason, string? elevationNeeded = null, string? detail = null)
        {
            if (detail is null)
                return (null, Refuse(record, status, reason, elevationNeeded));
            audit.Append(record with { Status = status, Reason = $"{reason}: {detail}" });
            return (null, new(status, reason, Problems: [detail]));
        }
    }

    /// <summary>
    /// The checks every placeholder-authenticated request shares: an open lease, a live placeholder of
    /// that lease, issued for this service, which the vault still has. Call under <see cref="gate"/>.
    /// A refusal has already been audited; <paramref name="record"/> gains what was learnt on the way.
    /// </summary>
    ((Lease Lease, Placeholder Placeholder, Service Service)? Admitted, Refusal? Refusal) Admit(string? token, string serviceSlug, DateTimeOffset now, ref AuditRecord record)
    {
        if (CurrentLease(now) is not { } current)
            return (null, Refuse(record, 503, "no-lease"));
        record = record with { LeaseId = current.Id };
        if (token is null)
            return (null, Refuse(record, 401, "no-placeholder"));

        var (placeholder, rejection) = placeholders.Resolve(token, current.Id);
        if (placeholder is null)
            return (null, Refuse(record, 401, rejection switch
            {
                PlaceholderRejection.Expired => "placeholder-expired",
                PlaceholderRejection.LeaseEnded => "placeholder-lease-ended",
                _ => "unknown-placeholder",
            }));
        record = record with { Consumer = placeholder.Request.Consumer };
        if (placeholder.Request.ServiceSlug != serviceSlug)
            return (null, Refuse(record, 403, "wrong-service"));
        if (vault.FindService(serviceSlug) is not { } service)
            return (null, Refuse(record, 404, "unknown-service"));
        return ((current, placeholder, service), null);
    }

    Refusal Refuse(AuditRecord record, int status, string reason, string? elevationNeeded = null)
    {
        audit.Append(record with { Status = status, Reason = elevationNeeded is null ? reason : $"{reason}: {elevationNeeded}" });
        return new(status, reason, elevationNeeded);
    }

    /// <summary>References to the leased DEK arrays, so tests can prove they are zeroed at lease end.</summary>
    internal IReadOnlyList<byte[]> LeasedDeks()
    {
        lock (gate)
            return deks.Values.ToArray();
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (lease is not null)
            {
                lease.Revoke();
                EndLease("shutdown");
            }
        }
        identity.Dispose();
    }

    Refusal? Check(string leaseId) =>
        CurrentLease(time.GetUtcNow()) is not { } current ? new(503, "no-lease")
        : current.Id != leaseId ? new(409, "lease-mismatch")
        : null;

    /// <summary>The open lease, ending it first if it has run out. Call under <see cref="gate"/>.</summary>
    Lease? CurrentLease(DateTimeOffset now)
    {
        if (lease is null)
            return null;
        var end = lease.Evaluate(now);
        if (end == LeaseEnd.None)
            return lease;
        EndLease(end.ToString());
        return null;
    }

    void EndLease(string reason)
    {
        var id = lease!.Id;
        foreach (var dek in deks.Values)
            Array.Clear(dek);
        deks.Clear();
        leaseKey?.Dispose();
        leaseKey = null;
        placeholders.RevokeLease(id);
        audit.Append(new(AuditKind.LeaseEnd, id, leaseDevice, Reason: reason));
        lease = null;
        leaseDevice = null;
        if (LeaseEnded is { } handlers)
            ThreadPool.QueueUserWorkItem(_ => handlers(id));
    }

    static bool Opens(SealedSecret secret, byte[] dek)
    {
        var value = SecretEnvelope.Open(secret, dek);
        if (value is null)
            return false;
        Array.Clear(value);
        return true;
    }

    static string? ParseBearer(string? authorization)
    {
        const string scheme = "Bearer ";
        if (authorization is null || !authorization.StartsWith(scheme, StringComparison.OrdinalIgnoreCase))
            return null;
        var token = authorization[scheme.Length..].Trim();
        return token.StartsWith(PlaceholderToken.Prefix, StringComparison.Ordinal) ? token : null;
    }

    static string PathOnly(string pathAndQuery)
    {
        var query = pathAndQuery.IndexOf('?', StringComparison.Ordinal);
        return query < 0 ? pathAndQuery : pathAndQuery[..query];
    }
}

/// <summary>
/// An allowed request in flight: the decrypted secret, handed out once, and the obligation to write
/// exactly one Allow record. Disposing zeroes the secret and, if <see cref="Complete"/> was never
/// called, records the request as aborted.
/// </summary>
public sealed class AllowedRequest : IDisposable
{
    readonly AuditLog audit;
    readonly AuditRecord record;
    readonly byte[] secret;
    bool completed;

    internal AllowedRequest(AuditLog audit, AuditRecord record, Service service, Grant grant, byte[] secret, DateTimeOffset leaseExpiresAt)
    {
        this.audit = audit;
        this.record = record;
        this.secret = secret;
        Service = service;
        Grant = grant;
        LeaseExpiresAt = leaseExpiresAt;
    }

    public Service Service { get; }
    public Grant Grant { get; }
    public string LeaseId => record.LeaseId!;
    public DateTimeOffset LeaseExpiresAt { get; }

    /// <summary>
    /// The secret as text (the full <c>Authorization</c> header value for <c>/svc</c>, the provisioner
    /// connection string for <c>/sql</c>), after which the decrypted bytes are zeroed. The returned
    /// string can't be zeroed; it lives until the GC reclaims it.
    /// </summary>
    public string TakeSecret()
    {
        var value = Encoding.UTF8.GetString(secret);
        Array.Clear(secret);
        return value;
    }

    public void Complete(int? status, string? reason = null)
    {
        if (completed)
            return;
        completed = true;
        audit.Append(record with { Status = status, Reason = reason ?? record.Reason });
    }

    /// <summary>A tunnel this request opened has closed: a second record, so the first shows it while it lasts.</summary>
    /// <param name="how"><c>closed</c> by either side, or <c>lease-ended</c>.</param>
    public void Closed(string how, long bytesUp, long bytesDown) =>
        audit.Append(record with { Status = StatusCodes.Status101SwitchingProtocols, Reason = $"{how}: {bytesUp} bytes up, {bytesDown} bytes down" });

    public void Dispose()
    {
        Array.Clear(secret);
        Complete(null, "aborted");
    }
}
