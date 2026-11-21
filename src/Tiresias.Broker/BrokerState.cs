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

/// <summary>What <see cref="BrokerState.ReplaceVault"/> did with a vault that changed on disk.</summary>
/// <param name="Unleased">Secrets of the open lease that have no DEK now, for the Keyring to seal; empty without a lease.</param>
/// <param name="Unapproved">
/// Leased secrets bound to their policy whose policy the new vault changes without a re-seal. When
/// there are any, the new vault was refused and the previous one kept.
/// </param>
/// <param name="RolledBack">
/// Secrets whose version in the new vault is lower than one this lease already saw: an older
/// <c>vault.json</c> restored, with its once-approved policy. When there are any, the new vault was
/// refused and the previous one kept.
/// </param>
public sealed record VaultReload(IReadOnlyList<string> Unleased, IReadOnlyList<string> Unapproved, IReadOnlyList<string>? RolledBack = null)
{
    public bool Refused => Unapproved.Count > 0 || RolledBack is { Count: > 0 };
}

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
    PublicKey? approvalKey;
    readonly Dictionary<string, DateTimeOffset> usedNonces = [];

    /// <summary>
    /// The highest version of each secret this lease has seen. A vault that goes below it is a
    /// rollback to an older, once-approved policy (docs/policy-integrity.md, *Rollback*).
    /// </summary>
    readonly Dictionary<string, int> highWater = [];

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
            RaiseHighWater(vault);
            leaseKey = Key.Create(KeyAgreementAlgorithm.X25519);
            leaseDevice = device;
            audit.Append(new(AuditKind.LeaseBegin, id, device));

            var offer = new LeaseOffer(id, leaseKey.PublicKey.Export(KeyBlobFormat.RawPublicKey),
                DateTimeOffset.FromUnixTimeSeconds(lease.HardCapAt.ToUnixTimeSeconds()));
            return new(offer, offer.Sign(identity));
        }
    }

    /// <summary>
    /// Accepts DEKs sealed to the lease key. Each must open under its lease/slug/approval-key context
    /// and must actually open its vault secret, so garbage is refused here rather than at the first
    /// request. The first seal that delivers such a DEK registers <paramref name="approvalKey"/> as
    /// the lease's: only whoever opens the vault can name the key that approves operations.
    /// </summary>
    /// <param name="approvalKey">The raw Ed25519 public key of <see cref="ApprovalKey"/> for this lease.</param>
    public (SealResult? Result, Refusal? Refusal) Seal(string leaseId, IReadOnlyDictionary<string, byte[]> sealedDeks, byte[]? approvalKey)
    {
        lock (gate)
        {
            if (Check(leaseId) is { } refusal)
                return (null, refusal);
            if (approvalKey is not { Length: 32 })
                return (null, new(400, "approval-key-required"));
            if (this.approvalKey is { } registered && !registered.Export(KeyBlobFormat.RawPublicKey).AsSpan().SequenceEqual(approvalKey))
            {
                audit.Append(new(AuditKind.Deny, leaseId, leaseDevice, Reason: "approval-key-mismatch"));
                return (null, new(409, "approval-key-mismatch"));
            }

            var accepted = new List<string>();
            var rejected = new List<string>();
            foreach (var (slug, box) in sealedDeks)
            {
                var secret = vault.FindSecret(slug);
                var dek = secret is null ? null : SealedBox.Open(leaseKey!, box, LeaseOffer.DekContext(leaseId, slug, approvalKey));
                if (dek is null || !Opens(secret!, dek, vault))
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
            if (accepted.Count > 0)
                this.approvalKey ??= PublicKey.Import(SignatureAlgorithm.Ed25519, approvalKey, KeyBlobFormat.RawPublicKey);
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
    /// seals the new one. A secret bound to its policy that is unchanged on disk but no longer opens
    /// means its policy changed without approval: the whole vault is refused and the previous one
    /// kept. A service whose policy changed loses its placeholders and elevations, which were
    /// approved for the old one.
    /// </summary>
    public VaultReload ReplaceVault(VaultDocument next)
    {
        lock (gate)
        {
            var rolledBack = lease is null ? Array.Empty<string>() : next.Secrets
                .Where(s => highWater.TryGetValue(s.Slug, out var seen) && s.Version < seen)
                .Select(s => s.Slug)
                .ToArray();
            if (rolledBack.Length > 0)
            {
                foreach (var slug in rolledBack)
                    audit.Append(new(AuditKind.Deny, lease?.Id, Reason: $"secret-rolled-back: {slug}; vault reload refused"));
                return new([], [], rolledBack);
            }

            var unapproved = deks
                .Where(d => vault.FindSecret(d.Key) is { PolicyHash: not null } current
                    && next.FindSecret(d.Key) is { } incoming
                    && SameCiphertext(current, incoming)
                    && Opens(current, d.Value, vault)
                    && !Opens(incoming, d.Value, next))
                .Select(d => d.Key)
                .ToArray();
            if (unapproved.Length > 0)
            {
                foreach (var slug in unapproved)
                    audit.Append(new(AuditKind.Deny, lease?.Id, Reason: $"policy-not-approved: {slug}; vault reload refused"));
                return new([], unapproved);
            }

            foreach (var (slug, dek) in deks.ToArray())
            {
                if (next.FindSecret(slug) is { } secret && Opens(secret, dek, next))
                    continue;
                Array.Clear(dek);
                deks.Remove(slug);
            }
            RetireChangedServices(next);
            vault = next;
            if (lease is not null)
                RaiseHighWater(next);
            return new(CurrentLease(time.GetUtcNow()) is null ? [] : next.Secrets.Where(s => !deks.ContainsKey(s.Slug)).Select(s => s.Slug).ToArray(), []);
        }
    }

    /// <summary>Call under <see cref="gate"/>, with a lease open.</summary>
    void RaiseHighWater(VaultDocument accepted)
    {
        foreach (var secret in accepted.Secrets)
            if (!highWater.TryGetValue(secret.Slug, out var seen) || secret.Version > seen)
                highWater[secret.Slug] = secret.Version;
    }

    /// <summary>Ends the placeholders and elevations of every service whose policy differs in <paramref name="next"/>. Call under <see cref="gate"/>.</summary>
    void RetireChangedServices(VaultDocument next)
    {
        foreach (var service in vault.Services)
        {
            if (next.FindService(service.Slug) is { } incoming
                && PolicyBinding.ServiceHash(incoming).AsSpan().SequenceEqual(PolicyBinding.ServiceHash(service)))
                continue;
            foreach (var revoked in placeholders.RevokeService(service.Slug))
                audit.Append(new(AuditKind.PlaceholderRevoked, revoked.LeaseId, revoked.Request.Consumer, service.Slug,
                    Token: AuditLog.TokenRef(revoked.TokenHash), Reason: "policy-changed"));
            lease?.DropElevations(service.Slug);
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

    /// <summary>Mints the placeholder <paramref name="signed"/> approves, exactly as approved.</summary>
    public (MintedPlaceholder? Minted, Refusal? Refusal) Mint(SignedApproval? signed)
    {
        lock (gate)
        {
            var now = time.GetUtcNow();
            if (CurrentLease(now) is not { } current)
                return (null, new(503, "no-lease"));
            var (approval, denied) = Approved(signed, Approval.MintOp, current, now, new(AuditKind.Deny, current.Id, Method: "MINT"));
            if (approval is null)
                return (null, denied);
            var request = approval.ToAccessRequest();
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
    public (AllowedRequest? Allowed, Refusal? Refusal) AuthorizeToken(string serviceSlug, string device, SignedApproval? signed) =>
        AuthorizeDeviceUse(serviceSlug, device, "TOKEN", AuditKind.Token,
            s => s.Upstream.Host.Equals(GitHub.GitHubAppSecret.ApiHost, StringComparison.OrdinalIgnoreCase), "not-a-token-service", needsApproval: true, signed);

    /// <summary>
    /// Lets a device ask RavenDB who a service's certificate is (<c>/clearance</c>), with that
    /// certificate. Only for a service the RavenDB setup saved, whose one grant is the certificate;
    /// not through the grant's rule: the answer is metadata about the certificate, never data, so it
    /// needs no signed approval (docs/step-up.md).
    /// </summary>
    public (AllowedRequest? Allowed, Refusal? Refusal) AuthorizeClearance(string serviceSlug, string device) =>
        AuthorizeDeviceUse(serviceSlug, device, "CLEARANCE", AuditKind.Allow, s => RavenSetupPlanner.Recognize(s) is not null, "not-a-raven-service");

    /// <summary>
    /// A device using a service's first grant itself, outside any placeholder: <c>/token</c> and
    /// <c>/clearance</c>. With <paramref name="needsApproval"/>, only with a signed token approval for this service.
    /// </summary>
    (AllowedRequest? Allowed, Refusal? Refusal) AuthorizeDeviceUse(string serviceSlug, string device, string method, AuditKind kind, Func<Service, bool> fits, string misfit,
        bool needsApproval = false, SignedApproval? signed = null)
    {
        var record = new AuditRecord(AuditKind.Deny, Consumer: device, Service: serviceSlug, Method: method);
        lock (gate)
        {
            var now = time.GetUtcNow();
            if (CurrentLease(now) is not { } current)
                return (null, Refuse(record, 503, "no-lease"));
            record = record with { LeaseId = current.Id };
            if (needsApproval)
            {
                var (approval, denied) = Approved(signed, Approval.TokenOp, current, now, record);
                if (approval is null)
                    return (null, denied);
                if (approval.Service != serviceSlug)
                    return (null, Refuse(record, 401, "approval-invalid"));
                record = record with { Consumer = approval.Consumer, Reason = approval.Purpose };
            }
            if (vault.FindService(serviceSlug) is not { } service)
                return (null, Refuse(record, 404, "unknown-service"));
            if (!fits(service) || service.Grants.Count == 0)
                return (null, Refuse(record, 400, misfit));
            var grant = service.Grants[0];
            record = record with { Grant = grant.Name };
            if (grant.RequiresElevation && !current.ActiveElevations(serviceSlug, now).Contains(grant.Name))
                return (null, Refuse(record, 403, "elevation-required", grant.Name));
            var secret = vault.FindSecret(grant.SecretSlug);
            if (secret is null || !deks.TryGetValue(grant.SecretSlug, out var dek))
                return (null, Refuse(record, 503, "secret-not-leased"));
            if (Open(secret, dek, vault) is not { } value)
                return (null, !PolicyBinding.Allows(vault, secret) ? Refuse(record, 403, "policy-not-approved") : Refuse(record, 500, "secret-unreadable"));
            return (new AllowedRequest(audit, record with { Kind = kind }, service, grant, value, current.HardCapAt), null);
        }
    }

    /// <summary>Records the elevation <paramref name="signed"/> approves, for the approved duration. Never outlives the lease.</summary>
    public (DateTimeOffset? ExpiresAt, Refusal? Refusal) Elevate(SignedApproval? signed)
    {
        lock (gate)
        {
            var now = time.GetUtcNow();
            if (CurrentLease(now) is not { } current)
                return (null, new(503, "no-lease"));
            var (approval, denied) = Approved(signed, Approval.ElevateOp, current, now, new(AuditKind.Deny, current.Id, leaseDevice, Method: "ELEVATE"));
            if (approval is null)
                return (null, denied);
            var (serviceSlug, grantName, duration) = (approval.Service, approval.Grant ?? "", TimeSpan.FromSeconds(approval.Seconds));
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
            if (Open(secret, dek, vault) is not { } value)
                return !PolicyBinding.Allows(vault, secret) ? Deny(403, "policy-not-approved") : Deny(500, "secret-unreadable");

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
            if (Open(secret, dek, vault) is not { } value)
                return !PolicyBinding.Allows(vault, secret) ? Deny(403, "policy-not-approved") : Deny(500, "secret-unreadable");

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

    /// <summary>
    /// The approval <paramref name="signed"/> carries, when the user gave it for this lease and this
    /// operation: it verifies under the lease's approval key, is fresh, and wasn't used before.
    /// Otherwise a 401, audited. Call under <see cref="gate"/>.
    /// </summary>
    (Approval? Approval, Refusal? Refusal) Approved(SignedApproval? signed, string op, Lease current, DateTimeOffset now, AuditRecord record)
    {
        if (signed is not { Approval: not null, Signature: not null })
            return (null, Refuse(record, 401, "approval-required"));
        if (approvalKey is null || signed.Verify(approvalKey) is not { } approval
            || approval.Op != op || approval.LeaseId != current.Id)
            return (null, Refuse(record, 401, "approval-invalid"));
        record = record with { Service = approval.Service, Consumer = approval.Consumer };
        var age = now - DateTimeOffset.FromUnixTimeSeconds(approval.IssuedAt);
        if (age > RequestSignature.MaxAge || age < -RequestSignature.MaxSkewAhead)
            return (null, Refuse(record, 401, "approval-stale"));
        foreach (var stale in usedNonces.Where(n => n.Value <= now).Select(n => n.Key).ToArray())
            usedNonces.Remove(stale);
        if (!usedNonces.TryAdd(approval.Nonce, now + RequestSignature.MaxAge + RequestSignature.MaxSkewAhead))
            return (null, Refuse(record, 401, "approval-replayed"));
        return (approval, null);
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
        approvalKey = null;
        usedNonces.Clear();
        highWater.Clear();
        placeholders.RevokeLease(id);
        audit.Append(new(AuditKind.LeaseEnd, id, leaseDevice, Reason: reason));
        lease = null;
        leaseDevice = null;
        if (LeaseEnded is { } handlers)
            ThreadPool.QueueUserWorkItem(_ => handlers(id));
    }

    /// <summary>Opens a vault secret as used from <paramref name="policy"/>: a bound secret opens only under the policy approved for it.</summary>
    static byte[]? Open(SealedSecret secret, byte[] dek, VaultDocument policy) =>
        PolicyBinding.Allows(policy, secret) ? SecretEnvelope.Open(secret, dek) : null;

    static bool SameCiphertext(SealedSecret a, SealedSecret b) =>
        a.Version == b.Version && a.Nonce.AsSpan().SequenceEqual(b.Nonce) && a.Ciphertext.AsSpan().SequenceEqual(b.Ciphertext);

    /// <summary>
    /// Whether a leased DEK is worth keeping: it opens its secret, and the secret isn't bound to a
    /// policy other than <paramref name="policy"/>. An unbound secret's DEK is kept, so the secret
    /// serves as soon as migration binds it (same DEK); using it is refused until then.
    /// </summary>
    static bool Opens(SealedSecret secret, byte[] dek, VaultDocument policy)
    {
        if (secret.PolicyHash is not null && !PolicyBinding.Allows(policy, secret))
            return false;
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
