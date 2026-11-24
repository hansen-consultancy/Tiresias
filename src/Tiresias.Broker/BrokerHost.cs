using AsicSharp.Configuration;
using AsicSharp.Services;
using Tiresias.Access;
using Tiresias.Audit;
using Tiresias.Leases;
using Tiresias.Trust;
using Tiresias.Vault;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using NSec.Cryptography;
using Tiresias.Forwarder;

namespace Tiresias.Broker;

/// <summary>
/// The broker's composition: services, middleware and endpoints on a builder the caller made. The
/// broker executable builds one from its command line; solo mode builds one inside the agent, on
/// loopback, with its own configuration.
/// </summary>
public static class BrokerHost
{
    static readonly string[] PlaceholderRoutes = ["/svc", "/sql", "/raven"];

    public static WebApplication Build(WebApplicationBuilder builder)
    {

        builder.Services.Configure<BrokerOptions>(builder.Configuration.GetSection("Broker"));
        builder.Services.TryAddSingleton(TimeProvider.System);
        // One instance: two writers on the same file would each keep their own prevHash and break the chain.
        // A host may register its own first, to subscribe before the startup trust check writes to it.
        builder.Services.TryAddSingleton(sp => new AuditLog(
            sp.GetRequiredService<IOptions<BrokerOptions>>().Value.AuditPath, sp.GetRequiredService<TimeProvider>()));
        builder.Services.AddSingleton(sp =>
        {
            var options = sp.GetRequiredService<IOptions<BrokerOptions>>().Value;
            var time = sp.GetRequiredService<TimeProvider>();
            return new BrokerState(
                VaultFile.Load(options.VaultPath),
                LeaseTerms.Workday(TimeZoneInfo.FindSystemTimeZoneById(options.TimeZone)),
                sp.GetRequiredService<AuditLog>(),
                BrokerIdentity.LoadOrCreate(sp.GetRequiredService<IIdentityKeyStore>(), sp.GetRequiredService<ILogger<BrokerState>>()),
                time,
                options.HighWaterPath is { } marks ? new HighWaterMarks(marks, PublicKey.Import(SignatureAlgorithm.Ed25519,
                    Convert.FromBase64String(options.RevisionPublicKey ?? throw new InvalidOperationException("Enroll the broker service's revision key before opening its vault.")),
                    KeyBlobFormat.RawPublicKey)) : null);
        });
        builder.Services.TryAddSingleton(sp => IdentityKeyStore.ForPlatform(
            sp.GetRequiredService<IOptions<BrokerOptions>>().Value.IdentityKeyPath, sp.GetRequiredService<ILogger<IIdentityKeyStore>>()));
        builder.Services.AddSingleton<DeviceKeys>();
        builder.Services.AddSingleton<ReplayGuard>();
        builder.Services.AddSingleton<SvcProxy>();
        builder.Services.TryAddSingleton<RavenHandlerFactory>(RavenClients.DefaultHandler);
        builder.Services.AddSingleton<RavenClients>();
        builder.Services.AddSingleton<SqlEndpoint>();
        builder.Services.AddSingleton<TokenEndpoint>();
        builder.Services.AddSingleton<ClearanceEndpoint>();
        builder.Services.TryAddSingleton<IGitHubInstallationTokens, GitHubInstallationTokens>();
        builder.Services.TryAddSingleton<ISqlGateway, SqlServerGateway>();
        builder.Services.AddHostedService<LeaseWatch>();
        builder.Services.AddSingleton<IClientProcessLookup>(OperatingSystem.IsWindows() ? new WindowsClientProcessLookup() : new NoClientProcessLookup());
        if (builder.Configuration["Broker:TimestampAuthorityUrl"] is { Length: > 0 } tsaUrl)
        {
            builder.Services.AddHttpClient<ITsaClient, TsaClient>();
            builder.Services.AddSingleton(new AsicTimestampOptions { TimestampAuthorityUrl = tsaUrl });
            builder.Services.AddSingleton<AuditAnchoring>();
            builder.Services.AddHostedService(sp => sp.GetRequiredService<AuditAnchoring>());
        }
        builder.Services.AddHttpClient(SvcProxy.ClientName)
            .ConfigureHttpClient(c => c.Timeout = TimeSpan.FromMinutes(10))
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false });

        var app = builder.Build();

        // Resolved now so a trust chain that fails verification stops the broker at startup, not at the first request.
        app.Services.GetRequiredService<DeviceKeys>();
        var sqlGateway = app.Services.GetRequiredService<ISqlGateway>();
        var ravenClients = app.Services.GetRequiredService<RavenClients>();
        var anchoring = app.Services.GetService<AuditAnchoring>();
        app.Services.GetRequiredService<BrokerState>().LeaseEnded += leaseId =>
        {
            ravenClients.EndLease(leaseId);
            _ = sqlGateway.EndLeaseAsync(leaseId);
            if (anchoring is not null)
                _ = anchoring.AnchorAsync();
        };

        // The Changes API on /raven; nothing else accepts an upgrade.
        app.UseWebSockets();

        if (app.Services.GetRequiredService<IOptions<BrokerOptions>>().Value.IdentifyLoopbackCaller)
            app.UseWhen(c => PlaceholderRoutes.Any(r => c.Request.Path.StartsWithSegments(r, StringComparison.Ordinal)),
                b => b.Use((context, next) =>
                {
                    LoopbackCaller.Stamp(context, context.RequestServices.GetRequiredService<IClientProcessLookup>());
                    return next(context);
                }));

        // Deny by default: everything but the placeholder-authenticated routes needs a device signature.
        app.UseWhen(c => !PlaceholderRoutes.Any(r => c.Request.Path.StartsWithSegments(r, StringComparison.Ordinal)),
            b => b.UseMiddleware<DeviceSignatureMiddleware>());

        app.MapPost("/lease/begin", (HttpContext context, BrokerState state) =>
        {
            var (offer, signature) = state.BeginLease((string)context.Items[DeviceSignatureMiddleware.DeviceItem]!);
            return Results.Ok(new LeaseBeginResponse(offer.LeaseId, Convert.ToBase64String(offer.LeaseKey),
                offer.HardCapAt.ToUnixTimeSeconds(), Convert.ToBase64String(signature)));
        });

        app.MapPost("/lease/seal", (LeaseSealRequest body, BrokerState state) =>
        {
            var (result, refusal) = state.Seal(body.LeaseId, body.Deks, body.ApprovalKey, body.RevisionSignature);
            return refusal is null ? Results.Ok(result) : Refused(refusal);
        });

        app.MapPost("/lease/heartbeat", (LeaseRef body, BrokerState state) =>
            state.Heartbeat(body.LeaseId) is { } refusal ? Refused(refusal) : Results.NoContent());

        app.MapPost("/lease/end", (BrokerState state) =>
        {
            state.End();
            return Results.NoContent();
        });

        app.MapPost("/placeholder", (SignedApproval? body, BrokerState state) =>
        {
            var (minted, refusal) = state.Mint(body);
            return refusal is null ? Results.Ok(minted) : Refused(refusal);
        });

        app.MapPost("/placeholder/revoke", (PlaceholderRef body, BrokerState state) =>
        {
            state.RevokePlaceholder(body.Token);
            return Results.NoContent();
        });

        app.MapPost("/token/{service}", (HttpContext context, string service, SignedApproval? body, TokenEndpoint endpoint) =>
            endpoint.HandleAsync(context, service, body));
        app.MapGet("/clearance/{service}", (HttpContext context, string service, ClearanceEndpoint endpoint) => endpoint.HandleAsync(context, service));

        app.MapPost("/elevate", (SignedApproval? body, BrokerState state) =>
        {
            var (expiresAt, refusal) = state.Elevate(body);
            return refusal is null ? Results.Ok(new { expiresAt }) : Refused(refusal);
        });

        app.MapGet("/trust/chain", (DeviceKeys devices) =>
            devices.Chain is { } chain ? Results.Bytes(chain.Serialized, "application/json") : Results.NotFound());

        app.MapPost("/trust/chain", async (HttpContext context, DeviceKeys devices, BrokerState state) =>
        {
            if (devices.Chain is not { } chain)
                return Results.NotFound();
            using var buffer = new MemoryStream();
            await context.Request.Body.CopyToAsync(buffer, context.RequestAborted);
            if (TrustLinkJson.ParseChain(buffer.ToArray()) is not { } links)
                return Results.BadRequest();
            var (added, failure) = chain.Extend(links, (string)context.Items[DeviceSignatureMiddleware.DeviceItem]!);
            if (added > 0)
                state.EndLeaseOfUntrustedDevice(device => devices.Find(device) is not null);
            return failure is null
                ? Results.Ok(new { added, head = chain.Current.Head })
                : Results.Json(new { reason = failure.Kind.ToString(), failure.Seq, failure.Detail }, statusCode: StatusCodes.Status409Conflict);
        });

        app.Map("/svc/{service}/{**path}", (HttpContext context, string service, SvcProxy proxy) => proxy.HandleAsync(context, service));

        app.Map("/raven/{instance}/{**path}", (HttpContext context, string instance, SvcProxy proxy) => proxy.HandleRavenAsync(context, instance));

        app.MapPost("/sql/{instance}/{grant}", (HttpContext context, string instance, string grant, SqlRequest body, SqlEndpoint endpoint) =>
            endpoint.HandleAsync(context, instance, grant, body));
        app.MapPost("/sql/{instance}/{grant}/login", (HttpContext context, string instance, string grant, SqlEndpoint endpoint) =>
            endpoint.HandleLoginAsync(context, instance, grant));

        return app;
    }

    static IResult Refused(Refusal refusal) =>
        Results.Json(new { refusal.Reason, refusal.ElevationNeeded, refusal.Problems }, statusCode: refusal.Status);
}

sealed record LeaseBeginResponse(string LeaseId, string LeaseKey, long HardCapAt, string Signature);

/// <param name="ApprovalKey">The lease's approval key (raw Ed25519 public key), bound into each DEK's context.</param>
sealed record LeaseSealRequest(string LeaseId, Dictionary<string, byte[]> Deks, byte[]? ApprovalKey, byte[]? RevisionSignature = null);

sealed record LeaseRef(string LeaseId);

sealed record PlaceholderRef(string Token);
