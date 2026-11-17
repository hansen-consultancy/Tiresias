using System.Collections.Concurrent;
using Tiresias.Audit;
using Tiresias.Transport;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;
using NSec.Cryptography;

namespace Tiresias.Broker;

/// <summary>
/// Gate in front of every management endpoint: the request must carry a fresh
/// <see cref="RequestSignature"/> from a configured device, and that exact signature must not have
/// been seen before. Ed25519 is deterministic, so a replay within the timestamp window carries the
/// same signature and is caught here.
/// </summary>
sealed class DeviceSignatureMiddleware(RequestDelegate next, DeviceKeys devices, ReplayGuard replay, TimeProvider time)
{
    public const string DeviceItem = "tir.device";

    const int MaxBodyBytes = 1 << 20;

    public async Task InvokeAsync(HttpContext context)
    {
        var request = context.Request;
        if (request.ContentLength > MaxBodyBytes)
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            return;
        }

        var deviceId = request.Headers[RequestSignature.DeviceHeader].ToString();
        var key = devices.Find(deviceId);
        var signature = TryBase64(request.Headers[RequestSignature.SignatureHeader].ToString());
        if (key is null || signature is null || !long.TryParse(request.Headers[RequestSignature.TimestampHeader], out var timestamp))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        using var buffer = new MemoryStream();
        await request.Body.CopyToAsync(buffer, context.RequestAborted);
        if (buffer.Length > MaxBodyBytes)
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            return;
        }

        var now = time.GetUtcNow();
        if (!RequestSignature.Verify(key, request.Method, RawTarget(context), timestamp, buffer.ToArray(), signature, now)
            || !replay.TryUse(signature, now + RequestSignature.MaxAge + RequestSignature.MaxSkewAhead, now))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        context.Items[DeviceItem] = deviceId;
        buffer.Position = 0;
        request.Body = buffer;
        await next(context);
    }

    /// <summary>The request target exactly as sent (path and query, still percent-encoded).</summary>
    public static string RawTarget(HttpContext context)
    {
        var raw = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
        return string.IsNullOrEmpty(raw)
            ? context.Request.PathBase + context.Request.Path + context.Request.QueryString
            : raw;
    }

    static byte[]? TryBase64(string value)
    {
        var bytes = new byte[value.Length];
        return Convert.TryFromBase64String(value, bytes, out var written) ? bytes[..written] : null;
    }
}

/// <summary>
/// The keys allowed to sign management requests: the verified trust chain's active device keys when
/// a chain is configured (paper keys excluded: they sign links, not requests), otherwise the static
/// <see cref="BrokerOptions.Devices"/>. Never both.
/// </summary>
sealed class DeviceKeys
{
    readonly Dictionary<string, PublicKey> configured = [];

    public DeviceKeys(IOptions<BrokerOptions> options, AuditLog audit)
    {
        var o = options.Value;
        if (o.TrustChainPath is { } path)
        {
            Chain = new TrustChainFile(path,
                o.PinnedGenesisHash ?? throw new InvalidOperationException("Broker:PinnedGenesisHash is required with Broker:TrustChainPath."), audit);
            return;
        }
        configured = o.Devices.ToDictionary(
            d => d.Key,
            d => PublicKey.Import(SignatureAlgorithm.Ed25519, Convert.FromBase64String(d.Value), KeyBlobFormat.RawPublicKey));
    }

    public TrustChainFile? Chain { get; }

    public PublicKey? Find(string deviceId) =>
        Chain is null ? configured.GetValueOrDefault(deviceId)
        : Chain.Current.Devices.GetValueOrDefault(deviceId) is { Paper: false } device ? device.Key
        : null;
}

/// <summary>Remembers each accepted signature until it could no longer pass the timestamp check anyway.</summary>
sealed class ReplayGuard
{
    readonly ConcurrentDictionary<string, DateTimeOffset> seen = new();

    /// <returns><c>false</c> when this signature was already used.</returns>
    public bool TryUse(byte[] signature, DateTimeOffset forgetAfter, DateTimeOffset now)
    {
        foreach (var stale in seen.Where(s => s.Value <= now).Select(s => s.Key).ToArray())
            seen.TryRemove(stale, out _);
        return seen.TryAdd(Convert.ToBase64String(signature), forgetAfter);
    }
}
