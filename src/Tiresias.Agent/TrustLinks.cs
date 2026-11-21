using System.Net;
using NSec.Cryptography;
using Tiresias.Client;
using Tiresias.Trust;

namespace Tiresias.Agent;

/// <summary>Trust-chain links this device builds and hands to its broker (docs/trust-links.md).</summary>
public static class TrustLinks
{
    /// <summary>
    /// Names this device's Windows Hello key in the tenant's trust chain, for a device enrolled
    /// before links needed one. Signed by the device key, the Hello key (one prompt) and the paper
    /// key whose raw bytes are <paramref name="recoveryKey"/>; the broker verifies and keeps it.
    /// </summary>
    /// <exception cref="InvalidOperationException">No chain, already bound, the broker refused, or the key isn't this user's paper key.</exception>
    public static async Task BindHelloAsync(byte[] recoveryKey)
    {
        if (KeyringStore.Tenant is not { GenesisHash: { } genesis } || KeyringStore.Broker is not { } broker)
            throw new InvalidOperationException("This device isn't enrolled with a trust chain.");
        var deviceId = KeyringStore.Settings.DeviceId;
        using var client = BrokerClient.For(broker);
        var (status, body) = await client.GetAsync("/trust/chain");
        if (status != HttpStatusCode.OK)
            throw new InvalidOperationException($"The broker served no trust chain ({(int)status}). In solo mode, start the Tiresias app first.");
        var chain = TrustLinkJson.ParseChain(body);
        var trust = BrokerTrust.Evaluate(chain, genesis, KeyringStore.ChainHead, Convert.FromBase64String(broker.IdentityKey), deviceId);
        if (!trust.Trusted)
            throw new InvalidOperationException(trust.Error);
        var state = TrustChainVerifier.Verify(chain!, genesis).State!;
        var device = state.Devices[deviceId];
        if (device.Hello is not null)
            throw new InvalidOperationException("This device's Windows Hello key is already in the trust chain.");

        using var paperKey = PaperKey.SigningKey(recoveryKey);
        var paperPublic = paperKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var paper = state.DevicesOf(device.User).FirstOrDefault(d => d.Paper && d.Key.Export(KeyBlobFormat.RawPublicKey).AsSpan().SequenceEqual(paperPublic))
            ?? throw new InvalidOperationException("That recovery key is not a paper key of this device's user in the trust chain.");

        using var deviceKey = KeyringStore.LoadOrCreateDeviceKey();
        var hello = HelloKeyWrapper.LinkKey(create: false);
        var link = TrustChain.Append(chain!, new BindHello(deviceId, hello.PublicKey), DateTimeOffset.UtcNow,
            new Signer(deviceId, deviceKey, hello), new Signer(paper.Id, paperKey));
        var posted = await client.PostBytesAsync("/trust/chain", TrustLinkJson.WriteChain([.. chain!, link]));
        if (!posted.Ok)
            throw new InvalidOperationException($"The broker refused the link: {posted.Describe()}");
    }
}
