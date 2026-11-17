using System.Security.Cryptography;
using Tiresias.Trust;

namespace Tiresias.Client;

/// <param name="Head">The head to remember for next time, when the chain is trusted.</param>
public sealed record BrokerTrustResult(ChainHead? Head, string? Error)
{
    public bool Trusted => Error is null;
}

/// <summary>
/// The Keyring's check of a tenant's trust chain, as its broker serves it, before sealing anything
/// to that broker: the chain replays from the genesis pinned at enrolment, does not roll back or
/// fork from the head this Keyring last accepted, still trusts this device, and, once the chain
/// names brokers, names the identity this Keyring pinned. A broker that fails any of these gets no
/// DEKs.
/// </summary>
public static class BrokerTrust
{
    public static BrokerTrustResult Evaluate(IReadOnlyList<TrustLink>? chain, string pinnedGenesisHash, ChainHead? acceptedHead, byte[] pinnedBrokerKey, string deviceId)
    {
        if (chain is null)
            return new(null, "The broker's trust chain is not valid JSON.");

        var (state, failure) = TrustChainVerifier.Verify(chain, pinnedGenesisHash, acceptedHead);
        if (failure is not null)
            return new(null, failure.Kind switch
            {
                TrustFailureKind.Rollback => $"The broker served an older trust chain than this Keyring accepted (seq {acceptedHead!.Seq}): a rollback.",
                TrustFailureKind.Fork => $"The broker's trust chain differs at seq {failure.Seq} from what this Keyring accepted: a fork.",
                TrustFailureKind.GenesisMismatch => "The broker's trust chain does not start at the genesis pinned at enrolment.",
                _ => $"The broker's trust chain fails verification: {failure.Kind} at seq {failure.Seq}: {failure.Detail}",
            });

        if (state!.Brokers.Count > 0 && !state.Brokers.Values.Any(k => CryptographicOperations.FixedTimeEquals(k, pinnedBrokerKey)))
            return new(null, "The trust chain does not list the broker identity this Keyring pinned.");
        if (!state.Devices.TryGetValue(deviceId, out var device) || device.Paper)
            return new(null, $"The trust chain no longer trusts this device ('{deviceId}').");
        return new(state.Head, null);
    }
}
