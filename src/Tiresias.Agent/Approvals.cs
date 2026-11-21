using Tiresias.Access;

namespace Tiresias.Agent;

/// <summary>
/// Signs what the user approved with the open lease's approval key, which the broker learnt at
/// unlock, so the broker mints, elevates or issues exactly that and nothing else. The key comes from
/// the Hello wrap: the app's held wrapper costs no prompt, a fresh one in <c>tir</c> costs one.
/// </summary>
public static class Approvals
{
    /// <param name="approval">Builds the approval from the lease id and the current time.</param>
    /// <exception cref="InvalidOperationException">No lease is open.</exception>
    public static SignedApproval Sign(HelloKeyWrapper hello, Func<string, DateTimeOffset, Approval> approval)
    {
        var leaseId = KeyringStore.Lease?.LeaseId ?? throw new InvalidOperationException("No lease is open: unlock first.");
        using var key = hello.ApprovalKey(leaseId);
        return approval(leaseId, DateTimeOffset.UtcNow).Sign(key);
    }

    public static SignedApproval Mint(HelloKeyWrapper hello, AccessRequest request) =>
        Sign(hello, (lease, now) => Approval.ForMint(lease, request, now));
}
