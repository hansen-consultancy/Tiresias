using System.Text.Json;
using Tiresias.Audit;
using Tiresias.Trust;

namespace Tiresias.Broker;

/// <summary>
/// The tenant's trust chain on disk and the head this broker has accepted, kept in
/// <c>{path}.head</c> so a rollback is caught across restarts. Construction verifies the chain
/// against the pinned genesis and that head and throws when it fails: a broker with an untrusted
/// chain does not start. Every link accepted for the first time, and every break-glass use in it,
/// is audited.
/// </summary>
sealed class TrustChainFile
{
    readonly string path;
    readonly string headPath;
    readonly string pinnedGenesisHash;
    readonly AuditLog audit;
    readonly Lock gate = new();
    volatile TrustState current;
    volatile byte[] serialized = [];

    public TrustChainFile(string path, string pinnedGenesisHash, AuditLog audit)
    {
        this.path = path;
        headPath = path + ".head";
        this.pinnedGenesisHash = pinnedGenesisHash;
        this.audit = audit;

        var links = TrustLinkJson.ParseChain(File.ReadAllBytes(path))
            ?? throw new InvalidDataException($"Trust chain '{path}' is not valid JSON.");
        var head = File.Exists(headPath) ? JsonSerializer.Deserialize<ChainHead>(File.ReadAllText(headPath), JsonSerializerOptions.Web) : null;
        var (state, failure) = Check(links, head, "startup");
        if (failure is not null)
            throw new InvalidDataException($"Trust chain '{path}' rejected: {failure.Kind} at seq {failure.Seq}: {failure.Detail}");
        current = Adopt(links, state!, head, "startup");
    }

    public TrustState Current => current;

    /// <summary>The accepted chain as JSON, for devices that verify it themselves before trusting this broker.</summary>
    public byte[] Serialized => serialized;

    /// <summary>Accepts <paramref name="links"/> if it verifies and extends the accepted head; the same chain again adds nothing.</summary>
    /// <param name="device">The device that submitted it, for the audit.</param>
    public (int Added, TrustFailure? Failure) Extend(IReadOnlyList<TrustLink> links, string device)
    {
        lock (gate)
        {
            var head = current.Head;
            var (state, failure) = Check(links, head, device);
            if (failure is not null)
                return (0, failure);

            var temp = path + ".tmp";
            File.WriteAllBytes(temp, TrustLinkJson.WriteChain(links));
            File.Move(temp, path, overwrite: true);
            current = Adopt(links, state!, head, device);
            return ((int)(state!.Head.Seq - head.Seq), null);
        }
    }

    (TrustState? State, TrustFailure? Failure) Check(IReadOnlyList<TrustLink> links, ChainHead? head, string by)
    {
        var result = TrustChainVerifier.Verify(links, pinnedGenesisHash, head);
        if (result.Failure is { } f)
            audit.Append(new(AuditKind.TrustRejected, Consumer: by, Reason: $"{f.Kind} at seq {f.Seq}: {f.Detail}"));
        return (result.State, result.Failure);
    }

    TrustState Adopt(IReadOnlyList<TrustLink> links, TrustState state, ChainHead? previous, string by)
    {
        serialized = TrustLinkJson.WriteChain(links);
        var from = previous?.Seq ?? -1;
        var temp = headPath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(state.Head, JsonSerializerOptions.Web));
        File.Move(temp, headPath, overwrite: true);

        for (var seq = from + 1; seq <= state.Head.Seq; seq++)
            audit.Append(new(AuditKind.TrustLink, Consumer: by, Reason: $"seq {seq} {TrustLinkJson.Kind(links[(int)seq].Body)}"));
        foreach (var use in state.BreakGlassUses.Where(u => u.Seq > from))
            audit.Append(new(AuditKind.BreakGlass, Consumer: by, Reason: $"paper key '{use.DeviceId}' of '{use.User}' signed seq {use.Seq}"));
        return state;
    }
}
