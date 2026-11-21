namespace Tiresias.UserSecrets;

/// <summary>The block history relevant to a request. A new block requires fresh consent even after it is cleared.</summary>
public readonly record struct ProgramRevision(long Service, long Local = 0);

public readonly record struct ReleaseScope(ProgramRevision Program, ProgramRevision Peer = default, string? PeerImage = null)
{
    public ReleaseScope(long generation) : this(new ProgramRevision(generation)) { }
}

public readonly record struct ReleasePolicy(ReleaseScope Scope, string? Refusal = null)
{
    public const string Changed = "The program's block status changed during this request. Request access again.";
    public const string Unavailable = "The admin tier could not verify this program's block status.";

    public string? RefusalSince(ReleasePolicy before) => Refusal ?? (Scope != before.Scope ? Changed : null);

    public ReleasePolicy WithPeer(string? image, ReleasePolicy peer) =>
        new(new(Scope.Program, peer.Scope.Program, image?.ToUpperInvariant()), Refusal ?? peer.Refusal);
}
