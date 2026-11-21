namespace Tiresias.EnvironmentVariables;

/// <summary>The authenticated environment used for a consent decision. Delivery checks the same
/// file before minting and again before releasing anything to the requester.</summary>
public sealed class EnvironmentSnapshot
{
    readonly Action ensureCurrent;

    internal EnvironmentSnapshot(SealedEnvironment environment, Action ensureCurrent)
    {
        Environment = environment;
        this.ensureCurrent = ensureCurrent;
    }

    public SealedEnvironment Environment { get; }

    public void EnsureCurrent() => ensureCurrent();

    public (IReadOnlyList<SealedVariable> Variables, IReadOnlyList<string> Missing, IReadOnlyList<string> Terms) SelectForCommand(
        string? directory, IReadOnlyList<string>? names, Uri endpoint)
    {
        var scoped = directory is null ? null : Environment.ResolveWithFolders(directory);
        var (variables, missing) = SealedVariables.Pick(scoped is null ? Environment.Global : [.. scoped.Select(v => v.Variable)], names);
        var folders = scoped?.ToDictionary(v => v.Variable.Name, v => v.Folder, StringComparer.OrdinalIgnoreCase);
        return (variables, missing, [.. variables.Select(v => EnvironmentVariableAccess.For(Environment, v.Name, folders?[v.Name], endpoint).Describe())]);
    }

    public async Task<Delivery> DeliverAsync(IEnumerable<SealedVariable> variables, Uri forwarder,
        Func<EnvironmentPlaceholder, CancellationToken, Task<MintedPlaceholder>> mint, Func<IEnumerable<string>, Task> revoke, CancellationToken ct,
        Func<bool>? sessionIsCurrent = null)
    {
        CheckRelease();
        var tokens = new List<string>();
        try
        {
            var delivery = await EnvironmentDelivery.DeliverAsync(Environment, variables, forwarder, MintAsync, ct);
            CheckRelease();
            return delivery;
        }
        catch
        {
            if (tokens.Count > 0)
                await revoke(tokens);
            throw;
        }

        void CheckRelease()
        {
            EnsureCurrent();
            if (sessionIsCurrent?.Invoke() == false)
                throw EnvironmentIntegrityException.SessionChanged();
        }

        async Task<MintedPlaceholder> MintAsync(EnvironmentPlaceholder placeholder, CancellationToken cancellation)
        {
            var result = await mint(placeholder, cancellation);
            if (result.Token is { } token)
                tokens.Add(token);
            return result;
        }
    }
}
