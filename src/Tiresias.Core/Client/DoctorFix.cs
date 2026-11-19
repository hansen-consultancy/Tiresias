namespace Tiresias.Client;

/// <summary>
/// What raises a finding: the flow that does it and what to fill that flow in with. A UI opens
/// the matching window filled in; <c>tir doctor</c> prints <see cref="Instruction"/>.
/// </summary>
public abstract record DoctorFix
{
    /// <summary>The command to run, or where in the app to go, for someone reading <c>tir doctor</c>.</summary>
    public abstract string Instruction { get; }
}

/// <summary>Open the project's user secrets in the app's secrets editor, to seal or repair them.</summary>
public sealed record ReviewUserSecrets(string UserSecretsId) : DoctorFix
{
    public override string Instruction => $"open {UserSecretsId} in the Tiresias app's secrets editor";
}

/// <summary>Seal these user environment variables out of Windows.</summary>
public sealed record ProtectVariables(IReadOnlyList<string> Names) : DoctorFix
{
    public override string Instruction => $"tir env protect {string.Join(' ', Names)}";

    public bool Equals(ProtectVariables? other) => other is not null && Names.SequenceEqual(other.Names);

    public override int GetHashCode() => Names.Aggregate(0, (hash, name) => HashCode.Combine(hash, name));
}

/// <summary>Reference the configuration provider that seals the project's user secrets.</summary>
public sealed record ReferenceConfigurationPackage(string Project) : DoctorFix
{
    public const string Package = "Tiresias.Extensions.Configuration";

    public override string Instruction => $"dotnet add \"{Project}\" package {Package}";
}

/// <summary>Let Tiresias issue a SQL login per lease for this server, replacing the stored password.</summary>
public sealed record SetUpSqlServer(string Server, string? Database) : DoctorFix
{
    public override string Instruction =>
        $"in the Tiresias app: Services, Set up a SQL Server for {Server}{(Database is null ? "" : $" ({Database})")}; then replace the connection string with the tiresias:sql reference it shows";
}

/// <summary>Seal the certificate as a RavenDB service the broker presents, then delete the file.</summary>
public sealed record SetUpRaven(string CertificatePath) : DoctorFix
{
    public override string Instruction =>
        $"in the Tiresias app: Services, Set up a RavenDB with {CertificatePath}; then delete the file and point the app at tiresias:raven";
}
