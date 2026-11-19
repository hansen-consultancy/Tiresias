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
        $"in the Tiresias app: Add..., Set up a SQL Server for {Server}{(Database is null ? "" : $" ({Database})")}; then replace the connection string with the tiresias:sql reference it shows";
}

/// <summary>Seal the certificate as a RavenDB service the broker presents, then delete the file.</summary>
public sealed record SetUpRaven(string CertificatePath) : DoctorFix
{
    public override string Instruction =>
        $"in the Tiresias app: Add..., Set up a RavenDB with {CertificatePath}; then delete the file and point the app at tiresias:raven";
}

/// <summary>The kinds of vault service the app has a setup window for.</summary>
public enum ServiceKind
{
    /// <summary>An HTTP API: the Services window's add form.</summary>
    Http,

    /// <summary>A SQL Server whose logins the broker issues per lease.</summary>
    SqlServer,

    /// <summary>A RavenDB the broker presents a client certificate to.</summary>
    RavenDb,
}

/// <summary>Add a vault service of a known kind; <paramref name="Upstream"/> fills in an HTTP service's address.</summary>
public sealed record AddService(ServiceKind Kind, string? Upstream = null) : DoctorFix
{
    public override string Instruction => Kind switch
    {
        ServiceKind.SqlServer => "in the Tiresias app: Add..., Set up a SQL Server",
        ServiceKind.RavenDb => "in the Tiresias app: Add..., Set up a RavenDB",
        _ => $"tir service add <slug> --upstream {Upstream ?? "<https-url>"}",
    };
}

/// <summary>Seal an environment variable, to hand to programs as its value or as a placeholder.</summary>
public sealed record SealVariable : DoctorFix
{
    public override string Instruction => "tir env set <NAME>, or Environment variables in the Tiresias app";
}

/// <summary>Seal a project's user secrets: the app's secrets editor, or <c>tir secrets</c> in the project's folder.</summary>
public sealed record SealUserSecrets : DoctorFix
{
    public override string Instruction => "tir secrets set <key> in the project's folder, or Secrets in the Tiresias app";
}

/// <summary>
/// Steps to follow outside Tiresias, for an option that needs no secret (E1): Tiresias holds
/// nothing, so there is nothing to set up. <paramref name="Topic"/> is the row of
/// <see cref="Page"/> that says how.
/// </summary>
public sealed record FollowGuide(string Topic) : DoctorFix
{
    /// <summary>The guide, relative to the repository: <i>Need no secret at all</i>.</summary>
    public const string Page = "docs/avoid-secrets.md";

    public override string Instruction => $"no secret to keep: see \"{Topic}\" in {Page}";
}
