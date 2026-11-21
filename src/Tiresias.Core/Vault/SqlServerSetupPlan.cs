using System.Text;
using System.Text.RegularExpressions;
using Tiresias.Policy;

namespace Tiresias.Vault;

/// <summary>What someone typed into the app's "Set up a SQL Server" form.</summary>
/// <param name="Server">As SQL Server tools take it: <c>host</c>, <c>host,port</c> or <c>host\instance</c>.</param>
public sealed record SqlServerSetupInput(string Slug, string Server, string Database);

public enum SqlServerSetupField { Slug, Server, Database }

public sealed record SqlServerSetupProblem(SqlServerSetupField Field, string Message);

/// <param name="Service">The service to save, or <c>null</c> when there are <see cref="Problems"/>.</param>
/// <param name="Replaces">The vault already has this service for the same database: setting up again renews its secrets.</param>
public sealed record SqlServerSetupPlan(Service? Service, IReadOnlyList<SqlServerSetupProblem> Problems, bool Replaces)
{
    /// <summary>The provisioner connection string, shared by both grants.</summary>
    public string ProvisionerSecret => $"{Service?.Slug}-provisioner";

    /// <summary>The signing certificate's password, needed again only to set the same server up again.</summary>
    public string SigningSecret => $"{Service?.Slug}-signing";

    public string Server { get; init; } = "";

    public string Database { get; init; } = "";
}

/// <summary>
/// The decision behind the app's SQL Server setup: validation and the service it saves, a
/// <c>mssql://</c> upstream with a <c>read</c> and a <c>write</c> grant that both hand out
/// temporary logins. Running <c>01-tiresias-setup.sql</c> and sealing the secrets is the caller's.
/// </summary>
public static class SqlServerSetupPlanner
{
    /// <summary>A database name the setup script can bracket and quote: no <c>]</c>, <c>'</c> or control characters.</summary>
    static readonly Regex DatabasePattern = new(@"^[^\]'\[\p{C}]{1,128}$", RegexOptions.CultureInvariant);

    static readonly Regex HostPattern = new(@"^[A-Za-z0-9]([A-Za-z0-9.-]{0,252})$", RegexOptions.CultureInvariant);

    public static SqlServerSetupPlan Plan(SqlServerSetupInput input, VaultDocument vault)
    {
        var problems = new List<SqlServerSetupProblem>();
        var slug = input.Slug.Trim();
        var server = input.Server.Trim();
        var database = input.Database.Trim();

        var host = HostOf(server);
        if (server.Length == 0)
            problems.Add(new(SqlServerSetupField.Server, "Type the server's name, e.g. sql.example.com, sql.example.com,1433 or sql.example.com\\SQLEXPRESS."));
        else if (host is null)
            problems.Add(new(SqlServerSetupField.Server, $"'{server}' isn't a server name SQL Server tools take: host, host,port or host\\instance."));

        if (database.Length == 0)
            problems.Add(new(SqlServerSetupField.Database, "Type the database the apps use. It must exist already."));
        else if (!DatabasePattern.IsMatch(database) || database.Equals("master", StringComparison.OrdinalIgnoreCase)
            || database is "tempdb" or "model" or "msdb")
            problems.Add(new(SqlServerSetupField.Database, $"'{database}' can't be set up: use an application database, without ] or ' in its name."));

        var replaces = false;
        if (!ServicePlanner.IsSlug(slug))
            problems.Add(new(SqlServerSetupField.Slug, $"'{slug}' can't be a service name: use lower-case letters, digits and dashes, e.g. appdb."));
        else if (vault.FindService(slug) is { } existing)
        {
            replaces = host is not null && existing.Upstream.Scheme == "mssql"
                && string.Equals(existing.Upstream.Host, host, StringComparison.OrdinalIgnoreCase)
                && string.Equals(Uri.UnescapeDataString(existing.Upstream.AbsolutePath.Trim('/')), database, StringComparison.OrdinalIgnoreCase);
            if (!replaces)
                problems.Add(new(SqlServerSetupField.Slug, $"A service named {slug} exists already for {existing.Upstream}. Pick another name."));
        }

        if (problems.Count > 0)
            return new(null, problems, false);

        var secret = $"{slug}-provisioner";
        var none = new RequestRule(new HashSet<string>(), []);
        var service = new Service(slug, new Uri($"mssql://{host}/{Uri.EscapeDataString(database)}"),
        [
            new Grant("read", secret, none, IssuesLogins: true),
            new Grant("write", secret, none, IssuesLogins: true),
        ]);
        return new(service, problems, replaces) { Server = server, Database = database };
    }

    /// <returns>The host part of <c>host</c>, <c>host,port</c> or <c>host\instance</c>, or <c>null</c> when it isn't one.</returns>
    static string? HostOf(string server)
    {
        var host = server;
        var comma = host.IndexOf(',', StringComparison.Ordinal);
        if (comma >= 0)
        {
            if (!ushort.TryParse(host[(comma + 1)..], out var port) || port == 0)
                return null;
            host = host[..comma];
        }
        var slash = host.IndexOf('\\', StringComparison.Ordinal);
        if (slash >= 0)
        {
            var instance = host[(slash + 1)..];
            if (instance.Length is 0 or > 16 || !instance.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '$'))
                return null;
            host = host[..slash];
        }
        if (host is "." or "(local)")
            host = "localhost";
        return HostPattern.IsMatch(host) ? host.ToLowerInvariant() : null;
    }

    /// <summary>
    /// A <c>sqlcmd</c> script as the batches to send, the way <c>sqlcmd</c> would: split on lines that
    /// are only <c>GO</c>, <c>$(Name)</c> replaced, <c>:on error exit</c> dropped (each batch stops the
    /// run when it fails anyway).
    /// </summary>
    /// <exception cref="InvalidDataException">A variable the script uses has no value, or another <c>:</c> command.</exception>
    public static IReadOnlyList<string> Batches(string script, IReadOnlyDictionary<string, string> variables)
    {
        var batches = new List<string>();
        var batch = new StringBuilder();
        foreach (var raw in script.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
        {
            var line = raw.TrimEnd();
            if (line.Trim().Equals("GO", StringComparison.OrdinalIgnoreCase))
            {
                Flush();
                continue;
            }
            if (line.StartsWith(':', StringComparison.Ordinal))
            {
                if (line.Equals(":on error exit", StringComparison.OrdinalIgnoreCase))
                    continue;
                throw new InvalidDataException($"The script uses {line}, which the setup can't run.");
            }
            batch.AppendLine(Regex.Replace(line, @"\$\((\w+)\)", m =>
                variables.TryGetValue(m.Groups[1].Value, out var value)
                    ? value
                    : throw new InvalidDataException($"The script needs $({m.Groups[1].Value}).")));
        }
        Flush();
        return batches;

        void Flush()
        {
            if (batch.ToString().Trim().Length > 0)
                batches.Add(batch.ToString());
            batch.Clear();
        }
    }
}
