using System.Data.Common;
using System.Text.Json;
using System.Text.Json.Nodes;
using Tiresias.Protocol;

namespace Tiresias.Client;

public static partial class Doctor
{
    static readonly Position LoginPerLease = new(Exposure.ShortLived, Control.Approved);
    static readonly Position Brokered = new(Exposure.BrokerOnly, Control.Approved);

    /// <summary>
    /// Findings in configuration: connection strings carrying a password, and private keys in
    /// files, found on disk or named by configuration. A value is read only to see whether it holds
    /// a password; lines name the key, the server and the file, never the password.
    /// </summary>
    /// <remarks>Of user secrets only the plaintext parts are read: sealed values need an unlock, which the doctor never asks for.</remarks>
    static IEnumerable<DoctorCheck> ConfigChecks(IEnumerable<DoctorFile> userSecrets, IEnumerable<DoctorFile> configFiles, IEnumerable<string> keyFiles)
    {
        var sources = userSecrets.Select(file => (Where: $"user secrets {UserSecretsIdOf(file.Path)}", Folder: (string?)null, Json: PlaintextSecrets(file.Text)))
            .Concat(configFiles.Select(file => (Where: file.Path, Folder: Path.GetDirectoryName(file.Path), Json: TryParse(file.Text))))
            .Where(source => source.Json is not null)
            .ToArray();

        var references = new List<CertificateReference>();
        foreach (var (where, folder, json) in sources)
        {
            foreach (var (key, value) in Leaves(json))
            {
                if (ConnectionString(where, key, value) is { } finding)
                    yield return finding;
                else if (CertificateReference.From(where, folder, key, value) is { } reference)
                    references.Add(reference);
            }
        }

        foreach (var path in keyFiles)
        {
            // References are resolved to full paths; a probe may hand over relative ones.
            var full = Path.GetFullPath(path);
            var named = references.Where(r => string.Equals(r.Path, full, StringComparison.OrdinalIgnoreCase)).ToArray();
            references.RemoveAll(named.Contains);
            var raven = named.Any(r => r.Raven) || Path.GetFileName(path).Contains("raven", StringComparison.OrdinalIgnoreCase);
            var namedBy = named.Length == 0 ? "" : $" ({string.Join(", ", named.Select(r => $"{r.Key} in {r.Where}"))} points at it)";
            yield return KeyFile($"certificate {path}", $"holds a private key in a file any program running as you can read{namedBy}", path, raven);
        }

        foreach (var reference in references)
            yield return KeyFile($"certificate {reference.Path}", $"{reference.Key} in {reference.Where} names a certificate file, whose private key any program running as you can read", reference.Path, reference.Raven);
    }

    static DoctorCheck KeyFile(string name, string detail, string path, bool raven) => raven
        ? new(name, DoctorStatus.Warn, $"{detail}. Let the broker present it instead, so the program never holds the key", new SetUpRaven(path), Position.Plaintext, Brokered)
        : new(name, DoctorStatus.Warn, $"{detail}. If it is a RavenDB client certificate, set up a RavenDB with it; otherwise import it into the Windows certificate store as non-exportable and delete the file", Now: Position.Plaintext);

    /// <summary>Server-like keys, in the order their value names the host best.</summary>
    static readonly string[] ServerKeys = ["server", "data source", "address", "addr", "network address", "host"];

    /// <summary>Keywords no other common provider (Npgsql, MySQL, SQLite, Oracle) accepts.</summary>
    static readonly string[] SqlServerOnlyKeys = ["multipleactiveresultsets", "multiple active result sets", "trusted_connection", "applicationintent", "application intent", "multisubnetfailover", "multi subnet failover"];

    /// <summary>
    /// Keywords SQL Server uses that some other provider also takes: MySQL's <c>User Id</c> and
    /// <c>Initial Catalog</c>, Npgsql's <c>Trust Server Certificate</c>, SQLite's <c>Encrypt</c>. Each
    /// inner array is one signal however it is spelled; two signals together are taken as SQL Server.
    /// </summary>
    static readonly string[][] SqlServerHints = [["user id"], ["initial catalog"], ["encrypt"], ["trustservercertificate", "trust server certificate"]];

    /// <summary>Keywords that mark another provider; any of them means the string isn't SQL Server's.</summary>
    static readonly string[] OtherProviderKeys = ["port", "username", "host", "sslmode", "ssl mode", "search path", "searchpath", "charset", "characterset", "character set", "allowuservariables", "allow user variables", "convertzerodatetime", "convert zero datetime", "allowpublickeyretrieval", "treattinyasboolean"];

    enum SqlServerMatch { No, Maybe, Yes }

    static DoctorCheck? ConnectionString(string where, string key, string value)
    {
        if (!value.Contains("password=", StringComparison.OrdinalIgnoreCase) && !value.Contains("pwd=", StringComparison.OrdinalIgnoreCase))
            return null;
        var builder = new DbConnectionStringBuilder();
        try
        {
            builder.ConnectionString = value;
        }
        catch (ArgumentException)
        {
            return null;
        }
        if (Get(builder, "password", "pwd") is null)
            return null;

        var server = Get(builder, ServerKeys);
        var database = Get(builder, "database", "initial catalog");
        var target = server is null ? "" : $" for {server}{(database is null ? "" : $"/{database}")}";
        var name = $"connection string {key} in {where}";
        const string plaintext = "in plain text, which any program running as you can read.";
        return (server is null ? SqlServerMatch.No : IsSqlServer(builder, server)) switch
        {
            SqlServerMatch.Yes => new(name, DoctorStatus.Warn, $"holds a password{target} {plaintext} Tiresias can issue a SQL login per lease instead, dropped when the lease ends",
                new SetUpSqlServer(server!, database), Position.Plaintext, LoginPerLease),
            SqlServerMatch.Maybe => new(name, DoctorStatus.Warn, $"holds a password{target} {plaintext} If this is SQL Server, Tiresias can issue a SQL login per lease instead; otherwise keep the connection string in sealed user secrets",
                new SetUpSqlServer(server!, database), Position.Plaintext, LoginPerLease),
            _ => new(name, DoctorStatus.Warn, $"holds a password{target} in plain text, which any program running as you can read. Tiresias issues logins for SQL Server only; for this one, keep the connection string in sealed user secrets",
                Now: Position.Plaintext, Better: Position.SealedApproved),
        };
    }

    static SqlServerMatch IsSqlServer(DbConnectionStringBuilder builder, string server)
    {
        // Oracle's Data Source is an EZConnect path or a TNS descriptor; SQLite's is a file.
        var notAHost = server.Contains('/', StringComparison.Ordinal) || server.Contains("DESCRIPTION", StringComparison.OrdinalIgnoreCase)
            || server.EndsWith(".db", StringComparison.OrdinalIgnoreCase) || server.EndsWith(".sqlite", StringComparison.OrdinalIgnoreCase);
        if (notAHost || OtherProviderKeys.Any(builder.ContainsKey))
            return SqlServerMatch.No;
        if (SqlServerOnlyKeys.Any(builder.ContainsKey))
            return SqlServerMatch.Yes;
        return SqlServerHints.Count(spellings => spellings.Any(builder.ContainsKey)) switch
        {
            0 => SqlServerMatch.No,
            1 => SqlServerMatch.Maybe,
            _ => SqlServerMatch.Yes,
        };
    }

    static string? Get(DbConnectionStringBuilder builder, params string[] keys) =>
        keys.Select(k => builder.TryGetValue(k, out var v) ? v?.ToString() : null).FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));

    /// <summary>A configuration key naming a certificate file; RavenDB's client reads one this way.</summary>
    sealed record CertificateReference(string Where, string Key, string Path, bool Raven)
    {
        static readonly string[] Extensions = [".pfx", ".p12", ".pem"];

        public static CertificateReference? From(string where, string? folder, string key, string value)
        {
            var last = key[(key.LastIndexOf(':', StringComparison.Ordinal) + 1)..];
            if (!last.Contains("certificate", StringComparison.OrdinalIgnoreCase) || !Extensions.Any(e => value.EndsWith(e, StringComparison.OrdinalIgnoreCase)))
                return null;
            // A relative path is relative to the app's folder; for appsettings that is the file's own.
            var path = System.IO.Path.IsPathRooted(value) ? System.IO.Path.GetFullPath(value)
                : folder is null ? value
                : System.IO.Path.GetFullPath(System.IO.Path.Combine(folder, value));
            return new(where, key, path, key.Contains("raven", StringComparison.OrdinalIgnoreCase));
        }
    }

    static string UserSecretsIdOf(string path)
    {
        // The folder name is the UserSecretsId. Split on both separators: the probe may hand over either.
        var parts = path.Split(['/', '\\'], StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 2 ? parts[^2] : path;
    }

    /// <summary>The plaintext part of a user-secrets file: all of a plain one, the additions beside a sealed one.</summary>
    static JsonNode? PlaintextSecrets(string? text)
    {
        switch (SecretsFile.Classify(text))
        {
            case SecretsFileKind.Plain:
                return TryParse(text);
            case SecretsFileKind.Sealed:
                try
                {
                    return SecretsFile.Read(text!).PlainAdditions;
                }
                catch (Exception e) when (e is InvalidDataException or FormatException or JsonException or InvalidOperationException)
                {
                    return null;
                }
            default:
                return null;
        }
    }

    static JsonNode? TryParse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;
        try
        {
            return Parse(text);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Every string value with its configuration key (<c>ConnectionStrings:Default</c>, arrays by index).</summary>
    static IEnumerable<(string Key, string Value)> Leaves(JsonNode? node, string? prefix = null)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var (name, child) in obj)
                    foreach (var leaf in Leaves(child, prefix is null ? name : $"{prefix}:{name}"))
                        yield return leaf;
                break;
            case JsonArray array:
                for (var i = 0; i < array.Count; i++)
                    foreach (var leaf in Leaves(array[i], prefix is null ? $"{i}" : $"{prefix}:{i}"))
                        yield return leaf;
                break;
            case JsonValue value when prefix is not null && value.TryGetValue<string>(out var text):
                yield return (prefix, text);
                break;
        }
    }
}
