using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.SqlClient;
using Tiresias.Policy;
using Tiresias.Vault;

namespace Tiresias.Agent;

/// <summary>How the one-off administrator connection signs in. Nothing about it is kept.</summary>
/// <param name="User"><c>null</c> for Windows authentication as the signed-in user.</param>
public sealed record SqlAdminSignIn(string? User = null, string? Password = null);

/// <param name="ProvisionerExists">The server has a <c>tiresias_provisioner</c> already: setting up gives it a new password.</param>
/// <param name="CertificateExists">The database is set up already; its signing password must be in this vault to set it up again.</param>
public sealed record SqlServerState(string Version, bool ProvisionerExists, bool CertificateExists, bool HasAgent);

/// <param name="Warnings">What didn't work but doesn't stop the service working, e.g. no cleanup job.</param>
public sealed record SqlServerSetupResult(Service Service, IReadOnlyList<string> Warnings);

/// <summary>
/// Sets a SQL Server database up for per-lease logins from the app: runs
/// <c>01-tiresias-setup.sql</c> (and the cleanup job, where SQL Server Agent runs) over one
/// administrator connection, checks the provisioner can sign in, then seals its connection string
/// in the vault and saves the service. The administrator's password is used for that connection
/// only. The logon trigger (<c>03</c>) is never applied: it would refuse the very logins this hands
/// to applications on other PCs.
/// </summary>
public static class SqlServerSetup
{
    const string Provisioner = "tiresias_provisioner";

    /// <summary>Connects as the administrator and reports what is there, so the app can ask before changing it.</summary>
    /// <exception cref="InvalidOperationException">Can't connect, not a sysadmin, or no such database; the message says which.</exception>
    public static async Task<SqlServerState> InspectAsync(SqlServerSetupPlan plan, SqlAdminSignIn admin, bool trustServerCertificate, CancellationToken ct)
    {
        await using var connection = await OpenAdminAsync(plan, admin, trustServerCertificate, ct);
        if (await ScalarAsync<int?>(connection, "SELECT IS_SRVROLEMEMBER(N'sysadmin');", ct) != 1)
            throw new InvalidOperationException($"{Describe(admin)} isn't a sysadmin on {plan.Server}; the setup creates logins and a server certificate, which needs one.");
        if (await ScalarAsync<int?>(connection, "SELECT DB_ID(@db);", ct, ("@db", plan.Database)) is null)
            throw new InvalidOperationException($"{plan.Server} has no database {plan.Database}. Create it first; the setup doesn't.");
        return new(
            await ScalarAsync<string>(connection, "SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(32)) + N' ' + CAST(SERVERPROPERTY('Edition') AS nvarchar(64));", ct) ?? "",
            await ScalarAsync<int?>(connection, $"SELECT SUSER_ID(N'{Provisioner}');", ct) is not null,
            await ScalarAsync<int>(connection, $"SELECT COUNT(*) FROM {Bracket(plan.Database)}.sys.certificates WHERE name = N'tiresias_signing';", ct) > 0,
            await ScalarAsync<int>(connection, "SELECT COUNT(*) FROM sys.dm_server_services WHERE servicename LIKE N'SQL Server Agent%' AND status = 4;", ct) > 0);
    }

    /// <summary>Runs the setup and saves the service. Call <see cref="InspectAsync"/> first and ask about what it found.</summary>
    /// <param name="hello">The agent's open Windows Hello wrapper: the vault is sealed to it.</param>
    /// <exception cref="InvalidOperationException">A step failed; the message names it. Nothing is saved to the vault unless every required step worked.</exception>
    public static async Task<SqlServerSetupResult> RunAsync(SqlServerSetupPlan plan, SqlAdminSignIn admin, bool trustServerCertificate,
        HelloKeyWrapper hello, IProgress<string> progress, CancellationToken ct)
    {
        var service = plan.Service ?? throw new InvalidOperationException("The plan has problems.");
        var warnings = new List<string>();
        var state = await InspectAsync(plan, admin, trustServerCertificate, ct);
        var signing = state.CertificateExists
            ? ReadSecret(plan.SigningSecret, hello) ?? throw new InvalidOperationException(
                $"{plan.Database} was set up for Tiresias from another vault, which holds its signing certificate's password. Set it up from there, "
                + "or have an administrator drop the tiresias_signing certificates and tiresias_signer (see 01-tiresias-setup.sql), then run this again.")
            : NewPassword();
        var password = NewPassword();
        IReadOnlyList<string> ddlTriggers = [];

        await using (var connection = await OpenAdminAsync(plan, admin, trustServerCertificate, ct))
        {
            if (state.ProvisionerExists)
            {
                progress.Report($"Giving {Provisioner} a new password");
                await ExecuteAsync(connection, $"ALTER LOGIN {Provisioner} WITH PASSWORD = N'{password}';", ct);
            }
            var variables = new Dictionary<string, string>
            {
                ["Database"] = plan.Database,
                ["ProvisionerPassword"] = password,
                ["SigningCertPassword"] = signing,
            };
            progress.Report($"Creating the tir schema, roles and signed procedures in {plan.Database}");
            await RunScriptAsync(connection, "01-tiresias-setup.sql", variables, ct);

            if (state.HasAgent)
            {
                progress.Report("Scheduling the cleanup job");
                try
                {
                    await RunScriptAsync(connection, "02-tiresias-cleanup-job.sql", variables, ct);
                }
                catch (SqlException e)
                {
                    warnings.Add($"The cleanup job couldn't be scheduled ({e.Message}). Leases still drop their logins when they end; the job only catches a broker that stopped mid-lease.");
                }
            }
            else
                warnings.Add("SQL Server Agent isn't running, so there is no cleanup job. Leases still drop their logins when they end; see 02-tiresias-cleanup-job.sql to schedule tir.DropExpired another way.");

            ddlTriggers = await NamesAsync(connection, $"SELECT name FROM {Bracket(plan.Database)}.sys.triggers WHERE parent_class = 0 AND is_disabled = 0 ORDER BY name;", ct);
        }

        var provisioner = ConnectionString(plan, new(Provisioner, password), trustServerCertificate);
        progress.Report($"Checking {Provisioner} can start a lease");
        await using (var check = new SqlConnection(provisioner))
        {
            try
            {
                await check.OpenAsync(ct);
            }
            catch (SqlException e)
            {
                throw new InvalidOperationException($"{Provisioner} can't sign in to {plan.Server} ({e.Message}). Is SQL Server authentication on? (Server properties, Security, SQL Server and Windows Authentication mode, then restart the service.)", e);
            }
            // A real lease, created and ended at once: a permission check alone misses what the
            // database runs around CREATE USER, such as an auditing DDL trigger.
            var trial = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
            try
            {
                await using (var begin = new SqlCommand("tir.BeginLease", check) { CommandType = System.Data.CommandType.StoredProcedure })
                {
                    begin.Parameters.AddWithValue("@LeaseId", trial);
                    begin.Parameters.AddWithValue("@Grant", "read");
                    begin.Parameters.AddWithValue("@ExpiresAt", DateTime.UtcNow.AddMinutes(5));
                    begin.Parameters.Add("@Login", System.Data.SqlDbType.NVarChar, 128).Direction = System.Data.ParameterDirection.Output;
                    begin.Parameters.Add("@Password", System.Data.SqlDbType.NVarChar, 128).Direction = System.Data.ParameterDirection.Output;
                    await begin.ExecuteNonQueryAsync(ct);
                }
                await using var end = new SqlCommand("tir.EndLease", check) { CommandType = System.Data.CommandType.StoredProcedure };
                end.Parameters.AddWithValue("@LeaseId", trial);
                await end.ExecuteNonQueryAsync(ct);
            }
            catch (SqlException e)
            {
                throw new InvalidOperationException($"{Provisioner} can't start a lease in {plan.Database}: {e.Message}{TriggerHint(e, ddlTriggers)}", e);
            }
        }

        progress.Report("Sealing the connection in the vault");
        Seal(plan.SigningSecret, signing, hello);
        Seal(plan.ProvisionerSecret, provisioner, hello);
        VaultEditor.SetService(service);
        return new(service, warnings);
    }

    static async Task<SqlConnection> OpenAdminAsync(SqlServerSetupPlan plan, SqlAdminSignIn admin, bool trustServerCertificate, CancellationToken ct)
    {
        var connection = new SqlConnection(ConnectionString(plan, admin, trustServerCertificate, database: "master"));
        try
        {
            await connection.OpenAsync(ct);
            return connection;
        }
        catch (SqlException e)
        {
            await connection.DisposeAsync();
            var hint = e.Message.Contains("certificate", StringComparison.OrdinalIgnoreCase)
                ? " The server's certificate isn't trusted by this PC; tick \"Trust the server's certificate\" for a server you know, such as one on your own network."
                : "";
            throw new InvalidOperationException($"Couldn't connect to {plan.Server} as {Describe(admin)}: {e.Message}{hint}", e);
        }
    }

    static string ConnectionString(SqlServerSetupPlan plan, SqlAdminSignIn signIn, bool trustServerCertificate, string? database = null)
    {
        var builder = new SqlConnectionStringBuilder
        {
            DataSource = plan.Server,
            InitialCatalog = database ?? plan.Database,
            Encrypt = SqlConnectionEncryptOption.Mandatory,
            TrustServerCertificate = trustServerCertificate,
            ConnectTimeout = 15,
            // Shows in the server's audit (APP_NAME(), DDL trigger logs) as what made the changes.
            ApplicationName = "Tiresias setup",
        };
        if (signIn.User is null)
            builder.IntegratedSecurity = true;
        else
        {
            builder.UserID = signIn.User;
            builder.Password = signIn.Password ?? "";
        }
        return builder.ConnectionString;
    }

    static string Describe(SqlAdminSignIn admin) => admin.User ?? $@"{Environment.UserDomainName}\{Environment.UserName}";

    static async Task RunScriptAsync(SqlConnection connection, string name, IReadOnlyDictionary<string, string> variables, CancellationToken ct)
    {
        foreach (var batch in SqlServerSetupPlanner.Batches(Script(name), variables))
        {
            try
            {
                await ExecuteAsync(connection, batch, ct);
            }
            catch (SqlException e) when (name.StartsWith("01", StringComparison.Ordinal))
            {
                throw new InvalidOperationException($"{name} failed: {e.Message}", e);
            }
        }
    }

    static string Script(string name)
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream($"sql/{name}")
            ?? throw new InvalidOperationException($"{name} isn't in this build.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    static async Task ExecuteAsync(SqlConnection connection, string sql, CancellationToken ct)
    {
        await using var command = new SqlCommand(sql, connection) { CommandTimeout = 120 };
        await command.ExecuteNonQueryAsync(ct);
    }

    static async Task<T?> ScalarAsync<T>(SqlConnection connection, string sql, CancellationToken ct, params (string Name, object Value)[] parameters)
    {
        await using var command = new SqlCommand(sql, connection);
        foreach (var (name, parameter) in parameters)
            command.Parameters.AddWithValue(name, parameter);
        var value = await command.ExecuteScalarAsync(ct);
        // SQL Server picks the width (DB_ID is smallint, COUNT int), so convert rather than unbox.
        return value is null or DBNull ? default
            : (T)Convert.ChangeType(value, Nullable.GetUnderlyingType(typeof(T)) ?? typeof(T), System.Globalization.CultureInfo.InvariantCulture);
    }

    static async Task<IReadOnlyList<string>> NamesAsync(SqlConnection connection, string sql, CancellationToken ct)
    {
        await using var command = new SqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync(ct);
        var names = new List<string>();
        while (await reader.ReadAsync(ct))
            names.Add(reader.GetString(0));
        return names;
    }

    /// <summary>
    /// A database DDL trigger runs as whoever ran the DDL, and a procedure's signature doesn't reach
    /// into it, so a trigger that writes an audit table refuses the provisioner (error 229 on that
    /// table). Name the triggers and the grant that fixes it; granting it is the administrator's call.
    /// </summary>
    static string TriggerHint(SqlException e, IReadOnlyList<string> ddlTriggers)
    {
        if (e.Number != 229 || ddlTriggers.Count == 0)
            return "";
        var table = System.Text.RegularExpressions.Regex.Match(e.Message, @"object '([^']+)', database '[^']+', schema '([^']+)'");
        var grant = table.Success ? $" To let it, run in the database: GRANT INSERT ON [{table.Groups[2].Value}].[{table.Groups[1].Value}] TO {Provisioner}; then set up again." : "";
        return $" The database runs {string.Join(", ", ddlTriggers)} on every CREATE USER, as the user who runs it, so {Provisioner} must be allowed what the trigger does.{grant}";
    }

    static string Bracket(string name) => $"[{name.Replace("]", "]]")}]";

    /// <summary>
    /// 32 characters from letters and digits, with at least one of each kind, which every password
    /// policy accepts and which needs no quoting in SQL or a connection string.
    /// </summary>
    internal static string NewPassword()
    {
        const string lower = "abcdefghijkmnopqrstuvwxyz", upper = "ABCDEFGHJKLMNPQRSTUVWXYZ", digits = "23456789";
        const string all = lower + upper + digits;
        while (true)
        {
            var password = RandomNumberGenerator.GetString(all, 32);
            if (password.Any(lower.Contains) && password.Any(upper.Contains) && password.Any(digits.Contains))
                return password;
        }
    }

    internal static string? ReadSecret(string slug, HelloKeyWrapper hello)
    {
        if (VaultEditor.Load().FindSecret(slug) is not { } secret || SecretEnvelope.UnwrapDek(secret, hello) is not { } dek)
            return null;
        try
        {
            return SecretEnvelope.Open(secret, dek) is { } value ? Encoding.UTF8.GetString(value) : null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    static void Seal(string slug, string value, HelloKeyWrapper hello)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        try
        {
            VaultEditor.SealSecret(slug, bytes, hello);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
