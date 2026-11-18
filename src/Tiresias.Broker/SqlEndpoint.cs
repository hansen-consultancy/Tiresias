using System.Data;
using System.Text.Json;
using System.Text.RegularExpressions;
using Tiresias.Transport;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;

namespace Tiresias.Broker;

/// <summary>Which database, as whom, and until when: everything a gateway needs to get a temporary login for a lease.</summary>
/// <param name="ProvisionerConnectionString">The grant's secret: connects as <c>tiresias_provisioner</c>, which may only run <c>tir.BeginLease</c>/<c>tir.EndLease</c>.</param>
public sealed record SqlLeaseTarget(string LeaseId, string Instance, string Grant, string ProvisionerConnectionString, DateTimeOffset ExpiresAt);

/// <param name="ReadOnly">Run inside a transaction that is always rolled back.</param>
public sealed record SqlQuery(string Sql, IReadOnlyDictionary<string, object?> Parameters, bool ReadOnly, int MaxRows, TimeSpan Timeout);

/// <param name="Truncated">More rows existed than <see cref="SqlQuery.MaxRows"/>.</param>
/// <param name="RecordsAffected">As SQL Server reports it; -1 for a SELECT.</param>
public sealed record SqlResult(IReadOnlyList<IReadOnlyDictionary<string, object?>> Rows, bool Truncated, int RecordsAffected);

/// <summary>A temporary login as an application's connection string, valid until <paramref name="ExpiresAt"/>.</summary>
public sealed record SqlLogin(string ConnectionString, DateTimeOffset ExpiresAt);

/// <summary>An error SQL Server raised for the caller's own statement (syntax, permission, timeout), safe to hand back.</summary>
public sealed class SqlStatementException(int number, string message) : Exception(message)
{
    public int Number { get; } = number;
}

/// <summary>
/// Runs statements as a lease's temporary login (<c>tir_&lt;lease&gt;_&lt;grant&gt;</c>), creating it on
/// first use through the provisioner and dropping it at lease end. The temporary password lives only
/// in this process's memory, for the lease; it is never logged, returned or written.
/// </summary>
public interface ISqlGateway
{
    /// <exception cref="SqlStatementException">SQL Server refused the statement.</exception>
    Task<SqlResult> QueryAsync(SqlLeaseTarget target, SqlQuery query, CancellationToken ct);

    /// <summary>
    /// The lease's temporary login as a connection string an application can use (pooled, unlike the
    /// broker's own), created on first use. The same login the broker runs statements as.
    /// </summary>
    Task<SqlLogin> LoginAsync(SqlLeaseTarget target, CancellationToken ct);

    /// <summary>Drops the lease's temporary logins and forgets their passwords. Never throws; the SQL Agent job is the backstop.</summary>
    Task EndLeaseAsync(string leaseId);
}

/// <summary><c>POST /sql/{instance}/{grant}</c> with <c>{ sql, parameters }</c> → <c>{ rows, truncated, recordsAffected }</c>.</summary>
sealed partial class SqlEndpoint(BrokerState state, ISqlGateway gateway, IOptions<BrokerOptions> options)
{
    public async Task<IResult> HandleAsync(HttpContext context, string instance, string grant, SqlRequest body)
    {
        if (string.IsNullOrWhiteSpace(body.Sql))
            return Results.Json(new { reason = "no-sql" }, statusCode: StatusCodes.Status400BadRequest);
        var parameters = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, value) in body.Parameters ?? [])
        {
            if (!ParameterName().IsMatch(name) || !TryScalar(value, out var scalar))
                return Results.Json(new { reason = "invalid-parameter", parameter = name }, statusCode: StatusCodes.Status400BadRequest);
            parameters[name] = scalar;
        }

        var observed = context.Request.Headers[ForwarderHeaders.ObservedProcess].FirstOrDefault();
        var (allowed, refusal) = state.AuthorizeSql(context.Request.Headers.Authorization, instance, grant, body.Sql,
            string.IsNullOrEmpty(observed) ? null : observed);
        if (refusal is not null)
            return Results.Json(new { refusal.Reason, refusal.ElevationNeeded, refusal.Problems }, statusCode: refusal.Status);

        using (allowed)
        {
            var target = new SqlLeaseTarget(allowed!.LeaseId, instance, grant, allowed.TakeSecret(), allowed.LeaseExpiresAt);
            var settings = options.Value;
            try
            {
                var result = await gateway.QueryAsync(target,
                    new(body.Sql, parameters, grant == SqlGrants.Read, settings.SqlMaxRows, TimeSpan.FromSeconds(settings.SqlTimeoutSeconds)),
                    context.RequestAborted);
                allowed.Complete(StatusCodes.Status200OK);
                return Results.Ok(new { rows = result.Rows, truncated = result.Truncated, recordsAffected = result.RecordsAffected });
            }
            catch (SqlStatementException e)
            {
                allowed.Complete(StatusCodes.Status422UnprocessableEntity, $"sql-error {e.Number}");
                return Results.Json(new { reason = "sql-error", number = e.Number, message = e.Message }, statusCode: StatusCodes.Status422UnprocessableEntity);
            }
        }
    }

    /// <summary><c>POST /sql/{instance}/{grant}/login</c> → <c>{ connectionString, expiresAt }</c>, for a grant that issues logins.</summary>
    public async Task<IResult> HandleLoginAsync(HttpContext context, string instance, string grant)
    {
        var observed = context.Request.Headers[ForwarderHeaders.ObservedProcess].FirstOrDefault();
        var (allowed, refusal) = state.AuthorizeSqlLogin(context.Request.Headers.Authorization, instance, grant,
            string.IsNullOrEmpty(observed) ? null : observed);
        if (refusal is not null)
            return Results.Json(new { refusal.Reason, refusal.ElevationNeeded, refusal.Problems }, statusCode: refusal.Status);

        using (allowed)
        {
            try
            {
                var login = await gateway.LoginAsync(new SqlLeaseTarget(allowed!.LeaseId, instance, grant, allowed.TakeSecret(), allowed.LeaseExpiresAt),
                    context.RequestAborted);
                allowed.Complete(StatusCodes.Status200OK);
                return Results.Ok(new { connectionString = login.ConnectionString, expiresAt = login.ExpiresAt.ToUnixTimeSeconds() });
            }
            catch (SqlStatementException e)
            {
                allowed!.Complete(StatusCodes.Status502BadGateway, $"sql-error {e.Number}");
                return Results.Json(new { reason = "sql-error", number = e.Number, message = e.Message }, statusCode: StatusCodes.Status502BadGateway);
            }
        }
    }

    /// <returns><c>false</c> for a value with no single SQL scalar meaning (an object or array).</returns>
    static bool TryScalar(JsonElement value, out object? scalar)
    {
        scalar = value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Number => value.TryGetInt64(out var l) ? l : value.GetDecimal(),
            _ => null,
        };
        return value.ValueKind is not (JsonValueKind.Object or JsonValueKind.Array);
    }

    [GeneratedRegex("^[A-Za-z_][A-Za-z0-9_]{0,127}$")]
    private static partial Regex ParameterName();
}

sealed record SqlRequest(string Sql, Dictionary<string, JsonElement>? Parameters);

/// <summary>
/// The real gateway, over Microsoft.Data.SqlClient. Pooling is off for the temporary logins, so a
/// dropped login leaves no pooled connection behind and every statement is a fresh session the
/// logon trigger sees.
/// </summary>
sealed class SqlServerGateway(ILogger<SqlServerGateway> logger) : ISqlGateway, IDisposable
{
    readonly SemaphoreSlim gate = new(1, 1);
    readonly Dictionary<(string LeaseId, string Instance, string Grant), (string Provisioner, string Temporary, DateTimeOffset ExpiresAt)> logins = [];

    public async Task<SqlResult> QueryAsync(SqlLeaseTarget target, SqlQuery query, CancellationToken ct)
    {
        try
        {
            var (connectionString, _) = await TemporaryLoginAsync(target, ct);
            await using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync(ct);
            await using var transaction = query.ReadOnly ? connection.BeginTransaction(IsolationLevel.ReadCommitted) : null;
            await using var command = new SqlCommand(query.Sql, connection, transaction) { CommandTimeout = (int)query.Timeout.TotalSeconds };
            foreach (var (name, value) in query.Parameters)
                command.Parameters.AddWithValue("@" + name, value ?? DBNull.Value);

            var rows = new List<IReadOnlyDictionary<string, object?>>();
            var truncated = false;
            int affected;
            await using (var reader = await command.ExecuteReaderAsync(ct))
            {
                while (await reader.ReadAsync(ct))
                {
                    if (rows.Count == query.MaxRows)
                    {
                        truncated = true;
                        break;
                    }
                    var row = new Dictionary<string, object?>(reader.FieldCount);
                    for (var i = 0; i < reader.FieldCount; i++)
                        row[reader.GetName(i) is { Length: > 0 } column ? column : $"column{i}"] = Json(reader.GetValue(i));
                    rows.Add(row);
                }
                if (truncated)
                    command.Cancel();
                affected = reader.RecordsAffected;
            }
            if (transaction is not null)
                await transaction.RollbackAsync(ct);
            return new(rows, truncated, affected);
        }
        catch (SqlException e)
        {
            throw new SqlStatementException(e.Number, e.Message);
        }
    }

    public async Task<SqlLogin> LoginAsync(SqlLeaseTarget target, CancellationToken ct)
    {
        try
        {
            var (connectionString, expiresAt) = await TemporaryLoginAsync(target, ct);
            // The broker's statements need a fresh session each; an application wants its pool.
            var forApp = new SqlConnectionStringBuilder(connectionString);
            forApp.Remove("Pooling");
            forApp.Remove("Application Name");
            return new(forApp.ConnectionString, expiresAt);
        }
        catch (SqlException e)
        {
            throw new SqlStatementException(e.Number, e.Message);
        }
    }

    public async Task EndLeaseAsync(string leaseId)
    {
        List<string> provisioners;
        await gate.WaitAsync();
        try
        {
            var ended = logins.Where(l => l.Key.LeaseId == leaseId).ToArray();
            foreach (var (key, _) in ended)
                logins.Remove(key);
            provisioners = ended.Select(l => l.Value.Provisioner).Distinct().ToList();
        }
        finally
        {
            gate.Release();
        }

        foreach (var provisioner in provisioners)
        {
            try
            {
                await using var connection = new SqlConnection(AsBroker(provisioner));
                await connection.OpenAsync();
                await using var command = new SqlCommand("tir.EndLease", connection) { CommandType = CommandType.StoredProcedure };
                command.Parameters.Add("@LeaseId", SqlDbType.VarChar, 32).Value = leaseId;
                await command.ExecuteNonQueryAsync();
            }
            catch (Exception e)
            {
                logger.LogWarning("tir.EndLease failed for lease {LeaseId} ({Error}); the cleanup job will drop its logins", leaseId, e.Message);
            }
        }
    }

    public void Dispose() => gate.Dispose();

    /// <summary>What the server's audit (APP_NAME(), DDL trigger logs, sessions) shows for the broker's own connections.</summary>
    const string ApplicationName = "Tiresias broker";

    // The sealed provisioner secret may name another application (or none); the broker's statements say who ran them.
    static string AsBroker(string connectionString) =>
        new SqlConnectionStringBuilder(connectionString) { ApplicationName = ApplicationName }.ConnectionString;

    async Task<(string ConnectionString, DateTimeOffset ExpiresAt)> TemporaryLoginAsync(SqlLeaseTarget target, CancellationToken ct)
    {
        await gate.WaitAsync(ct);
        try
        {
            var key = (target.LeaseId, target.Instance, target.Grant);
            if (logins.TryGetValue(key, out var known))
                return (known.Temporary, known.ExpiresAt);

            await using var connection = new SqlConnection(AsBroker(target.ProvisionerConnectionString));
            await connection.OpenAsync(ct);
            await using var command = new SqlCommand("tir.BeginLease", connection) { CommandType = CommandType.StoredProcedure };
            command.Parameters.Add("@LeaseId", SqlDbType.VarChar, 32).Value = target.LeaseId;
            command.Parameters.Add("@Grant", SqlDbType.VarChar, 16).Value = target.Grant;
            // The procedure refuses more than 10 hours; the workday cap is under that, the clamp is for clock skew.
            var expires = target.ExpiresAt.UtcDateTime < DateTime.UtcNow.AddHours(10) ? target.ExpiresAt.UtcDateTime : DateTime.UtcNow.AddHours(10).AddMinutes(-1);
            command.Parameters.Add("@ExpiresAt", SqlDbType.DateTime2).Value = expires;
            var login = command.Parameters.Add("@Login", SqlDbType.NVarChar, 128);
            login.Direction = ParameterDirection.Output;
            var password = command.Parameters.Add("@Password", SqlDbType.NVarChar, 128);
            password.Direction = ParameterDirection.Output;
            await command.ExecuteNonQueryAsync(ct);

            var temporary = new SqlConnectionStringBuilder(target.ProvisionerConnectionString)
            {
                UserID = (string)login.Value,
                Password = (string)password.Value,
                IntegratedSecurity = false,
                Pooling = false,
                ApplicationName = ApplicationName,
            }.ConnectionString;
            var expiresAt = new DateTimeOffset(expires, TimeSpan.Zero);
            logins[key] = (target.ProvisionerConnectionString, temporary, expiresAt);
            return (temporary, expiresAt);
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>A column value as something System.Text.Json writes faithfully; anything exotic (UDTs, sql_variant oddities) as text.</summary>
    static object? Json(object value) => value switch
    {
        DBNull => null,
        string or bool or byte or short or int or long or float or double or decimal or Guid
            or DateTime or DateTimeOffset or TimeSpan or byte[] => value,
        _ => value.ToString(),
    };
}
