using System.ComponentModel;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Tiresias.AdminTier;
using Tiresias.Protocol;
using Tiresias.UserSecrets;

namespace Tiresias.Agent;

public static class AdminProgramBlocks
{
    // Only a confirmed absence permits ordinary operation. A stopped or older service still owns its blocks.
    public static async Task<ReleasePolicy> CheckAsync(string? program, CancellationToken ct)
    {
        try
        {
            var path = Path.IsPathFullyQualified(program ?? "") ? program : null;
            return await AdminBlockCheck.ReadAsync(AdminClient.ServiceInstalled(), path,
                hash => AdminClient.SendAsync(AdminOps.BlocksCheck, new JsonObject { ["program"] = path, ["sha256"] = hash }, ct: ct), Hash);
        }
        catch (Exception e) when (e is Win32Exception or UnauthorizedAccessException or IOException or JsonException or System.Security.SecurityException)
        {
        }
        return new(default, ReleasePolicy.Unavailable);
    }

    static string? Hash(string path)
    {
        try
        {
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return Convert.ToHexString(SHA256.HashData(file));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return null;
        }
    }

    /// <returns>The installed tier's list, or null when there is no tier.</returns>
    public static async Task<IReadOnlyList<AdminBlockedProgram>?> ListAsync()
    {
        var installed = AdminClient.ServiceInstalled();
        if (installed == false)
            return null;
        if (installed == true)
        {
            try
            {
                var programs = await AdminBlocks.ReadAllAsync(async after =>
                {
                    var reply = await AdminClient.SendAsync(AdminOps.BlocksList, new JsonObject { ["after"] = after }).ConfigureAwait(false);
                    return reply?.ResultAs<AdminBlocks>();
                }).ConfigureAwait(false);
                if (programs is not null)
                    return programs;
            }
            catch (Exception e) when (e is Win32Exception or UnauthorizedAccessException or JsonException or System.Security.SecurityException)
            {
                throw new IOException(ReleasePolicy.Unavailable, e);
            }
        }
        throw new IOException(ReleasePolicy.Unavailable);
    }

    public static AdminSetupResult Unblock(string program)
    {
        var reply = AdminClient.SendAsync(AdminOps.BlocksUnblock, new JsonObject { ["program"] = program }).GetAwaiter().GetResult();
        return reply?.Status == AdminStatus.Ok ? AdminSetupResult.Done : AdminSetupResult.Failed;
    }
}
