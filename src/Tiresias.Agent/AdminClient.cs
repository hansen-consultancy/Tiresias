using System.ComponentModel;
using System.IO.Pipes;
using System.Reflection;
using System.Security.Principal;
using Tiresias.AdminTier;
using Tiresias.Protocol;

namespace Tiresias.Agent;

/// <summary>
/// The app's and tir's end of the admin pipe. A reply counts only when the pipe's server is the
/// process the Service Control Manager runs as <c>TiresiasAdmin</c>: a program that took the pipe's
/// name first is not the service, and is never told or believed anything.
/// </summary>
public static class AdminClient
{
    static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(2);
    static readonly TimeSpan ReplyTimeout = TimeSpan.FromSeconds(5);

    /// <summary>This build's version, to tell an older service.</summary>
    public static string AppVersion { get; } =
        (typeof(AdminClient).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0").Split('+', 2)[0];

    /// <summary>Whether the service exists, from the Service Control Manager alone: no pipe, no wait.</summary>
    public static bool Installed => ServiceInstalled() == true;

    /// <summary>Null when the Service Control Manager cannot confirm the service's presence or absence.</summary>
    public static bool? ServiceInstalled()
    {
        if (DemoMode.On)
            return false;
        try
        {
            return AdminService.Query().Exists;
        }
        catch (Exception e) when (e is Win32Exception or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return null;
        }
    }

    /// <summary>The admin tier as it is now, read without a prompt. Never throws: a tier that can't be read reads as not answering.</summary>
    public static async Task<AdminTierFacts> FactsAsync()
    {
        if (DemoMode.On)
            return new(false, false, null, AppVersion);
        AdminService.State service;
        try
        {
            service = AdminService.Query();
        }
        catch (Win32Exception)
        {
            return new(false, false, null, AppVersion);
        }
        if (!service.Exists || !service.Running)
            return new(service.Exists, false, null, AppVersion);
        var reply = await SendAsync(new(AdminWire.ProtocolVersion, AdminOps.Status), service.ProcessId, ReplyTimeout, CancellationToken.None);
        return new(true, true, reply?.ResultAs<AdminStatusResult>(), AppVersion);
    }

    /// <summary>
    /// One request to the running service; <c>null</c> when it isn't installed or running, can't be
    /// reached, or the pipe isn't the service's. <paramref name="reply"/> bounds the wait for the answer.
    /// </summary>
    public static async Task<AdminReply?> SendAsync(string op, System.Text.Json.Nodes.JsonObject? args = null, TimeSpan? reply = null, CancellationToken ct = default)
    {
        AdminService.State service;
        try
        {
            service = AdminService.Query();
        }
        catch (Win32Exception)
        {
            return null;
        }
        return service.Running
            ? await SendAsync(new(AdminWire.ProtocolVersion, op, args), service.ProcessId, reply ?? ReplyTimeout, ct)
            : null;
    }

    static async Task<AdminReply?> SendAsync(AdminRequest request, int serviceProcessId, TimeSpan reply, CancellationToken ct)
    {
        // Identification only: the service may read who is asking, never act as them.
        await using var pipe = new NamedPipeClientStream(".", AdminWire.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(ConnectTimeout + reply);
        try
        {
            await pipe.ConnectAsync(ConnectTimeout, timeout.Token);
            if (!ServicePipeIdentity.Matches(pipe, serviceProcessId))
                return null;
            if (AdminService.Query().ProcessId != serviceProcessId)
                throw new IOException("The admin service restarted while connecting.");
            await AdminWire.WriteAsync(pipe, request, timeout.Token);
            return await AdminWire.ReadAsync<AdminReply>(pipe, timeout.Token);
        }
        catch (Exception e) when (e is IOException or TimeoutException or OperationCanceledException or UnauthorizedAccessException or Win32Exception
            or InvalidDataException or System.Text.Json.JsonException)
        {
            return null;
        }
    }
}
