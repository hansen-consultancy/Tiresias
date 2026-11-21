using System.IO.Pipes;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Tiresias.AdminTier;
using Tiresias.Decoys;
using Tiresias.Protocol;

namespace Tiresias.Admin;

/// <summary>
/// Serves <c>\\.\pipe\tiresias.admin</c>: one request and one reply per connection, each caller
/// named from its process's token and judged by <see cref="AdminCallerPolicy"/> before anything is
/// done, every request appended to the action log. Refuses to start while its state folder isn't
/// one only SYSTEM and Administrators control, or while another process holds the pipe's name.
/// </summary>
sealed class AdminPipeService(ILogger<AdminPipeService> logger) : BackgroundService
{
    /// <summary>A client that connects and then says nothing is dropped after this.</summary>
    static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(10);

    static readonly string Version =
        (typeof(AdminPipeService).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0")
        .Split('+', 2)[0];

    static readonly string StateRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Tiresias");
    static readonly string StateFolder = Path.Combine(StateRoot, "Admin");

    ActionLog? log;
    DecoyHold? decoys;
    Freezer? freezer;

    protected override async Task ExecuteAsync(CancellationToken stop)
    {
        foreach (var folder in new[] { StateRoot, StateFolder })
            if (!Trusted(folder))
                throw new InvalidOperationException($"{folder} is missing, a link, or not owned by SYSTEM or Administrators; run the install step again.");
        log = new ActionLog(Path.Combine(StateFolder, "actions.jsonl"));
        freezer = new Freezer(StateFolder, logger);
        await using var hold = decoys = new DecoyHold(StateFolder, freezer, logger);

        // The next instance is created before a connected one is served, so the name is never free
        // for another process to take.
        var listening = Create(first: true);
        var running = new List<Task>();
        try
        {
            while (!stop.IsCancellationRequested)
            {
                try
                {
                    await listening.WaitForConnectionAsync(stop);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                var connected = listening;
                var connectedUtc = DateTime.UtcNow;
                listening = Create(first: false);
                running.RemoveAll(t => t.IsCompleted);
                running.Add(ServeAsync(connected, connectedUtc, stop));
            }
        }
        finally
        {
            await listening.DisposeAsync();
            await Task.WhenAll(running);
        }
    }

    static bool Trusted(string folder)
    {
        var info = new DirectoryInfo(folder);
        if (!info.Exists)
            return false;
        var owner = info.GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier))?.Value;
        return AdminFolders.Trusted(info.Attributes.HasFlag(FileAttributes.ReparsePoint), owner);
    }

    /// <summary>SYSTEM full control; signed-in users connect, read and write, but never create an instance; nobody over the network.</summary>
    static NamedPipeServerStream Create(bool first)
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));
        var options = PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : PipeOptions.None);
        return NamedPipeServerStreamAcl.Create(AdminWire.PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, options, 0, 0, security);
    }

    async Task ServeAsync(NamedPipeServerStream pipe, DateTime connectedUtc, CancellationToken stop)
    {
        await using (pipe)
        {
            var client = PipeCallerIdentity.Identify(pipe, connectedUtc);
            AdminRequest? request = null;
            try
            {
                using (var read = CancellationTokenSource.CreateLinkedTokenSource(stop))
                {
                    read.CancelAfter(RequestTimeout);
                    request = await AdminWire.ReadAsync<AdminRequest>(pipe, read.Token);
                }
                var reply = await AnswerAsync(request, client, stop);
                Record(request.Op, client, reply.Status, reply.Message);
                await AdminWire.WriteAsync(pipe, reply, stop);
            }
            catch (Exception e) when (e is IOException or InvalidDataException or System.Text.Json.JsonException or OperationCanceledException or EndOfStreamException)
            {
                // A malformed or abandoned request; the exception's text may quote the request, so only its kind is kept.
                Record(request?.Op, client, AdminStatus.Error, $"connection failed ({e.GetType().Name})");
            }
        }
    }

    async Task<AdminReply> AnswerAsync(AdminRequest request, PipeClientInfo client, CancellationToken stop)
    {
        if (client.Caller is not { } caller)
            return AdminReply.Refused($"the caller can't be named: {client.Problem}");
        var decision = AdminCallerPolicy.Decide(request, caller);
        if (!decision.Allowed)
            return AdminReply.Refused(decision.Reason!);
        // Every action is the acting user's: the caller's own, or its session's user for an elevated caller.
        var user = decision.ActingFor!;
        var args = request.Args ?? [];
        switch (request.Op)
        {
            case AdminOps.Status:
                var held = decoys!.Status(user);
                return AdminReply.Ok(new AdminStatusResult(Version, AdminWire.ProtocolVersion, new AdminFeatures(held.Held, held.Listening, held.Auditing, freezer!.Count(user))));
            case AdminOps.DecoysStatus:
                return AdminReply.Ok(decoys!.Status(user));
            case AdminOps.DecoysAdopt:
                var set = AdoptedSet(args["set"]);
                if (set is null)
                    return AdminReply.Refused("argument set is out of range");
                var files = AdminWire.FromNode<string[]>(args["files"]) ?? [];
                return decoys!.Adopt(user, new(set, files)) is { } refused
                    ? AdminReply.Refused(refused)
                    : AdminReply.Ok(decoys.Status(user));
            case AdminOps.DecoysRelease:
                return AdminReply.Ok(new AdminDecoysRelease(user, await decoys!.ReleaseAsync(user)));
            case AdminOps.EventsWait:
                var ack = AdminWire.FromNode<long[]>(args["ack"]) ?? [];
                var wait = TimeSpan.FromSeconds(args["wait"]!.GetValue<int>());
                return AdminReply.Ok(new AdminEvents(await decoys!.WaitAsync(user, ack, wait, stop)));
            case AdminOps.Freeze:
                var (froze, notFrozen) = freezer!.Freeze(user, args["pid"]!.GetValue<int>());
                return froze is not null ? AdminReply.Ok(froze) : AdminReply.Refused(notFrozen!);
            case AdminOps.Thaw:
                var (thawed, notThawed) = freezer!.Thaw(user, args["program"]!.GetValue<string>());
                return thawed is not null ? AdminReply.Ok(thawed) : AdminReply.Refused(notThawed!);
            case AdminOps.Teardown:
                var all = freezer!.ThawAll();
                await decoys!.TearDownAsync();
                return AdminReply.Ok(all);
            default:
                // The policy refuses every op not built yet; reaching here is a bug, not a request to act on.
                return new AdminReply(AdminStatus.Error, Message: "not built");
        }
    }

    /// <summary>The wire's set, read back as <c>decoys.json</c> is, so <see cref="DecoySet.Parse"/> judges it as it judges that file.</summary>
    static DecoySet? AdoptedSet(System.Text.Json.Nodes.JsonNode? node)
    {
        try
        {
            return AdminWire.FromNode<DecoySet>(node) is { } set ? DecoySet.Parse(set.ToJson()) : null;
        }
        catch (System.Text.Json.JsonException)
        {
            return null;
        }
    }

    void Record(string? op, PipeClientInfo client, AdminStatus result, string? reason)
    {
        var line = AdminAction.Of(DateTimeOffset.Now, op, client.Caller, client.Pid, client.Image, result.ToString().ToLowerInvariant(),
            result == AdminStatus.Ok ? null : reason ?? client.Problem).ToLine();
        try
        {
            log!.Append(line);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            logger.LogError("The action log can't be written: {Kind}", e.GetType().Name);
        }
    }
}
