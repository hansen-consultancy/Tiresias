using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Tiresias.EnvironmentVariables;
using Tiresias.Protocol;

namespace Tiresias.Agent;

/// <summary>
/// Where <c>tir-remote</c> in a devcontainer asks for sealed variables: <c>127.0.0.1:7782</c>, which
/// Docker Desktop relays <c>host.docker.internal</c> to (docs/devcontainers.md). Started with the
/// first ticket, never before. Every connection comes from Docker Desktop's backend, so only the
/// ticket says who asks: a request without a live one is refused before its body is read, and no
/// refusal or log line carries the ticket.
/// </summary>
public sealed class DevcontainerEndpoint(DevcontainerTickets tickets,
    Func<string, DevcontainerTicket, DevcontainerRequest, CancellationToken, Task<DevcontainerReply>> ask,
    Action<string> refused) : IAsyncDisposable
{
    public static readonly Uri Url = new($"http://127.0.0.1:{DevcontainerWire.Port}");

    WebApplication? app;
    readonly SemaphoreSlim starting = new(1, 1);

    /// <summary>Starts listening, once. Throws <see cref="IOException"/> when the port is taken.</summary>
    public async Task EnsureStartedAsync()
    {
        await starting.WaitAsync();
        try
        {
            if (app is not null)
                return;
            var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [], ContentRootPath = AppContext.BaseDirectory });
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(k =>
            {
                k.Listen(IPAddress.Loopback, DevcontainerWire.Port);
                k.Limits.MaxRequestBodySize = DevcontainerWire.MaxRequestBytes;
                k.AddServerHeader = false;
            });
            var built = builder.Build();
            built.MapPost(DevcontainerWire.EnvironmentPath, (Delegate)HandleAsync);
            try
            {
                await built.StartAsync();
            }
            catch (Exception e) when (e is IOException or SocketException)
            {
                await built.DisposeAsync();
                throw new IOException($"Devcontainers can't reach Tiresias: another program is using port {DevcontainerWire.Port}.", e);
            }
            app = built;
        }
        finally
        {
            starting.Release();
        }
    }

    async Task<IResult> HandleAsync(HttpContext context)
    {
        var ticket = DevcontainerWire.Ticket(context.Request.Headers.Authorization);
        if (tickets.Find(ticket) is not { } devcontainer)
        {
            refused(ticket is null ? "a devcontainer request without a ticket" : "a devcontainer request with an unknown or ended ticket");
            return Results.Json(new DevcontainerReply(false, Message: "No live Tiresias ticket: start VS Code with tir run -- code <folder>."),
                DevcontainerWire.Json, statusCode: StatusCodes.Status401Unauthorized);
        }
        DevcontainerRequest? request;
        try
        {
            request = await JsonSerializer.DeserializeAsync<DevcontainerRequest>(context.Request.Body, DevcontainerWire.Json, context.RequestAborted);
        }
        catch (Exception e) when (e is JsonException or BadHttpRequestException)
        {
            request = null;
        }
        if (request is null)
            return Results.Json(new DevcontainerReply(false, Message: "Not a Tiresias request."), DevcontainerWire.Json, statusCode: StatusCodes.Status400BadRequest);
        if (request.V > DevcontainerWire.Version)
            return Results.Json(new DevcontainerReply(false, Message: "This tir-remote is newer than the Tiresias app: update the app."),
                DevcontainerWire.Json, statusCode: StatusCodes.Status400BadRequest);
        return Results.Json(await ask(ticket!, devcontainer, request, context.RequestAborted), DevcontainerWire.Json);
    }

    public async ValueTask DisposeAsync()
    {
        if (app is not null)
            await app.DisposeAsync();
        starting.Dispose();
    }
}
