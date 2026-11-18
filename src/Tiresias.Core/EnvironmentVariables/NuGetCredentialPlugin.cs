using System.Text.Json.Nodes;

namespace Tiresias.EnvironmentVariables;

/// <summary>A credential found for a package source, or why there is none (<paramref name="Password"/> null).</summary>
public sealed record NuGetCredential(string? Username, string? Password, string? Message = null);

/// <summary>
/// NuGet's cross-platform plugin protocol (version 2), credential half only: line-delimited JSON
/// messages over the plugin's standard streams. The plugin claims authentication for every source
/// and answers <c>GetAuthenticationCredentials</c> through <paramref name="lookup"/>; any other
/// operation is declined, so NuGet carries on as if the plugin weren't there.
/// </summary>
/// <param name="lookup">Asked for one source URI; <c>isRetry</c> means NuGet's last answer was refused by the feed.</param>
public sealed class NuGetCredentialPlugin(TextReader input, TextWriter output, Func<Uri, bool, CancellationToken, Task<NuGetCredential>> lookup)
{
    public const string ProtocolVersion = "2.0.0";

    /// <summary>Sent while a lookup waits for the user, well inside NuGet's per-request timeout (five seconds by default).</summary>
    static readonly TimeSpan ProgressEvery = TimeSpan.FromSeconds(2);

    readonly Lock writing = new();

    /// <summary>Serves until NuGet sends <c>Close</c> or closes the stream.</summary>
    public async Task RunAsync(CancellationToken stop)
    {
        // NuGet's handshake is symmetric: each side sends one and answers the other's.
        await SendAsync(new JsonObject
        {
            ["RequestId"] = Guid.NewGuid().ToString(),
            ["Type"] = "Request",
            ["Method"] = "Handshake",
            ["Payload"] = new JsonObject { ["ProtocolVersion"] = ProtocolVersion, ["MinimumProtocolVersion"] = "1.0.0" },
        }, stop);

        var running = new List<Task>();
        while (await input.ReadLineAsync(stop) is { } line)
        {
            if (line.Length == 0 || JsonNode.Parse(line) is not JsonObject message || (string?)message["Type"] != "Request")
                continue;
            var method = (string?)message["Method"];
            if (method == "Close")
                break;
            // Each request is answered on its own, so a credential waiting for the user doesn't hold up the rest.
            running.RemoveAll(t => t.IsCompleted);
            running.Add(AnswerAsync((string?)message["RequestId"] ?? "", method, message["Payload"] as JsonObject, stop));
        }
        await Task.WhenAll(running);
    }

    async Task AnswerAsync(string id, string? method, JsonObject? payload, CancellationToken stop)
    {
        JsonObject reply = method switch
        {
            "Handshake" => new() { ["ResponseCode"] = "Success", ["ProtocolVersion"] = ProtocolVersion },
            "Initialize" or "SetLogLevel" or "SetCredentials" or "MonitorNuGetProcessExit" => Success(),
            "GetOperationClaims" => new() { ["ResponseCode"] = "Success", ["Claims"] = new JsonArray("Authentication") },
            "GetAuthenticationCredentials" => await CredentialsAsync(id, method, payload, stop),
            _ => new() { ["ResponseCode"] = "NotFound" },
        };
        await SendAsync(new JsonObject { ["RequestId"] = id, ["Type"] = "Response", ["Method"] = method, ["Payload"] = reply }, stop);
    }

    async Task<JsonObject> CredentialsAsync(string id, string method, JsonObject? payload, CancellationToken stop)
    {
        if (!Uri.TryCreate((string?)payload?["Uri"], UriKind.Absolute, out var uri))
            return new() { ["ResponseCode"] = "NotFound" };
        var isRetry = payload?["IsRetry"]?.GetValue<bool>() == true;

        var asking = lookup(uri, isRetry, stop);
        while (await Task.WhenAny(asking, Task.Delay(ProgressEvery, stop)) != asking)
            await SendAsync(new JsonObject { ["RequestId"] = id, ["Type"] = "Progress", ["Method"] = method, ["Payload"] = new JsonObject() }, stop);
        var credential = await asking;

        return credential.Password is null
            ? new() { ["ResponseCode"] = "NotFound", ["Message"] = credential.Message }
            : new()
            {
                ["ResponseCode"] = "Success",
                ["Username"] = credential.Username,
                ["Password"] = credential.Password,
                ["Message"] = credential.Message,
                ["AuthenticationTypes"] = new JsonArray("Basic"),
            };
    }

    static JsonObject Success() => new() { ["ResponseCode"] = "Success" };

    /// <summary>One whole line at a time: progress and answers to concurrent requests interleave by line, never inside one.</summary>
    Task SendAsync(JsonObject message, CancellationToken stop)
    {
        stop.ThrowIfCancellationRequested();
        var line = message.ToJsonString();
        lock (writing)
        {
            output.WriteLine(line);
            output.Flush();
        }
        return Task.CompletedTask;
    }
}
