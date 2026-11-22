using System.IO.Pipes;
using Tiresias.Client;

namespace Tiresias.Agent;

/// <summary>
/// Looks inside the Docker engine for <see cref="Doctor.Contents"/>, only when the user asked: GET
/// requests through an engine pipe their account can open, nothing that writes, execs or pulls.
/// Every response goes through <see cref="NameScan"/>, so a variable's value is never a string and
/// its bytes are cleared once scanned.
/// </summary>
static class EngineProbe
{
    /// <summary>More than this many containers or images are not inspected; the rest are left out.</summary>
    const int MaxInspected = 200;

    static readonly TimeSpan PerCall = TimeSpan.FromSeconds(10);

    /// <summary>The first open engine pipe that answers, the active engine first; <c>null</c> engine when none does.</summary>
    public static async Task<ReachContents> ReadAsync(ReachFacts facts, CancellationToken ct)
    {
        var pipes = facts.Engines.Where(e => e.GrantedTo.Count > 0)
            .OrderBy(e => e.Kind switch { EngineKind.Current => 0, EngineKind.Linux => 1, _ => 2 })
            .Select(e => e.Name);
        foreach (var pipe in pipes)
        {
            try
            {
                using var http = Client(pipe);
                using (var ping = await http.GetAsync("_ping", ct))
                    if (!ping.IsSuccessStatusCode)
                        continue;
                return new(await ContentsAsync(http, pipe, ct));
            }
            catch (Exception e) when (e is HttpRequestException or IOException or TimeoutException or TaskCanceledException && !ct.IsCancellationRequested)
            {
                // Docker isn't running behind this pipe, or stopped answering: try the next.
            }
        }
        return new(null);
    }

    static async Task<EngineContents> ContentsAsync(HttpClient http, string pipe, CancellationToken ct)
    {
        var listed = (await GetAsync(http, "containers/json?all=1", EngineScan.Containers, ct)).Take(MaxInspected).ToArray();
        var images = new List<EngineImage>();
        foreach (var (id, tag) in (await GetAsync(http, "images/json", EngineScan.Images, ct)).Take(MaxInspected))
            images.Add(new(id, tag, await GetAsync(http, $"images/{Uri.EscapeDataString(id)}/json", EngineScan.Env, ct)));
        var containers = new List<EngineContainer>();
        foreach (var c in listed)
            containers.Add(new(c.Name, c.Running, c.ImageId, await GetAsync(http, $"containers/{Uri.EscapeDataString(c.Id)}/json", EngineScan.Env, ct), c.Mounts, c.Workspace));
        return new(pipe, containers, images);
    }

    static async Task<T> GetAsync<T>(HttpClient http, string path, SpanScanner<T> scan, CancellationToken ct)
    {
        using var response = await http.GetAsync(path, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();
        await using var body = await response.Content.ReadAsStreamAsync(ct);
        return await NameScan.ReadAsync(body, scan, ct);
    }

    /// <summary>HTTP over the engine's named pipe; the host name is a placeholder the engine ignores.</summary>
    static HttpClient Client(string pipe) =>
        new(new SocketsHttpHandler
        {
            ConnectCallback = async (_, ct) =>
            {
                var stream = new NamedPipeClientStream(".", pipe, PipeDirection.InOut, PipeOptions.Asynchronous);
                await stream.ConnectAsync(TimeSpan.FromSeconds(2), ct);
                return stream;
            },
        })
        { BaseAddress = new Uri("http://docker/"), Timeout = PerCall };
}
