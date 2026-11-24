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

    /// <summary>The list calls carry labels and mounts, never an environment, so they may be larger than an inspect.</summary>
    const int MaxListBytes = 16 << 20;

    /// <summary>Each call's deadline, the body included: headers that come and a body that never ends would otherwise hang the run.</summary>
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
            catch (Exception e) when (e is HttpRequestException or IOException or InvalidDataException or TimeoutException or OperationCanceledException && !ct.IsCancellationRequested)
            {
                // Docker isn't running behind this pipe, stopped answering, or listed more than we read: try the next.
            }
        }
        return new(null);
    }

    /// <summary>
    /// The two lists must answer whole, or nothing was looked at. A container or image that can't be
    /// inspected (removed since it was listed, or too large) is left out and counted, not a reason to
    /// drop everything else.
    /// </summary>
    static async Task<EngineContents> ContentsAsync(HttpClient http, string pipe, CancellationToken ct)
    {
        var listed = await GetAsync(http, "containers/json?all=1", EngineScan.Containers, MaxListBytes, ct);
        var listedImages = await GetAsync(http, "images/json", EngineScan.Images, MaxListBytes, ct);
        var leftOut = Math.Max(0, listed.Count - MaxInspected) + Math.Max(0, listedImages.Count - MaxInspected);
        var images = new List<EngineImage>();
        foreach (var (id, tag) in listedImages.Take(MaxInspected))
        {
            if (await InspectAsync(http, $"images/{Uri.EscapeDataString(id)}/json", ct) is { } env)
                images.Add(new(id, tag, env));
            else
                leftOut++;
        }
        var containers = new List<EngineContainer>();
        foreach (var c in listed.Take(MaxInspected))
        {
            if (await InspectAsync(http, $"containers/{Uri.EscapeDataString(c.Id)}/json", ct) is { } env)
                containers.Add(new(c.Name, c.Running, c.ImageId, env, c.Mounts, c.Workspace));
            else
                leftOut++;
        }
        return new(pipe, containers, images, leftOut);
    }

    /// <summary>One inspect's environment names; <c>null</c> when it is gone (404) or too large. Any other failure fails the look.</summary>
    static async Task<IReadOnlyList<ScannedName>?> InspectAsync(HttpClient http, string path, CancellationToken ct)
    {
        try
        {
            return await GetAsync(http, path, EngineScan.Env, NameScan.MaxBytes, ct);
        }
        catch (HttpRequestException e) when (e.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }
        catch (InvalidDataException)
        {
            return null;
        }
    }

    static async Task<T> GetAsync<T>(HttpClient http, string path, SpanScanner<T> scan, int maxBytes, CancellationToken ct)
    {
        using var call = CancellationTokenSource.CreateLinkedTokenSource(ct);
        call.CancelAfter(PerCall);
        using var response = await http.GetAsync(path, HttpCompletionOption.ResponseHeadersRead, call.Token);
        response.EnsureSuccessStatusCode();
        await using var body = await response.Content.ReadAsStreamAsync(call.Token);
        return await NameScan.ReadAsync(body, scan, maxBytes, call.Token);
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
