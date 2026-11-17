namespace Tiresias.Forwarder;

/// <summary>
/// The forwarder accepts placeholder-authenticated requests and holds the path to the broker, so
/// it must never be reachable from the network. Every way the host can be told where to listen is
/// checked before it starts; anything that isn't a literal loopback address (a wildcard, a LAN IP,
/// a bare port list) is refused rather than narrowed.
/// </summary>
static class LoopbackGuard
{
    /// <returns>Each configured listen address that isn't loopback. Empty means safe to start.</returns>
    public static IReadOnlyList<string> NonLoopback(IConfiguration configuration)
    {
        var urls = (configuration["urls"] ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Concat(configuration.GetSection("Kestrel:Endpoints").GetChildren().Select(e => e["Url"]).OfType<string>());
        var exposed = urls.Where(u => !IsLoopback(u)).ToList();

        // HTTP_PORTS / HTTPS_PORTS bind every interface.
        foreach (var key in new[] { "http_ports", "https_ports" })
            if (!string.IsNullOrWhiteSpace(configuration[key]))
                exposed.Add($"{key}={configuration[key]}");
        return exposed;
    }

    /// <summary><c>localhost</c>, <c>127.0.0.0/8</c> or <c>[::1]</c>. Wildcards (<c>*</c>, <c>+</c>) don't parse as a URI and so aren't.</summary>
    public static bool IsLoopback(string url) => Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.IsLoopback;
}
