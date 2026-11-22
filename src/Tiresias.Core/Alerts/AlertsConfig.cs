using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Tiresias.Protocol;
using Tiresias.UserSecrets;
using Tiresias.Vault;

namespace Tiresias.Alerts;

/// <summary>
/// One place alerts go, as sealed in <c>alerts.json</c>. Its address and credentials can be secrets (a
/// key in a webhook's query, an <c>Authorization</c> header, an ntfy topic or token), so every sink
/// prints as its kind and id only: a log line or an exception that prints one shows nothing to steal.
/// </summary>
/// <param name="Id">The name the user gave it, e.g. <c>siem</c>. Not secret: logs and findings use it.</param>
public abstract record AlertSink(string Id, AlertSeverity Threshold, AlertRedaction Redaction)
{
    /// <summary>The <c>kind</c> in <c>alerts.json</c>.</summary>
    public abstract string Kind { get; }

    /// <summary>Whether <paramref name="other"/> delivers to the same place with the same credentials.</summary>
    public abstract bool SameTarget(AlertSink other);

    public sealed override string ToString() => $"{Kind} {Id}";
}

/// <summary>A webhook: <c>tiresias.alert/v1</c> JSON posted to <see cref="Url"/> with the user's headers.</summary>
public sealed record WebhookSink(
    string Id,
    Uri Url,
    IReadOnlyList<KeyValuePair<string, string>> Headers,
    AlertSeverity Threshold = AlertSeverity.High,
    AlertRedaction Redaction = AlertRedaction.Public) : AlertSink(Id, Threshold, Redaction)
{
    public override string Kind => "webhook";

    public override bool SameTarget(AlertSink other) => other is WebhookSink o && Url == o.Url && Headers.SequenceEqual(o.Headers);
}

/// <summary>An ntfy topic on any ntfy server (docs/alerts.md, <i>Sinks</i>), with an optional access token.</summary>
/// <param name="Topic">The topic's full URL, e.g. <c>https://ntfy.sh/&lt;topic&gt;</c>.</param>
/// <param name="Token">Sent as <c>Authorization: Bearer</c>; <c>null</c> for an open topic.</param>
public sealed record NtfySink(
    string Id,
    Uri Topic,
    string? Token,
    AlertSeverity Threshold = AlertSeverity.High,
    AlertRedaction Redaction = AlertRedaction.Public) : AlertSink(Id, Threshold, Redaction)
{
    public override string Kind => "ntfy";

    public override bool SameTarget(AlertSink other) => other is NtfySink o && Topic == o.Topic && Token == o.Token;
}

/// <summary>
/// The LcdHub on this machine (docs/alerts.md, <i>Sinks</i>): status items over the per-user pipe
/// <c>LcdHub</c>. No address and no credential; a machine has one hub, so it has at most one such sink.
/// </summary>
public sealed record LcdHubSink(
    string Id,
    AlertSeverity Threshold = AlertSeverity.Warning,
    AlertRedaction Redaction = AlertRedaction.Public) : AlertSink(Id, Threshold, Redaction)
{
    public override string Kind => "lcdhub";

    public override bool SameTarget(AlertSink other) => other is LcdHubSink;
}

/// <summary>
/// What a user narrowed about a sink without Windows Hello, kept in <c>app.json</c>: muted, a raised
/// threshold, or removed. It can only take away from what <c>alerts.json</c> allows, never add.
/// </summary>
/// <param name="Threshold">Raises the sealed threshold; a lower one is ignored.</param>
/// <param name="Removed">Gone at once; its definition leaves <c>alerts.json</c> at the next sealed save.</param>
public sealed record SinkNarrowing(bool Muted = false, AlertSeverity? Threshold = null, bool Removed = false);

/// <summary>
/// The sealed alert configuration (docs/alerts.md, <i>Sinks</i>): the machine label, the per-install
/// key and the sinks. Everything here can widen what leaves the machine, so it changes only by a
/// sealed save, which needs the Windows Hello wrapper.
/// </summary>
public sealed record AlertsConfig
{
    /// <summary>The document's own version, inside the sealed envelope.</summary>
    public const int Version = 1;

    public AlertsConfig(string machine, byte[] installKey, IReadOnlyList<AlertSink> sinks)
    {
        // AlertSetup checks the label, the key and unique ids; so a config that exists can always plan.
        _ = new AlertSetup(machine, installKey, [.. sinks.Select(s => new SinkDefinition(s.Id, s.Threshold))]);
        Machine = machine;
        InstallKey = installKey;
        Sinks = sinks;
    }

    public string Machine { get; }
    public byte[] InstallKey { get; }
    public IReadOnlyList<AlertSink> Sinks { get; }

    /// <summary>A first configuration: the label the user typed and a fresh install key, no sinks yet.</summary>
    public static AlertsConfig New(string machine) => new(machine.Trim(), RandomNumberGenerator.GetBytes(32), []);

    /// <summary>Adds <paramref name="sink"/>, replacing one with the same id.</summary>
    public AlertsConfig With(AlertSink sink) =>
        new(Machine, InstallKey, [.. Sinks.Where(s => s.Id != sink.Id), sink]);

    /// <summary>Without the sinks <paramref name="narrowing"/> marks removed: what the next sealed save writes.</summary>
    public AlertsConfig Purged(IReadOnlyDictionary<string, SinkNarrowing>? narrowing) =>
        new(Machine, InstallKey, [.. Sinks.Where(s => narrowing?.GetValueOrDefault(s.Id)?.Removed != true)]);

    /// <summary>The sinks not removed, muted ones included.</summary>
    public IReadOnlyList<AlertSink> Live(IReadOnlyDictionary<string, SinkNarrowing>? narrowing) => Purged(narrowing).Sinks;

    /// <summary>What the planner works from: the sealed sinks, narrowed.</summary>
    public AlertSetup Setup(IReadOnlyDictionary<string, SinkNarrowing>? narrowing) =>
        new(Machine, InstallKey, [.. Live(narrowing).Select(s =>
        {
            var narrowed = narrowing?.GetValueOrDefault(s.Id);
            var threshold = narrowed?.Threshold is { } raised && raised > s.Threshold ? raised : s.Threshold;
            return new SinkDefinition(s.Id, threshold, s.Redaction, narrowed?.Muted == true);
        })]);

    public JsonObject ToDocument()
    {
        var sinks = new JsonArray();
        foreach (var sink in Sinks)
        {
            var node = new JsonObject { ["id"] = sink.Id, ["kind"] = sink.Kind };
            switch (sink)
            {
                case WebhookSink webhook:
                    var headers = new JsonObject();
                    foreach (var (name, value) in webhook.Headers)
                        headers[name] = value;
                    node["url"] = webhook.Url.OriginalString;
                    node["headers"] = headers;
                    break;
                case NtfySink ntfy:
                    node["url"] = ntfy.Topic.OriginalString;
                    if (ntfy.Token is not null)
                        node["token"] = ntfy.Token;
                    break;
            }
            node["threshold"] = Name(sink.Threshold);
            node["redaction"] = sink.Redaction == AlertRedaction.Trusted ? "trusted" : "public";
            sinks.Add(node);
        }
        return new JsonObject
        {
            ["v"] = Version,
            ["machine"] = Machine,
            ["installKey"] = Convert.ToBase64String(InstallKey),
            ["sinks"] = sinks,
        };
    }

    /// <returns><c>null</c> for an empty document: alerts were never set up.</returns>
    /// <exception cref="InvalidDataException">Not a document <see cref="ToDocument"/> wrote, or a newer version.</exception>
    public static AlertsConfig? FromDocument(JsonObject document)
    {
        if (document.Count == 0)
            return null;
        if ((int?)document["v"] != Version)
            throw new InvalidDataException($"alerts.json is version {document["v"]}; this build reads {Version}.");
        try
        {
            var sinks = (document["sinks"] as JsonArray ?? []).Select(node =>
            {
                var sink = node as JsonObject ?? throw new InvalidDataException("An alert sink is not an object.");
                var id = (string)sink["id"]!;
                var threshold = Parse((string)sink["threshold"]!);
                var redaction = (string?)sink["redaction"] == "trusted" ? AlertRedaction.Trusted : AlertRedaction.Public;
                return (string?)sink["kind"] switch
                {
                    "webhook" => (AlertSink)new WebhookSink(id, Url(sink),
                        (sink["headers"] as JsonObject ?? []).Select(h => KeyValuePair.Create(h.Key, (string)h.Value!)).ToArray(), threshold, redaction),
                    "ntfy" => new NtfySink(id, Url(sink), (string?)sink["token"], threshold, redaction),
                    "lcdhub" => new LcdHubSink(id, threshold, redaction),
                    var kind => throw new InvalidDataException($"Alert sink kind '{kind}' is not one this build knows."),
                };
            }).ToArray();
            return new((string)document["machine"]!, Convert.FromBase64String((string)document["installKey"]!), sinks);
        }
        catch (Exception e) when (e is InvalidOperationException or FormatException or ArgumentException or NullReferenceException)
        {
            // The type only: the message could quote a URL.
            throw new InvalidDataException($"alerts.json is not a document this build wrote ({e.GetType().Name}).");
        }
    }

    public override string ToString() => $"alerts for {Machine}, {Sinks.Count} sink(s)";

    static string Name(AlertSeverity severity) => severity.ToString().ToLowerInvariant();

    static Uri Url(JsonObject sink) => new((string)sink["url"]!, UriKind.Absolute);

    static AlertSeverity Parse(string name) => Enum.Parse<AlertSeverity>(name, ignoreCase: true);
}

/// <summary>
/// <c>alerts.json</c> sealed as a user-secrets document under <c>tiresias:alerts</c>, for Windows Hello
/// and the recovery key, like the sealed environment. Unlike a <c>secrets.json</c>, plain keys written
/// beside the envelope are refused, not merged: anything that could add a sink must go through a sealed save.
/// </summary>
public static class AlertsFile
{
    /// <summary>The sealing id. A <c>:</c> can't be in a folder name, so no project's user secrets share it.</summary>
    public const string Id = "tiresias:alerts";

    /// <returns>The configuration (<c>null</c> when none is set up) and the version it was read from (0 for none).</returns>
    /// <exception cref="InvalidDataException">Unsealed, edited beside the seal, or doesn't open with <paramref name="hello"/>.</exception>
    public static (AlertsConfig? Config, int Version) Open(string? fileText, IKeyWrapper hello)
    {
        var kind = SecretsFile.Classify(fileText);
        if (kind == SecretsFileKind.None)
            return (null, 0);
        if (kind != SecretsFileKind.Sealed)
            throw new InvalidDataException("alerts.json is not sealed, so it is ignored: set alerts up again in the app.");
        var load = UserSecretsVault.Open(Id, fileText, hello);
        if (load.NeedsSealing)
            throw new InvalidDataException("alerts.json was edited outside the app, so it is ignored: set alerts up again in the app.");
        return (AlertsConfig.FromDocument(load.Document), load.Version);
    }

    /// <summary>The file text for <paramref name="config"/> as the version after <paramref name="loadedVersion"/>.</summary>
    public static string Seal(AlertsConfig config, int loadedVersion, IKeyWrapper hello, IKeyWrapper recovery) =>
        UserSecretsVault.Seal(Id, loadedVersion + 1, config.ToDocument(), [hello, recovery]);
}
