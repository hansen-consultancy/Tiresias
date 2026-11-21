using Tiresias.Agent;
using Tiresias.Alerts;
using Tiresias.Vault;

namespace Tiresias.App;

/// <summary>
/// The app's end of alerts (docs/alerts.md): opens <c>alerts.json</c> at unlock and keeps it in the
/// <see cref="AlertCenter"/> until the app exits; a widening edit is a sealed save, which needs the
/// Windows Hello wrapper; muting and removing only write <c>app.json</c>.
/// </summary>
internal sealed class AppAlerts : IAsyncDisposable
{
    readonly Lock gate = new();
    IKeyWrapper? openedWith;

    public AppAlerts()
    {
        // A demo runs beside the installed app, so it leaves the real LcdHub to that app.
        Center = new AlertCenter(new HttpAlertTransport(), TimeProvider.System, AppLog.Info,
            DemoMode.On ? null : new LcdHubLink(TimeProvider.System, AppLog.Info));
        Center.Start();
    }

    public AlertCenter Center { get; }

    /// <summary>Raised after the configuration in use changed: opened, a sink added, muted or removed.</summary>
    public event Action? Changed;

    public bool Opened { get; private set; }

    public static IReadOnlyDictionary<string, SinkNarrowing> Narrowing => AppSettings.Load().Alerts ?? new Dictionary<string, SinkNarrowing>();

    /// <summary>
    /// Opens <c>alerts.json</c> with the wrapper of this unlock, once per unlock, and writes out a
    /// removal made while locked. A file that won't open turns alerts off, logged, rather than failing the unlock.
    /// </summary>
    public void Unlocked(IKeyWrapper hello)
    {
        lock (gate)
        {
            if (ReferenceEquals(openedWith, hello))
                return;
            openedWith = hello;
        }
        try
        {
            var (config, version) = AlertsStore.Open(hello);
            var narrowing = Narrowing;
            if (config is not null && config.Sinks.Any(s => narrowing.GetValueOrDefault(s.Id)?.Removed == true))
            {
                config = config.Purged(narrowing);
                AlertsStore.Save(config, version, hello);
                SaveNarrowing(WithoutRemoved(narrowing));
            }
            Use(config);
        }
        catch (Exception e) when (e is InvalidDataException or IOException or UnauthorizedAccessException or InvalidOperationException
            or System.Text.Json.JsonException or System.Security.Cryptography.CryptographicException)
        {
            AppLog.Error(e, "alerts.json not opened, alerts are off");
            Use(null);
        }
    }

    /// <summary>Adds <paramref name="sink"/> (a widening edit): a sealed save with the Hello wrapper. Asks for the label with the first sink.</summary>
    /// <exception cref="InvalidOperationException">No recovery key, or no label for a first sink.</exception>
    public void Add(string? machine, AlertSink sink, IKeyWrapper hello)
    {
        var (config, version) = AlertsStore.Open(hello);
        var narrowing = Narrowing;
        config = (config ?? AlertsConfig.New(machine is { Length: > 0 } ? machine : throw new InvalidOperationException("Alerts need a machine label.")))
            .Purged(narrowing).With(sink);
        AlertsStore.Save(config, version, hello);
        var kept = WithoutRemoved(narrowing);
        kept.Remove(sink.Id);
        SaveNarrowing(kept);
        Use(config);
    }

    /// <summary>Mutes or unmutes a sink: narrowing only, no Windows Hello.</summary>
    public void Mute(string id, bool muted) => Narrow(id, n => n with { Muted = muted });

    /// <summary>
    /// Removes a sink: narrowing only, so it stops at once with no Windows Hello; its definition leaves
    /// <c>alerts.json</c> now if unlocked, else at the next unlock.
    /// </summary>
    public void Remove(string id, IKeyWrapper? hello)
    {
        Narrow(id, n => n with { Removed = true });
        if (hello is null)
            return;
        lock (gate)
            openedWith = null;
        Unlocked(hello);
    }

    void Narrow(string id, Func<SinkNarrowing, SinkNarrowing> change)
    {
        var narrowing = new Dictionary<string, SinkNarrowing>(Narrowing);
        narrowing[id] = change(narrowing.GetValueOrDefault(id) ?? new());
        SaveNarrowing(narrowing);
        Use(Center.Config);
    }

    void Use(AlertsConfig? config)
    {
        Center.Use(config, Narrowing);
        Opened = true;
        Changed?.Invoke();
    }

    static Dictionary<string, SinkNarrowing> WithoutRemoved(IReadOnlyDictionary<string, SinkNarrowing> narrowing) =>
        narrowing.Where(n => !n.Value.Removed).ToDictionary();

    static void SaveNarrowing(IReadOnlyDictionary<string, SinkNarrowing> narrowing) =>
        (AppSettings.Load() with { Alerts = narrowing.Count == 0 ? null : narrowing }).Save();

    public ValueTask DisposeAsync() => Center.DisposeAsync();
}
