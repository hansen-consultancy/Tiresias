using System.Windows.Threading;
using Tiresias.Agent;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.App;

/// <summary>
/// Runs the checks in the background, shortly after the app starts and every few hours, so the tray
/// can badge findings Home hasn't shown yet. Home reports what it showed through <see cref="Shown"/>.
/// UI thread only.
/// </summary>
static class FindingWatch
{
    static readonly TimeSpan FirstRun = TimeSpan.FromMinutes(1);
    static readonly TimeSpan Every = TimeSpan.FromHours(4);

    static DispatcherTimer? timer;
    static bool running;

    /// <summary>How many findings Home hasn't shown yet; 0 until the first run.</summary>
    public static int NewCount { get; private set; }

    /// <summary>Raised on the UI thread when <see cref="NewCount"/> changes.</summary>
    public static event Action? Changed;

    static string SeenPath => Path.Combine(KeyringStore.Directory, "seen-findings.json");

    public static void Start()
    {
        timer = new DispatcherTimer { Interval = FirstRun };
        timer.Tick += async (_, _) =>
        {
            timer.Interval = Every;
            await CheckAsync();
        };
        timer.Start();
        // A sink that starts or stops failing is a finding that comes or goes: badge it now, not in hours.
        App.Current.Alerts.Center.FailingChanged += () => App.Current.Dispatcher.BeginInvoke(async () => await CheckAsync());
    }

    public static void Stop() => timer?.Stop();

    /// <summary>Home showed these checks' findings: they are seen, the badge clears, and so do the LcdHub's alert items.</summary>
    public static void Shown(IReadOnlyList<DoctorCheck> checks)
    {
        var open = FindingBadge.Open(checks, DismissalStore.Load());
        try
        {
            Directory.CreateDirectory(KeyringStore.Directory);
            var temp = SeenPath + ".tmp";
            File.WriteAllText(temp, FindingBadge.ToJson(open));
            File.Move(temp, SeenPath, overwrite: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            AppLog.Error(e, "seen findings");
        }
        Set(0);
        App.Current.Alerts.Center.FindingsShown();
    }

    /// <summary>Runs the checks off the UI thread, unless Home is running them itself.</summary>
    static async Task CheckAsync()
    {
        if (running || App.Current.IsOpen<Views.StatusWindow>())
            return;
        running = true;
        try
        {
            var probe = new MachineProbe(ProjectIndexStore.Load().Folders)
            {
                Hello = App.Current.Host.Keys.Hello,
                FailingAlertSinks = App.Current.Alerts.Center.Failing,
            };
            var checks = await Task.Run(() => Doctor.RunAsync(probe));
            var dismissals = DismissalStore.Load();
            Home.LastFindings = FindingView.Of(checks, dismissals).Open.Count;
            Set(FindingBadge.New(FindingBadge.Open(checks, dismissals), ReadSeen()));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidDataException)
        {
            AppLog.Error(e, "background checks");
        }
        finally
        {
            running = false;
        }
    }

    static IReadOnlySet<string> ReadSeen()
    {
        try
        {
            return FindingBadge.Parse(File.Exists(SeenPath) ? File.ReadAllText(SeenPath) : null);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return FindingBadge.Parse(null);
        }
    }

    static void Set(int count)
    {
        if (count == NewCount)
            return;
        NewCount = count;
        Changed?.Invoke();
    }
}
