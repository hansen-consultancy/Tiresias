using System.Net.Http;
using System.Reflection;
using System.Windows;
using System.Windows.Threading;
using Tiresias.App.Logic;
using Tiresias.App.Views;
using Velopack;
using Velopack.Sources;

namespace Tiresias.App;

/// <summary>
/// Updates from this repository's GitHub Releases (the <c>app-v*</c> tags), through Velopack. The
/// app checks at start and daily, downloads in the background, then offers "restart to apply" in
/// the tray. Restarting shows the release notes first, waits while a consent dialog, the editor or
/// the wizard is open, and quits the normal way (ending the lease) before Velopack swaps the
/// files. If applying fails, Velopack keeps the version that was running.
/// </summary>
sealed class AppUpdates(App app, TrayController tray) : IDisposable
{
    const string Repository = "https://github.com/hansen-consultancy/Tiresias";

    readonly DispatcherTimer timer = new() { Interval = UpdatePlan.Tick };
    UpdateManager? manager;
    UpdateInfo? ready;
    bool checking;

    public static string CurrentVersion =>
        typeof(AppUpdates).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0";

    public void Start()
    {
        manager = new UpdateManager(new GithubSource(Repository, accessToken: null, prerelease: UpdatePlan.FollowsPrereleases(CurrentVersion)));
        if (!manager.IsInstalled)
        {
            // Run from a build folder (dotnet run, dotnet publish): there is nothing to update in place.
            AppLog.Info("not installed with the installer; updates are off");
            return;
        }
        if (manager.UpdatePendingRestart is { } pending)
            tray.OfferUpdate(pending.Version.ToString(), () => Offer(pending));
        timer.Tick += async (_, _) => await CheckAsync();
        timer.Start();
        _ = CheckAsync();
    }

    async Task CheckAsync()
    {
        if (manager is null || checking || ready is not null || !UpdatePlan.IsDue(AppSettings.Load().LastUpdateCheck, DateTimeOffset.UtcNow))
            return;
        checking = true;
        try
        {
            var info = await manager.CheckForUpdatesAsync();
            if (info is not null)
            {
                await manager.DownloadUpdatesAsync(info);
                ready = info;
                AppLog.Info($"update {info.TargetFullRelease.Version} downloaded");
                tray.OfferUpdate(info.TargetFullRelease.Version.ToString(), () => Offer(info.TargetFullRelease));
            }
            (AppSettings.Load() with { LastUpdateCheck = DateTimeOffset.UtcNow }).Save();
        }
        catch (Exception e) when (e is HttpRequestException or IOException or TaskCanceledException or InvalidOperationException
            or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            // No network, GitHub unavailable, a rate limit: nothing for the user to do; the next tick tries again.
            AppLog.Error(e, "update check");
        }
        finally
        {
            checking = false;
        }
    }

    /// <summary>The tray item: release notes, then restart, unless something must not be interrupted.</summary>
    void Offer(VelopackAsset release)
    {
        if (app.Busy)
        {
            AskWindow.Tell(null, null, Text.Get("Update_Busy"));
            return;
        }
        var window = new UpdateWindow(release.Version.ToString(), release.NotesMarkdown);
        if (window.ShowDialog() != true)
            return;
        // Something may have opened while the notes were read.
        if (app.Busy)
        {
            AskWindow.Tell(null, null, Text.Get("Update_Busy"));
            return;
        }
        AppLog.Info($"applying update {release.Version}");
        manager!.WaitExitThenApplyUpdates(release, silent: true, restart: true);
        app.Quit();
    }

    public void Dispose() => timer.Stop();
}
