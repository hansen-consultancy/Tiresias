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
/// files. If applying fails, Velopack keeps the version that was running; it says nothing, so
/// the app checks for what would block it before quitting and says so at the next start (#149).
/// About and the tray can also ask now (<see cref="CheckNowAsync"/>), whatever the daily limit says.
/// </summary>
sealed class AppUpdates(App app, TrayController tray) : IDisposable
{
    readonly DispatcherTimer timer = new() { Interval = UpdatePlan.Tick };
    UpdateManager? manager;
    /// <summary>Downloaded, or already staged by Velopack at start: what "restart to apply" applies.</summary>
    VelopackAsset? ready;
    bool checking;

    public static string CurrentVersion =>
        typeof(AppUpdates).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0";

    public void Start()
    {
        manager = new UpdateManager(new GithubSource(AppBuild.Repository, accessToken: null, prerelease: UpdatePlan.FollowsPrereleases(CurrentVersion)));
        if (!manager.IsInstalled)
        {
            // Run from a build folder (dotnet run, dotnet publish): there is nothing to update in place.
            AppLog.Info("not installed with the installer; updates are off");
            return;
        }
        ReportFailedApply();
        if (manager.UpdatePendingRestart is { } pending)
        {
            ready = pending;
            tray.OfferUpdate(pending.Version.ToString(), () => Offer(pending));
        }
        timer.Tick += async (_, _) => await CheckAsync();
        timer.Start();
        _ = CheckAsync();
    }

    async Task CheckAsync()
    {
        if (manager is null || checking || ready is not null || !UpdatePlan.IsDue(AppSettings.Load().LastUpdateCheck, DateTimeOffset.UtcNow))
            return;
        await CheckCoreAsync();
    }

    /// <summary>
    /// "Check for updates": asks GitHub now, then offers the update or says there is none. An update
    /// already downloaded is offered without asking again.
    /// </summary>
    public async Task CheckNowAsync()
    {
        if (manager is null)
        {
            // A demo, or a build folder: nothing updates in place.
            AskWindow.Tell(null, null, Text.Get("Update_Off"));
            return;
        }
        if (ready is { } staged)
        {
            Offer(staged);
            return;
        }
        if (checking)
        {
            AskWindow.Tell(null, null, Text.Get("Update_Checking"));
            return;
        }
        switch (await CheckCoreAsync())
        {
            case true:
                Offer(ready!);
                break;
            case false:
                AskWindow.Tell(null, null, Text.Format("Update_Latest", CurrentVersion));
                break;
            default:
                AskWindow.Tell(null, null, Text.Get("Update_CheckFailed"));
                break;
        }
    }

    /// <summary>Checks and downloads; <c>true</c> when an update is ready, <c>false</c> when there is none, <c>null</c> when the check failed.</summary>
    async Task<bool?> CheckCoreAsync()
    {
        checking = true;
        try
        {
            var info = await manager!.CheckForUpdatesAsync();
            if (info is not null)
            {
                await manager.DownloadUpdatesAsync(info);
                var release = ready = info.TargetFullRelease;
                AppLog.Info($"update {release.Version} downloaded");
                tray.OfferUpdate(release.Version.ToString(), () => Offer(release));
            }
            (AppSettings.Load() with { LastUpdateCheck = DateTimeOffset.UtcNow }).Save();
            return info is not null;
        }
        catch (Exception e) when (e is HttpRequestException or IOException or TaskCanceledException or InvalidOperationException
            or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            // No network, GitHub unavailable, a rate limit: the next tick tries again.
            AppLog.Error(e, "update check");
            return null;
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
        var version = release.Version.ToString();
        var users = InstallFolderUsers.Find(InstallRoot);
        if (users.Count > 0)
        {
            AppLog.Info($"update {version} waits: the install folder is in use by {string.Join(", ", users)}");
            AskWindow.Tell(null, null, Text.Format("Update_FolderInUse", string.Join('\n', users)));
            return;
        }
        AppLog.Info($"applying update {version}");
        (AppSettings.Load() with { ApplyingUpdate = version }).Save();
        manager!.WaitExitThenApplyUpdates(release, silent: true, restart: true);
        app.Quit();
    }

    /// <summary>Velopack's root: the folder above the running version's.</summary>
    static string InstallRoot => Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory))!;

    void ReportFailedApply()
    {
        var settings = AppSettings.Load();
        if (settings.ApplyingUpdate is not { } applying)
            return;
        (settings with { ApplyingUpdate = null }).Save();
        if (!UpdatePlan.ApplyFailed(applying, CurrentVersion))
            return;
        var users = InstallFolderUsers.Find(InstallRoot);
        AppLog.Info($"update {applying} wasn't applied; still {CurrentVersion}" + (users.Count > 0 ? $"; folder in use by {string.Join(", ", users)}" : ""));
        AskWindow.Tell(null, null, users.Count > 0
            ? Text.Format("Update_NotApplied_Users", applying, string.Join('\n', users))
            : Text.Format("Update_NotApplied", applying));
    }

    public void Dispose() => timer.Stop();
}
