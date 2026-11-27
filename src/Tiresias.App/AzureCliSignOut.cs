using System.Diagnostics;
using System.Runtime.InteropServices;
using Tiresias.Agent;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.App;

/// <summary>
/// Signs the Azure CLI out when About's setting says so (<see cref="AzSignOutPlan"/>): as Tiresias
/// locks, or once the PC has been idle. The CLI has no timeout of its own, and its cached Entra
/// session is the "az signed in" finding. Signing out is the CLI's own <c>az account clear</c>, which
/// forgets every account where <c>az logout</c> forgets only the current one. Nothing is started
/// while the CLI's profile names no account.
/// </summary>
sealed partial class AzureCliSignOut : IDisposable
{
    static readonly TimeSpan Look = TimeSpan.FromMinutes(1);

    readonly CancellationTokenSource stop = new();
    /// <summary>Off until <see cref="Start"/>: a demo's settings folder isn't known before then.</summary>
    volatile AppSettings settings = new();
    int running;

    /// <summary>The Azure CLI on this app's <c>PATH</c>; <c>null</c> when there is none, and in a demo, which has no programs.</summary>
    public static string? Program => DemoMode.On ? null : AzSignOutPlan.Find(Environment.GetEnvironmentVariable("PATH"), File.Exists);

    /// <summary>Starts watching for idle time. The watch costs one look a minute, and reads nothing unless the setting is on.</summary>
    public void Start()
    {
        Reload();
        _ = WatchIdleAsync(stop.Token);
    }

    /// <summary>About saved the setting.</summary>
    public void Reload() => settings = AppSettings.Load();

    /// <summary>Tiresias locked. Returns at once: the lock holds up a session event.</summary>
    public void OnLock(string reason)
    {
        if (AzSignOutPlan.OnLock(settings.AzSignOut))
            _ = Task.Run(() => SignOutAsync($"Tiresias locked: {reason}"));
    }

    async Task WatchIdleAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(Look);
        var done = false;
        try
        {
            while (await timer.WaitForNextTickAsync(ct))
            {
                var now = settings;
                (var signOut, done) = AzSignOutPlan.OnIdle(now.AzSignOut, now.AzSignOutIdleMinutes, Idle(), done);
                if (signOut)
                    await SignOutAsync($"the PC was idle for {AzSignOutPlan.IdleMinutes(now.AzSignOutIdleMinutes)} minutes");
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    async Task SignOutAsync(string why)
    {
        // A lock while the idle sign-out runs, or two locks in a row, is one sign-out.
        if (Interlocked.Exchange(ref running, 1) == 1)
            return;
        try
        {
            if (!SignedIn())
                return;
            // The CLI would sign the real machine out.
            if (DemoMode.On)
            {
                AppLog.Info($"az: a demo leaves the Azure CLI signed in ({why})");
                return;
            }
            if (Program is not { } az)
            {
                AppLog.Info($"az: signed in, but az is not on PATH, so it stays signed in ({why})");
                return;
            }
            // /s keeps the quotes around the path whatever it holds: an older install is under Program Files (x86).
            var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"), $"/d /s /c \"\"{az}\" account clear\"")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var process = Process.Start(start);
            if (process is null)
                return;
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(1));
            try
            {
                await process.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException)
            {
                process.Kill(entireProcessTree: true);
                AppLog.Info($"az: signing out took over a minute and was stopped ({why})");
                return;
            }
            AppLog.Info(process.ExitCode == 0 ? $"az: signed out ({why})" : $"az: signing out failed, exit code {process.ExitCode} ({why})");
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            AppLog.Error(e, "az: signing out");
        }
        finally
        {
            Volatile.Write(ref running, 0);
        }
    }

    /// <summary>Whether the CLI's profile names an account: what the "az signed in" finding reads, never a token.</summary>
    static bool SignedIn() =>
        new MachineProbe().CliConfigs.AzureProfile is { } profile && Doctor.CliSignIns(new(null, profile), null).Any();

    /// <summary>How long since the last keyboard or mouse input in this session; none when Windows won't say.</summary>
    static TimeSpan Idle()
    {
        var last = new LastInput { Size = (uint)Marshal.SizeOf<LastInput>() };
        return GetLastInputInfo(ref last) ? TimeSpan.FromMilliseconds(unchecked((uint)Environment.TickCount - last.Time)) : TimeSpan.Zero;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LastInput
    {
        public uint Size;
        public uint Time;
    }

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetLastInputInfo(ref LastInput info);

    public void Dispose()
    {
        stop.Cancel();
        stop.Dispose();
    }
}
