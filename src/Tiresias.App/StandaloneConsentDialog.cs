using System.Windows;
using Microsoft.Win32;
using Tiresias.App.Views;
using Tiresias.UserSecrets;

namespace Tiresias.App;

/// <summary>Hosts one consent window inside a standalone tir process, without starting the tray app or its agent.</summary>
public static class StandaloneConsentDialog
{
    public static Task<bool> AskEnvironmentAsync(IReadOnlyList<string> commandLine, IReadOnlyList<string> terms)
    {
        var answer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            try
            {
                answer.SetResult(Ask(commandLine, terms));
            }
            catch (Exception e)
            {
                answer.SetException(e);
            }
        }) { IsBackground = true, Name = "Tiresias consent" };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        return answer.Task;
    }

    static bool Ask(IReadOnlyList<string> commandLine, IReadOnlyList<string> terms)
    {
        var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown, ThemeMode = ThemeMode.System };
        app.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri("/Tiresias;component/WindowStyles.xaml", UriKind.Relative) });
        using var session = new CancellationTokenSource(UserSecretsService.ConsentTimeout);
        void SessionSwitch(object? sender, SessionSwitchEventArgs e)
        {
            if (e.Reason is SessionSwitchReason.SessionLock or SessionSwitchReason.SessionLogoff
                or SessionSwitchReason.ConsoleDisconnect or SessionSwitchReason.RemoteDisconnect)
                session.Cancel();
        }
        void SessionEnding(object? sender, SessionEndingEventArgs e) => session.Cancel();
        void PowerChanged(object? sender, PowerModeChangedEventArgs e)
        {
            if (e.Mode == PowerModes.Suspend)
                session.Cancel();
        }
        try
        {
            SystemEvents.SessionSwitch += SessionSwitch;
            SystemEvents.SessionEnding += SessionEnding;
            SystemEvents.PowerModeChanged += PowerChanged;
            var view = ConsentView.ForEnvironment(Path.GetFileName(commandLine[0]), commandLine, terms, Environment.ProcessPath)
                with { CanReportIncident = false };
            var choice = ConsentWindow.AskAsync(view, UserSecretsService.ConsentTimeout, 0, session.Token);
            _ = choice.ContinueWith(_ => app.Dispatcher.InvokeAsync(app.Shutdown), TaskScheduler.Default);
            app.Run();
            return !session.IsCancellationRequested && choice.IsCompletedSuccessfully && choice.Result == ConsentChoice.AllowOnce;
        }
        finally
        {
            SystemEvents.SessionSwitch -= SessionSwitch;
            SystemEvents.SessionEnding -= SessionEnding;
            SystemEvents.PowerModeChanged -= PowerChanged;
        }
    }
}
