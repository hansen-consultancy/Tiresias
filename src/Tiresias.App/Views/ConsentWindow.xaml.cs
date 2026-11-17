using System.ComponentModel;
using System.Windows;
using System.Windows.Threading;
using Tiresias.UserSecrets;

namespace Tiresias.App.Views;

/// <summary>What one consent screen shows.</summary>
/// <param name="Program">The executable asking, as the pipe or the connection identified it; <c>null</c> when it couldn't be.</param>
/// <param name="Items">User secrets: the keys (never values). A placeholder: the consent lines tir prints.</param>
/// <param name="AllowSession">Offer "Allow for this session": user secrets only, where the agent remembers the answer.</param>
public sealed record ConsentView(string Heading, string? Program, string ListLabel, IReadOnlyList<string> Items, string Note, bool AllowSession);

/// <summary>
/// The consent dialog: topmost, names the program and lists what it gets, and answers Deny when it
/// is closed, times out, or the session locks (the caller cancels the token).
/// </summary>
public partial class ConsentWindow : Window
{
    readonly TaskCompletionSource<ConsentAnswer> answer = new(TaskCreationOptions.RunContinuationsAsynchronously);
    readonly DispatcherTimer tick = new() { Interval = TimeSpan.FromSeconds(1) };
    readonly DateTimeOffset deadline;

    ConsentWindow(ConsentView view, TimeSpan timeout, int waiting)
    {
        InitializeComponent();
        deadline = DateTimeOffset.Now + timeout;
        Heading.Text = view.Heading;
        ProgramLabel.Text = Text.Get("Consent_ProgramLabel");
        ProgramPath.Text = view.Program ?? Text.Get("Consent_ProgramUnknown");
        ListLabel.Text = view.ListLabel;
        Items.ItemsSource = view.Items.Count > 0 ? view.Items : [Text.Get("Consent_NoKeys")];
        Note.Text = waiting > 0 ? $"{view.Note} {Text.Format("Consent_Waiting", waiting)}" : view.Note;
        AllowSession.Visibility = view.AllowSession ? Visibility.Visible : Visibility.Collapsed;
        tick.Tick += (_, _) => UpdateCountdown();
        UpdateCountdown();
        tick.Start();
    }

    /// <summary>Shows the dialog and completes with the answer; Deny when <paramref name="ct"/> is cancelled first.</summary>
    public static Task<ConsentAnswer> AskAsync(ConsentView view, TimeSpan timeout, int waiting, CancellationToken ct)
    {
        var window = new ConsentWindow(view, timeout, waiting);
        var registration = ct.Register(() => window.Dispatcher.BeginInvoke(() => window.Finish(ConsentAnswer.Deny)));
        window.answer.Task.ContinueWith(_ => registration.Dispose(), TaskScheduler.Default);
        window.Show();
        window.Activate();
        window.DenyButton.Focus();
        return window.answer.Task;
    }

    void UpdateCountdown()
    {
        var left = deadline - DateTimeOffset.Now;
        if (left <= TimeSpan.Zero)
        {
            Finish(ConsentAnswer.Deny);
            return;
        }
        Countdown.Text = Text.Format("Consent_Countdown", $"{(int)left.TotalMinutes}:{left.Seconds:00}");
    }

    void Finish(ConsentAnswer result)
    {
        if (!answer.TrySetResult(result))
            return;
        tick.Stop();
        Close();
    }

    void OnAllowOnce(object sender, RoutedEventArgs e) => Finish(ConsentAnswer.AllowOnce);

    void OnAllowSession(object sender, RoutedEventArgs e) => Finish(ConsentAnswer.AllowForSession);

    void OnDeny(object sender, RoutedEventArgs e) => Finish(ConsentAnswer.Deny);

    protected override void OnClosing(CancelEventArgs e)
    {
        answer.TrySetResult(ConsentAnswer.Deny);
        tick.Stop();
        base.OnClosing(e);
    }
}
