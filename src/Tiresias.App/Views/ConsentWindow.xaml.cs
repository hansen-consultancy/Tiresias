using System.Diagnostics;
using System.ComponentModel;
using System.Windows;
using System.Windows.Threading;

namespace Tiresias.App.Views;

/// <summary>What one consent screen shows.</summary>
/// <param name="Program">The executable asking, as the pipe or the connection identified it; <c>null</c> when it couldn't be.</param>
/// <param name="Items">User secrets: the keys (never values). A placeholder: the consent lines tir prints.</param>
/// <param name="AllowSession">Offer "Allow for this session": user secrets only, where the agent remembers the answer.</param>
/// <param name="Unlock">Tiresias is locked: the one way forward is "Unlock with Windows Hello" (or Deny), and there is no list.</param>
/// <param name="Command">The command line about to run, shown under the heading.</param>
public sealed record ConsentView(string Heading, string? Program, string ListLabel, IReadOnlyList<string> Items, string Note, bool AllowSession, bool Unlock = false, string? Command = null);

/// <summary>The button the user pressed; closing, timing out or locking counts as <see cref="Deny"/>.</summary>
public enum ConsentChoice
{
    Deny,
    AllowOnce,
    AllowForSession,
    /// <summary>"This wasn't me": deny, lock, and block the program.</summary>
    NotMe,
}

/// <summary>
/// The consent dialog: topmost, names the program and lists what it gets, and answers Deny when it
/// is closed, times out, or the session locks (the caller cancels the token).
/// </summary>
public partial class ConsentWindow : Window
{
    readonly TaskCompletionSource<ConsentChoice> answer = new(TaskCreationOptions.RunContinuationsAsynchronously);
    readonly DispatcherTimer tick = new() { Interval = TimeSpan.FromSeconds(1) };
    readonly DateTimeOffset deadline;
    readonly string? program;

    ConsentWindow(ConsentView view, TimeSpan timeout, int waiting)
    {
        InitializeComponent();
        deadline = DateTimeOffset.Now + timeout;
        Heading.Text = view.Heading;
        if (view.Command is { Length: > 0 } command)
        {
            Command.Text = command;
            Command.Visibility = Visibility.Visible;
        }
        ProgramLabel.Text = Text.Get("Consent_ProgramLabel");
        ProgramName.Text = view.Program is null ? Text.Get("Consent_ProgramUnknown") : Path.GetFileName(view.Program);
        ProgramFolder.Text = view.Program is null ? "" : Path.GetDirectoryName(view.Program) ?? "";
        ProgramFolder.Visibility = ProgramFolder.Text.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
        program = view.Program;
        OpenFolderLine.Visibility = File.Exists(view.Program) ? Visibility.Visible : Visibility.Collapsed;
        ListLabel.Text = view.ListLabel;
        Items.ItemsSource = view.Items.Count > 0 ? view.Items : [Text.Get("Consent_NoKeys")];
        Items.Visibility = view.Unlock ? Visibility.Collapsed : Visibility.Visible;
        if (view.Unlock)
            AllowOnce.Content = Text.Get("Consent_Unlock");
        Note.Text = waiting > 0 ? $"{view.Note} {Text.Format("Consent_Waiting", waiting)}" : view.Note;
        AllowSession.Visibility = view.AllowSession ? Visibility.Visible : Visibility.Collapsed;
        tick.Tick += (_, _) => UpdateCountdown();
        UpdateCountdown();
        tick.Start();
    }

    /// <summary>Shows the dialog and completes with the answer; Deny when <paramref name="ct"/> is cancelled first.</summary>
    public static Task<ConsentChoice> AskAsync(ConsentView view, TimeSpan timeout, int waiting, CancellationToken ct)
    {
        var window = new ConsentWindow(view, timeout, waiting);
        var registration = ct.Register(() => window.Dispatcher.BeginInvoke(() => window.Finish(ConsentChoice.Deny)));
        window.answer.Task.ContinueWith(_ => registration.Dispose(), TaskScheduler.Default);
        window.Show();
        window.Activate();
        window.DenyButton.Focus();
        return window.answer.Task;
    }

    /// <summary>Explorer on the program's folder with the file selected, to look at it before answering.</summary>
    void OnOpenFolder(object sender, RoutedEventArgs e)
    {
        if (File.Exists(program))
            Process.Start(new ProcessStartInfo("explorer.exe") { ArgumentList = { $"/select,{program}" }, UseShellExecute = false });
    }

    void UpdateCountdown()
    {
        var left = deadline - DateTimeOffset.Now;
        if (left <= TimeSpan.Zero)
        {
            Finish(ConsentChoice.Deny);
            return;
        }
        Countdown.Text = Text.Format("Consent_Countdown", $"{(int)left.TotalMinutes}:{left.Seconds:00}");
    }

    void Finish(ConsentChoice result)
    {
        if (!answer.TrySetResult(result))
            return;
        tick.Stop();
        Close();
    }

    void OnAllowOnce(object sender, RoutedEventArgs e) => Finish(ConsentChoice.AllowOnce);

    void OnAllowSession(object sender, RoutedEventArgs e) => Finish(ConsentChoice.AllowForSession);

    void OnDeny(object sender, RoutedEventArgs e) => Finish(ConsentChoice.Deny);

    void OnNotMe(object sender, RoutedEventArgs e) => Finish(ConsentChoice.NotMe);

    protected override void OnClosing(CancelEventArgs e)
    {
        answer.TrySetResult(ConsentChoice.Deny);
        tick.Stop();
        base.OnClosing(e);
    }
}
