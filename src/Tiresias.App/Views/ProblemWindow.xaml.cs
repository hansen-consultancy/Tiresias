using System.Reflection;
using System.Windows;
using Tiresias.App.Logic;

namespace Tiresias.App.Views;

/// <summary>
/// Every error the user sees: what happened, why it matters, what to do next, a button that does
/// it, and "Copy details" for support. The exception itself goes to the log, never on screen.
/// </summary>
public partial class ProblemWindow : Window
{
    readonly Problem problem;
    readonly string? technical;

    ProblemWindow(Problem problem, string? technical, Action? retry, Action? finishSetup, Action? openStatus)
    {
        InitializeComponent();
        this.problem = problem;
        this.technical = technical;
        Title = Text.Of(problem.Title);
        Heading.Text = Text.Of(problem.Title);
        What.Text = Text.Of(problem.What);
        Why.Text = Text.Of(problem.Why);
        Next.Text = Text.Of(problem.Next);

        (string? label, Action? act) = problem.Action switch
        {
            ProblemAction.TryAgain when retry is not null => (Text.Get("Common_TryAgain"), retry),
            ProblemAction.OpenHelloSettings => (Text.Get("Problem_Action_HelloSettings"), Desktop.OpenHelloSettings),
            ProblemAction.OpenDataFolder => (Text.Get("Problem_Action_DataFolder"), Desktop.OpenDataFolder),
            ProblemAction.FinishSetup when finishSetup is not null => (Text.Get("Problem_Action_FinishSetup"), finishSetup),
            ProblemAction.OpenStatus when openStatus is not null => (Text.Get("Problem_Action_Status"), openStatus),
            _ => (null, null),
        };
        if (label is null)
            ActionButton.Visibility = Visibility.Collapsed;
        else
        {
            ActionButton.Content = label;
            ActionButton.Tag = act;
        }
    }

    /// <summary>Explains <paramref name="error"/> (logged in full) in its own window.</summary>
    /// <param name="retry">What "Try again" does, when trying again makes sense.</param>
    public static void Show(Exception error, string context, Action? retry = null, Action? finishSetup = null, Action? openStatus = null)
    {
        AppLog.Error(error, context);
        Show(Desktop.Classify(error), error.Message, retry, finishSetup, openStatus);
    }

    public static void Show(ProblemKind kind, string? technical = null, Action? retry = null, Action? finishSetup = null, Action? openStatus = null)
    {
        var window = new ProblemWindow(Problems.Explain(kind), technical, retry, finishSetup, openStatus);
        window.Show();
        window.Activate();
    }

    void OnAction(object sender, RoutedEventArgs e)
    {
        Close();
        (ActionButton.Tag as Action)?.Invoke();
    }

    void OnCopyDetails(object sender, RoutedEventArgs e)
    {
        var version = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "?";
        try
        {
            Clipboard.SetText(Problems.Details(problem, technical, version, AppLog.Path, DateTimeOffset.Now));
            Copied.Visibility = Visibility.Visible;
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            // Another program holds the clipboard; the button can simply be pressed again.
        }
    }

    void OnClose(object sender, RoutedEventArgs e) => Close();
}
