using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using Tiresias.Agent;
using Tiresias.EnvironmentVariables;

namespace Tiresias.App.Views;

/// <summary>What happened after "This wasn't me".</summary>
/// <param name="Asked">The consent dialog's heading: what the program asked for.</param>
/// <param name="Program">The program's image path, or <c>null</c> when unknown.</param>
/// <param name="Process">The running process, when Tiresias could find it.</param>
/// <param name="Parents">The processes that started it, nearest first.</param>
/// <param name="Blocked">Whether the program is now on the blocklist.</param>
public sealed record IncidentView(string Asked, string? Program, ShellIdentity? Process, IReadOnlyList<string> Parents, bool Blocked);

/// <summary>
/// The follow-up to "This wasn't me": Tiresias is locked, and here is the program to look at, a way
/// to end it and where to scan. It changes nothing on the system itself: no network or security
/// setting, nothing that needs an administrator.
/// </summary>
public partial class IncidentWindow : Window
{
    readonly IncidentView view;

    IncidentWindow(IncidentView view)
    {
        InitializeComponent();
        this.view = view;
        What.Text = Text.Format("Incident_What", view.Asked);
        ProgramName.Text = view.Program is null ? Text.Get("Consent_ProgramUnknown") : Path.GetFileName(view.Program);
        ProgramFolder.Text = view.Program is null ? "" : Path.GetDirectoryName(view.Program) ?? "";
        ProgramFolder.Visibility = ProgramFolder.Text.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
        OpenFolderLine.Visibility = File.Exists(view.Program) ? Visibility.Visible : Visibility.Collapsed;
        Blocked.Text = Text.Get(view.Blocked ? "Incident_Blocked" : "Incident_NotBlocked");
        Parents.Text = view.Parents.Count == 0 ? Text.Get("Incident_ParentsUnknown") : string.Join(Environment.NewLine, view.Parents);
        ShowProcessState();
    }

    public static void Show(IncidentView view)
    {
        var window = new IncidentWindow(view);
        window.Show();
        window.Activate();
    }

    void ShowProcessState()
    {
        var running = view.Process is { } p && ProcessTree.IsRunning(p.ProcessId, p.Started);
        ProcessState.Text = view.Process is not { } process ? Text.Get("Incident_ProcessNotFound")
            : running ? Text.Format("Incident_ProcessRunning", process.ProcessId)
            : Text.Format("Incident_ProcessEnded", process.ProcessId);
        EndProcess.IsEnabled = running;
    }

    /// <summary>Ends the process itself, after checking its id still belongs to it rather than to a later process.</summary>
    void OnEndProcess(object sender, RoutedEventArgs e)
    {
        if (view.Process is not { } process || !ProcessTree.IsRunning(process.ProcessId, process.Started))
        {
            ShowProcessState();
            return;
        }
        try
        {
            using var running = System.Diagnostics.Process.GetProcessById(process.ProcessId);
            running.Kill();
            running.WaitForExit(TimeSpan.FromSeconds(5));
            AppLog.Info($"ended {process.Program} ({process.ProcessId}) after This wasn't me");
            ShowProcessState();
        }
        catch (Exception error) when (error is Win32Exception or InvalidOperationException or ArgumentException or NotSupportedException)
        {
            AppLog.Error(error, $"ending {process.Program} ({process.ProcessId})");
            ProcessState.Text = Text.Format("Incident_EndFailed", process.ProcessId, error.Message);
        }
    }

    void OnOpenFolder(object sender, RoutedEventArgs e)
    {
        if (File.Exists(view.Program))
            System.Diagnostics.Process.Start(new ProcessStartInfo("explorer.exe") { ArgumentList = { $"/select,{view.Program}" }, UseShellExecute = false })?.Dispose();
    }

    /// <summary>Windows Security on Virus &amp; threat protection, where the user picks a custom scan of the folder.</summary>
    void OnOpenSecurity(object sender, RoutedEventArgs e) => Desktop.Open("windowsdefender://threat/");

    void OnStatus(object sender, RoutedEventArgs e) => App.Current.ShowWindow<StatusWindow>();

    void OnClose(object sender, RoutedEventArgs e) => Close();
}
