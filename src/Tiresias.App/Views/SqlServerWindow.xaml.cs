using System.Collections.ObjectModel;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Tiresias.Agent;
using Tiresias.App.Logic;
using Tiresias.Vault;

namespace Tiresias.App.Views;

/// <summary>
/// "Set up a SQL Server": prepares one database for per-lease logins and adds it as a service, so
/// an app's <c>secrets.json</c> can say <c>tiresias:sql/{name}/read</c> instead of holding a
/// password. The administrator signs in once, for this window only; nothing about that sign-in is
/// kept. The work is <see cref="SqlServerSetup"/>; this window asks before anything that changes
/// what other vaults rely on. Running the setup again is safe: the script is idempotent.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001", Justification = "Closed disposes the model; WPF never disposes a Window.")]
public partial class SqlServerWindow : Window
{
    readonly SqlServerViewModel model = new();

    /// <summary>Raised after a service was saved, so the Services window can show it.</summary>
    public event Action<string>? Saved;

    public SqlServerWindow()
    {
        InitializeComponent();
        Desktop.ExcludeFromCapture(this, evenInDemo: true);
        DataContext = model;
        model.Saved += slug => Saved?.Invoke(slug);
        Closed += (_, _) => model.Dispose();
    }

    /// <summary>Filled in from a finding: the server and database a connection string named.</summary>
    public SqlServerWindow(string server, string? database)
        : this()
    {
        model.Server = server;
        model.Database = database ?? "";
    }

    void OnClose(object sender, RoutedEventArgs e) => Close();
}

public sealed partial class SqlServerViewModel : ObservableObject, IDisposable
{
    static Window? Owner() => Application.Current.Windows.OfType<SqlServerWindow>().FirstOrDefault();

    CancellationTokenSource? running;
    bool attempted;

    public event Action<string>? Saved;

    public ObservableCollection<string> Steps { get; } = [];

    public ObservableCollection<string> Warnings { get; } = [];

    public string WindowsLabel { get; } = Text.Format("Sql_Windows", $@"{Environment.UserDomainName}\{Environment.UserName}");

    [ObservableProperty]
    public partial string Server { get; set; } = "";

    [ObservableProperty]
    public partial string Database { get; set; } = "";

    [ObservableProperty]
    public partial string Slug { get; set; } = "";

    [ObservableProperty]
    public partial bool TrustServerCertificate { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(UseSqlLogin))]
    public partial bool UseWindows { get; set; } = true;

    public bool UseSqlLogin
    {
        get => !UseWindows;
        set => UseWindows = !value;
    }

    [ObservableProperty]
    public partial string User { get; set; } = "sa";

    [ObservableProperty]
    public partial string AdminPassword { get; set; } = "";

    [ObservableProperty]
    public partial string ServerError { get; set; } = "";

    [ObservableProperty]
    public partial string DatabaseError { get; set; } = "";

    [ObservableProperty]
    public partial string SlugError { get; set; } = "";

    [ObservableProperty]
    public partial string UserError { get; set; } = "";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsIdle), nameof(CanGoBack))]
    [NotifyCanExecuteChangedFor(nameof(SetUpCommand))]
    public partial bool IsBusy { get; set; }

    public bool IsIdle => !IsBusy;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsEditing), nameof(CanGoBack))]
    public partial bool IsDone { get; set; }

    public bool IsEditing => !IsDone;

    public bool CanGoBack => IsDone && !IsBusy;

    [ObservableProperty]
    public partial bool HasSteps { get; set; }

    [ObservableProperty]
    public partial string Failure { get; set; } = "";

    [ObservableProperty]
    public partial string DoneHeading { get; set; } = "";

    [ObservableProperty]
    public partial string Snippet { get; set; } = "";

    /// <summary>The database name suggests the service name until someone types one.</summary>
    bool slugTyped;

    partial void OnDatabaseChanged(string value)
    {
        if (!slugTyped)
        {
            var suggestion = new string(value.Trim().ToLowerInvariant().Select(c => char.IsAsciiLetterOrDigit(c) ? c : '-').ToArray()).Trim('-');
            Slug = suggestion;
            slugTyped = false;
        }
        Revalidate();
    }

    partial void OnSlugChanged(string value)
    {
        slugTyped = true;
        Revalidate();
    }

    partial void OnServerChanged(string value) => Revalidate();

    partial void OnUserChanged(string value) => UserError = "";

    partial void OnAdminPasswordChanged(string value) => UserError = "";

    void Revalidate()
    {
        if (attempted)
            Validate();
    }

    SqlServerSetupPlan? Validate()
    {
        SqlServerSetupPlan plan;
        try
        {
            plan = SqlServerSetupPlanner.Plan(new(Slug, Server, Database), VaultEditor.Load());
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException or System.Text.Json.JsonException)
        {
            Failure = Text.Get("Services_Unreadable");
            AppLog.Error(e, "sql setup: vault unreadable");
            return null;
        }
        ServerError = string.Join("\n", plan.Problems.Where(p => p.Field == SqlServerSetupField.Server).Select(p => p.Message));
        DatabaseError = string.Join("\n", plan.Problems.Where(p => p.Field == SqlServerSetupField.Database).Select(p => p.Message));
        SlugError = string.Join("\n", plan.Problems.Where(p => p.Field == SqlServerSetupField.Slug).Select(p => p.Message));
        return plan.Service is null ? null : plan;
    }

    bool CanSetUp() => !IsBusy;

    [RelayCommand(CanExecute = nameof(CanSetUp))]
    async Task SetUpAsync()
    {
        attempted = true;
        Failure = "";
        if (Validate() is not { } plan)
            return;
        if (UseSqlLogin && (User.Trim().Length == 0 || AdminPassword.Length == 0))
        {
            UserError = Text.Get("Sql_UserMissing");
            return;
        }
        if (App.Current.Host.Keys.Hello is null)
            await App.Current.UnlockAsync(PromptReason.DatabaseSetup, interactive: true);
        if (App.Current.Host.Keys.Hello is not { } hello)
        {
            Failure = Text.Get("Sql_Locked");
            return;
        }

        var admin = UseSqlLogin ? new SqlAdminSignIn(User.Trim(), AdminPassword) : new SqlAdminSignIn();
        running = new CancellationTokenSource();
        var ct = running.Token;
        Steps.Clear();
        Warnings.Clear();
        HasSteps = true;
        IsBusy = true;
        try
        {
            Steps.Add(Text.Format("Sql_StepConnecting", plan.Server));
            var state = await Task.Run(() => SqlServerSetup.InspectAsync(plan, admin, TrustServerCertificate, ct), ct);
            Steps.Add(Text.Format("Sql_StepConnected", state.Version));

            if (state.ProvisionerExists && !plan.Replaces
                && !AskWindow.Confirm(Owner(), Text.Get("Sql_ProvisionerExistsTitle"), Text.Format("Sql_ProvisionerExistsBody", plan.Server), Text.Get("Sql_SetUp")))
            {
                Steps.Add(Text.Get("Sql_StepStopped"));
                return;
            }

            var progress = new Progress<string>(Steps.Add);
            var result = await Task.Run(() => SqlServerSetup.RunAsync(plan, admin, TrustServerCertificate, hello, progress, ct), ct);
            if (!await PolicyApproval.ApplyAsync(Owner(), [result.Service], []))
            {
                Failure = Text.Get("Policy_Declined");
                return;
            }
            AppLog.Info($"sql setup: service {result.Service.Slug} saved for {result.Service.Upstream}");
            foreach (var warning in result.Warnings)
                Warnings.Add(warning);
            DoneHeading = Text.Format(plan.Replaces ? "Sql_DoneAgainHeading" : "Sql_DoneHeading", result.Service.Slug);
            Snippet = ServiceUsages.For(result.Service).Snippet;
            IsDone = true;
            Saved?.Invoke(result.Service.Slug);
        }
        catch (OperationCanceledException)
        {
            Steps.Add(Text.Get("Sql_StepStopped"));
        }
        catch (InvalidOperationException e)
        {
            Failure = e.Message;
            AppLog.Info($"sql setup failed: {e.Message}");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException
            or System.Text.Json.JsonException or System.Security.Cryptography.CryptographicException)
        {
            ProblemWindow.Show(e, "setting up a SQL Server");
        }
        finally
        {
            IsBusy = false;
            running.Dispose();
            running = null;
        }
    }

    [RelayCommand]
    void Copy() => Clipboard.SetText(Snippet);

    [RelayCommand]
    void Back()
    {
        IsDone = false;
        HasSteps = false;
        Steps.Clear();
        Warnings.Clear();
    }

    /// <summary>The window closed: stop a setup in progress (rerunning it is safe) and forget the password.</summary>
    public void Dispose()
    {
        running?.Cancel();
        AdminPassword = "";
    }
}
