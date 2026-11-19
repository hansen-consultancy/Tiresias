using System.IO;
using System.Security.Cryptography;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using Tiresias.Agent;
using Tiresias.Vault;

namespace Tiresias.App.Views;

/// <summary>
/// "Set up a RavenDB": seals a client certificate in the vault and adds the server as a service,
/// so an app's <c>secrets.json</c> can say <c>tiresias:raven/{name}</c> instead of pointing at a
/// .pfx. The certificate is checked against the database before anything is saved. The work is
/// <see cref="RavenSetup"/>; the picked file and its password stay in this window only.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001", Justification = "Closed disposes the model; WPF never disposes a Window.")]
public partial class RavenServerWindow : Window
{
    readonly RavenServerViewModel model = new();

    /// <summary>Raised after a service was saved, so the Services window can show it.</summary>
    public event Action<string>? Saved;

    /// <param name="existing">A service this setup saved, to edit: its certificate stays unless another file is picked.</param>
    public RavenServerWindow(RavenSetupInput? existing = null)
    {
        InitializeComponent();
        Desktop.ExcludeFromCapture(this);
        if (existing is not null)
            model.Edit(existing);
        DataContext = model;
        model.Saved += slug => Saved?.Invoke(slug);
        Closed += (_, _) => model.Dispose();
    }

    void OnClose(object sender, RoutedEventArgs e) => Close();
}

public sealed partial class RavenServerViewModel : ObservableObject, IDisposable
{
    static Window? Owner() => Application.Current.Windows.OfType<RavenServerWindow>().FirstOrDefault();

    CancellationTokenSource? running;
    bool attempted;
    byte[]? pfx;

    public event Action<string>? Saved;

    public System.Collections.ObjectModel.ObservableCollection<string> Steps { get; } = [];

    [ObservableProperty]
    public partial string Heading { get; set; } = Text.Get("Raven_Heading");

    [ObservableProperty]
    public partial string DatabaseHint { get; set; } = Text.Get("Raven_DatabaseHint");

    [ObservableProperty]
    public partial string Server { get; set; } = "";

    [ObservableProperty]
    public partial string Database { get; set; } = "";

    [ObservableProperty]
    public partial string Slug { get; set; } = "";

    [ObservableProperty]
    public partial bool AllowChanges { get; set; }

    [ObservableProperty]
    public partial string FileName { get; set; } = "";

    [ObservableProperty]
    public partial string CertificatePassword { get; set; } = "";

    [ObservableProperty]
    public partial string CertificateInfo { get; set; } = "";

    [ObservableProperty]
    public partial string CertificateError { get; set; } = "";

    [ObservableProperty]
    public partial string ServerError { get; set; } = "";

    [ObservableProperty]
    public partial string DatabaseError { get; set; } = "";

    [ObservableProperty]
    public partial string SlugError { get; set; } = "";

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
            Slug = new string(value.Trim().ToLowerInvariant().Select(c => char.IsAsciiLetterOrDigit(c) ? c : '-').ToArray()).Trim('-');
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

    partial void OnCertificatePasswordChanged(string value) => CertificateError = "";

    void Revalidate()
    {
        if (attempted)
            Validate();
    }

    RavenSetupPlan? Validate()
    {
        RavenSetupPlan plan;
        try
        {
            plan = RavenSetupPlanner.Plan(new(Slug, Server, Database, AllowChanges), VaultEditor.Load());
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException or System.Text.Json.JsonException)
        {
            Failure = Text.Get("Services_Unreadable");
            AppLog.Error(e, "raven setup: vault unreadable");
            return null;
        }
        ServerError = string.Join("\n", plan.Problems.Where(p => p.Field == RavenSetupField.Server).Select(p => p.Message));
        DatabaseError = string.Join("\n", plan.Problems.Where(p => p.Field == RavenSetupField.Database).Select(p => p.Message));
        SlugError = string.Join("\n", plan.Problems.Where(p => p.Field == RavenSetupField.Slug).Select(p => p.Message));
        return plan.Service is null ? null : plan;
    }

    /// <summary>
    /// Opens on a saved service. The database isn't part of the service, so it is asked again: the
    /// kept certificate is checked against it before the change is saved.
    /// </summary>
    public void Edit(RavenSetupInput existing)
    {
        slugTyped = true;
        Slug = existing.Slug;
        Server = existing.Server;
        AllowChanges = existing.AllowChanges;
        Heading = Text.Format("Raven_EditHeading", existing.Slug);
        DatabaseHint = Text.Get("Raven_EditDatabaseHint");
        CertificateInfo = Text.Get("Raven_Keeps");
    }

    [RelayCommand]
    void Browse()
    {
        var dialog = new OpenFileDialog { Filter = Text.Get("Raven_FileFilter"), Title = Text.Get("Raven_Browse") };
        if (dialog.ShowDialog() != true)
            return;
        Forget();
        try
        {
            pfx = File.ReadAllBytes(dialog.FileName);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            CertificateError = Text.Format("Raven_FileUnreadable", e.Message);
            return;
        }
        FileName = dialog.FileName;
        Inspect(quiet: true);
    }

    /// <param name="quiet">Just picked: a file that needs a password asks for one rather than reporting an error.</param>
    bool Inspect(bool quiet)
    {
        CertificateInfo = CertificateError = "";
        if (pfx is null)
        {
            CertificateError = Text.Get("Raven_FileMissing");
            return false;
        }
        try
        {
            var who = RavenSetup.Inspect(pfx, CertificatePassword);
            CertificateInfo = Text.Format("Raven_CertificateInfo", who.Subject, who.NotAfter.ToString("d", System.Globalization.CultureInfo.CurrentCulture), who.Thumbprint);
            return true;
        }
        catch (InvalidOperationException e)
        {
            if (quiet && CertificatePassword.Length == 0)
                CertificateInfo = Text.Get("Raven_NeedsPassword");
            else
                CertificateError = e.Message;
            return false;
        }
    }

    bool CanSetUp() => !IsBusy;

    [RelayCommand(CanExecute = nameof(CanSetUp))]
    async Task SetUpAsync()
    {
        attempted = true;
        Failure = "";
        var plan = Validate();
        // A service set up before keeps its certificate unless another file is picked.
        var keep = pfx is null && plan is { Replaces: true };
        if ((!keep && !Inspect(quiet: false)) || plan is null)
            return;
        if (App.Current.Host.Keys.Hello is null)
            await App.Current.UnlockAsync(interactive: true);
        if (App.Current.Host.Keys.Hello is not { } hello)
        {
            Failure = Text.Get("Raven_Locked");
            return;
        }

        running = new CancellationTokenSource();
        var ct = running.Token;
        var file = keep ? null : pfx;
        var password = CertificatePassword;
        Steps.Clear();
        HasSteps = true;
        IsBusy = true;
        try
        {
            var progress = new Progress<string>(Steps.Add);
            var service = await Task.Run(() => RavenSetup.RunAsync(plan, file, password, hello, progress, ct), ct);
            if (!await PolicyApproval.ApplyAsync(Owner(), [service], []))
            {
                Failure = Text.Get("Policy_Declined");
                return;
            }
            AppLog.Info($"raven setup: service {service.Slug} saved for {service.Upstream}");
            DoneHeading = Text.Format(keep ? "Raven_DoneEditHeading" : plan.Replaces ? "Sql_DoneAgainHeading" : "Sql_DoneHeading", service.Slug);
            Snippet = ServiceUsages.For(service, plan.Database).Snippet;
            IsDone = true;
            Saved?.Invoke(service.Slug);
        }
        catch (OperationCanceledException)
        {
            Steps.Add(Text.Get("Raven_StepStopped"));
        }
        catch (InvalidOperationException e)
        {
            Failure = e.Message;
            AppLog.Info($"raven setup failed: {e.Message}");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException
            or System.Text.Json.JsonException or CryptographicException)
        {
            ProblemWindow.Show(e, "setting up a RavenDB");
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
    }

    void Forget()
    {
        if (pfx is not null)
            CryptographicOperations.ZeroMemory(pfx);
        pfx = null;
        FileName = CertificateInfo = CertificateError = "";
    }

    /// <summary>The window closed: stop a check in progress and forget the file and its password.</summary>
    public void Dispose()
    {
        running?.Cancel();
        if (running is null)
            Forget();
        CertificatePassword = "";
    }
}
