using System.Collections.ObjectModel;
using System.Text;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Tiresias.Agent;
using Tiresias.Policy;
using Tiresias.Vault;

namespace Tiresias.App.Views;

/// <summary>
/// The vault's services, as <c>tir service list|add|remove</c> sees them: slug, upstream and grants,
/// never a secret value. Adding goes through <see cref="ServicePlanner"/>, the same decision as the
/// CLI, and its problems are shown beside the field they are about. A new secret's value is typed
/// into a password box, so the window stays out of screen capture; the value is dropped when the
/// agent locks or the window closes. In solo mode the broker uses a saved service from its next
/// request.
/// </summary>
public partial class ServicesWindow : Window
{
    readonly ServicesViewModel model = new();

    public ServicesWindow()
    {
        InitializeComponent();
        Desktop.ExcludeFromCapture(this);
        DataContext = model;
        App.Current.Host.StateChanged += OnAgentStateChanged;
        Closed += (_, _) =>
        {
            App.Current.Host.StateChanged -= OnAgentStateChanged;
            model.Value = "";
        };
    }

    void OnAgentStateChanged() => Dispatcher.BeginInvoke(model.RefreshLockState);

    void OnClose(object sender, RoutedEventArgs e) => Close();
}

public sealed record ServiceRow(string Slug, string Upstream, string Grants);

public sealed partial class ServicesViewModel : ObservableObject
{
    bool attempted;

    public ServicesViewModel()
    {
        Reload();
        RefreshLockState();
    }

    public ObservableCollection<ServiceRow> Rows { get; } = [];

    /// <summary>Secret names already in the vault, to pick from instead of typing a new value.</summary>
    public ObservableCollection<string> Secrets { get; } = [];

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RemoveCommand))]
    public partial ServiceRow? SelectedRow { get; set; }

    [ObservableProperty]
    public partial string State { get; set; } = "";

    [ObservableProperty]
    public partial string Message { get; set; } = "";

    [ObservableProperty]
    public partial bool NeedsUnlock { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsListing))]
    public partial bool IsAdding { get; set; }

    public bool IsListing => !IsAdding;

    [ObservableProperty]
    public partial string Slug { get; set; } = "";

    [ObservableProperty]
    public partial string Upstream { get; set; } = "";

    [ObservableProperty]
    public partial string Secret { get; set; } = "";

    [ObservableProperty]
    public partial string Value { get; set; } = "";

    [ObservableProperty]
    public partial string Methods { get; set; } = "GET";

    [ObservableProperty]
    public partial string Allow { get; set; } = "";

    [ObservableProperty]
    public partial bool Elevation { get; set; }

    [ObservableProperty]
    public partial bool NeedsValue { get; set; }

    [ObservableProperty]
    public partial string SecretHint { get; set; } = "";

    [ObservableProperty]
    public partial string AllowHint { get; set; } = "";

    [ObservableProperty]
    public partial string SlugError { get; set; } = "";

    [ObservableProperty]
    public partial string UpstreamError { get; set; } = "";

    [ObservableProperty]
    public partial string SecretError { get; set; } = "";

    [ObservableProperty]
    public partial string ValueError { get; set; } = "";

    [ObservableProperty]
    public partial string MethodsError { get; set; } = "";

    [ObservableProperty]
    public partial string AllowError { get; set; } = "";

    /// <summary>Locked, the value just typed is forgotten, as the secrets editor forgets its values.</summary>
    public void RefreshLockState()
    {
        var unlocked = App.Current.Host.Keys.IsUnlocked;
        if (!unlocked)
            Value = "";
        NeedsUnlock = !unlocked;
        State = Text.Get(unlocked ? "Services_StateUnlocked" : "Services_StateLocked");
    }

    [RelayCommand]
    async Task UnlockAsync()
    {
        await App.Current.UnlockAsync(interactive: true);
        RefreshLockState();
    }

    [RelayCommand]
    void Add()
    {
        Slug = Upstream = Secret = Value = Allow = "";
        Methods = "GET";
        Elevation = false;
        attempted = false;
        ClearErrors();
        Message = "";
        IsAdding = true;
        Hints();
    }

    [RelayCommand]
    void Cancel()
    {
        Value = "";
        IsAdding = false;
        Message = "";
    }

    [RelayCommand(CanExecute = nameof(CanRemove))]
    void Remove()
    {
        if (SelectedRow is not { } row)
            return;
        if (MessageBox.Show(Text.Format("Services_RemoveConfirmBody", row.Slug), Text.Get("Services_RemoveConfirmTitle"),
                MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
            return;
        try
        {
            VaultEditor.RemoveService(row.Slug);
            AppLog.Info($"service {row.Slug} removed");
            Reload();
            Message = Text.Format("Services_Removed", row.Slug);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException or System.Text.Json.JsonException)
        {
            ProblemWindow.Show(e, "removing a service");
        }
    }

    bool CanRemove() => SelectedRow is not null;

    [RelayCommand]
    void Save()
    {
        attempted = true;
        VaultDocument vault;
        try
        {
            vault = VaultEditor.Load();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException or System.Text.Json.JsonException)
        {
            ProblemWindow.Show(e, "reading the vault");
            return;
        }
        var plan = Validate(vault);
        if (plan.Service is not { } service)
            return;
        if (plan.NeedsSecret)
        {
            if (App.Current.Host.Keys.Hello is not { } hello)
            {
                ValueError = Text.Get("Services_ValueLocked");
                return;
            }
            if (Value.Length == 0)
            {
                ValueError = Text.Get("Services_ValueEmpty");
                return;
            }
            var bytes = Encoding.UTF8.GetBytes(Value);
            try
            {
                VaultEditor.SealSecret(plan.SecretSlug, bytes, hello);
            }
            catch (Exception e) when (e is InvalidOperationException or IOException or UnauthorizedAccessException
                or InvalidDataException or System.Text.Json.JsonException or System.Security.Cryptography.CryptographicException)
            {
                ProblemWindow.Show(e, "sealing a service's secret");
                return;
            }
            finally
            {
                Array.Clear(bytes);
            }
            AppLog.Info($"secret {plan.SecretSlug} sealed for service {service.Slug}");
        }
        try
        {
            VaultEditor.AddService(service);
        }
        catch (Exception e) when (e is InvalidOperationException or IOException or UnauthorizedAccessException
            or InvalidDataException or System.Text.Json.JsonException)
        {
            ProblemWindow.Show(e, "adding a service");
            return;
        }
        AppLog.Info($"service {service.Slug} added");
        Value = "";
        IsAdding = false;
        Reload();
        SelectedRow = Rows.FirstOrDefault(r => r.Slug == service.Slug);
        Message = Text.Format(plan.AllowsEveryPath ? "Services_AddedEveryPath" : "Services_Added", service.Slug);
    }

    partial void OnSlugChanged(string value) => Changed();

    partial void OnUpstreamChanged(string value) => Changed();

    partial void OnSecretChanged(string value) => Changed();

    partial void OnMethodsChanged(string value) => Changed();

    partial void OnAllowChanged(string value) => Changed();

    partial void OnValueChanged(string value)
    {
        if (value.Length > 0)
            ValueError = "";
    }

    /// <summary>Hints follow every keystroke; problems only after the first Save, so an empty form isn't all red.</summary>
    void Changed()
    {
        if (!IsAdding)
            return;
        Hints();
        if (attempted)
        {
            try
            {
                Validate(VaultEditor.Load());
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException or System.Text.Json.JsonException)
            {
                // Save reports it; typing shouldn't.
            }
        }
    }

    void Hints()
    {
        var secret = Secret.Trim().Length > 0 ? Secret.Trim() : Slug.Trim();
        var known = Secrets.Contains(secret);
        NeedsValue = secret.Length > 0 && !known;
        SecretHint = secret.Length == 0 ? Text.Get("Services_SecretHint")
            : known ? Text.Format("Services_SecretExists", secret)
            : Text.Format("Services_SecretNew", secret);
        AllowHint = Text.Get(Allow.Trim().Length == 0 ? "Services_AllowEveryPath" : "Services_AllowHint");
    }

    ServicePlan Validate(VaultDocument vault)
    {
        var plan = ServicePlanner.Plan(new ServiceInput(
            Slug, Upstream, Secret,
            [Methods],
            Allow.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            RequiresElevation: Elevation), vault);
        ClearErrors();
        foreach (var problem in plan.Problems)
        {
            var text = Explain(problem);
            switch (problem.Field)
            {
                case ServiceField.Slug or ServiceField.Grant:
                    SlugError = Join(SlugError, text);
                    break;
                case ServiceField.Upstream:
                    UpstreamError = Join(UpstreamError, text);
                    break;
                case ServiceField.Secret:
                    SecretError = Join(SecretError, text);
                    break;
                case ServiceField.Methods:
                    MethodsError = Join(MethodsError, text);
                    break;
                default:
                    AllowError = Join(AllowError, text);
                    break;
            }
        }
        return plan;

        static string Join(string existing, string text) => existing.Length == 0 ? text : $"{existing}\n{text}";
    }

    /// <summary>The planner's problem in the app's words, which talk about fields rather than <c>tir</c>'s options.</summary>
    static string Explain(ServiceProblem problem) => problem.Kind switch
    {
        ServiceProblemKind.SlugInvalid => Text.Get("Services_ProblemSlugInvalid"),
        ServiceProblemKind.SlugTaken => Text.Format("Services_ProblemSlugTaken", problem.Value),
        ServiceProblemKind.UpstreamInvalid => Text.Format("Services_ProblemUpstreamInvalid", problem.Detail),
        ServiceProblemKind.UpstreamNotHttps => Text.Format("Services_ProblemUpstreamNotHttps", problem.Detail),
        ServiceProblemKind.SecretInvalid => Text.Get("Services_ProblemSecretInvalid"),
        ServiceProblemKind.GrantInvalid => Text.Get("Services_ProblemGrantInvalid"),
        ServiceProblemKind.MethodInvalid => Text.Format("Services_ProblemMethodInvalid", problem.Value),
        ServiceProblemKind.AllowInvalid or ServiceProblemKind.DenyInvalid => Text.Format("Services_ProblemPatternInvalid", problem.Value, problem.Detail),
        _ => problem.Message,
    };

    void ClearErrors() => SlugError = UpstreamError = SecretError = ValueError = MethodsError = AllowError = "";

    void Reload()
    {
        Rows.Clear();
        Secrets.Clear();
        VaultDocument vault;
        try
        {
            vault = VaultEditor.Load();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException or System.Text.Json.JsonException)
        {
            Message = Text.Get("Services_Unreadable");
            AppLog.Error(e, "services: vault unreadable");
            return;
        }
        foreach (var secret in vault.Secrets.Select(s => s.Slug).Order(StringComparer.Ordinal))
            Secrets.Add(secret);
        foreach (var service in vault.Services.OrderBy(s => s.Slug, StringComparer.Ordinal))
            Rows.Add(new(service.Slug, service.Upstream.ToString(), string.Join("\n", service.Grants.Select(g => Describe(g, vault)))));
        if (Rows.Count == 0)
            Message = Text.Get("Services_None");
    }

    static string Describe(Grant grant, VaultDocument vault)
    {
        var text = Text.Format("Services_Grant", grant.Name, string.Join(", ", grant.Rule.Methods.Order(StringComparer.Ordinal)),
            string.Join("  ", grant.Rule.Allow), grant.SecretSlug);
        if (grant.RequiresElevation)
            text += Text.Get("Services_GrantElevated");
        if (vault.FindSecret(grant.SecretSlug) is null)
            text += Text.Get("Services_GrantSecretMissing");
        return text;
    }
}
