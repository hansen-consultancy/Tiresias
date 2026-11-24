using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Tiresias.Agent;
using Tiresias.App.Logic;
using Tiresias.EnvironmentVariables;

namespace Tiresias.App.Views;

/// <summary>
/// The sealed environment: user environment variables moved out of Windows, put back, added and
/// removed. Values are typed here but never shown; the window is excluded from screen capture.
/// </summary>
public partial class EnvironmentPage : UserControl
{
    readonly EnvironmentViewModel model = new();

    public EnvironmentPage()
    {
        InitializeComponent();
        DataContext = model;
        Loaded += async (_, _) =>
        {
            await model.LoadAsync();
            ShowPick();
        };
    }

    /// <summary>A finding's fix: <paramref name="variable"/> checked under Sealed, <paramref name="service"/> chosen, and the placeholder section in view.</summary>
    public void PickForPlaceholder(string variable, string? service)
    {
        model.Pick = (variable, service);
        if (IsLoaded)
            ShowPick();
    }

    void ShowPick()
    {
        if (model.ApplyPick())
        {
            PlaceholderSection.IsExpanded = true;
            PlaceholderSection.BringIntoView();
        }
    }

    void OnBrowse(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog { Title = Text.Get("Env_FolderPick") };
        if (dialog.ShowDialog(Window.GetWindow(this)) == true)
            model.NewFolder = dialog.FolderName;
    }

    void OnAdd(object sender, RoutedEventArgs e)
    {
        model.Add(NewValue.Password);
        NewValue.Clear();
    }

}

/// <param name="folder">For a sealed variable kept for one folder: that folder; <c>null</c> for the global set and for Windows' own.</param>
/// <param name="canPick">False for a row shown only to say why nothing can be done with it.</param>
public sealed partial class VariableRow(string name, string detail, bool isChecked, string? folder = null, bool canPick = true) : ObservableObject
{
    public string Name { get; } = name;

    public bool CanPick { get; } = canPick;

    public string? Folder { get; } = folder;

    public string Detail { get; } = detail;

    [ObservableProperty]
    public partial bool IsChecked { get; set; } = isChecked;

    public IReadOnlyList<DetailField> Details => [new(Text.Get("Env_ColName"), Name), new(Text.Get("Env_ColDetail"), Detail)];
}

public sealed partial class EnvironmentViewModel : ObservableObject
{
    public ObservableCollection<VariableRow> Sealed { get; } = [];

    public ObservableCollection<VariableRow> InWindows { get; } = [];

    /// <summary>Package sources NuGet asks Tiresias for; <see cref="VariableRow.Name"/> is the source URL.</summary>
    public ObservableCollection<VariableRow> NuGetMapped { get; } = [];

    /// <summary>Credentials still in NuGet.Config, in the order of <see cref="nugetSteps"/>.</summary>
    public ObservableCollection<VariableRow> NuGetFound { get; } = [];

    IReadOnlyList<NuGetImportStep> nugetSteps = [];

    /// <summary>Vault services a placeholder can stand in for.</summary>
    public ObservableCollection<string> PlaceholderServices { get; } = [];

    [ObservableProperty]
    public partial string? PlaceholderService { get; set; }

    /// <summary>Empty means the name that follows from the variable's (<c>OPENAI_API_KEY</c> gives <c>OPENAI_BASE_URL</c>).</summary>
    [ObservableProperty]
    public partial string PlaceholderBaseUrl { get; set; } = "";

    [ObservableProperty]
    public partial string PlaceholderSummary { get; set; } = "";

    [ObservableProperty]
    public partial string NuGetSummary { get; set; } = "";

    [ObservableProperty]
    public partial Visibility NuGetMappedVisibility { get; set; } = Visibility.Collapsed;

    /// <summary>The NuGet card opens when it lists a feed, mapped or found (docs/app-design.md, rule 3).</summary>
    [ObservableProperty]
    public partial bool NuGetListsFeeds { get; set; }

    /// <summary>The Windows card lists every user variable; it opens only when one looks like a secret.</summary>
    [ObservableProperty]
    public partial bool WindowsHasSecrets { get; set; }

    [ObservableProperty]
    public partial Visibility NuGetFoundVisibility { get; set; } = Visibility.Collapsed;

    [ObservableProperty]
    public partial bool CanEdit { get; set; }

    [ObservableProperty]
    public partial string Message { get; set; } = "";

    [ObservableProperty]
    public partial string SealedSummary { get; set; } = "";

    [ObservableProperty]
    public partial string WindowsSummary { get; set; } = "";

    [ObservableProperty]
    public partial string NewName { get; set; } = "";

    /// <summary>Empty for the global set; a folder keeps the variable for commands run in it and below.</summary>
    [ObservableProperty]
    public partial string NewFolder { get; set; } = "";

    /// <summary>Unlocks if needed (one Windows Hello prompt), then lists both sides.</summary>
    public async Task LoadAsync()
    {
        if (!App.Current.Host.Keys.IsUnlocked && !(await App.Current.UnlockAsync(PromptReason.EnvironmentVariables, interactive: true)).Ok)
        {
            Message = Text.Get("Env_Locked");
            return;
        }
        Refresh();
    }

    void Refresh()
    {
        if (App.Current.Host.Keys.Hello is not { } hello)
        {
            CanEdit = false;
            Message = Text.Get("Env_Locked");
            return;
        }
        var sealedNow = EnvironmentStore.Open(hello).Environment;
        var user = EnvironmentStore.UserVariables();
        Sealed.Clear();
        foreach (var variable in sealedNow.Global)
            Sealed.Add(new(variable.Name, sealedNow.PlaceholderFor(variable.Name) is { } placeholder ? Text.Format("Env_DetailPlaceholder", placeholder.Service) : "", false));
        foreach (var set in sealedNow.Folders.OrderBy(f => f.Folder, StringComparer.OrdinalIgnoreCase))
            foreach (var variable in set.Variables)
                Sealed.Add(new(variable.Name, Text.Format("Env_DetailFolder", set.Folder), false, set.Folder));
        InWindows.Clear();
        // A decoy is bait left for whatever reads the environment: listed, so it isn't a mystery, but never ticked or sealed.
        var secrets = user.Count(v => v.LooksSecret && !v.Decoy);
        foreach (var variable in user.OrderBy(v => v.Decoy).ThenByDescending(v => v.LooksSecret))
            InWindows.Add(variable.Decoy
                ? new(variable.Name, Text.Get("Env_DetailDecoy"), false, canPick: false)
                : new(variable.Name, Text.Format(variable.LooksSecret ? "Env_DetailSecret" : "Env_Detail", variable.Length), variable.LooksSecret));
        SealedSummary = Sealed.Count == 0 ? Text.Get("Env_NoneSealed") : Text.Format("Env_SealedSummary", Sealed.Count);
        var decoys = user.Where(v => v.Decoy).Select(v => v.Name).ToArray();
        WindowsSummary = (secrets > 0 ? Text.Format("Env_WindowsSummary", secrets, user.Count - decoys.Length) : Text.Format("Env_WindowsNoSecrets", user.Count - decoys.Length))
            + (decoys.Length > 0 ? " " + Text.Format("Env_WindowsDecoys", string.Join(", ", decoys)) : "");
        WindowsHasSecrets = secrets > 0;
        RefreshNuGet(sealedNow);
        RefreshPlaceholders();
        CanEdit = true;
    }

    /// <summary>A variable and service to select once loaded, from a finding's fix.</summary>
    internal (string Variable, string? Service)? Pick { get; set; }

    /// <summary>Checks the picked variable alone and chooses its service; whether there was one to pick.</summary>
    internal bool ApplyPick()
    {
        if (Pick is not { } pick || !CanEdit)
            return false;
        Pick = null;
        foreach (var row in Sealed)
            row.IsChecked = row.Folder is null && string.Equals(row.Name, pick.Variable, StringComparison.OrdinalIgnoreCase);
        if (pick.Service is { Length: > 0 } service && PlaceholderServices.Contains(service))
            PlaceholderService = service;
        return true;
    }

    void RefreshPlaceholders()
    {
        var selected = PlaceholderService;
        PlaceholderServices.Clear();
        try
        {
            foreach (var slug in PlaceholderMinter.Services())
                PlaceholderServices.Add(slug);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            AppLog.Info($"environment: couldn't read the vault's services: {e.Message}");
        }
        PlaceholderService = selected is not null && PlaceholderServices.Contains(selected) ? selected : PlaceholderServices.FirstOrDefault();
        PlaceholderSummary = Text.Get(PlaceholderServices.Count == 0 ? "Env_PlaceholderNoServices" : "Env_PlaceholderSummary");
    }

    /// <summary>The one checked global variable is handed out as a placeholder for the chosen service from now on.</summary>
    [RelayCommand]
    void AddPlaceholder()
    {
        var picked = Checked(Sealed);
        if (picked.Length != 1 || picked[0].Folder is not null)
        {
            Message = Text.Get("Env_PlaceholderPickOne");
            return;
        }
        var name = picked[0].Name;
        if (PlaceholderService is not { } service)
        {
            Message = Text.Get("Env_PlaceholderNoServices");
            return;
        }
        var baseUrl = PlaceholderBaseUrl.Trim() is { Length: > 0 } typed ? typed : SealedEnvironment.BaseUrlVariableFor(name);
        if (baseUrl is null || baseUrl.Contains('=', StringComparison.Ordinal))
        {
            Message = Text.Get("Env_PlaceholderNeedsBaseUrl");
            return;
        }
        Act(picked, hello =>
        {
            var (environment, version) = EnvironmentStore.Open(hello);
            if (environment.IsSealedAnywhere(baseUrl))
                throw new InvalidOperationException(Text.Format("Env_PlaceholderBaseUrlSealed", baseUrl));
            EnvironmentStore.Save(environment.WithPlaceholder(new(name, service, baseUrl)), version, hello);
            return [Text.Format("Env_PlaceholderAddedItem", name, service, baseUrl)];
        }, "Env_PlaceholderAdded");
        PlaceholderBaseUrl = "";
    }

    /// <summary>The checked variables are handed out as their value again; the vault service keeps its secret.</summary>
    [RelayCommand]
    void RemovePlaceholder()
    {
        var picked = Checked(Sealed);
        Act(picked, hello =>
        {
            var (environment, version) = EnvironmentStore.Open(hello);
            var removing = picked.Select(r => r.Name).Where(n => environment.PlaceholderFor(n) is not null).ToArray();
            foreach (var name in removing)
                environment = environment.WithoutPlaceholder(name);
            EnvironmentStore.Save(environment, version, hello);
            return removing;
        }, "Env_PlaceholderRemoved");
    }

    /// <summary>The feeds mapped, and what NuGet.Config in the user's profile still holds. Read only; nothing changes until a button.</summary>
    void RefreshNuGet(SealedEnvironment sealedNow)
    {
        NuGetMapped.Clear();
        foreach (var source in sealedNow.NuGetSources)
            NuGetMapped.Add(new(source.Source, Text.Format("Env_NuGetMappedDetail", source.Variable, source.Username), false));
        NuGetFound.Clear();
        try
        {
            nugetSteps = NuGetImporter.Plan(sealedNow, directory: null);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            nugetSteps = [];
            AppLog.Info($"environment: couldn't read NuGet.Config: {e.Message}");
        }
        foreach (var step in nugetSteps)
            NuGetFound.Add(new(step.DisplayUrl ?? step.Credential.Key, step.Skip is { } why
                ? Text.Format("Env_NuGetSkip", why)
                : Text.Format(step.SealClearText ? "Env_NuGetSealClearText" : step.ProtectFirst ? "Env_NuGetProtect" : "Env_NuGetSealed", step.Variable, Path.GetFileName(step.File)),
                step.Acts, canPick: step.Acts));
        NuGetMappedVisibility = NuGetMapped.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        NuGetFoundVisibility = NuGetFound.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        NuGetListsFeeds = NuGetMapped.Count + NuGetFound.Count > 0;
        NuGetSummary = NuGetMapped.Count == 0 && NuGetFound.Count == 0 ? Text.Get("Env_NuGetNone")
            : nugetSteps.Any(s => s.Acts) ? Text.Get("Env_NuGetFoundSummary")
            : Text.Format("Env_NuGetSummary", NuGetMapped.Count);
    }

    /// <summary>Seals what the checked feeds need, maps them, and takes their credentials out of NuGet.Config, after a yes.</summary>
    [RelayCommand]
    void ImportNuGet()
    {
        var picked = nugetSteps.Where((s, i) => s.Acts && NuGetFound[i].IsChecked).ToArray();
        if (picked.Length == 0)
        {
            Message = Text.Get("Env_NothingPicked");
            return;
        }
        if (!AskWindow.Confirm(null, Text.Get("Env_NuGetImportTitle"),
                Text.Format("Env_NuGetImportBody", string.Join(", ", picked.Select(s => s.Credential.Key)), string.Join(", ", picked.Select(s => s.File).Distinct(StringComparer.OrdinalIgnoreCase))),
                Text.Get("Env_NuGetImport")))
            return;
        Act([.. picked.Select(s => new VariableRow(s.Credential.Key, "", true))], hello =>
        {
            NuGetImporter.Apply(picked, hello);
            return [.. picked.Select(s => s.Credential.Key)];
        }, "Env_NuGetImported");
    }

    /// <summary>NuGet stops asking Tiresias for the checked feeds; their variables stay sealed.</summary>
    [RelayCommand]
    void RemoveNuGet()
    {
        var picked = Checked(NuGetMapped);
        Act(picked, hello =>
        {
            var (environment, version) = EnvironmentStore.Open(hello);
            foreach (var row in picked)
                environment = environment.WithoutNuGetSource(row.Name);
            EnvironmentStore.Save(environment, version, hello);
            return [.. picked.Select(r => r.Name)];
        }, "Env_NuGetRemoved");
    }

    [RelayCommand]
    void Protect()
    {
        var picked = Checked(InWindows);
        Act(picked, hello => EnvironmentStore.Protect(picked.Select(r => r.Name), hello), "Env_Protected");
    }

    /// <summary>Only the global set came from Windows; a folder's variable stays sealed, and the message says so.</summary>
    [RelayCommand]
    void PutBack()
    {
        var picked = Checked(Sealed);
        var global = picked.Where(r => r.Folder is null).ToArray();
        if (picked.Length > 0 && global.Length == 0)
        {
            Message = Text.Get("Env_PutBackFolder");
            return;
        }
        Act(global, hello => EnvironmentStore.PutBack(global.Select(r => r.Name), hello), "Env_PutBackDone");
    }

    [RelayCommand]
    void Remove()
    {
        var picked = Checked(Sealed);
        if (picked.Length == 0 || !AskWindow.Confirm(null, Text.Get("Env_RemoveTitle"), Text.Format("Env_RemoveBody", string.Join(", ", picked.Select(r => r.Name))), Text.Get("Env_Remove")))
            return;
        Act(picked, hello =>
        {
            var (environment, version) = EnvironmentStore.Open(hello);
            environment = environment.WithoutGlobal(picked.Where(r => r.Folder is null).Select(r => r.Name));
            foreach (var folder in picked.Where(r => r.Folder is not null).GroupBy(r => r.Folder!, StringComparer.OrdinalIgnoreCase))
                environment = environment.WithoutFolder(folder.Key, folder.Select(r => r.Name));
            EnvironmentStore.Save(environment, version, hello);
            return [.. picked.Select(r => r.Name)];
        }, "Env_Removed");
    }

    public void Add(string value)
    {
        var name = NewName.Trim();
        var folder = NewFolder.Trim();
        if (name.Length == 0 || value.Length == 0 || name.Contains('=', StringComparison.Ordinal))
        {
            Message = Text.Get("Env_AddInvalid");
            return;
        }
        if (folder.Length > 0 && !Path.IsPathFullyQualified(folder))
        {
            Message = Text.Get("Env_FolderInvalid");
            return;
        }
        Act([new(name, "", true)], hello =>
        {
            var (environment, version) = EnvironmentStore.Open(hello);
            SealedVariable[] added = [new(name, value)];
            EnvironmentStore.Save(folder.Length == 0 ? environment.WithGlobal(added) : environment.WithFolder(Path.GetFullPath(folder), added), version, hello);
            return [name];
        }, "Env_Added");
        NewName = "";
    }

    static VariableRow[] Checked(IEnumerable<VariableRow> rows) => [.. rows.Where(r => r.IsChecked)];

    void Act(IReadOnlyList<VariableRow> picked, Func<Agent.HelloKeyWrapper, IReadOnlyList<string>> action, string done)
    {
        if (picked.Count == 0)
        {
            Message = Text.Get("Env_NothingPicked");
            return;
        }
        if (App.Current.Host.Keys.Hello is not { } hello)
        {
            Message = Text.Get("Env_Locked");
            return;
        }
        try
        {
            var result = action(hello);
            Message = Text.Format(done, string.Join(", ", result));
            AppLog.Info($"environment: {done} {result.Count} variable(s)");
        }
        catch (Exception e) when (e is InvalidOperationException or IOException or UnauthorizedAccessException or InvalidDataException)
        {
            ProblemWindow.Show(e, "environment variables");
        }
        Refresh();
    }
}
