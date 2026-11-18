using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Tiresias.Agent;
using Tiresias.EnvironmentVariables;

namespace Tiresias.App.Views;

/// <summary>
/// The sealed environment: user environment variables moved out of Windows, put back, added and
/// removed. Values are typed here but never shown; the window is excluded from screen capture.
/// </summary>
public partial class EnvironmentWindow : Window
{
    readonly EnvironmentViewModel model = new();

    public EnvironmentWindow()
    {
        InitializeComponent();
        Desktop.ExcludeFromCapture(this);
        DataContext = model;
        Loaded += async (_, _) => await model.LoadAsync();
    }

    void OnBrowse(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog { Title = Text.Get("Env_FolderPick") };
        if (dialog.ShowDialog(this) == true)
            model.NewFolder = dialog.FolderName;
    }

    void OnAdd(object sender, RoutedEventArgs e)
    {
        model.Add(NewValue.Password);
        NewValue.Clear();
    }

    void OnClose(object sender, RoutedEventArgs e) => Close();
}

/// <param name="folder">For a sealed variable kept for one folder: that folder; <c>null</c> for the global set and for Windows' own.</param>
public sealed partial class VariableRow(string name, string detail, bool isChecked, string? folder = null) : ObservableObject
{
    public string Name { get; } = name;

    public string? Folder { get; } = folder;

    public string Detail { get; } = detail;

    [ObservableProperty]
    public partial bool IsChecked { get; set; } = isChecked;
}

public sealed partial class EnvironmentViewModel : ObservableObject
{
    public ObservableCollection<VariableRow> Sealed { get; } = [];

    public ObservableCollection<VariableRow> InWindows { get; } = [];

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
        if (!App.Current.Host.Keys.IsUnlocked && !(await App.Current.UnlockAsync(interactive: true)).Ok)
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
            Sealed.Add(new(variable.Name, "", false));
        foreach (var set in sealedNow.Folders.OrderBy(f => f.Folder, StringComparer.OrdinalIgnoreCase))
            foreach (var variable in set.Variables)
                Sealed.Add(new(variable.Name, Text.Format("Env_DetailFolder", set.Folder), false, set.Folder));
        InWindows.Clear();
        foreach (var variable in user.OrderByDescending(v => v.LooksSecret))
            InWindows.Add(new(variable.Name,
                Text.Format(variable.LooksSecret ? "Env_DetailSecret" : "Env_Detail", variable.Length), variable.LooksSecret));
        SealedSummary = Sealed.Count == 0 ? Text.Get("Env_NoneSealed") : Text.Format("Env_SealedSummary", Sealed.Count);
        WindowsSummary = Text.Format("Env_WindowsSummary", user.Count(v => v.LooksSecret));
        CanEdit = true;
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
