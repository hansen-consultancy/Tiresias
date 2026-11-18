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

    void OnAdd(object sender, RoutedEventArgs e)
    {
        model.Add(NewValue.Password);
        NewValue.Clear();
    }

    void OnClose(object sender, RoutedEventArgs e) => Close();
}

public sealed partial class VariableRow(string name, string detail, bool isChecked) : ObservableObject
{
    public string Name { get; } = name;

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
        var sealedNow = EnvironmentStore.Open(hello).Variables;
        var user = EnvironmentStore.UserVariables();
        Sealed.Clear();
        foreach (var variable in sealedNow)
            Sealed.Add(new(variable.Name, "", false));
        InWindows.Clear();
        foreach (var variable in user.OrderByDescending(v => v.LooksSecret))
            InWindows.Add(new(variable.Name,
                Text.Format(variable.LooksSecret ? "Env_DetailSecret" : "Env_Detail", variable.Length), variable.LooksSecret));
        SealedSummary = sealedNow.Count == 0 ? Text.Get("Env_NoneSealed") : Text.Format("Env_SealedSummary", sealedNow.Count);
        WindowsSummary = Text.Format("Env_WindowsSummary", user.Count(v => v.LooksSecret));
        CanEdit = true;
    }

    [RelayCommand]
    void Protect() => Act(InWindows, (names, hello) => EnvironmentStore.Protect(names, hello), "Env_Protected");

    [RelayCommand]
    void PutBack() => Act(Sealed, (names, hello) => EnvironmentStore.PutBack(names, hello), "Env_PutBackDone");

    [RelayCommand]
    void Remove()
    {
        var names = Checked(Sealed);
        if (names.Length == 0 || !AskWindow.Confirm(null, Text.Get("Env_RemoveTitle"), Text.Format("Env_RemoveBody", string.Join(", ", names)), Text.Get("Env_Remove")))
            return;
        Act(Sealed, (picked, hello) =>
        {
            var (variables, version) = EnvironmentStore.Open(hello);
            EnvironmentStore.Save(SealedVariables.Without(variables, picked), version, hello);
            return picked;
        }, "Env_Removed");
    }

    public void Add(string value)
    {
        var name = NewName.Trim();
        if (name.Length == 0 || value.Length == 0 || name.Contains('=', StringComparison.Ordinal))
        {
            Message = Text.Get("Env_AddInvalid");
            return;
        }
        Act([new(name, "", true)], (_, hello) =>
        {
            var (variables, version) = EnvironmentStore.Open(hello);
            EnvironmentStore.Save(SealedVariables.With(variables, [new(name, value)]), version, hello);
            return [name];
        }, "Env_Added");
        NewName = "";
    }

    static string[] Checked(IEnumerable<VariableRow> rows) => [.. rows.Where(r => r.IsChecked).Select(r => r.Name)];

    void Act(IEnumerable<VariableRow> rows, Func<IReadOnlyList<string>, Agent.HelloKeyWrapper, IReadOnlyList<string>> action, string done)
    {
        var names = Checked(rows);
        if (names.Length == 0)
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
            var result = action(names, hello);
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
