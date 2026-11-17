using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using Tiresias.Agent;
using Tiresias.Protocol;
using Tiresias.UserSecrets;

namespace Tiresias.App.Views;

/// <summary>
/// The user-secrets editor: a project's keys with their values masked until shown one by one. The
/// window is excluded from screen capture, its values are dropped when the agent locks, and saving
/// always seals: there is no way to write the file back in clear.
/// </summary>
public partial class SecretsWindow : Window
{
    readonly SecretsViewModel model = new();

    public SecretsWindow()
    {
        InitializeComponent();
        Desktop.ExcludeFromCapture(this);
        DataContext = model;
        App.Current.Host.StateChanged += OnAgentStateChanged;
        Closed += (_, _) =>
        {
            App.Current.Host.StateChanged -= OnAgentStateChanged;
            model.Forget();
        };
    }

    void OnAgentStateChanged() => Dispatcher.BeginInvoke(() =>
    {
        if (!App.Current.Host.Keys.IsUnlocked)
            model.Forget();
    });

    protected override void OnClosing(CancelEventArgs e)
    {
        if (model.IsDirty)
        {
            var choice = MessageBox.Show(this, Text.Get("Secrets_UnsavedBody"), Text.Get("Secrets_UnsavedTitle"),
                MessageBoxButton.YesNoCancel, MessageBoxImage.Question, MessageBoxResult.Cancel);
            if (choice == MessageBoxResult.Cancel || (choice == MessageBoxResult.Yes && !model.TrySave()))
                e.Cancel = true;
        }
        base.OnClosing(e);
    }

    void OnClose(object sender, RoutedEventArgs e) => Close();
}

public sealed record ProjectChoice(string Id, string Label);

public sealed partial class SecretRow : ObservableObject
{
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsHidden))]
    public partial bool IsRevealed { get; set; }

    [ObservableProperty]
    public partial string Key { get; set; } = "";

    [ObservableProperty]
    public partial string Value { get; set; } = "";

    public bool IsHidden => !IsRevealed;
}

public sealed partial class SecretsViewModel : ObservableObject
{
    UserSecretsFolder? folder;
    UserSecretsLoad? loaded;
    IReadOnlyList<KeyValuePair<string, string>> original = [];

    public SecretsViewModel()
    {
        Projects = new(UserSecretsFiles.All().Select(f => new ProjectChoice(f.Id, Label(f))));
        State = Text.Get(Projects.Count == 0 ? "Secrets_StateNoProjects" : "Secrets_StatePick");
    }

    public ObservableCollection<ProjectChoice> Projects { get; }

    public ObservableCollection<SecretRow> Rows { get; } = [];

    [ObservableProperty]
    public partial ProjectChoice? SelectedProject { get; set; }

    [ObservableProperty]
    public partial SecretRow? SelectedRow { get; set; }

    [ObservableProperty]
    public partial string State { get; set; } = "";

    [ObservableProperty]
    public partial string Message { get; set; } = "";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(AddCommand), nameof(RemoveCommand), nameof(SaveCommand))]
    public partial bool CanEdit { get; set; }

    [ObservableProperty]
    public partial bool NeedsUnlock { get; set; }

    public bool IsDirty => CanEdit && !Edited().SequenceEqual(original);

    partial void OnSelectedProjectChanged(ProjectChoice? value) => _ = OpenAsync();

    [RelayCommand]
    async Task UnlockAsync()
    {
        var (ok, _) = await App.Current.UnlockAsync(interactive: true);
        if (ok)
            await OpenAsync();
    }

    [RelayCommand]
    void FindProject()
    {
        var dialog = new OpenFileDialog { Filter = Text.Get("Secrets_ProjectFilter"), Title = Text.Get("Secrets_FindProject") };
        if (dialog.ShowDialog() != true)
            return;
        try
        {
            var id = UserSecretsFiles.IdFromProject(dialog.FileName);
            var choice = Projects.FirstOrDefault(p => p.Id == id)
                ?? new ProjectChoice(id, $"{Path.GetFileNameWithoutExtension(dialog.FileName)} ({id})");
            if (!Projects.Contains(choice))
                Projects.Add(choice);
            SelectedProject = choice;
        }
        catch (Exception e) when (e is InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            Message = e.Message;
        }
    }

    [RelayCommand(CanExecute = nameof(CanEdit))]
    void Add()
    {
        var row = new SecretRow { IsRevealed = true };
        Rows.Add(row);
        SelectedRow = row;
    }

    [RelayCommand(CanExecute = nameof(CanEdit))]
    void Remove()
    {
        if (SelectedRow is { } row)
            Rows.Remove(row);
    }

    [RelayCommand(CanExecute = nameof(CanEdit))]
    void Save() => TrySave();

    public bool TrySave()
    {
        if (folder is null || loaded is null || App.Current.Host.Keys.Hello is not { } hello)
        {
            Message = Text.Get("Secrets_LockedCannotSave");
            return false;
        }
        try
        {
            var edited = Edited();
            var document = (JsonObject)loaded.Document.DeepClone();
            var changed = UserSecretsEdit.Apply(document, edited);
            UserSecretsFiles.Save(folder, loaded, document, hello);
            AppLog.Info($"user secrets {folder.Id}: saved, {changed} key(s) changed");
            Message = Text.Format("Secrets_Saved", changed);
            Load(folder, hello);
            return true;
        }
        catch (ArgumentException e)
        {
            // An empty or duplicate key: the user can fix it in place.
            Message = e.Message;
            return false;
        }
        catch (Exception e) when (e is InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            Message = Text.Get("Secrets_SaveFailed");
            ProblemWindow.Show(e, "saving user secrets");
            return false;
        }
    }

    /// <summary>Drops every value from memory, as when the agent locks.</summary>
    public void Forget()
    {
        foreach (var row in Rows)
            row.Value = "";
        Rows.Clear();
        loaded = null;
        original = [];
        CanEdit = false;
        NeedsUnlock = folder is not null;
        if (folder is not null)
            State = Text.Get("Secrets_StateLocked");
    }

    async Task OpenAsync()
    {
        Message = "";
        if (SelectedProject is not { } project)
            return;
        folder = UserSecretsFiles.Folder(project.Id);
        if (App.Current.Host.Keys.Hello is not { } hello)
        {
            Forget();
            return;
        }
        try
        {
            await Task.Yield();
            Load(folder, hello);
        }
        catch (Exception e) when (e is InvalidOperationException or IOException or UnauthorizedAccessException
            or System.Text.Json.JsonException or InvalidDataException or FormatException)
        {
            Forget();
            State = Text.Get("Secrets_StateUnreadable");
            ProblemWindow.Show(e, $"opening user secrets {project.Id}");
        }
    }

    void Load(UserSecretsFolder at, HelloKeyWrapper hello)
    {
        loaded = UserSecretsFiles.Open(at, hello);
        original = UserSecretsEdit.Flatten(loaded.Document);
        Rows.Clear();
        foreach (var (key, value) in original)
            Rows.Add(new SecretRow { Key = key, Value = value });
        CanEdit = true;
        NeedsUnlock = false;
        State = loaded.Version == 0
            ? Text.Format("Secrets_StateNotSealed", Rows.Count)
            : Text.Format("Secrets_StateSealed", Rows.Count, loaded.Version);
    }

    IReadOnlyList<KeyValuePair<string, string>> Edited() =>
        Rows.Select(r => new KeyValuePair<string, string>(r.Key.Trim(), r.Value)).ToArray();

    static string Label(UserSecretsFolder f) => f.Kind switch
    {
        SecretsFileKind.Sealed => Text.Format("Secrets_ProjectSealed", f.Id),
        SecretsFileKind.Plain => Text.Format("Secrets_ProjectPlain", f.Id),
        _ => f.Id,
    };
}

/// <summary><c>v:Password.Value</c>: a two-way bindable value for a <see cref="PasswordBox"/>, which has none by design.</summary>
public static class Password
{
    public static readonly DependencyProperty ValueProperty = DependencyProperty.RegisterAttached(
        "Value", typeof(string), typeof(Password), new FrameworkPropertyMetadata("", FrameworkPropertyMetadataOptions.BindsTwoWayByDefault, OnValueChanged));

    public static string GetValue(PasswordBox box) => (string)box.GetValue(ValueProperty);

    public static void SetValue(PasswordBox box, string value) => box.SetValue(ValueProperty, value);

    static void OnValueChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not PasswordBox box)
            return;
        box.PasswordChanged -= OnPasswordChanged;
        if (box.Password != (string)e.NewValue)
            box.Password = (string)e.NewValue;
        box.PasswordChanged += OnPasswordChanged;
    }

    static void OnPasswordChanged(object sender, RoutedEventArgs e)
    {
        var box = (PasswordBox)sender;
        SetValue(box, box.Password);
    }
}
