using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using Tiresias.Agent;
using Tiresias.App.Logic;
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
        Loaded += (_, _) => _ = model.RescanAsync();
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
            var choice = AskWindow.Show(this, Text.Get("Secrets_UnsavedTitle"), Text.Get("Secrets_UnsavedBody"),
                Text.Get("Secrets_Save"), Text.Get("Secrets_Discard"), Text.Get("Common_Cancel"));
            if (choice is null || (choice == true && !model.TrySave()))
                e.Cancel = true;
        }
        base.OnClosing(e);
    }

    void OnClose(object sender, RoutedEventArgs e) => Close();

    /// <summary>Opens <paramref name="id"/>'s secrets, as the status page's Review does.</summary>
    public void Select(string id) => model.Select(id);
}

/// <summary>One project in the picker.</summary>
/// <param name="Label">Name and state, as the list shows it.</param>
/// <param name="Group">Named projects, or the ids no known project uses.</param>
/// <param name="Detail">Where the project is, or why no project is named.</param>
public sealed record ProjectChoice(string Id, string Label, string Group, string Detail, bool Known);

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
    /// <summary>The window this model drives, so a question opens over it.</summary>
    static Window? Owner() => Application.Current.Windows.OfType<SecretsWindow>().FirstOrDefault();

    UserSecretsFolder? folder;
    UserSecretsLoad? loaded;
    IReadOnlyList<KeyValuePair<string, string>> original = [];
    bool relabelling;
    ProjectIndex index = ProjectIndexStore.Load();
    IReadOnlyList<string> unused = [];
    bool scanning, rescanQueued;

    /// <summary>Ids opened here (Find a project, the status page) that have no folder yet.</summary>
    readonly HashSet<string> extraIds = new(StringComparer.OrdinalIgnoreCase);

    public SecretsViewModel()
    {
        ProjectView = new ListCollectionView(Projects);
        ProjectView.GroupDescriptions.Add(new PropertyGroupDescription(nameof(ProjectChoice.Group)));
        Rebuild();
        State = Text.Get(Projects.Count == 0 ? "Secrets_StateNoProjects" : "Secrets_StatePick");
    }

    public ObservableCollection<ProjectChoice> Projects { get; } = [];

    /// <summary><see cref="Projects"/> grouped: named projects, then the ids no known project uses.</summary>
    public ListCollectionView ProjectView { get; }

    public ObservableCollection<string> Folders { get; } = [];

    public ObservableCollection<SecretRow> Rows { get; } = [];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectedDetail), nameof(CanRecycleSelected))]
    public partial ProjectChoice? SelectedProject { get; set; }

    public string SelectedDetail => SelectedProject?.Detail ?? "";

    /// <summary>The open project is one no scanned project uses, and its folder is there to move.</summary>
    public bool CanRecycleSelected => SelectedProject is { } p && unused.Contains(p.Id, StringComparer.OrdinalIgnoreCase);

    [ObservableProperty]
    public partial SecretRow? SelectedRow { get; set; }

    [ObservableProperty]
    public partial string State { get; set; } = "";

    [ObservableProperty]
    public partial string Message { get; set; } = "";

    [ObservableProperty]
    public partial string ScanStatus { get; set; } = "";

    [ObservableProperty]
    public partial string RecycleUnusedLabel { get; set; } = "";

    [ObservableProperty]
    public partial bool HasUnused { get; set; }

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(AddCommand), nameof(RemoveCommand), nameof(SaveCommand))]
    public partial bool CanEdit { get; set; }

    [ObservableProperty]
    public partial bool NeedsUnlock { get; set; }

    /// <summary>Open and still plaintext on disk: Seal now applies.</summary>
    [ObservableProperty]
    public partial bool IsPlain { get; set; }

    /// <summary>Open and sealed: Store in clear applies.</summary>
    [ObservableProperty]
    public partial bool IsSealed { get; set; }

    public void Select(string id)
    {
        if (!Projects.Any(p => string.Equals(p.Id, id, StringComparison.OrdinalIgnoreCase)))
        {
            extraIds.Add(id);
            Rebuild();
        }
        SelectedProject = Projects.First(p => string.Equals(p.Id, id, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Rescans the remembered folders in the background; a request during a scan runs one more after it.</summary>
    public async Task RescanAsync()
    {
        if (scanning)
        {
            rescanQueued = true;
            return;
        }
        scanning = true;
        try
        {
            do
            {
                rescanQueued = false;
                if (index.Folders.Count > 0)
                    ScanStatus = Text.Get("Secrets_Scanning");
                index = await Task.Run(() => ProjectIndexStore.Rescan());
                Rebuild();
            }
            while (rescanQueued);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            AppLog.Error(e, "scanning for projects");
            Rebuild();
        }
        finally
        {
            scanning = false;
        }
    }

    [RelayCommand]
    async Task AddFolderAsync()
    {
        var dialog = new OpenFolderDialog { Title = Text.Get("Secrets_FolderPickTitle") };
        if (dialog.ShowDialog(Owner()) != true)
            return;
        index = ProjectIndexStore.Update(i => i.WithFolder(dialog.FolderName));
        AppLog.Info($"project folder added: {dialog.FolderName}");
        await RescanAsync();
    }

    [RelayCommand]
    void RemoveFolder(string path)
    {
        index = ProjectIndexStore.Update(i => i.WithoutFolder(path));
        AppLog.Info($"project folder removed: {path}");
        Rebuild();
    }

    [RelayCommand]
    Task ScanNowAsync() => RescanAsync();

    [RelayCommand]
    void RecycleSelected()
    {
        if (SelectedProject is { } project && CanRecycleSelected)
            Recycle([project.Id]);
    }

    [RelayCommand]
    void RecycleUnused() => Recycle(unused);

    /// <summary>
    /// Moves folders no scanned project uses to the Recycle Bin, after asking: a project kept
    /// somewhere not scanned may still use one, and the Recycle Bin is where it comes back from.
    /// </summary>
    void Recycle(IReadOnlyList<string> ids)
    {
        if (ids.Count == 0)
            return;
        var body = Text.Format("Secrets_RecycleBody", ids.Count, string.Join(", ", index.Folders));
        if (!AskWindow.Confirm(Owner(), Text.Get("Secrets_RecycleTitle"), body, Text.Get("Secrets_Recycle")))
            return;
        if (SelectedProject is { } open && ids.Contains(open.Id, StringComparer.OrdinalIgnoreCase))
        {
            Forget();
            folder = null;
            NeedsUnlock = false;
            SelectedProject = null;
            State = Text.Get("Secrets_StatePick");
        }
        var failed = new List<string>();
        foreach (var id in ids.ToArray())
        {
            if (Desktop.Recycle(UserSecretsFiles.Folder(id).Directory))
                extraIds.Remove(id);
            else
                failed.Add(id);
        }
        AppLog.Info($"user secrets: {ids.Count - failed.Count} unused folder(s) moved to the Recycle Bin, {failed.Count} failed");
        var moved = ids.Count - failed.Count;
        Rebuild();
        Message = failed.Count == 0
            ? Text.Format("Secrets_Recycled", moved)
            : Text.Format("Secrets_RecycleFailed", string.Join(", ", failed));
    }

    [RelayCommand]
    void StoreInClear()
    {
        if (folder is null || loaded is null || App.Current.Host.Keys.Hello is not { } hello)
        {
            Message = Text.Get("Secrets_LockedCannotSave");
            return;
        }
        if (!AskWindow.Confirm(Owner(), Text.Get("Secrets_ClearConfirmTitle"), Text.Format("Secrets_ClearConfirmBody", folder.Id), Text.Get("Secrets_StoreInClear")))
            return;
        try
        {
            var document = (JsonObject)loaded.Document.DeepClone();
            UserSecretsEdit.Apply(document, Edited());
            UserSecretsFiles.StoreInClear(folder, document);
            AppLog.Info($"user secrets {folder.Id}: stored in clear");
            Load(folder, hello);
            Rebuild();
            Message = Text.Get("Secrets_StoredInClear");
        }
        catch (ArgumentException e)
        {
            Message = e.Message;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            ProblemWindow.Show(e, "storing user secrets in clear");
        }
    }

    public bool IsDirty => CanEdit && !Edited().SequenceEqual(original);

    partial void OnSelectedProjectChanged(ProjectChoice? value)
    {
        if (!relabelling)
            _ = OpenAsync();
    }

    [RelayCommand]
    async Task UnlockAsync()
    {
        var (ok, _) = await App.Current.UnlockAsync(interactive: true);
        if (ok)
            await OpenAsync();
    }

    /// <summary>Opens the project's secrets and remembers the project, so its name shows from now on.</summary>
    [RelayCommand]
    void FindProject()
    {
        var dialog = new OpenFileDialog { Filter = Text.Get("Secrets_ProjectFilter"), Title = Text.Get("Secrets_FindProject") };
        if (dialog.ShowDialog() != true)
            return;
        try
        {
            var id = UserSecretsFiles.IdFromProject(dialog.FileName);
            index = ProjectIndexStore.Update(i => i.Linked(new(Path.GetFullPath(dialog.FileName), id)));
            Rebuild();
            Select(id);
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
        // The first seal can break an app that doesn't use Tiresias yet: say so once, before it happens.
        if (loaded.Version == 0 && File.Exists(folder.FilePath)
            && !AskWindow.Confirm(Owner(), Text.Get("Secrets_SealConfirmTitle"), Text.Format("Secrets_SealConfirmBody", folder.Id), Text.Get("Secrets_Seal")))
            return false;
        try
        {
            var edited = Edited();
            var document = (JsonObject)loaded.Document.DeepClone();
            var changed = UserSecretsEdit.Apply(document, edited);
            UserSecretsFiles.Save(folder, loaded, document, hello);
            AppLog.Info($"user secrets {folder.Id}: saved, {changed} key(s) changed");
            Load(folder, hello);
            Rebuild();
            Message = Text.Format("Secrets_Saved", changed);
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
        IsPlain = false;
        IsSealed = false;
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
            ? Text.Format("Secrets_StateNotSealed", KeyCount(Rows.Count))
            : Text.Format("Secrets_StateSealed", KeyCount(Rows.Count), loaded.Version);
        IsPlain = loaded.Version == 0 && Rows.Count > 0;
        IsSealed = loaded.Version > 0;
    }

    /// <summary>
    /// Refills the picker from the folders on disk and the project index, keeping the open project
    /// selected without reopening it: after a scan, a save (the "(sealed)" label), or a removal.
    /// </summary>
    void Rebuild()
    {
        var folders = UserSecretsFiles.All();
        var kinds = folders.ToDictionary(f => f.Id, f => f.Kind, StringComparer.OrdinalIgnoreCase);
        var entries = ProjectList.Build(folders.Select(f => f.Id).Concat(extraIds), index);
        unused = [.. ProjectList.Unused(entries, index).Where(kinds.ContainsKey)];
        var selectedId = SelectedProject?.Id;
        relabelling = true;
        try
        {
            Projects.Clear();
            foreach (var entry in entries)
                Projects.Add(Choice(entry, kinds.GetValueOrDefault(entry.Id, SecretsFileKind.None)));
            SelectedProject = selectedId is null ? null : Projects.FirstOrDefault(p => string.Equals(p.Id, selectedId, StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            relabelling = false;
        }
        Folders.Clear();
        foreach (var path in index.Folders)
            Folders.Add(path);
        HasUnused = unused.Count > 0;
        RecycleUnusedLabel = Text.Format("Secrets_RecycleUnused", unused.Count);
        ScanStatus = index.Folders.Count == 0
            ? Text.Get("Secrets_NoFolders")
            : Text.Format("Secrets_Scanned", entries.Count(e => e.Known), entries.Count);
        OnPropertyChanged(nameof(SelectedDetail));
        OnPropertyChanged(nameof(CanRecycleSelected));
    }

    ProjectChoice Choice(ProjectEntry entry, SecretsFileKind kind)
    {
        var name = entry.Paths.Count > 1 ? Text.Format("Secrets_ProjectMore", entry.Name, entry.Paths.Count - 1) : entry.Name;
        var label = kind switch
        {
            SecretsFileKind.Sealed => Text.Format("Secrets_ProjectSealed", name),
            SecretsFileKind.Plain => Text.Format("Secrets_ProjectPlain", name),
            _ => name,
        };
        var detail = entry.Known
            ? string.Join(Environment.NewLine, entry.Paths)
            : Text.Get(index.Folders.Count == 0 ? "Secrets_NotScannedDetail" : "Secrets_NoProjectDetail");
        return new(entry.Id, label, Text.Get(entry.Known ? "Secrets_GroupProjects" : "Secrets_GroupUnknown"), detail, entry.Known);
    }

    IReadOnlyList<KeyValuePair<string, string>> Edited() =>
        Rows.Select(r => new KeyValuePair<string, string>(r.Key.Trim(), r.Value)).ToArray();

    static string KeyCount(int count) => count == 1 ? Text.Get("Secrets_KeyCountOne") : Text.Format("Secrets_KeyCount", count);
}

/// <summary>What a screen reader says for a folder's Remove button: which folder it stops scanning.</summary>
public sealed class RemoveFolderName : IValueConverter
{
    public static RemoveFolderName Instance { get; } = new();

    public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture) =>
        Text.Format("Secrets_RemoveFolderName", value);

    public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture) =>
        throw new NotSupportedException();
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
