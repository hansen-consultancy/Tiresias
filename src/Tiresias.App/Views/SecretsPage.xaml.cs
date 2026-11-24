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
public partial class SecretsPage : UserControl
{
    readonly SecretsViewModel model = new();

    public SecretsPage()
    {
        InitializeComponent();
        DataContext = model;
        App.Current.Host.StateChanged += OnAgentStateChanged;
        Loaded += (_, _) => _ = model.RescanAsync();
        Unloaded += (_, _) =>
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

    /// <summary>Asked before the shell leaves this page or closes: unsaved changes are saved, discarded, or keep it open.</summary>
    public bool CanLeave()
    {
        if (!model.IsDirty)
            return true;
        var choice = AskWindow.Show(Window.GetWindow(this), Text.Get("Secrets_UnsavedTitle"), Text.Get("Secrets_UnsavedBody"),
            Text.Get("Secrets_Save"), Text.Get("Secrets_Discard"), Text.Get("Common_Cancel"));
        return choice is not null && (choice == false || model.TrySave());
    }


    /// <summary>Opens <paramref name="id"/>'s secrets, as the status page's Review does.</summary>
    public void Select(string id) => model.Select(id);
}

/// <summary>One project in the picker.</summary>
/// <param name="Label">Name and state, as the list shows it.</param>
/// <param name="Group">Named projects, or the ids no known project uses.</param>
/// <param name="Detail">Where the project is, or why no project is named: one line however many checkouts use it.</param>
/// <param name="Paths">Every project file using the id, shown on demand.</param>
/// <param name="Content">What its file holds, read without unlocking: a sealed file counts as secrets.</param>
/// <param name="Name">The label without its state, which the list shows beside a mark of its own.</param>
/// <param name="PlainAdditions">Plain keys beside a sealed file's envelope, not sealed until the next run.</param>
public sealed record ProjectChoice(string Id, string Label, string Group, string Detail, bool Known, IReadOnlyList<string> Paths, SecretsContent Content,
    string Name, ProjectState State, int PlainAdditions)
{
    public string StateText => State == ProjectState.PlainAdded ? Text.Format("Secrets_State_PlainAdded", PlainAdditions) : Text.Get(State switch
    {
        ProjectState.Sealed => "Secrets_State_Sealed",
        ProjectState.NotSealed => "Secrets_State_NotSealed",
        ProjectState.Settings => "Secrets_State_Settings",
        ProjectState.Empty => "Secrets_State_Empty",
        _ => "Secrets_State_Invalid",
    });
}

public sealed partial class SecretRow : ObservableObject
{
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsHidden))]
    public partial bool IsRevealed { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Details))]
    public partial string Key { get; set; } = "";

    [ObservableProperty]
    public partial string Value { get; set; } = "";

    public bool IsHidden => !IsRevealed;

    public IReadOnlyList<DetailField> Details => [new(Text.Get("Secrets_ColKey"), Key)];
}

public sealed partial class SecretsViewModel : ObservableObject
{
    /// <summary>The window this model drives, so a question opens over it.</summary>
    static Window? Owner() => Application.Current.Windows.OfType<StatusWindow>().FirstOrDefault();

    UserSecretsFolder? folder;
    UserSecretsLoad? loaded;
    IReadOnlyList<KeyValuePair<string, string>> original = [];
    bool relabelling;
    ProjectIndex index = ProjectIndexStore.Load();
    IReadOnlyList<string> unused = [];
    IReadOnlyList<string> empties = [];
    bool scanning, rescanQueued;

    /// <summary>The open file is sealed and opened with no keys: nothing in it to protect.</summary>
    bool openedEmpty;

    /// <summary>The last rescan in this window finished: until it does, no id is called unused.</summary>
    bool scanned;

    /// <summary>Ids opened here (Find a project, the status page) that have no folder yet, or an empty one: listed anyway.</summary>
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
    [NotifyPropertyChangedFor(nameof(SelectedDetail), nameof(CanRecycleSelected), nameof(SelectedPaths), nameof(SelectedPathsHeader), nameof(SelectedPathsVisibility))]
    public partial ProjectChoice? SelectedProject { get; set; }

    public string SelectedDetail => SelectedProject?.Detail ?? "";

    public IReadOnlyList<string> SelectedPaths => SelectedProject?.Paths ?? [];

    public string SelectedPathsHeader => Text.Format("Finding_ShowAll", SelectedPaths.Count);

    public Visibility SelectedPathsVisibility => SelectedPaths.Count > 1 ? Visibility.Visible : Visibility.Collapsed;

    /// <summary>The open project's folder is there to move: no scanned project uses it, or it holds no keys.</summary>
    public bool CanRecycleSelected => SelectedProject is { } p
        && (unused.Contains(p.Id, StringComparer.OrdinalIgnoreCase) || empties.Contains(p.Id, StringComparer.OrdinalIgnoreCase) || openedEmpty);

    /// <summary>Empty folders are listed too: the foot line's link turns this on and off.</summary>
    [ObservableProperty]
    public partial bool ShowEmpty { get; set; }

    partial void OnShowEmptyChanged(bool value) => Rebuild();

    [ObservableProperty]
    public partial bool HasEmpty { get; set; }

    [ObservableProperty]
    public partial string EmptyFoldersLabel { get; set; } = "";

    [ObservableProperty]
    public partial string RecycleEmptyLabel { get; set; } = "";

    [ObservableProperty]
    public partial SecretRow? SelectedRow { get; set; }

    [ObservableProperty]
    public partial string State { get; set; } = "";

    [ObservableProperty]
    public partial string Message { get; set; } = "";

    [ObservableProperty]
    public partial string ScanStatus { get; set; } = "";

    /// <summary>What the side bar's count is made of: how many folders are sealed, not yet, settings only or empty.</summary>
    [ObservableProperty]
    public partial string Stats { get; set; } = "";

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
                scanned = true;
                Rebuild();
            }
            while (rescanQueued);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            AppLog.Error(e, "scanning for projects");
            scanned = false;
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
            Recycle([project.Id], empty: !unused.Contains(project.Id, StringComparer.OrdinalIgnoreCase));
    }

    [RelayCommand]
    void RecycleUnused() => Recycle(unused, empty: false);

    [RelayCommand]
    void RecycleEmpty() => Recycle(empties, empty: true);

    [RelayCommand]
    void ToggleEmpty() => ShowEmpty = !ShowEmpty;

    /// <summary>
    /// Moves folders to the Recycle Bin, after asking: a project kept somewhere not scanned may still
    /// use an unused one, and the Recycle Bin is where it comes back from. An <paramref name="empty"/>
    /// one holds no keys, and <c>dotnet user-secrets set</c> creates it again when a project needs it.
    /// </summary>
    void Recycle(IReadOnlyList<string> ids, bool empty)
    {
        if (ids.Count == 0)
            return;
        var body = empty
            ? Text.Format("Secrets_RecycleEmptyBody", ids.Count)
            : Text.Format("Secrets_RecycleBody", ids.Count, string.Join(", ", index.Folders));
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
        AppLog.Info($"user secrets: {ids.Count - failed.Count} {(empty ? "empty" : "unused")} folder(s) moved to the Recycle Bin, {failed.Count} failed");
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
        var (ok, _) = await App.Current.UnlockAsync(PromptReason.Secrets, interactive: true);
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
        // An empty file has nothing to protect: sealing it would only make it look like a real one.
        if (loaded.Keys.Count == 0 && Rows.Count == 0)
        {
            Message = Text.Get("Secrets_NothingToSeal");
            return true;
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
        openedEmpty = false;
        OnPropertyChanged(nameof(CanRecycleSelected));
        NeedsUnlock = folder is not null;
        if (folder is not null)
            State = Text.Get("Secrets_StateLocked");
    }

    async Task OpenAsync()
    {
        Message = "";
        if (SelectedProject is not { } project)
            return;
        try
        {
            folder = UserSecretsFiles.Folder(project.Id);
        }
        catch (InvalidOperationException e)
        {
            // A cloned project's <UserSecretsId> that would leave the user-secrets folder.
            folder = null;
            Forget();
            State = Text.Get("Secrets_StateUnreadable");
            ProblemWindow.Show(e, $"opening user secrets {project.Id}");
            return;
        }
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
        openedEmpty = loaded.Version > 0 && Rows.Count == 0;
        State = Rows.Count == 0 ? Text.Get(openedEmpty ? "Secrets_StateSealedEmpty" : "Secrets_StateEmpty")
            : loaded.Version == 0 ? Text.Format("Secrets_StateNotSealed", KeyCount(Rows.Count))
            : Text.Format("Secrets_StateSealed", KeyCount(Rows.Count), loaded.Version);
        IsPlain = loaded.Version == 0 && Rows.Count > 0;
        IsSealed = loaded.Version > 0;
        OnPropertyChanged(nameof(CanRecycleSelected));
    }

    /// <summary>
    /// Refills the picker from the folders on disk and the project index, keeping the open project
    /// selected without reopening it: after a scan, a save (the "(sealed)" label), or a removal.
    /// </summary>
    void Rebuild()
    {
        var folders = UserSecretsFiles.All();
        var kinds = folders.ToDictionary(f => f.Id, f => (f.Kind, f.Content, f.PlainAdditions), StringComparer.OrdinalIgnoreCase);
        var entries = ProjectList.Build(folders.Select(f => f.Id).Concat(extraIds), index);
        unused = scanned ? [.. ProjectList.Unused(entries, index).Where(kinds.ContainsKey)] : [];
        empties = [.. folders.Where(f => kinds[f.Id].Content == SecretsContent.Empty).Select(f => f.Id)];
        var listed = ProjectList.Listed(entries, id => kinds.TryGetValue(id, out var k) ? k.Content : SecretsContent.Empty, extraIds, ShowEmpty);
        var selectedId = SelectedProject?.Id;
        relabelling = true;
        try
        {
            Projects.Clear();
            foreach (var entry in listed)
                Projects.Add(Choice(entry, kinds.GetValueOrDefault(entry.Id, (SecretsFileKind.None, SecretsContent.Empty, 0))));
            SelectedProject = selectedId is null ? null : Projects.FirstOrDefault(p => string.Equals(p.Id, selectedId, StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            relabelling = false;
        }
        Folders.Clear();
        foreach (var path in index.Folders)
            Folders.Add(path);
        Stats = StatsLine(SecretsStats.Of(kinds.Values.Select(k => SecretsStats.StateOf(k.Kind, k.Content, k.PlainAdditions))));
        HasUnused = unused.Count > 0;
        RecycleUnusedLabel = Text.Format("Secrets_RecycleUnused", unused.Count);
        HasEmpty = empties.Count > 0;
        EmptyFoldersLabel = Text.Format(ShowEmpty ? "Secrets_EmptyFoldersHide" : "Secrets_EmptyFolders", empties.Count);
        RecycleEmptyLabel = Text.Format("Secrets_RecycleEmpty", empties.Count);
        ScanStatus = index.Folders.Count == 0
            ? Text.Get("Secrets_NoFolders")
            : Text.Format("Secrets_Scanned", entries.Count(e => e.Known), entries.Count);
        OnPropertyChanged(nameof(SelectedDetail));
        OnPropertyChanged(nameof(CanRecycleSelected));
    }

    ProjectChoice Choice(ProjectEntry entry, (SecretsFileKind Kind, SecretsContent Content, int PlainAdditions) file)
    {
        var paths = ProjectPaths.Of(entry.Paths);
        var name = paths.OnlyCheckouts ? Text.Format("Secrets_ProjectCheckouts", entry.Name, entry.Paths.Count)
            : paths.More > 0 ? Text.Format("Secrets_ProjectMore", entry.Name, paths.More)
            : entry.Name;
        var label = (file.Kind, file.Content) switch
        {
            (SecretsFileKind.Sealed, _) when file.PlainAdditions > 0 => Text.Format("Secrets_ProjectPlainAdded", name, file.PlainAdditions),
            (SecretsFileKind.Sealed, _) => Text.Format("Secrets_ProjectSealed", name),
            (_, SecretsContent.Empty) => Text.Format("Secrets_ProjectEmpty", name),
            (_, SecretsContent.Settings) => Text.Format("Secrets_ProjectSettings", name),
            (SecretsFileKind.Plain, _) => Text.Format("Secrets_ProjectPlain", name),
            _ => name,
        };
        var detail = !entry.Known ? Text.Get(index.Folders.Count == 0 ? "Secrets_NotScannedDetail" : "Secrets_NoProjectDetail")
            : paths.OnlyCheckouts ? Text.Format("Secrets_DetailCheckouts", paths.First, paths.Copies)
            : paths.More > 0 ? Text.Format("Secrets_DetailMore", paths.First, paths.More)
            : paths.First;
        return new(entry.Id, label, Text.Get(entry.Known ? "Secrets_GroupProjects" : "Secrets_GroupUnknown"), detail, entry.Known, entry.Paths, file.Content,
            name, SecretsStats.StateOf(file.Kind, file.Content, file.PlainAdditions), file.PlainAdditions);
    }

    static string StatsLine(SecretsStats stats)
    {
        var parts = new (int Count, string Key)[]
        {
            (stats.Sealed, "Secrets_Stats_Sealed"), (stats.PlainAdded, "Secrets_Stats_PlainAdded"), (stats.NotSealed, "Secrets_Stats_NotSealed"), (stats.Settings, "Secrets_Stats_Settings"),
            (stats.Empty, "Secrets_Stats_Empty"), (stats.Invalid, "Secrets_Stats_Invalid"),
        };
        return Text.Format("Secrets_Stats", stats.Total, string.Join(", ", parts.Where(p => p.Count > 0).Select(p => Text.Format(p.Key, p.Count))));
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
    // The default is null, not "": the box starts listening in OnValueChanged, which a binding to an
    // empty string would never raise, leaving the box deaf to typing.
    public static readonly DependencyProperty ValueProperty = DependencyProperty.RegisterAttached(
        "Value", typeof(string), typeof(Password), new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.BindsTwoWayByDefault, OnValueChanged));

    public static string GetValue(PasswordBox box) => (string?)box.GetValue(ValueProperty) ?? "";

    public static void SetValue(PasswordBox box, string value) => box.SetValue(ValueProperty, value);

    static void OnValueChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not PasswordBox box)
            return;
        box.PasswordChanged -= OnPasswordChanged;
        var value = (string?)e.NewValue ?? "";
        if (box.Password != value)
            box.Password = value;
        box.PasswordChanged += OnPasswordChanged;
    }

    static void OnPasswordChanged(object sender, RoutedEventArgs e)
    {
        var box = (PasswordBox)sender;
        SetValue(box, box.Password);
    }
}
