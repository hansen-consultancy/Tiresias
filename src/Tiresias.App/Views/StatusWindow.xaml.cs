using System.Globalization;
using System.Collections.ObjectModel;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Tiresias.AdminTier;
using Tiresias.Agent;
using Tiresias.App.Logic;
using Tiresias.Client;
using Tiresias.Decoys;
using Tiresias.Vault;

namespace Tiresias.App.Views;

/// <summary>
/// The status page: the lock state and every <c>tir doctor</c> check, run on this machine. It follows
/// the agent: a lock or unlock from anywhere (tray, <c>tir</c>, a consent dialog, Win+L) re-runs it.
/// </summary>
public partial class StatusWindow : Window
{
    readonly StatusViewModel model = new();

    public StatusWindow()
    {
        InitializeComponent();
        // Pages show secret values (Secrets, Services, Environment), so the whole window stays out of capture.
        Desktop.ExcludeFromCapture(this);
        // Selected here, not in XAML: selecting there runs OnNav before the page host exists.
        Show(null);
        DataContext = model;
        Loaded += (_, _) => model.Refresh();
        // Back from a window opened here, Home may have a new area in use.
        Activated += (_, _) => model.ShowAreas();
        App.Current.Host.StateChanged += OnAgentStateChanged;
        App.Current.Guard.Changed += OnGuardChanged;
        App.Current.Host.DecoyTouched += OnDecoyTouched;
        App.Current.Alerts.Center.FailingChanged += OnAlertsFailingChanged;
        Closed += (_, _) =>
        {
            App.Current.Host.StateChanged -= OnAgentStateChanged;
            App.Current.Guard.Changed -= OnGuardChanged;
            App.Current.Host.DecoyTouched -= OnDecoyTouched;
            App.Current.Alerts.Center.FailingChanged -= OnAlertsFailingChanged;
        };
    }

    void OnGuardChanged() => Dispatcher.BeginInvoke(model.ShowGuard);

    /// <summary>A decoy use is a new finding: run the checks again.</summary>
    void OnDecoyTouched(DecoyTouch _) => Dispatcher.BeginInvoke(model.Refresh);

    /// <summary>A sink started or stopped failing: its finding comes or goes.</summary>
    void OnAlertsFailingChanged() => Dispatcher.BeginInvoke(model.Refresh);

    async void OnUnblock(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).DataContext is BlockedRow row)
            await UnblockAsync(row.Path);
    }

    /// <summary>With the admin tier, one UAC prompt thaws a program it froze, lifts its network block and unblocks it.</summary>
    async Task UnblockAsync(string program)
    {
        try
        {
            if (await AdminProgramBlocks.ListAsync() is not null &&
                (await AdminTierElevation.RunAsync("unblock-program", program) != AdminSetupResult.Done ||
                (await AdminProgramBlocks.ListAsync())?.Any(p => string.Equals(p.Path, program, StringComparison.OrdinalIgnoreCase)) != false))
            {
                model.GuardMessage = Text.Get("Status_UnblockIncomplete");
                return;
            }
            App.Current.Guard.Unblock(program);
            AppLog.Info($"unblocked {program}");
            model.Refresh();
        }
        catch (IOException e)
        {
            AppLog.Error(e, "unblocking program");
            model.GuardMessage = Text.Get("Status_BlocksUnavailable");
        }
    }

    /// <summary>Places one decoy at its default place, once the user agreed in the ask-first window.</summary>
    void OnPlaceDecoy(object sender, RoutedEventArgs e)
    {
        // A Hyperlink is a FrameworkContentElement, not a FrameworkElement.
        if (((FrameworkContentElement)sender).DataContext is not DecoyLink link)
            return;
        var where = DecoyStore.DefaultPath(link.Kind);
        var what = link.Kind switch
        {
            DecoyKind.PasswordsFile => where,
            DecoyKind.Project => Text.Format("Decoys_WhereProject", where),
            _ => Text.Format("Decoys_WhereVariables", string.Join(" and ", DecoyPlan.VariableNames)),
        };
        if (!AskWindow.Confirm(this, link.Label, Text.Format("Decoys_PlaceBody", what), Text.Get("Decoys_PlaceAction")))
            return;
        try
        {
            var placed = AdminDecoys.Place(link.Kind, link.Kind == DecoyKind.Variables ? null : where);
            AppLog.Info($"placed a decoy ({placed.Kind}) at {placed.Where}");
            model.ShowDecoys();
            // The doctor's decoys check says whether they are listened for.
            model.Refresh();
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            model.ShowDecoys(ex.Message);
        }
    }

    async void OnRemoveDecoys(object sender, RoutedEventArgs e)
    {
        if (!AskWindow.Confirm(this, Text.Get("Decoys_RemoveHeading"), Text.Get("Decoys_RemoveBody"), Text.Get("Decoys_RemoveAction")))
            return;
        // Held by the admin tier: getting the set back takes the UAC prompt; then it is removed as always.
        if (DecoyStore.Current is null && await Task.Run(AdminDecoys.Status) is ({ Held: true } or { NeedsVerification: true })
            && (await AdminTierElevation.RunAsync("release-decoys") is not AdminSetupResult.Done || DecoyStore.Current is null))
        {
            model.ShowDecoys(Text.Get("Decoys_StillHeld"));
            return;
        }
        var (left, kept) = DecoyStore.RemoveAll();
        AppLog.Info($"removed the decoys; {left.Count} left, {kept.Count} kept as changed");
        model.ShowDecoys(string.Join(" ", new[]
        {
            kept.Count == 0 ? "" : Text.Format("Decoys_RemoveKept", string.Join(", ", kept)),
            left.Count == 0 ? "" : Text.Format("Decoys_RemoveLeft", string.Join(", ", left)),
        }.Where(m => m.Length > 0)));
        model.Refresh();
    }

    async void OnEnrollDecoys(object sender, RoutedEventArgs e)
    {
        var result = await AdminTierElevation.RunAsync("adopt-decoys");
        model.ShowDecoys(result == AdminSetupResult.Done ? "" : Text.Get("Decoys_EnrollmentIncomplete"));
        model.Refresh();
    }

    void OnAgentStateChanged() => Dispatcher.BeginInvoke(model.Refresh);

    /// <summary>The environment page; its changes can clear the exposed-variables check, so coming back Home re-runs the checks.</summary>
    EnvironmentPage? ShowEnvironment() => Navigate<EnvironmentPage>();

    bool recheckOnHome;

    bool navigating;

    /// <summary>Shows page <typeparamref name="T"/>, new each time; <c>null</c> when the page open now keeps the window (unsaved secrets).</summary>
    public T? Navigate<T>() where T : UserControl, new()
    {
        if (!CanLeavePage())
            return null;
        var page = new T();
        recheckOnHome |= page is EnvironmentPage;
        Show(page);
        return page;
    }

    /// <summary>Back to Home, re-running the checks when the page left could have changed them.</summary>
    public void ShowHome()
    {
        if (!CanLeavePage())
            return;
        Show(null);
        if (recheckOnHome)
        {
            recheckOnHome = false;
            model.Refresh();
        }
        else
            model.ShowAreas();
    }

    void Show(UserControl? page)
    {
        PageHost.Content = page;
        PageHost.Visibility = page is null ? Visibility.Collapsed : Visibility.Visible;
        HomePage.Visibility = page is null ? Visibility.Visible : Visibility.Collapsed;
        navigating = true;
        Nav.SelectedItem = page switch
        {
            SecretsPage => NavSecrets,
            ServicesPage => NavServices,
            EnvironmentPage => NavEnvironment,
            ActivityPage => NavActivity,
            InstalledPage => NavInstalled,
            AboutPage => NavAbout,
            _ => NavHome,
        };
        navigating = false;
    }

    /// <summary>A page that edits what the agent serves is open, so the app must not quit or update under it.</summary>
    internal bool Editing => PageHost.Content is SecretsPage or ServicesPage;

    /// <summary>The last run's checks as text, for About's Copy details.</summary>
    internal string Details() => model.Details();

    internal bool CanLeavePage() => PageHost.Content is not SecretsPage secrets || secrets.CanLeave();

    void OnNav(object sender, SelectionChangedEventArgs e)
    {
        if (navigating || Nav.SelectedItem is not ListBoxItem { Tag: string place })
            return;
        object? shown = place switch
        {
            "Secrets" => Navigate<SecretsPage>(),
            "Services" => Navigate<ServicesPage>(),
            "Environment" => ShowEnvironment(),
            "Activity" => Navigate<ActivityPage>(),
            "Installed" => Navigate<InstalledPage>(),
            "About" => Navigate<AboutPage>(),
            _ => null,
        };
        if (place == "Home")
            ShowHome();
        if (PageHost.Content is not null && (place == "Home" || shown is null))
        {
            // The page open now kept the window: put the selection back on it.
            navigating = true;
            Nav.SelectedItem = e.RemovedItems.Count > 0 ? e.RemovedItems[0] : NavHome;
            navigating = false;
        }
    }

    /// <summary>Escape on a page goes back Home; on Home it closes the window.</summary>
    protected override void OnPreviewKeyDown(System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.Escape && System.Windows.Input.Keyboard.FocusedElement is not (TextBox or PasswordBox))
        {
            if (PageHost.Content is null)
                Close();
            else
                ShowHome();
            e.Handled = true;
        }
        base.OnPreviewKeyDown(e);
    }

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        if (!CanLeavePage())
            e.Cancel = true;
        base.OnClosing(e);
    }

    void OnAdd(object sender, RoutedEventArgs e) => App.Current.ShowWindow<NeedsWindow>();

    void OnRestore(object sender, RoutedEventArgs e)
    {
        var window = App.Current.ShowWindow<RecoveryWindow>();
        window.Closed -= OnRecoveryClosed;
        window.Closed += OnRecoveryClosed;
    }

    void OnRecoveryClosed(object? sender, EventArgs e) => model.Refresh();

    async void OnLookInside(object sender, RoutedEventArgs e) => await model.LookInsideAsync();

    /// <summary>Opens the window that fixes the row's finding, filled in from it.</summary>
    void OnReview(object sender, RoutedEventArgs e)
    {
        var fix = ((FrameworkElement)sender).DataContext switch
        {
            CheckRow row => row.Fix,
            FindingRow row => row.Check.Fix,
            _ => null,
        };
        switch (fix)
        {
            case ReviewUserSecrets { UserSecretsId: var id }:
                Navigate<SecretsPage>()?.Select(id);
                break;
            case ProtectVariables:
                ShowEnvironment();
                break;
            case SetUpSqlServer { Server: var server, Database: var database }:
                new SqlServerWindow(server, database) { Owner = this }.ShowDialog();
                model.Refresh();
                break;
            case SetUpRaven { CertificatePath: var path }:
                SetUpRaven(path);
                break;
            case ReferenceConfigurationPackage or ImportNuGetCredentials { InProfile: false }:
                model.CopyFix(fix.Instruction);
                break;
            case ImportNuGetCredentials:
                ShowEnvironment();
                break;
            case SealRegistryToken token:
                SealToken(token);
                break;
            case RemoveTokenFromRemote remote:
                model.CopyFix(remote.Instruction);
                break;
            case ReplaceRavenCertificate { Service: var slug }
                when VaultEditor.Load().FindService(slug) is { } service && RavenSetupPlanner.Recognize(service) is { } existing:
                new RavenServerWindow(existing) { Owner = this }.ShowDialog();
                model.Refresh();
                break;
            case UsePlaceholder { Variable: var variable, Service: var service }:
                ShowEnvironment()?.PickForPlaceholder(variable, service);
                break;
            case RemoveExtension remove:
                _ = RemoveExtensionAsync(remove);
                break;
            case RevealFile { Path: var path }:
                Desktop.Reveal(path);
                break;
            case DisableStartup { Machine: false } startup:
                TurnOffAtLogOn(startup);
                break;
            case DisableStartup:
                Desktop.Open("ms-settings:startupapps");
                break;
            case RemoveEntry { Machine: false } entry:
                _ = RemoveEntryAsync(entry);
                break;
            case RemoveEntry or Repair { Command: not null }:
                model.CopyFix(fix.Instruction);
                break;
            case UninstallApp:
                Navigate<InstalledPage>();
                break;
            case ReviewAlerts:
                Navigate<AboutPage>();
                break;
            case UnblockProgram { Path: var program }:
                _ = UnblockAsync(program);
                break;
            case ThawProgram { Path: var frozen }:
                _ = UnblockAsync(frozen);
                break;
            case RunThroughExec { Setup: { } setup }:
                Navigate<ServicesPage>()?.Add(setup.Upstream);
                break;
            case RunThroughExec exec:
                model.CopyFix(exec.Instruction);
                break;
            case InjectAtRunTime inject:
                model.CopyFix(inject.Commands);
                break;
            case ReachGuide:
                Desktop.Open(FindingView.ReachGuideUrl(AppBuild.Repository));
                break;
        }
    }

    /// <summary>Seal a registry token out of its file, once the user agreed to Tiresias reading it once.</summary>
    async void SealToken(SealRegistryToken token)
    {
        if (AskWindow.Show(this, Text.Get("Finding_TokenHeading"), Text.Format("Finding_TokenBody", token.File, token.Variable),
                Text.Get("Finding_TokenSeal"), cancel: Text.Get("Common_Cancel")) != true)
            return;
        if (!App.Current.Host.Keys.IsUnlocked && !(await App.Current.UnlockAsync(interactive: true)).Ok || App.Current.Host.Keys.Hello is not { } hello)
            return;
        try
        {
            RegistryTokenImporter.Import(token.File, token.Entry, token.Variable, hello);
        }
        catch (Exception e) when (e is InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            AskWindow.Show(this, null, e.Message, Text.Get("Common_OK"));
        }
        model.Refresh();
    }

    /// <summary>Runs the host's own uninstall command once the user approves, then checks again.</summary>
    async Task RemoveExtensionAsync(RemoveExtension remove)
    {
        if (!AskWindow.Confirm(this, Text.Format("Finding_RemoveExtensionHeading", remove.Id, remove.Host.Name),
                Text.Format("Finding_RemoveExtensionBody", remove.Instruction, remove.Host.Name), Text.Get("Finding_Remove")))
            return;
        var removed = await Desktop.RemoveExtensionAsync(remove);
        model.FindingMessage = removed
            ? Text.Format("Finding_Removed", remove.Id, remove.Host.Name)
            : Text.Format("Finding_RemoveFailed", remove.Id, remove.Instruction);
        if (removed)
            model.Refresh();
    }

    /// <summary>Turns a log-on entry off once the user approves, then checks again.</summary>
    void TurnOffAtLogOn(DisableStartup startup)
    {
        if (!AskWindow.Confirm(this, Text.Format("Finding_DisableStartupHeading", startup.Name), Text.Get("Finding_DisableStartupBody"), Text.Get("Finding_TurnOff")))
            return;
        var off = Desktop.DisableStartup(startup);
        model.FindingMessage = off ? Text.Format("Finding_StartupOff", startup.Name) : Text.Format("Finding_RemoveFailed", startup.Name, startup.Instruction);
        if (off)
            model.Refresh();
    }

    /// <summary>Saves and deletes an uninstall entry once the user approves, then checks again.</summary>
    async Task RemoveEntryAsync(RemoveEntry remove)
    {
        if (!AskWindow.Confirm(this, Text.Format("Finding_RemoveEntryHeading", remove.Name), Text.Get("Finding_RemoveEntryBody"), Text.Get("Finding_Remove")))
            return;
        var backup = await Desktop.RemoveEntryAsync(remove);
        model.FindingMessage = backup is not null
            ? Text.Format("Finding_EntryRemoved", remove.Name, backup)
            : Text.Format("Finding_RemoveFailed", remove.Name, remove.Instruction);
        if (backup is not null)
            model.Refresh();
    }

    /// <summary>Set up a RavenDB with the file found; once it is sealed, offer to move the file to the Recycle Bin.</summary>
    void SetUpRaven(string path)
    {
        var window = RavenServerWindow.ForFile(path);
        window.Owner = this;
        var saved = false;
        window.Saved += _ => saved = true;
        window.ShowDialog();
        if (saved && File.Exists(path)
            && AskWindow.Show(this, Text.Get("Finding_RecycleHeading"), Text.Format("Finding_RecycleBody", path),
                Text.Get("Finding_Recycle"), cancel: Text.Get("Finding_Keep"), safeFirst: true) == true
            && !Desktop.Recycle(path))
            AskWindow.Show(this, null, Text.Format("Finding_RecycleFailed", path), Text.Get("Common_OK"));
        model.Refresh();
    }

    void OnDismiss(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).DataContext is FindingRow row)
            row.IsDismissing = true;
    }

    void OnCancelDismiss(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).DataContext is FindingRow row)
        {
            row.IsDismissing = false;
            row.Reason = "";
        }
    }

    void OnConfirmDismiss(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).DataContext is FindingRow { CanDismiss: true } row)
            model.Dismiss(row.Checks, row.Reason);
    }

    void OnMoreFindings(object sender, RoutedEventArgs e) => model.ShowAllFindings();

    /// <summary>Opens a finding's card; on the page, the one open before closes, so one next step shows at a time.</summary>
    void OnOpenFinding(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).DataContext is FindingRow row)
            model.Open(row);
    }

    void OnRestoreFinding(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).DataContext is DismissedRow row)
            model.RestoreFindings(row.Keys);
    }
}

/// <summary>
/// A finding, or findings of one kind shown as one line with their count: where the delivery sits,
/// where its fix takes it, the fix (for one), its members (for a group), and Dismiss with a reason.
/// </summary>
public sealed partial class FindingRow(IReadOnlyList<DoctorCheck> checks) : ObservableObject
{
    public FindingRow(DoctorCheck check)
        : this([check])
    {
    }

    public IReadOnlyList<DoctorCheck> Checks { get; } = checks;

    /// <summary>The finding when there is one; for a group, the first, which speaks for the kind.</summary>
    public DoctorCheck Check => Checks[0];

    public bool IsGroup => Checks.Count > 1;

    /// <summary>A group's findings, each with its own fix and Dismiss; built when first shown.</summary>
    public IReadOnlyList<FindingRow> Members => members ??= IsGroup ? [.. Checks.Select(c => new FindingRow(c) { IsOpen = true })] : [];

    IReadOnlyList<FindingRow>? members;

    public Visibility MembersVisibility => IsGroup ? Visibility.Visible : Visibility.Collapsed;

    /// <summary>Open: the whole card with its fix; closed: one line to click. A group's members start open.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(OpenVisibility), nameof(ClosedVisibility))]
    public partial bool IsOpen { get; set; }

    public Visibility OpenVisibility => IsOpen ? Visibility.Visible : Visibility.Collapsed;

    public Visibility ClosedVisibility => IsOpen ? Visibility.Collapsed : Visibility.Visible;

    /// <summary>Its place in the list, shown in the badge; 0 for a group's member, which shows its status glyph instead.</summary>
    public int Number { get; init; }

    public Visibility NumberVisibility => Number > 0 ? Visibility.Visible : Visibility.Collapsed;

    public Visibility GlyphVisibility => Number > 0 ? Visibility.Collapsed : Visibility.Visible;

    public string Name { get; } = FindingView.Title(checks);

    public string Detail { get; } = FindingView.Detail(checks);

    public Visibility DetailVisibility => Detail.Length == 0 ? Visibility.Collapsed : Visibility.Visible;

    /// <summary>Where it is and where the fix takes it, in words; the codes stay in Copy details.</summary>
    public string Moves { get; } = PositionText.Moves(checks[0].Now, checks[0].Better);

    /// <summary><see cref="Moves"/> in three parts, so the place the fix leads to can stand out.</summary>
    public string MovesNow => Check.Now is { } now ? PositionText.Short(now) : "";

    public string MovesArrow => Check.Now is not null && Check.Better is not null ? " → " : "";

    public string MovesBetter => Check.Now is not null && Check.Better is { } better ? PositionText.Short(better) : "";

    public string? MovesMeaning => PositionText.Meaning(Check.Now, Check.Better) is { Length: > 0 } meaning ? meaning : null;

    /// <summary>Failure, warning, or for hygiene (status ok) a plain information mark.</summary>
    public string Glyph => Check.Status switch { DoctorStatus.Fail => "\uEA39", DoctorStatus.Warn => "\uE7BA", _ => "\uE946" };

    public Brush? Brush => Application.Current.TryFindResource(Check.Status switch
    {
        DoctorStatus.Fail => "SystemFillColorCriticalBrush",
        DoctorStatus.Warn => "SystemFillColorCautionBrush",
        _ => "TextFillColorSecondaryBrush",
    }) as Brush;

    public string FixLabel { get; } = FindingView.GroupButton(checks) is { } button ? Text.Get(button.Label) : "";

    public Visibility FixVisibility => FixLabel.Length == 0 ? Visibility.Collapsed : Visibility.Visible;

    public string FixName => Text.Format("Finding_FixName", FixLabel, Name);

    public string DismissLabel => Text.Get(IsGroup ? "Finding_DismissAll" : "Finding_Dismiss");

    public string DismissName => Text.Format("Finding_DismissName", Name);

    public string Spoken => $"{Name}. {Detail} {Moves}";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DismissingVisibility), nameof(ActionsVisibility))]
    public partial bool IsDismissing { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanDismiss))]
    public partial string Reason { get; set; } = "";

    public bool CanDismiss => !string.IsNullOrWhiteSpace(Reason);

    public Visibility DismissingVisibility => IsDismissing ? Visibility.Visible : Visibility.Collapsed;

    public Visibility ActionsVisibility => IsDismissing ? Visibility.Collapsed : Visibility.Visible;
}

/// <summary>Findings set aside together, with the reason given and Show again.</summary>
public sealed record DismissedRow(IReadOnlyList<string> Keys, string Name, string Reason)
{
    public string RestoreName => Text.Format("Finding_RestoreName", Name);
}

/// <summary>One check as a row. Status is said in words and a glyph, never by colour alone.</summary>
/// <param name="Fix">The check's fix; Review opens its window, for the fixes this window has one for.</param>
public sealed record CheckRow(string Name, string StatusText, string Glyph, Brush? Brush, string Detail, DoctorFix? Fix = null)
{
    public string Spoken => $"{Name}: {StatusText}. {Detail}";

    public Visibility ReviewVisibility => ReviewName.Length == 0 ? Visibility.Collapsed : Visibility.Visible;

    public string ReviewName => Fix switch
    {
        ReviewUserSecrets { UserSecretsId: var id } => Text.Format("Status_ReviewName", id),
        ProtectVariables => Text.Get("Status_ReviewEnvironment"),
        _ => "",
    };
}

/// <summary>A decoy placed, as Home's decoys card lists it.</summary>
public sealed record DecoyRow(string Name, string Where, string Since);

/// <summary>A link on the decoys card placing one kind at its default place.</summary>
public sealed record DecoyLink(DecoyKind Kind, string Label);

/// <summary>A program refused without asking since "This wasn't me".</summary>
public sealed record BlockedRow(string Path, string Since)
{
    public string UnblockName => Text.Format("Status_UnblockName", Path);
}

public sealed partial class StatusViewModel : ObservableObject
{
    public ObservableCollection<BlockedRow> Blocked { get; } = [];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(GuardVisibility))]
    public partial Visibility LockedDownVisibility { get; set; } = Visibility.Collapsed;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(GuardVisibility))]
    public partial string GuardMessage { get; set; } = "";

    public Visibility GuardVisibility => LockedDownVisibility == Visibility.Visible || Blocked.Count > 0 || GuardMessage.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
    int guardRead;

    /// <summary>The lockdown and the blocklist as they are now.</summary>
    public async void ShowGuard()
    {
        int read = ++guardRead;
        IReadOnlyList<AdminBlockedProgram> service = [];
        string message = "";
        try
        {
            service = await AdminProgramBlocks.ListAsync() ?? [];
        }
        catch (IOException e)
        {
            AppLog.Error(e, "reading blocked programs");
            message = Text.Get("Status_BlocksUnavailable");
        }
        if (read != guardRead)
            return;
        GuardMessage = message;
        var list = App.Current.Guard.Current;
        Blocked.Clear();
        var programs = service.Select(p => new BlockedProgram(p.Path, p.Sha256, p.Since)).Concat(list.Programs);
        foreach (var program in programs.DistinctBy(p => p.Path, StringComparer.OrdinalIgnoreCase).OrderByDescending(p => p.Since))
            Blocked.Add(new(program.Path, Text.Format("Status_BlockedSince", program.Since.ToLocalTime())));
        LockedDownVisibility = list.LockedDown ? Visibility.Visible : Visibility.Collapsed;
        OnPropertyChanged(nameof(GuardVisibility));
    }

    public ObservableCollection<DecoyRow> Decoys { get; } = [];

    public ObservableCollection<DecoyLink> DecoyLinks { get; } = [];

    [ObservableProperty]
    public partial Visibility DecoysRemovableVisibility { get; set; } = Visibility.Collapsed;

    [ObservableProperty]
    public partial Visibility DecoysEnrollVisibility { get; set; } = Visibility.Collapsed;

    /// <summary>Why the last place or remove fell short; empty when it didn't.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DecoyMessageVisibility))]
    public partial string DecoyMessage { get; set; } = "";

    public Visibility DecoyMessageVisibility => DecoyMessage.Length == 0 ? Visibility.Collapsed : Visibility.Visible;

    /// <summary>The decoys as <c>decoys.json</c> has them now.</summary>
    public void ShowDecoys(string message = "")
    {
        DecoySet? set;
        try
        {
            set = DecoyStore.Current;
        }
        catch (IOException)
        {
            set = null;
        }
        var card = DecoyCard.Of(set, AdminClient.Installed ? AdminDecoys.Status() : null);
        Decoys.Clear();
        foreach (var placed in card.Placed)
            Decoys.Add(new(Text.Get(DecoyCard.Keys(placed.Kind).Name), placed.Where, Text.Format("Decoys_Since", placed.Placed.ToLocalTime())));
        foreach (var kind in card.Held)
            Decoys.Add(new(Text.Get(DecoyCard.Keys(kind).Name), Text.Get(card.Listening ? "Decoys_Held" : "Decoys_PendingListener"), ""));
        DecoyLinks.Clear();
        foreach (var kind in card.Placeable)
            DecoyLinks.Add(new(kind, Text.Get(DecoyCard.Keys(kind).Place)));
        DecoysRemovableVisibility = card.Removable ? Visibility.Visible : Visibility.Collapsed;
        DecoysEnrollVisibility = card.CanEnroll ? Visibility.Visible : Visibility.Collapsed;
        DecoyMessage = message.Length == 0 && card.NeedsVerification ? Text.Get("Decoys_VerifyLegacy") : message;
    }

    [ObservableProperty]
    public partial string Headline { get; set; } = "";

    /// <summary>Solo or not: About shows it; Home keeps it only for Copy details.</summary>
    string mode = "";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Summary))]
    public partial bool IsRunning { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(RestoreVisibility))]
    public partial string RestoreText { get; set; } = "";

    public Visibility RestoreVisibility => RestoreText.Length == 0 ? Visibility.Collapsed : Visibility.Visible;

    static readonly string Build = Text.Format("Status_Build", Text.Of(AppBuild.Current.Label), AppBuild.Current.Folder);

    [ObservableProperty]
    public partial string LockLabel { get; set; } = "";

    /// <summary>Draws the lock beside the headline: open and green while unlocked.</summary>
    [ObservableProperty]
    public partial bool IsUnlocked { get; set; }

    /// <summary>Lock right here, or unlock with one Hello prompt; the agent's state change refreshes the page.</summary>
    [RelayCommand]
    async Task ToggleLockAsync()
    {
        if (App.Current.Host.Keys.IsUnlocked)
            await App.Current.LockAsync();
        else
            await App.Current.UnlockAsync(interactive: true);
    }

    /// <summary>Checks that warn or fail; they stay in view.</summary>
    public ObservableCollection<CheckRow> Checks { get; } = [];

    /// <summary>Checks that passed, behind one line.</summary>
    public ObservableCollection<CheckRow> Passed { get; } = [];

    public Visibility PassedVisibility => Passed.Count == 0 ? Visibility.Collapsed : Visibility.Visible;

    public string PassedHeader => Text.Format("Status_PassedHeader", Passed.Count);

    /// <summary>The passed checks, opened from the link at the foot of the page.</summary>
    [ObservableProperty]
    public partial bool ShowPassed { get; set; }

    [RelayCommand]
    void TogglePassed() => ShowPassed = !ShowPassed;

    /// <summary>The dismissed findings, opened from the link at the foot of the page.</summary>
    [ObservableProperty]
    public partial bool ShowDismissed { get; set; }

    [RelayCommand]
    void ToggleDismissed() => ShowDismissed = !ShowDismissed;

    /// <summary>The findings shown: the first <see cref="FirstFindings"/> until Show all, since the page has one scroll region and a drive of repositories has hundreds.</summary>
    public ObservableCollection<FindingRow> Findings { get; } = [];

    const int FirstFindings = 20;

    IReadOnlyList<FindingRow> allFindings = [];

    bool showAllFindings;

    public Visibility MoreFindingsVisibility => Findings.Count < allFindings.Count ? Visibility.Visible : Visibility.Collapsed;

    public string MoreFindingsLabel => Text.Format("Finding_ShowAll", allFindings.Count);

    public void ShowAllFindings()
    {
        showAllFindings = true;
        ShowFindings();
    }

    void ShowFindings()
    {
        Findings.Clear();
        foreach (var row in showAllFindings ? allFindings : allFindings.Take(FirstFindings))
            Findings.Add(row);
        OnPropertyChanged(nameof(MoreFindingsVisibility));
        OnPropertyChanged(nameof(MoreFindingsLabel));
    }

    /// <summary>Opens one finding and closes the rest on the page; a group's member opens on its own.</summary>
    public void Open(FindingRow row)
    {
        if (allFindings.Contains(row))
            foreach (var other in allFindings)
                other.IsOpen = ReferenceEquals(other, row);
        else
            row.IsOpen = true;
    }

    public ObservableCollection<DismissedRow> Dismissed { get; } = [];

    /// <summary>The page's heading: how many findings need you, else how many checks, else that nothing does.</summary>
    public string Summary => IsRunning && last.Count == 0 ? Text.Get("Status_Running")
        : allFindings.Count == 1 ? Text.Get("Status_SummaryOne")
        : allFindings.Count > 1 ? Text.Format("Status_SummaryMany", allFindings.Count)
        : Checks.Count == 1 ? Text.Get("Status_SummaryCheck")
        : Checks.Count > 0 ? Text.Format("Status_SummaryChecks", Checks.Count)
        : Text.Get("Status_SummaryNone");

    public int CheckCount => Math.Max(last.Count, 1);

    public int PassCount => Passed.Count;

    public string ProgressText => last.Count == 0 ? "" : Text.Format("Status_Progress", Passed.Count, last.Count);

    public Visibility DismissedVisibility => Dismissed.Count == 0 ? Visibility.Collapsed : Visibility.Visible;

    public string DismissedHeader => Text.Format("Finding_DismissedHeader", Dismissed.Count);

    /// <summary>A line under the findings: what was copied, or why a dismissal couldn't be kept.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FindingMessageVisibility))]
    public partial string FindingMessage { get; set; } = "";

    public Visibility FindingMessageVisibility => FindingMessage.Length == 0 ? Visibility.Collapsed : Visibility.Visible;

    /// <summary>The last run's lines, so a dismissal re-sorts them without probing the machine again.</summary>
    IReadOnlyList<DoctorCheck> last = [];

    bool rerun;

    /// <summary>Check now was pressed: the next run looks inside the Docker engine.</summary>
    bool lookInside;

    /// <summary>Looks inside the containers now, as part of a full run of the checks.</summary>
    public async Task LookInsideAsync()
    {
        lookInside = true;
        if (IsRunning)
            rerun = true;
        else
            await RunAsync();
    }

    /// <summary>The containers card: while an engine is open to every program, the way to look inside it.</summary>
    void ShowReach()
    {
        var setting = AppSettings.Load().ReachScan;
        ReachVisibility = last.Any(c => c.Name is Doctor.DockerEngineCheck or Doctor.WslDisksCheck or Doctor.WslContentsCheck) ? Visibility.Visible : Visibility.Collapsed;
        ReachText = ReachMemory.LookedAt is { } at ? Text.Format("Reach_Looked", at.ToLocalTime()) : Text.Get("Reach_Intro");
        ReachDailyVisibility = setting == ReachScan.Off ? Visibility.Collapsed : Visibility.Visible;
        isReachDaily = setting == ReachScan.Daily;
        OnPropertyChanged(nameof(IsReachDaily));
    }

    [ObservableProperty]
    public partial Visibility ReachVisibility { get; set; } = Visibility.Collapsed;

    [ObservableProperty]
    public partial string ReachText { get; set; } = "";

    [ObservableProperty]
    public partial Visibility ReachDailyVisibility { get; set; } = Visibility.Collapsed;

    bool isReachDaily;

    /// <summary>The Check daily switch, saved as it changes.</summary>
    public bool IsReachDaily
    {
        get => isReachDaily;
        set
        {
            if (isReachDaily == value)
                return;
            isReachDaily = value;
            (AppSettings.Load() with { ReachScan = value ? ReachScan.Daily : ReachScan.Once }).Save();
            OnPropertyChanged();
        }
    }

    /// <summary>The state line now, then the checks; a change during a run queues one more run rather than overlapping it.</summary>
    public void Refresh()
    {
        ShowState();
        if (IsRunning)
            rerun = true;
        else
            _ = RunAsync();
    }

    void ShowState()
    {
        ShowGuard();
        ShowDecoys();
        var view = TrayStatus.Describe(App.Current.Snapshot());
        Headline = Text.Of(view.Headline);
        mode = Text.Get(view.Mode is null ? "Status_ModeNone" : "Status_ModeSolo");
        IsUnlocked = App.Current.Host.Keys.IsUnlocked;
        LockLabel = Text.Get(IsUnlocked ? "Tray_Lock" : "Tray_Unlock");
        ShowAreas();
    }

    /// <summary>Home's areas: those in use, plus any a fix from the last run opens.</summary>
    public void ShowAreas()
    {
        areas = Home.Areas(last.Select(c => c.Fix).OfType<DoctorFix>());
        OnPropertyChanged(nameof(SecretsVisibility));
        OnPropertyChanged(nameof(ServicesVisibility));
        OnPropertyChanged(nameof(EnvironmentVisibility));
        OnPropertyChanged(nameof(ActivityVisibility));
        _ = ShowCountsAsync();
    }

    [ObservableProperty]
    public partial string SecretsCount { get; set; } = "";

    [ObservableProperty]
    public partial string ServicesCount { get; set; } = "";

    [ObservableProperty]
    public partial string VariablesCount { get; set; } = "";

    [ObservableProperty]
    public partial string ActivityCount { get; set; } = "";

    /// <summary>The counts beside the places; one that can't be read shows nothing rather than a guess.</summary>
    async Task ShowCountsAsync()
    {
        var counts = await Task.Run(Home.Counts);
        SecretsCount = Count(counts.Secrets);
        ServicesCount = Count(counts.Services);
        VariablesCount = Count(counts.Variables);
        ActivityCount = counts.ActivityToday is { } today ? Text.Format("Nav_ActivityToday", today) : "";
    }

    static string Count(int? count) => count?.ToString(CultureInfo.CurrentCulture) ?? "";

    IReadOnlySet<HomeArea> areas = new HashSet<HomeArea>();

    Visibility AreaVisibility(HomeArea area) => areas.Contains(area) ? Visibility.Visible : Visibility.Collapsed;

    public Visibility SecretsVisibility => AreaVisibility(HomeArea.UserSecrets);

    public Visibility ServicesVisibility => AreaVisibility(HomeArea.Services);

    public Visibility EnvironmentVisibility => AreaVisibility(HomeArea.EnvironmentVariables);

    public Visibility ActivityVisibility => AreaVisibility(HomeArea.Activity);

    [RelayCommand]
    async Task RunAsync()
    {
        IsRunning = true;
        last = [];
        Show();
        ShowState();
        try
        {
            // The project folders the secrets editor scans are where appsettings and certificates live.
            var clock = System.Diagnostics.Stopwatch.StartNew();
            var probe = new MachineProbe(ProjectIndexStore.Load().Folders)
            {
                Hello = App.Current.Host.Keys.Hello,
                FailingAlertSinks = App.Current.Alerts.Center.Failing,
            };
            var asked = lookInside;
            lookInside = false;
            last = await Task.Run(async () => await Doctor.RunAsync(probe, await ReachMemory.ForRunAsync(probe, asked)));
            ShowReach();
            var checks = clock.Elapsed;
            Show();
            // Measured until the page has been laid out and drawn, which is what the wait looks like.
            await Application.Current.Dispatcher.InvokeAsync(() => { }, System.Windows.Threading.DispatcherPriority.ContextIdle);
            var walk = probe.Scan is { } scan ? $", {scan.Elapsed.TotalSeconds:0.0}s walking {scan.Folders} folders for {scan.Files} files" : "";
            AppLog.Info($"status checks took {checks.TotalSeconds:0.0}s{walk}; showing {last.Count} lines took {(clock.Elapsed - checks).TotalSeconds:0.0}s more");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidDataException)
        {
            AppLog.Error(e, "status checks");
            Checks.Add(new(Text.Get("Status_CheckFailed"), Text.Get("Status_Fail"), "\uEA39", Brush("SystemFillColorCriticalBrush"), e.Message));
        }
        finally
        {
            IsRunning = false;
        }
        await ShowRestoreAsync();
        if (rerun)
        {
            rerun = false;
            await RunAsync();
        }
    }

    /// <summary>Sorts the last run's lines into findings, dismissed findings and the other checks.</summary>
    void Show()
    {
        var split = FindingView.Of(last, DismissalStore.Load());
        allFindings = [.. split.Open.Select((group, i) => new FindingRow(group) { IsOpen = i == 0, Number = i + 1 })];
        if (last.Count > 0)
        {
            Home.LastFindings = allFindings.Count;
            FindingWatch.Shown(last);
        }
        ShowFindings();
        Dismissed.Clear();
        foreach (var group in split.Dismissed)
            Dismissed.Add(new(group.Keys, group.Title, group.Reason));
        Checks.Clear();
        Passed.Clear();
        foreach (var check in split.Others)
            (check.Status == DoctorStatus.Ok ? Passed : Checks).Add(Row(check));
        OnPropertyChanged(nameof(PassedVisibility));
        OnPropertyChanged(nameof(PassedHeader));
        OnPropertyChanged(nameof(Summary));
        OnPropertyChanged(nameof(CheckCount));
        OnPropertyChanged(nameof(PassCount));
        OnPropertyChanged(nameof(ProgressText));
        OnPropertyChanged(nameof(DismissedVisibility));
        OnPropertyChanged(nameof(DismissedHeader));
        ShowAreas();
    }

    public void Dismiss(IEnumerable<DoctorCheck> checks, string reason) =>
        ChangeDismissals(d => checks.Aggregate(d, (all, check) => all.Dismiss(check, reason, DateTimeOffset.Now)));

    public void RestoreFindings(IEnumerable<string> keys) => ChangeDismissals(d => keys.Aggregate(d, (all, key) => all.Restore(key)));

    void ChangeDismissals(Func<Dismissals, Dismissals> change)
    {
        try
        {
            DismissalStore.Update(change);
            FindingMessage = "";
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            AppLog.Error(e, "saving dismissals");
            FindingMessage = Text.Format("Finding_DismissFailed", e.Message);
        }
        Show();
    }

    /// <summary>A fix outside the app: its command goes to the clipboard, and the page says so.</summary>
    public void CopyFix(string command)
    {
        try
        {
            Clipboard.SetText(command);
            FindingMessage = Text.Format("Finding_Copied", command);
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            FindingMessage = Text.Format("Finding_CopyFailed", command);
        }
    }

    /// <summary>Whether anything sealed here needs the recovery key; known only while unlocked, since it takes this PC's Hello key.</summary>
    async Task ShowRestoreAsync()
    {
        var hello = App.Current.Host.Keys.Hello;
        try
        {
            var unopened = hello is null ? [] : await Task.Run(() => RecoveryRestore.Unopened(hello));
            RestoreText = unopened.Count == 0 ? "" : Text.Format("Status_RestoreBody", unopened.Count);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidDataException
            or ObjectDisposedException or System.Security.Cryptography.CryptographicException)
        {
            // Locked meanwhile, or a damaged file the checks above already report.
            AppLog.Error(e, "status: sealed secrets this PC can't open");
            RestoreText = "";
        }
    }

    /// <summary>The state and every check of the last run, as text for a bug report; About copies it with its own facts.</summary>
    public string Details()
    {
        var sb = new StringBuilder().AppendLine(Headline).AppendLine(mode).AppendLine(Build);
        foreach (var check in allFindings.SelectMany(row => row.Checks))
            sb.AppendLine(CultureInfo.CurrentCulture, $"{check.Status}  {check.Name}: {check.Detail} [{FindingView.Moves(check)}]");
        foreach (var row in Checks.Concat(Passed))
            sb.AppendLine(CultureInfo.CurrentCulture, $"{row.StatusText}  {row.Name}: {row.Detail}");
        return sb.ToString();
    }

    static CheckRow Row(DoctorCheck check) => check.Status switch
    {
        DoctorStatus.Ok => new(check.Name, Text.Get("Status_Ok"), "\uE73E", Brush("SystemFillColorSuccessBrush"), check.Detail, check.Fix),
        DoctorStatus.Warn => new(check.Name, Text.Get("Status_Warn"), "\uE7BA", Brush("SystemFillColorCautionBrush"), check.Detail, check.Fix),
        _ => new(check.Name, Text.Get("Status_Fail"), "\uEA39", Brush("SystemFillColorCriticalBrush"), check.Detail, check.Fix),
    };

    static Brush? Brush(string key) => Application.Current.TryFindResource(key) as Brush;
}
