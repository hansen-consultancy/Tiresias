using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Tiresias.AdminTier;
using Tiresias.Agent;
using Tiresias.App.Logic;
using Tiresias.Client;
using Tiresias.Protocol;

namespace Tiresias.App.Views;

/// <summary>
/// First run: Windows Hello, the recovery key (shown once, two groups asked back; or, where sealed
/// secrets are already here, the key they were sealed with typed back), the mode (solo by default),
/// done. Closing it halfway is fine: the next start resumes at the first missing step.
/// Excluded from screen capture, since it shows the recovery key.
/// </summary>
public partial class FirstRunWindow : Window
{
    readonly FirstRunViewModel model = new();

    public FirstRunWindow()
    {
        InitializeComponent();
        Desktop.ExcludeFromCapture(this);
        DataContext = model;
        model.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(FirstRunViewModel.Step))
                ShowStep();
        };
        model.Finished += Close;
        ShowStep();
    }

    void ShowStep()
    {
        var panelStep = model.Step == FirstRunStep.RecoveryMigrate ? FirstRunStep.RecoveryRestore : model.Step;
        foreach (var panel in new Panel[] { Welcome, Hello, RecoveryCreate, RecoveryUnavailable, RecoveryShow, RecoveryConfirm, Restore, Mode, RecoveryType, AdminTierPanel, Done })
            panel.Visibility = (FirstRunStep)panel.Tag == panelStep ? Visibility.Visible : Visibility.Collapsed;
        if (model.Step == FirstRunStep.RecoveryConfirm)
            Dispatcher.BeginInvoke(() => FirstGroup.Focus());
        else if (model.Step == FirstRunStep.RecoveryType)
            Dispatcher.BeginInvoke(() => TypedKey.Focus());
        else if (panelStep == FirstRunStep.RecoveryRestore)
            Dispatcher.BeginInvoke(() => RestoreKey.Focus());
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        base.OnClosing(e);
        // A pending enrollment or restore is still using the paper cleared by OnClosed.
        if (model.IsWorking && model.Step != FirstRunStep.Done)
            e.Cancel = true;
    }

    protected override void OnClosed(EventArgs e)
    {
        model.Forget();
        App.Current.Refresh();
        base.OnClosed(e);
    }

    /// <summary>On the admin tier's offer the second button is <b>Not now</b>, which moves on rather than closing.</summary>
    void OnClose(object sender, RoutedEventArgs e)
    {
        if (model.IsWorking)
            return;
        if (model.Step == FirstRunStep.AdminTier)
            model.NotNow();
        else
            Close();
    }
}

public sealed partial class FirstRunViewModel : ObservableObject
{
    byte[]? recoveryKey;
    FirstRunPaper? pendingPaper;

    /// <summary>The typed key was adopted, so this PC has a recovery key: a new one can no longer be made.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(LostVisibility))]
    public partial bool RestoreDone { get; set; }

    public Visibility LostVisibility => RestoreDone ? Visibility.Collapsed : Visibility.Visible;

    public FirstRunViewModel()
    {
        MoveFrom(App.SetupFacts(), resume: true);
        UpdateLabels();
    }

    public event Action? Finished;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(RestoreTitle), nameof(RestoreBody))]
    public partial FirstRunStep Step { get; set; }

    public string RestoreTitle => Text.Get(Step == FirstRunStep.RecoveryMigrate ? "FirstRun_RecoveryMigrate_Title" : "FirstRun_RecoveryRestore_Title");
    public string RestoreBody => Text.Get(Step == FirstRunStep.RecoveryMigrate ? "FirstRun_RecoveryMigrate_Body" : "FirstRun_RecoveryRestore_Body");

    [ObservableProperty]
    public partial string StepLabel { get; set; } = "";

    [ObservableProperty]
    public partial string PrimaryLabel { get; set; } = "";

    [ObservableProperty]
    public partial string CloseLabel { get; set; } = "";

    [ObservableProperty]
    public partial string Message { get; set; } = "";

    [ObservableProperty]
    public partial string KeyText { get; set; } = "";

    [ObservableProperty]
    public partial bool WroteItDown { get; set; }

    [ObservableProperty]
    public partial string FirstGroupLabel { get; set; } = "";

    [ObservableProperty]
    public partial string SecondGroupLabel { get; set; } = "";

    [ObservableProperty]
    public partial string FirstAnswer { get; set; } = "";

    [ObservableProperty]
    public partial string SecondAnswer { get; set; } = "";

    [ObservableProperty]
    public partial bool IsSolo { get; set; } = true;

    /// <summary>A broker or secrets only matter to a developer or a team: elsewhere the Mode step offers solo alone (docs/developer-tools.md).</summary>
    public bool DeveloperTools { get; } = DeveloperSignals.View().Shown;

    [ObservableProperty]
    public partial bool IsBroker { get; set; }

    [ObservableProperty]
    public partial bool IsSecretsOnly { get; set; }

    [ObservableProperty]
    public partial string TypedKey { get; set; } = "";

    [ObservableProperty]
    public partial string RestoreKey { get; set; } = "";

    [ObservableProperty]
    public partial string Fingerprint { get; set; } = "";

    partial void OnRestoreKeyChanged(string value) => Fingerprint = RecoveryViewModel.FingerprintText(value);

    [ObservableProperty]
    public partial string RestoreResult { get; set; } = "";

    [ObservableProperty]
    public partial bool CanReplaceKey { get; set; }

    [ObservableProperty]
    public partial string LostKeyText { get; set; } = "";

    [ObservableProperty]
    public partial string DoneText { get; set; } = "";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(PrimaryCommand))]
    [NotifyCanExecuteChangedFor(nameof(NewRecoveryKeyCommand), nameof(SkipSoloCommand), nameof(ShowKeyAgainCommand))]
    public partial bool IsWorking { get; set; }

    SetupMode Chosen => IsBroker ? SetupMode.Broker : IsSecretsOnly ? SetupMode.SecretsOnly : SetupMode.Solo;

    partial void OnStepChanged(FirstRunStep value)
    {
        Message = "";
        UpdateLabels();
    }

    bool CanAct() => !IsWorking;

    /// <summary>The one button that moves the wizard on; what it does depends on the step.</summary>
    [RelayCommand(CanExecute = nameof(CanAct))]
    async Task PrimaryAsync()
    {
        IsWorking = true;
        try
        {
            switch (Step)
            {
                case FirstRunStep.Welcome:
                    MoveFrom(App.SetupFacts());
                    break;
                case FirstRunStep.RecoveryUnavailable:
                    MoveFrom(App.SetupFacts(), resume: true);
                    break;
                case FirstRunStep.Hello:
                    await SetUpAsync(() => App.Current.Host.Keys.Unlock(create: true));
                    App.Current.Refresh();
                    MoveFrom(App.SetupFacts());
                    break;
                case FirstRunStep.RecoveryShow:
                    if (!WroteItDown)
                    {
                        Message = Text.Get("FirstRun_RecoveryShow_NotConfirmed");
                        return;
                    }
                    Step = FirstRunStep.RecoveryConfirm;
                    break;
                case FirstRunStep.RecoveryCreate:
                    ShowNewKey(await Task.Run(() => RecoveryKey.Create()));
                    break;
                case FirstRunStep.RecoveryConfirm:
                    var first = FirstAnswer;
                    var second = SecondAnswer;
                    if (pendingPaper is not { } paper || !await Task.Run(() => paper.TryEnroll(first, second)))
                    {
                        Message = Text.Get("FirstRun_RecoveryConfirm_Mismatch");
                        return;
                    }
                    pendingPaper = null;
                    KeyText = "";
                    MoveFrom(App.SetupFacts());
                    break;
                case FirstRunStep.RecoveryRestore:
                case FirstRunStep.RecoveryMigrate:
                    await RestoreAsync();
                    break;
                case FirstRunStep.Mode:
                    await ChooseModeAsync();
                    break;
                case FirstRunStep.RecoveryType:
                    var typed = PaperKey.Parse(TypedKey);
                    if (typed is null)
                    {
                        Message = Text.Get("FirstRun_RecoveryType_Invalid");
                        return;
                    }
                    recoveryKey = typed;
                    await SetUpSoloAsync();
                    break;
                case FirstRunStep.AdminTier:
                    var result = await AdminTierElevation.RunAsync("install");
                    if (result == AdminSetupResult.Done)
                        MoveOn(FirstRunStep.Done);
                    else
                        Message = Text.Of(AdminTierCard.Outcome(result, removing: false));
                    break;
                case FirstRunStep.Done:
                    Finished?.Invoke();
                    break;
            }
        }
        catch (InvalidOperationException e) when (e is not HelloException && Step is (FirstRunStep.RecoveryType or FirstRunStep.RecoveryRestore
            or FirstRunStep.RecoveryMigrate or FirstRunStep.RecoveryCreate or FirstRunStep.RecoveryConfirm))
        {
            Message = e.Message;
        }
        catch (Exception e) when (e is InvalidOperationException or IOException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidDataException
            or System.Security.Cryptography.CryptographicException or System.Net.Http.HttpRequestException)
        {
            ProblemWindow.Show(e, $"first run, step {Step}", retry: () => PrimaryCommand.Execute(null));
        }
        finally
        {
            IsWorking = false;
        }
    }

    [RelayCommand(CanExecute = nameof(CanAct))]
    void ShowKeyAgain()
    {
        if (recoveryKey is null)
            return;
        KeyText = PaperKey.Format(recoveryKey);
        WroteItDown = false;
        Step = FirstRunStep.RecoveryShow;
    }

    [RelayCommand(CanExecute = nameof(CanAct))]
    async Task NewRecoveryKeyAsync()
    {
        if (!CanReplaceKey)
            return;
        IsWorking = true;
        try
        {
            var keepImportedLocked = Step == FirstRunStep.RecoveryRestore;
            ShowNewKey(await Task.Run(() => keepImportedLocked ? RecoveryKey.Create(keepImportedSecretsLocked: true) : RecoveryKey.ReplaceUnused()));
        }
        catch (Exception e) when (e is InvalidOperationException or IOException or UnauthorizedAccessException or System.Text.Json.JsonException
            or InvalidDataException or System.Security.Cryptography.CryptographicException)
        {
            Message = e.Message;
        }
        finally
        {
            IsWorking = false;
        }
    }

    /// <summary>The admin tier declined: nothing changes, and About offers it later.</summary>
    public void NotNow()
    {
        AppLog.Info("first run: admin tier not set up (not now)");
        MoveOn(FirstRunStep.Done);
    }

    [RelayCommand(CanExecute = nameof(CanAct))]
    void SkipSolo()
    {
        IsSecretsOnly = true;
        IsSolo = IsBroker = false;
        Finish(SetupMode.SecretsOnly);
    }

    /// <summary>Zeroes the recovery key held for this run.</summary>
    public void Forget()
    {
        if (recoveryKey is not null)
            Array.Clear(recoveryKey);
        recoveryKey = null;
        KeyText = "";
        pendingPaper = null;
        TypedKey = RestoreKey = FirstAnswer = SecondAnswer = "";
        Fingerprint = "";
    }

    /// <summary>
    /// Gives the sealed secrets here to this PC's Windows Hello, and this PC takes the typed key as
    /// its recovery key, held for the run so solo setup needn't ask for it again. Anything the key
    /// didn't open is listed once before moving on.
    /// </summary>
    async Task RestoreAsync()
    {
        if (RestoreDone)
        {
            MoveFrom(App.SetupFacts());
            return;
        }
        var paper = PaperKey.Parse(RestoreKey);
        if (paper is null)
        {
            Message = Text.Get("FirstRun_RecoveryType_Invalid");
            return;
        }
        RestoreSummary summary;
        try
        {
            await SetUpAsync(() => App.Current.Host.Keys.Unlock(create: true));
            var hello = App.Current.Host.Keys.Hello!;
            summary = await Task.Run(() => RecoveryRestore.Run(paper, hello));
            Forget();
            if (RecoveryKey.PublicKey is { } recipient && PaperKey.Matches(paper, Convert.FromBase64String(recipient)))
                recoveryKey = paper;
            else
                Array.Clear(paper);
        }
        catch
        {
            Array.Clear(paper);
            throw;
        }
        AppLog.Info($"first run: recovery restore, {summary.Restored} restored, {summary.AlreadyOpen} already open, {summary.NotOpened.Count} not opened");
        RestoreKey = "";
        App.Current.Refresh();
        if (!RecoveryKey.IsEnrolled)
        {
            RestoreResult = RecoveryViewModel.Describe(summary) + Environment.NewLine + Text.Get("FirstRun_RecoveryMigrate_StillNeeded");
            return;
        }
        if (summary.NotOpened.Count == 0)
        {
            MoveFrom(App.SetupFacts());
            return;
        }
        RestoreResult = RecoveryViewModel.Describe(summary) + Environment.NewLine + Text.Get("FirstRun_RecoveryRestore_Later");
        RestoreDone = true;
    }

    async Task ChooseModeAsync()
    {
        var facts = App.SetupFacts();
        if (!facts.RecoverySet)
        {
            MoveFrom(facts, resume: true);
            return;
        }
        var next = FirstRunPlan.Next(FirstRunStep.Mode, facts, Chosen, haveRecoveryKey: recoveryKey is not null);
        if (Chosen != SetupMode.Solo || facts.Enrolled)
        {
            Finish(Chosen);
            return;
        }
        if (next == FirstRunStep.RecoveryType)
        {
            MoveOn(next);
            return;
        }
        await SetUpSoloAsync();
    }

    async Task SetUpSoloAsync()
    {
        // Signing genesis shows a Hello prompt: keep the window responsive meanwhile.
        await SetUpAsync(() => SoloBroker.Setup(recoveryKey!));
        Forget();
        // Starts the in-app broker and opens the first lease; already unlocked, so no second Hello prompt.
        await App.Current.UnlockAsync(PromptReason.SetUp, interactive: true);
        Finish(SetupMode.Solo);
    }

    /// <summary>A setup step that shows a Hello prompt, off the UI thread, with setup named as its reason.</summary>
    static async Task SetUpAsync(Action step)
    {
        using var because = HelloPrompts.Because(PromptReason.SetUp);
        await Task.Run(step);
    }

    void Finish(SetupMode mode)
    {
        if (mode != SetupMode.Solo)
            (AppSettings.Load() with { SetupSkipped = true }).Save();
        DoneText = Text.Get(mode switch
        {
            SetupMode.Solo => "FirstRun_Done_Solo",
            SetupMode.Broker => "FirstRun_Done_Broker",
            _ => "FirstRun_Done_SecretsOnly",
        });
        MoveOn(FirstRunPlan.Finishing(App.SetupFacts()));
    }

    void ShowNewKey(PendingRecoveryKey candidate)
    {
        Forget();
        recoveryKey = candidate.Paper;
        pendingPaper = new FirstRunPaper(candidate.Paper, candidate.Enroll);
        KeyText = PaperKey.Format(candidate.Paper);
        Fingerprint = RecoveryViewModel.FingerprintText(candidate.Paper);
        WroteItDown = false;
        Step = FirstRunStep.RecoveryShow;
    }

    void MoveFrom(SetupFacts facts, bool resume = false)
    {
        MoveOn(resume ? FirstRunPlan.Start(facts) : FirstRunPlan.Next(Step, facts));
        if (facts.RecoveryError is { } error)
            Message = error;
    }

    void MoveOn(FirstRunStep next)
    {
        if (next is FirstRunStep.RecoveryType or FirstRunStep.RecoveryMigrate)
            UpdateLostKey();
        else if (next == FirstRunStep.RecoveryRestore)
        {
            CanReplaceKey = true;
            LostKeyText = Text.Get("FirstRun_RecoveryRestore_LostBody");
        }
        if (next == FirstRunStep.Done && DoneText.Length == 0)
            DoneText = Text.Get(KeyringStore.Broker is null ? "FirstRun_Done_SecretsOnly" : "FirstRun_Done_Enrolled");
        Step = next;
    }

    void UpdateLostKey()
    {
        try
        {
            CanReplaceKey = RecoveryKey.CanReplaceUnused;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidDataException
            or InvalidOperationException or System.Security.Cryptography.CryptographicException)
        {
            AppLog.Error(e, "checking whether the unused recovery key can be replaced");
            CanReplaceKey = false;
        }
        LostKeyText = Text.Get(CanReplaceKey ? "FirstRun_RecoveryType_LostCanReplace" : "FirstRun_RecoveryType_LostKeep");
    }

    void UpdateLabels()
    {
        if (pendingPaper is { } paper)
        {
            FirstGroupLabel = Text.Format("FirstRun_RecoveryConfirm_Group", paper.Challenge.First + 1);
            SecondGroupLabel = Text.Format("FirstRun_RecoveryConfirm_Group", paper.Challenge.Second + 1);
        }
        StepLabel = Step switch
        {
            FirstRunStep.Welcome => Text.Get("FirstRun_StepWelcome"),
            FirstRunStep.Done => Text.Get("FirstRun_StepDone"),
            _ => Text.Get("FirstRun_StepSetup"),
        };
        PrimaryLabel = Text.Get(Step switch
        {
            FirstRunStep.Welcome => "FirstRun_Primary_Start",
            FirstRunStep.Hello => "FirstRun_Primary_Hello",
            FirstRunStep.RecoveryCreate => "FirstRun_RecoveryRestore_New",
            FirstRunStep.RecoveryUnavailable => "Common_TryAgain",
            FirstRunStep.RecoveryConfirm => "FirstRun_Primary_Enroll",
            FirstRunStep.AdminTier => "FirstRun_Primary_AdminTier",
            FirstRunStep.Done => "FirstRun_Primary_Finish",
            _ => "FirstRun_Primary_Continue",
        });
        CloseLabel = Text.Get(Step switch
        {
            FirstRunStep.Done => "Common_Close",
            FirstRunStep.AdminTier => "FirstRun_AdminTier_NotNow",
            _ => "FirstRun_Later",
        });
    }
}
