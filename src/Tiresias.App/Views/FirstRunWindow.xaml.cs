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
using Tiresias.UserSecrets;
using Tiresias.Vault;

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
        foreach (var panel in new Panel[] { Welcome, Hello, RecoveryShow, RecoveryConfirm, Restore, Mode, RecoveryType, AdminTierPanel, Done })
            panel.Visibility = (FirstRunStep)panel.Tag == model.Step ? Visibility.Visible : Visibility.Collapsed;
        if (model.Step == FirstRunStep.RecoveryConfirm)
            Dispatcher.BeginInvoke(() => FirstGroup.Focus());
        else if (model.Step == FirstRunStep.RecoveryType)
            Dispatcher.BeginInvoke(() => TypedKey.Focus());
        else if (model.Step == FirstRunStep.RecoveryRestore)
            Dispatcher.BeginInvoke(() => RestoreKey.Focus());
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
        if (model.Step == FirstRunStep.AdminTier)
            model.NotNow();
        else
            Close();
    }
}

public sealed partial class FirstRunViewModel : ObservableObject
{
    byte[]? recoveryKey;
    IReadOnlyList<string> words = [];
    (int First, int Second) challenge;

    /// <summary>The typed key was adopted, so this PC has a recovery key: a new one can no longer be made.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(LostVisibility))]
    public partial bool RestoreDone { get; set; }

    public Visibility LostVisibility => RestoreDone ? Visibility.Collapsed : Visibility.Visible;

    public FirstRunViewModel()
    {
        MoveOn(FirstRunPlan.Start(App.SetupFacts()));
        UpdateLabels();
    }

    public event Action? Finished;

    [ObservableProperty]
    public partial FirstRunStep Step { get; set; }

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

    [ObservableProperty]
    public partial bool IsBroker { get; set; }

    [ObservableProperty]
    public partial bool IsSecretsOnly { get; set; }

    [ObservableProperty]
    public partial string TypedKey { get; set; } = "";

    [ObservableProperty]
    public partial string RestoreKey { get; set; } = "";

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
                    MoveOn(FirstRunPlan.Next(Step, App.SetupFacts()));
                    break;
                case FirstRunStep.Hello:
                    await Task.Run(() => App.Current.Host.Keys.Unlock(create: true));
                    App.Current.Refresh();
                    MoveOn(FirstRunPlan.Next(Step, App.SetupFacts()));
                    break;
                case FirstRunStep.RecoveryShow:
                    if (!WroteItDown)
                    {
                        Message = Text.Get("FirstRun_RecoveryShow_NotConfirmed");
                        return;
                    }
                    Step = FirstRunStep.RecoveryConfirm;
                    break;
                case FirstRunStep.RecoveryConfirm:
                    if (!PaperKey.Confirm(words, challenge, FirstAnswer, SecondAnswer))
                    {
                        Message = Text.Get("FirstRun_RecoveryConfirm_Mismatch");
                        return;
                    }
                    KeyText = "";
                    MoveOn(FirstRunPlan.Next(Step, App.SetupFacts()));
                    break;
                case FirstRunStep.RecoveryRestore:
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
        catch (InvalidOperationException e) when (Step is FirstRunStep.RecoveryType or FirstRunStep.RecoveryRestore && e is not HelloException)
        {
            // The key typed is a key, but not this device's: say so in place.
            Message = e.Message;
        }
        catch (Exception e) when (e is InvalidOperationException or IOException or UnauthorizedAccessException
            or System.Security.Cryptography.CryptographicException or System.Net.Http.HttpRequestException)
        {
            ProblemWindow.Show(e, $"first run, step {Step}", retry: () => PrimaryCommand.Execute(null));
        }
        finally
        {
            IsWorking = false;
        }
    }

    [RelayCommand]
    void ShowKeyAgain()
    {
        if (recoveryKey is null)
            return;
        KeyText = PaperKey.Format(recoveryKey);
        WroteItDown = false;
        Step = FirstRunStep.RecoveryShow;
    }

    /// <summary>The key was lost before anything was sealed to it: forget its public half and make a new one.</summary>
    [RelayCommand]
    void ReplaceKey()
    {
        if (!CanReplaceKey)
            return;
        KeyringStore.Settings = KeyringStore.Settings with { RecoveryPublicKey = null };
        AppLog.Info("recovery key replaced during first run (nothing was sealed to the old one)");
        MoveOn(FirstRunStep.RecoveryShow);
    }

    /// <summary>The paper for the sealed secrets here is gone: carry on with a new key, leaving them locked until it turns up.</summary>
    [RelayCommand]
    void NewRecoveryKey()
    {
        AppLog.Info("first run: new recovery key chosen over restoring the sealed secrets here");
        MoveOn(FirstRunStep.RecoveryShow);
    }

    /// <summary>The admin tier declined: nothing changes, and About offers it later.</summary>
    public void NotNow()
    {
        AppLog.Info("first run: admin tier not set up (not now)");
        MoveOn(FirstRunStep.Done);
    }

    [RelayCommand]
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
            MoveOn(FirstRunPlan.Next(Step, App.SetupFacts()));
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
            await Task.Run(() => App.Current.Host.Keys.Unlock(create: true));
            var hello = App.Current.Host.Keys.Hello!;
            summary = await Task.Run(() => RecoveryRestore.Run(paper, hello));
        }
        catch
        {
            Array.Clear(paper);
            throw;
        }
        AppLog.Info($"first run: recovery restore, {summary.Restored} restored, {summary.AlreadyOpen} already open, {summary.NotOpened.Count} not opened");
        Forget();
        recoveryKey = paper;
        RestoreKey = "";
        App.Current.Refresh();
        if (summary.NotOpened.Count == 0)
        {
            MoveOn(FirstRunPlan.Next(Step, App.SetupFacts()));
            return;
        }
        RestoreResult = RecoveryViewModel.Describe(summary) + Environment.NewLine + Text.Get("FirstRun_RecoveryRestore_Later");
        RestoreDone = true;
    }

    async Task ChooseModeAsync()
    {
        var next = FirstRunPlan.Next(FirstRunStep.Mode, App.SetupFacts(), Chosen, haveRecoveryKey: recoveryKey is not null);
        if (Chosen != SetupMode.Solo || App.SetupFacts().Enrolled)
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
        await Task.Run(() => SoloBroker.Setup(recoveryKey!));
        Forget();
        // Starts the in-app broker and opens the first lease; already unlocked, so no second Hello prompt.
        await App.Current.UnlockAsync(interactive: true);
        Finish(SetupMode.Solo);
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

    /// <summary>Enters a step, doing what it needs on the way in (the recovery key is created as its page opens).</summary>
    void MoveOn(FirstRunStep next)
    {
        if (next == FirstRunStep.RecoveryShow)
        {
            Forget();
            recoveryKey = RecoveryKey.Create();
            words = PaperKey.Words(recoveryKey);
            challenge = PaperKey.Challenge(words.Count);
            KeyText = PaperKey.Format(recoveryKey);
            WroteItDown = false;
            FirstAnswer = SecondAnswer = "";
        }
        if (next == FirstRunStep.RecoveryType)
            UpdateLostKey();
        if (next == FirstRunStep.Done && DoneText.Length == 0)
            DoneText = Text.Get(KeyringStore.Tenant is { Solo: true } ? "FirstRun_Done_Solo" : "FirstRun_Done_Broker");
        Step = next;
    }

    void UpdateLostKey()
    {
        var vault = KeyringStore.Settings.VaultPath;
        var secrets = File.Exists(vault) ? VaultFile.Load(vault).Secrets.Count : 0;
        var sealedFiles = UserSecretsFiles.All().Count(f => f.Kind == SecretsFileKind.Sealed);
        CanReplaceKey = FirstRunPlan.CanReplaceRecoveryKey(secrets, sealedFiles);
        LostKeyText = Text.Get(CanReplaceKey ? "FirstRun_RecoveryType_LostCanReplace" : "FirstRun_RecoveryType_LostKeep");
    }

    void UpdateLabels()
    {
        if (Step == FirstRunStep.RecoveryType)
            UpdateLostKey();
        FirstGroupLabel = Text.Format("FirstRun_RecoveryConfirm_Group", challenge.First + 1);
        SecondGroupLabel = Text.Format("FirstRun_RecoveryConfirm_Group", challenge.Second + 1);
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
