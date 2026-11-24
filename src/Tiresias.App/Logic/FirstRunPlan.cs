namespace Tiresias.App.Logic;

public enum FirstRunStep
{
    Welcome,
    /// <summary>Create the Windows Hello credential (one prompt).</summary>
    Hello,
    /// <summary>Prepare a new paper key before showing it to the user.</summary>
    RecoveryCreate,
    /// <summary>The recovery key is created and shown, once.</summary>
    RecoveryShow,
    /// <summary>Two of its groups are asked back.</summary>
    RecoveryConfirm,
    /// <summary>Sealed secrets are here but no recovery key: the paper they were sealed with is typed, and they are given to this PC.</summary>
    RecoveryRestore,
    /// <summary>Verify the paper for a previous setup and enroll it with administrator approval.</summary>
    RecoveryMigrate,
    /// <summary>Enrollment or its dependencies could not be read. Retry without changing them.</summary>
    RecoveryUnavailable,
    /// <summary>Solo (default), a broker, or user secrets only.</summary>
    Mode,
    /// <summary>Resuming solo setup after the key was shown in an earlier run: it is typed back from paper.</summary>
    RecoveryType,
    /// <summary>Optional, once, after the vault: set up the admin tier (UAC) or not now.</summary>
    AdminTier,
    Done,
}

public enum SetupMode
{
    Solo,
    Broker,
    SecretsOnly,
}

/// <summary>What is already in place on this machine; read without a prompt.</summary>
/// <param name="Skipped">The user chose to finish without a broker (user secrets only, or enrolling later).</param>
/// <param name="SealedWithoutKey">Sealed secrets are here while no recovery key is stored: copied from another PC, or left by an earlier setup.</param>
/// <param name="AdminTierInstalled">The admin tier is already set up, so the wizard doesn't offer it.</param>
/// <param name="RecoveryNeedsVerification">An earlier recovery recipient or trust enrollment exists without a protected recovery enrollment.</param>
public sealed record SetupFacts(bool HelloReady, bool RecoverySet, bool Enrolled, bool Skipped, bool SealedWithoutKey = false, bool AdminTierInstalled = true,
    bool RecoveryNeedsVerification = false, string? RecoveryError = null);

/// <summary>
/// The wizard resumes from the Hello credential, protected recovery enrollment, and chosen mode.
/// An unconfirmed paper key is discarded when the wizard closes. Once enrolled, only the paper
/// held by the user can supply the private key for a resumed solo setup.
/// </summary>
public static class FirstRunPlan
{
    public static bool Needed(SetupFacts f) => f.RecoveryError is not null || !f.HelloReady || !f.RecoverySet || (!f.Enrolled && !f.Skipped);

    public static FirstRunStep Start(SetupFacts f) =>
        f.RecoveryError is not null ? FirstRunStep.RecoveryUnavailable
        : !Needed(f) ? FirstRunStep.Done
        : !f.HelloReady && !f.RecoverySet ? FirstRunStep.Welcome
        : !f.HelloReady ? FirstRunStep.Hello
        : !f.RecoverySet ? NewOrRestore(f)
        : FirstRunStep.Mode;

    /// <param name="haveRecoveryKey">This run created the key and still holds it, so solo setup needn't ask for it.</param>
    public static FirstRunStep Next(FirstRunStep step, SetupFacts f, SetupMode mode = SetupMode.Solo, bool haveRecoveryKey = false) =>
        f.RecoveryError is not null ? FirstRunStep.RecoveryUnavailable : step switch
    {
        FirstRunStep.Welcome => f.HelloReady ? Next(FirstRunStep.Hello, f) : FirstRunStep.Hello,
        FirstRunStep.Hello or FirstRunStep.RecoveryMigrate => Start(f),
        FirstRunStep.RecoveryConfirm or FirstRunStep.RecoveryRestore => f.RecoverySet && f.Enrolled && !f.Skipped ? Finishing(f) : Start(f),
        FirstRunStep.RecoveryCreate => FirstRunStep.RecoveryShow,
        FirstRunStep.RecoveryShow => FirstRunStep.RecoveryConfirm,
        FirstRunStep.Mode => mode == SetupMode.Solo && !f.Enrolled && !haveRecoveryKey ? FirstRunStep.RecoveryType : Finishing(f),
        _ => FirstRunStep.Done,
    };

    /// <summary>
    /// The step once the vault is set up: the admin tier's offer, unless it is in place already, then
    /// done. Declining it changes nothing, and it isn't offered again: About has it.
    /// </summary>
    public static FirstRunStep Finishing(SetupFacts f) => f.AdminTierInstalled ? FirstRunStep.Done : FirstRunStep.AdminTier;

    /// <summary>A new recovery key would leave sealed secrets already here unrecoverable, so their own key is asked for first.</summary>
    static FirstRunStep NewOrRestore(SetupFacts f) => f.RecoveryNeedsVerification ? FirstRunStep.RecoveryMigrate
        : f.SealedWithoutKey ? FirstRunStep.RecoveryRestore : FirstRunStep.RecoveryCreate;
}
