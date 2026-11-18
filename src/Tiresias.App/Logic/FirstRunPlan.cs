namespace Tiresias.App.Logic;

public enum FirstRunStep
{
    Welcome,
    /// <summary>Create the Windows Hello credential (one prompt).</summary>
    Hello,
    /// <summary>The recovery key is created and shown, once.</summary>
    RecoveryShow,
    /// <summary>Two of its groups are asked back.</summary>
    RecoveryConfirm,
    /// <summary>Sealed secrets are here but no recovery key: the paper they were sealed with is typed, and they are given to this PC.</summary>
    RecoveryRestore,
    /// <summary>Solo (default), a broker, or user secrets only.</summary>
    Mode,
    /// <summary>Resuming solo setup after the key was shown in an earlier run: it is typed back from paper.</summary>
    RecoveryType,
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
public sealed record SetupFacts(bool HelloReady, bool RecoverySet, bool Enrolled, bool Skipped, bool SealedWithoutKey = false);

/// <summary>
/// The first-run wizard as a resumable sequence. Each step leaves something durable behind (the
/// Hello credential, the recovery key, the enrolment), so a wizard closed halfway starts again at
/// the first thing missing, never redoing or skipping one. The recovery key is the one step that
/// cannot be repeated: it is shown once, so a resumed solo setup asks for it back instead.
/// </summary>
public static class FirstRunPlan
{
    public static bool Needed(SetupFacts f) => !f.HelloReady || !f.RecoverySet || (!f.Enrolled && !f.Skipped);

    public static FirstRunStep Start(SetupFacts f) =>
        !Needed(f) ? FirstRunStep.Done
        : !f.HelloReady && !f.RecoverySet ? FirstRunStep.Welcome
        : !f.HelloReady ? FirstRunStep.Hello
        : !f.RecoverySet ? NewOrRestore(f)
        : FirstRunStep.Mode;

    /// <param name="haveRecoveryKey">This run created the key and still holds it, so solo setup needn't ask for it.</param>
    public static FirstRunStep Next(FirstRunStep step, SetupFacts f, SetupMode mode = SetupMode.Solo, bool haveRecoveryKey = false) => step switch
    {
        FirstRunStep.Welcome => f.HelloReady ? Next(FirstRunStep.Hello, f) : FirstRunStep.Hello,
        FirstRunStep.Hello => f.RecoverySet ? FirstRunStep.Mode : NewOrRestore(f),
        FirstRunStep.RecoveryShow => FirstRunStep.RecoveryConfirm,
        FirstRunStep.RecoveryConfirm or FirstRunStep.RecoveryRestore => f.Enrolled ? FirstRunStep.Done : FirstRunStep.Mode,
        FirstRunStep.Mode => mode == SetupMode.Solo && !f.Enrolled && !haveRecoveryKey ? FirstRunStep.RecoveryType : FirstRunStep.Done,
        _ => FirstRunStep.Done,
    };

    /// <summary>A new recovery key would leave sealed secrets already here unrecoverable, so their own key is asked for first.</summary>
    static FirstRunStep NewOrRestore(SetupFacts f) => f.SealedWithoutKey ? FirstRunStep.RecoveryRestore : FirstRunStep.RecoveryShow;

    /// <summary>
    /// A lost recovery key can simply be replaced while nothing is sealed to it yet. After that, the
    /// old key is the only way back into those secrets if Hello is lost, so it is kept.
    /// </summary>
    public static bool CanReplaceRecoveryKey(int vaultSecrets, int sealedUserSecretsFiles) => vaultSecrets == 0 && sealedUserSecretsFiles == 0;
}
