namespace Tiresias.App.Logic;

/// <summary>What a Windows Hello or UAC prompt is about to be shown for.</summary>
public enum PromptPurpose
{
    /// <summary>A prompt nobody named a reason for; the card still says it is Tiresias asking.</summary>
    Unnamed,
    Unlock,
    UnlockAtStart,
    ProgramAsked,
    Secrets,
    Services,
    EnvironmentVariables,
    Alerts,
    SealToken,
    Recovery,
    SetUp,
    DatabaseSetup,
    ApproveChange,
    AdminInstall,
    AdminRemove,
    AdminReleaseDecoys,
    AdminAdoptDecoys,
    AdminUnblock,
    AdminReviewIncidents,
}

/// <summary>Why a prompt shows: its purpose, and the program it names when there is one.</summary>
public sealed record PromptReason(PromptPurpose Purpose, string? Program = null)
{
    public static readonly PromptReason Unnamed = new(PromptPurpose.Unnamed);
    public static readonly PromptReason Unlock = new(PromptPurpose.Unlock);
    public static readonly PromptReason UnlockAtStart = new(PromptPurpose.UnlockAtStart);
    public static readonly PromptReason Secrets = new(PromptPurpose.Secrets);
    public static readonly PromptReason Services = new(PromptPurpose.Services);
    public static readonly PromptReason EnvironmentVariables = new(PromptPurpose.EnvironmentVariables);
    public static readonly PromptReason Alerts = new(PromptPurpose.Alerts);
    public static readonly PromptReason SealToken = new(PromptPurpose.SealToken);
    public static readonly PromptReason Recovery = new(PromptPurpose.Recovery);
    public static readonly PromptReason SetUp = new(PromptPurpose.SetUp);
    public static readonly PromptReason DatabaseSetup = new(PromptPurpose.DatabaseSetup);
    public static readonly PromptReason ApproveChange = new(PromptPurpose.ApproveChange);

    /// <summary>A program asked for secrets while Tiresias was locked; <paramref name="image"/> is its path or file name, if known.</summary>
    public static PromptReason ProgramAsked(string? image) => new(PromptPurpose.ProgramAsked, image);
}

/// <summary>The prompt Windows shows: neither takes words of ours, which is why the card exists.</summary>
public enum PromptKind
{
    Hello,
    Uac,
}

/// <summary>The card shown just before the prompt: a heading naming the prompt, and the reason.</summary>
public sealed record PromptCardView(Phrase Heading, Phrase Reason);

/// <summary>
/// Puts a prompt's reason in words. Windows Hello's <c>RequestSignAsync</c> and the UAC prompt
/// show only Windows' own text, so this is the one place the user learns why Tiresias asked.
/// </summary>
public static class PromptWhy
{
    public static PromptCardView Describe(PromptReason why, PromptKind kind) => new(
        kind == PromptKind.Uac ? new("Prompt_HeadingUac") : new("Prompt_HeadingHello"),
        Reason(why));

    static Phrase Reason(PromptReason why) => why.Purpose switch
    {
        PromptPurpose.Unlock => new("Prompt_Unlock"),
        PromptPurpose.UnlockAtStart => new("Prompt_UnlockAtStart"),
        PromptPurpose.ProgramAsked when FileName(why.Program) is { } program => new("Prompt_ProgramAsked", program),
        PromptPurpose.ProgramAsked => new("Prompt_ProgramAskedUnknown"),
        PromptPurpose.Secrets => new("Prompt_Secrets"),
        PromptPurpose.Services => new("Prompt_Services"),
        PromptPurpose.EnvironmentVariables => new("Prompt_EnvironmentVariables"),
        PromptPurpose.Alerts => new("Prompt_Alerts"),
        PromptPurpose.SealToken => new("Prompt_SealToken"),
        PromptPurpose.Recovery => new("Prompt_Recovery"),
        PromptPurpose.SetUp => new("Prompt_SetUp"),
        PromptPurpose.DatabaseSetup => new("Prompt_DatabaseSetup"),
        PromptPurpose.ApproveChange => new("Prompt_ApproveChange"),
        PromptPurpose.AdminInstall => new("Prompt_AdminInstall"),
        PromptPurpose.AdminRemove => new("Prompt_AdminRemove"),
        PromptPurpose.AdminReleaseDecoys => new("Prompt_AdminReleaseDecoys"),
        PromptPurpose.AdminAdoptDecoys => new("Prompt_AdminAdoptDecoys"),
        PromptPurpose.AdminUnblock when FileName(why.Program) is { } program => new("Prompt_AdminUnblock", program),
        PromptPurpose.AdminUnblock => new("Prompt_AdminUnblockUnknown"),
        PromptPurpose.AdminReviewIncidents => new("Prompt_AdminReviewIncidents"),
        _ => new("Prompt_Unnamed"),
    };

    /// <summary>
    /// The reason for an elevated <c>--admin-tier</c> step, by the verb it is started with. A verb
    /// this list doesn't know still gets a card, worded for a step Tiresias didn't name.
    /// </summary>
    public static PromptReason ForAdminStep(string verb, string? argument) => verb switch
    {
        "install" => new(PromptPurpose.AdminInstall),
        "remove" => new(PromptPurpose.AdminRemove),
        "release-decoys" => new(PromptPurpose.AdminReleaseDecoys),
        "adopt-decoys" => new(PromptPurpose.AdminAdoptDecoys),
        "unblock-program" => new(PromptPurpose.AdminUnblock, argument),
        "review-incidents" => new(PromptPurpose.AdminReviewIncidents),
        _ => PromptReason.Unnamed,
    };

    /// <summary>A program by its file name, which is what the prompt's user recognises; a full path would wrap the card.</summary>
    static string? FileName(string? image) =>
        string.IsNullOrWhiteSpace(image) ? null : image.Replace('\\', '/').Split('/')[^1] is { Length: > 0 } name ? name : null;
}
