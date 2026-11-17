using System.Globalization;
using System.Text;

namespace Tiresias.App.Logic;

/// <summary>The failures the app explains to the user, each with its own words and next step.</summary>
public enum ProblemKind
{
    HelloNotSetUp,
    HelloCancelled,
    HelloCredentialMissing,
    HelloUnavailable,
    BrokerUnreachable,
    BrokerRefused,
    VaultUnreadable,
    NoRecoveryKey,
    SoloBrokerDown,
    FileAccess,
    Unexpected,
}

/// <summary>The one button that moves the user on from a problem.</summary>
public enum ProblemAction
{
    None,
    TryAgain,
    OpenHelloSettings,
    OpenStatus,
    OpenDataFolder,
    FinishSetup,
}

/// <summary>What happened, why it matters, what to do, and the button that does it.</summary>
public sealed record Problem(ProblemKind Kind, Phrase Title, Phrase What, Phrase Why, Phrase Next, ProblemAction Action);

public static class Problems
{
    public static Problem Explain(ProblemKind kind) => kind switch
    {
        ProblemKind.HelloNotSetUp => new(kind, new("Problem_HelloNotSetUp_Title"), new("Problem_HelloNotSetUp_What"),
            new("Problem_HelloNotSetUp_Why"), new("Problem_HelloNotSetUp_Next"), ProblemAction.OpenHelloSettings),
        ProblemKind.HelloCancelled => new(kind, new("Problem_HelloCancelled_Title"), new("Problem_HelloCancelled_What"),
            new("Problem_HelloCancelled_Why"), new("Problem_HelloCancelled_Next"), ProblemAction.TryAgain),
        ProblemKind.HelloCredentialMissing => new(kind, new("Problem_HelloCredentialMissing_Title"), new("Problem_HelloCredentialMissing_What"),
            new("Problem_HelloCredentialMissing_Why"), new("Problem_HelloCredentialMissing_Next"), ProblemAction.None),
        ProblemKind.HelloUnavailable => new(kind, new("Problem_HelloUnavailable_Title"), new("Problem_HelloUnavailable_What"),
            new("Problem_HelloUnavailable_Why"), new("Problem_HelloUnavailable_Next"), ProblemAction.TryAgain),
        ProblemKind.BrokerUnreachable => new(kind, new("Problem_BrokerUnreachable_Title"), new("Problem_BrokerUnreachable_What"),
            new("Problem_BrokerUnreachable_Why"), new("Problem_BrokerUnreachable_Next"), ProblemAction.TryAgain),
        ProblemKind.BrokerRefused => new(kind, new("Problem_BrokerRefused_Title"), new("Problem_BrokerRefused_What"),
            new("Problem_BrokerRefused_Why"), new("Problem_BrokerRefused_Next"), ProblemAction.OpenStatus),
        ProblemKind.VaultUnreadable => new(kind, new("Problem_VaultUnreadable_Title"), new("Problem_VaultUnreadable_What"),
            new("Problem_VaultUnreadable_Why"), new("Problem_VaultUnreadable_Next"), ProblemAction.OpenDataFolder),
        ProblemKind.NoRecoveryKey => new(kind, new("Problem_NoRecoveryKey_Title"), new("Problem_NoRecoveryKey_What"),
            new("Problem_NoRecoveryKey_Why"), new("Problem_NoRecoveryKey_Next"), ProblemAction.FinishSetup),
        ProblemKind.SoloBrokerDown => new(kind, new("Problem_SoloBrokerDown_Title"), new("Problem_SoloBrokerDown_What"),
            new("Problem_SoloBrokerDown_Why"), new("Problem_SoloBrokerDown_Next"), ProblemAction.TryAgain),
        ProblemKind.FileAccess => new(kind, new("Problem_FileAccess_Title"), new("Problem_FileAccess_What"),
            new("Problem_FileAccess_Why"), new("Problem_FileAccess_Next"), ProblemAction.OpenDataFolder),
        _ => new(ProblemKind.Unexpected, new("Problem_Unexpected_Title"), new("Problem_Unexpected_What"),
            new("Problem_Unexpected_Why"), new("Problem_Unexpected_Next"), ProblemAction.OpenDataFolder),
    };

    /// <summary>
    /// The text "Copy details" puts on the clipboard for a support request: the problem, the
    /// technical message and where the log is. No stack trace (that is in the log) and no secret:
    /// messages never carry values by design.
    /// </summary>
    public static string Details(Problem problem, string? technicalMessage, string appVersion, string logPath, DateTimeOffset now)
    {
        var sb = new StringBuilder();
        sb.AppendLine(CultureInfo.InvariantCulture, $"Tiresias {appVersion}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"Time: {now:u}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"Problem: {problem.Kind}");
        if (!string.IsNullOrWhiteSpace(technicalMessage))
            sb.AppendLine(CultureInfo.InvariantCulture, $"Message: {technicalMessage.Trim()}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"OS: {Environment.OSVersion.VersionString}");
        sb.Append(CultureInfo.InvariantCulture, $"Log: {logPath}");
        return sb.ToString();
    }
}
