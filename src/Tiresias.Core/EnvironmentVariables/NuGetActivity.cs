using Tiresias.Audit;

namespace Tiresias.EnvironmentVariables;

/// <summary>How the app answered the NuGet credential plugin for a mapped feed.</summary>
public enum NuGetOutcome
{
    /// <summary>The user allowed this one request.</summary>
    AllowedOnce,
    /// <summary>The user allowed the program until the agent locks.</summary>
    AllowedForSession,
    /// <summary>Handed over without asking: an earlier allow for this session covers the program.</summary>
    CoveredBySession,
    /// <summary>The user denied it, or the question went unanswered.</summary>
    Denied,
    /// <summary>NuGet asked again after the token it got was refused; Tiresias doesn't answer a retry.</summary>
    RetryRefused,
    /// <summary>The feed is mapped to a variable that isn't sealed (any more).</summary>
    NotSealed,
}

/// <summary>The activity record of a NuGet credential request: program, feed and variable name, never the token.</summary>
public static class NuGetActivity
{
    public const string Consumer = "nuget";

    /// <param name="program">The image path of the program that ran the plugin.</param>
    /// <param name="processId">Its process, recorded as <c>(pid N)</c> after the path like the forwarder's records.</param>
    public static AuditRecord Record(NuGetOutcome outcome, string program, int processId, string source, string variable) =>
        new(outcome is NuGetOutcome.AllowedOnce or NuGetOutcome.AllowedForSession or NuGetOutcome.CoveredBySession ? AuditKind.Allow : AuditKind.Deny,
            Consumer: Consumer, Service: source, Process: $"{program} (pid {processId})", Reason: $"{variable}: {Describe(outcome)}");

    static string Describe(NuGetOutcome outcome) => outcome switch
    {
        NuGetOutcome.AllowedOnce => "allowed once",
        NuGetOutcome.AllowedForSession => "allowed for this session",
        NuGetOutcome.CoveredBySession => "allowed earlier for this session",
        NuGetOutcome.Denied => "denied",
        NuGetOutcome.RetryRefused => "retry after a refused token, not answered",
        _ => "not sealed",
    };
}
