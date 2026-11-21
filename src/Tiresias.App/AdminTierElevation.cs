using System.ComponentModel;
using System.Diagnostics;
using Tiresias.AdminTier;

namespace Tiresias.App;

/// <summary>
/// Starts this app again elevated, <c>Tiresias.exe --admin-tier install|remove</c>, through the UAC
/// prompt, and reads back what it did. Program handles that command before any window opens.
/// </summary>
static class AdminTierElevation
{
    public const string Argument = "--admin-tier";

    /// <returns>The step's result, or <c>null</c> when the UAC prompt was declined.</returns>
    public static async Task<AdminSetupResult?> RunAsync(string verb)
    {
        AppLog.Info($"admin tier: {verb} asked for (UAC)");
        var result = await Task.Run(() => Run(verb, TimeSpan.FromMinutes(5)));
        AppLog.Info($"admin tier: {verb} {(result is null ? "declined at the UAC prompt" : result.ToString())}");
        return result;
    }

    /// <summary>Waits at most <paramref name="wait"/>; a step still running then counts as failed.</summary>
    public static AdminSetupResult? Run(string verb, TimeSpan wait)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo(Environment.ProcessPath!, [Argument, verb])
            {
                UseShellExecute = true,
                Verb = "runas",
            });
            if (process is null)
                return AdminSetupResult.Failed;
            if (!process.WaitForExit(wait))
                return AdminSetupResult.Failed;
            return Enum.IsDefined((AdminSetupResult)process.ExitCode) ? (AdminSetupResult)process.ExitCode : AdminSetupResult.Failed;
        }
        catch (Win32Exception e)
        {
            return e.NativeErrorCode == ErrorCancelled ? null : AdminSetupResult.Failed;
        }
    }

    const int ErrorCancelled = 1223;
}
