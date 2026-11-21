using System.ComponentModel;
using System.Diagnostics;
using Tiresias.AdminTier;

namespace Tiresias.App;

/// <summary>
/// Starts this app again elevated, <c>Tiresias.exe --admin-tier install|remove|release-decoys</c>, through the UAC
/// prompt, and reads back what it did. Program handles that command before any window opens.
/// </summary>
static class AdminTierElevation
{
    public const string Argument = "--admin-tier";

    /// <returns>The step's result, or <c>null</c> when the UAC prompt was declined.</returns>
    public static async Task<AdminSetupResult?> RunAsync(string verb, string? argument = null)
    {
        if (Tiresias.Agent.DemoMode.On)
        {
            AppLog.Info($"admin tier: {verb} left alone in demo mode");
            return null;
        }
        AppLog.Info($"admin tier: {verb} asked for (UAC)");
        var result = await Task.Run(() => Run(verb, TimeSpan.FromMinutes(5), argument));
        AppLog.Info($"admin tier: {verb} {(result is null ? "declined at the UAC prompt" : result.ToString())}");
        return result;
    }

    /// <summary>Waits at most <paramref name="wait"/>; a step still running then counts as failed.</summary>
    public static AdminSetupResult? Run(string verb, TimeSpan wait, string? argument = null)
    {
        try
        {
            var start = new ProcessStartInfo(Environment.ProcessPath!, [Argument, verb])
            {
                UseShellExecute = true,
                Verb = "runas",
            };
            if (argument is not null)
                start.ArgumentList.Add(argument);
            using var process = Process.Start(start);
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
