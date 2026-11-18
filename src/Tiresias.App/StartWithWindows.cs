using Microsoft.Win32;
using Tiresias.App.Logic;

namespace Tiresias.App;

/// <summary>
/// Starts the app when the user signs in to Windows (HKCU <c>Run</c>, no admin rights), so apps that
/// start at sign-in too find the agent. Turned on by the installer, off on uninstall, and switchable
/// on the status page. Only an installed copy registers: a development build's folder goes stale.
/// </summary>
static class StartWithWindows
{
    const string Key = @"Software\Microsoft\Windows\CurrentVersion\Run";
    const string Name = "Tiresias";

    static string Exe => Environment.ProcessPath!;

    /// <summary>Whether Windows starts this copy at sign-in; an entry left by another copy doesn't count.</summary>
    public static bool IsOn
    {
        get
        {
            try
            {
                using var run = Registry.CurrentUser.OpenSubKey(Key);
                return SignInStart.Starts(run?.GetValue(Name) as string, Exe);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                AppLog.Error(e, "sign-in start");
                return false;
            }
        }
    }

    /// <summary>Never throws: a failure is logged and reported as <c>false</c>, and the app still runs when started by hand.</summary>
    public static bool Set(bool on)
    {
        try
        {
            using var run = Registry.CurrentUser.CreateSubKey(Key, writable: true);
            if (on)
                run.SetValue(Name, SignInStart.Command(Exe));
            else
                run.DeleteValue(Name, throwOnMissingValue: false);
            AppLog.Info(on ? $"starts at sign-in: {Exe}" : "no longer starts at sign-in");
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            AppLog.Error(e, "sign-in start");
            return false;
        }
    }
}
