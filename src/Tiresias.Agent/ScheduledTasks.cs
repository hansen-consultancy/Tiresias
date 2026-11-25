using System.Runtime.InteropServices;
using System.Security.Principal;
using Tiresias.Client;

namespace Tiresias.Agent;

/// <summary>
/// The scheduled tasks that start a program when someone signs in, read through the Task Scheduler's
/// own COM interface, in process and as the user: only the tasks the user may read, nothing run.
/// Windows' own tasks (<c>\Microsoft\Windows</c>) and those for another user's log-on only are left out. None in demo mode.
/// </summary>
static class ScheduledTasks
{
    const int LogOnTrigger = 9; // TASK_TRIGGER_LOGON
    const int ExecAction = 0; // TASK_ACTION_EXEC
    const int IncludeHidden = 1; // TASK_ENUM_HIDDEN

    public static IReadOnlyList<StartupEntry> AtLogOn()
    {
        if (DemoMode.On || Type.GetTypeFromProgID("Schedule.Service") is not { } type)
            return [];
        List<StartupEntry> entries = [];
        dynamic? service = null;
        try
        {
            service = Activator.CreateInstance(type)!;
            service.Connect();
            Walk(service.GetFolder(@"\"), entries, SurfaceProbe.Tray());
        }
        catch (Exception e) when (e is COMException or UnauthorizedAccessException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException or InvalidCastException)
        {
        }
        finally
        {
            if (service is not null)
                Marshal.FinalReleaseComObject(service);
        }
        return entries;
    }

    static void Walk(dynamic folder, List<StartupEntry> entries, HashSet<string> tray)
    {
        string path = folder.Path;
        if (path.Equals(@"\Microsoft\Windows", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith(@"\Microsoft\Windows\", StringComparison.OrdinalIgnoreCase))
            return;
        dynamic tasks = folder.GetTasks(IncludeHidden);
        for (var i = 1; i <= (int)tasks.Count; i++)
        {
            try
            {
                Read(tasks[i], entries, tray);
            }
            catch (Exception e) when (e is COMException or UnauthorizedAccessException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException or InvalidCastException)
            {
            }
        }
        dynamic folders = folder.GetFolders(0);
        for (var i = 1; i <= (int)folders.Count; i++)
        {
            try
            {
                Walk(folders[i], entries, tray);
            }
            catch (Exception e) when (e is COMException or UnauthorizedAccessException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException or InvalidCastException)
            {
            }
        }
    }

    /// <summary>
    /// A log-on trigger that fires when the current user signs in: no account named, the user, or a
    /// group the user is in (by name or SID). One naming an account that can't be resolved counts too,
    /// so an entry is shown rather than hidden; only another user's account is left out.
    /// </summary>
    static bool ForYou(string? user)
    {
        if (string.IsNullOrEmpty(user))
            return true;
        using var you = WindowsIdentity.GetCurrent();
        SecurityIdentifier sid;
        try
        {
            sid = user.StartsWith("S-", StringComparison.OrdinalIgnoreCase)
                ? new SecurityIdentifier(user)
                : (SecurityIdentifier)new NTAccount(user).Translate(typeof(SecurityIdentifier));
        }
        catch (Exception e) when (e is IdentityNotMappedException or ArgumentException or SystemException)
        {
            return true;
        }
        return sid == you.User || you.Groups?.Contains(sid) == true;
    }

    static void Read(dynamic task, List<StartupEntry> entries, HashSet<string> tray)
    {
        dynamic definition = task.Definition;
        dynamic triggers = definition.Triggers;
        bool? on = null;
        for (var i = 1; i <= (int)triggers.Count; i++)
        {
            dynamic trigger = triggers[i];
            if ((int)trigger.Type == LogOnTrigger && ForYou(trigger.UserId as string))
                on = on == true || (bool)trigger.Enabled;
        }
        if (on is null)
            return;
        on = on.Value && (bool)task.Enabled;
        dynamic actions = definition.Actions;
        for (var i = 1; i <= (int)actions.Count; i++)
        {
            dynamic action = actions[i];
            if ((int)action.Type != ExecAction || action.Path is not string { Length: > 0 } command
                || Doctor.ExecutableIn(Environment.ExpandEnvironmentVariables(command)) is not { } program)
                continue;
            entries.Add(SurfaceProbe.Entry((string)task.Name, StartupEntry.ScheduledTask, program, null, tray, on.Value));
        }
    }
}
