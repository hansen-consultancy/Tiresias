using System.Runtime.InteropServices;
using Tiresias.Client;

namespace Tiresias.Agent;

/// <summary>
/// The scheduled tasks that start a program when someone signs in, read through the Task Scheduler's
/// own COM interface, in process and as the user: only the tasks the user may read, nothing run.
/// Windows' own tasks (<c>\Microsoft\Windows</c>) and those for another user's log-on are left out. None in demo mode.
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
        if (path.StartsWith(@"\Microsoft\Windows", StringComparison.OrdinalIgnoreCase))
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

    /// <summary>A log-on trigger for anyone (no user named) or for the current user, by account name or SID.</summary>
    static bool ForYou(string? user)
    {
        if (string.IsNullOrEmpty(user))
            return true;
        using var you = System.Security.Principal.WindowsIdentity.GetCurrent();
        return user.Equals(you.Name, StringComparison.OrdinalIgnoreCase) || user.Equals(you.User?.Value, StringComparison.OrdinalIgnoreCase)
            || user.Equals(Environment.UserName, StringComparison.OrdinalIgnoreCase);
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
