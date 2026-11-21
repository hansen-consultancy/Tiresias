using System.ComponentModel;
using System.Runtime.InteropServices;
using Tiresias.AdminTier;
using Tiresias.Protocol;

namespace Tiresias.Agent;

/// <summary>The <c>TiresiasAdmin</c> service through the Service Control Manager: read by anyone, changed only elevated.</summary>
static unsafe partial class AdminService
{
    /// <param name="ProcessId">The process the SCM runs the service in; 0 when it isn't running.</param>
    public sealed record State(bool Exists, bool Running, int ProcessId)
    {
        public AdminServiceFacts Facts => new(Exists, Running);
    }

    public static State Query()
    {
        using var scm = Manager(ScManagerConnect);
        var service = OpenServiceW(scm.Handle, AdminWire.ServiceName, ServiceQueryStatus);
        if (service == IntPtr.Zero)
            return Marshal.GetLastPInvokeError() == ErrorServiceDoesNotExist ? new(false, false, 0) : throw new Win32Exception();
        try
        {
            var status = Status(service);
            return new(true, status.CurrentState == ServiceRunning, status.CurrentState == ServiceRunning ? (int)status.ProcessId : 0);
        }
        finally
        {
            CloseServiceHandle(service);
        }
    }

    /// <summary>Creates the service as LocalSystem, or sets an existing one's binary, account and start type again.</summary>
    public static void CreateOrConfigure(string binary, bool exists)
    {
        using var scm = Manager(ScManagerAllAccess);
        var path = $"\"{binary}\"";  // Quoted: %ProgramFiles% has a space, and an unquoted path runs C:\Program.exe.
        var service = exists
            ? OpenServiceW(scm.Handle, AdminWire.ServiceName, ServiceAllAccess)
            : CreateServiceW(scm.Handle, AdminWire.ServiceName, DisplayName, ServiceAllAccess, ServiceWin32OwnProcess, ServiceAutoStart,
                ServiceErrorNormal, path, null, IntPtr.Zero, null, null, null);
        if (service == IntPtr.Zero)
            throw new Win32Exception();
        try
        {
            if (exists && !ChangeServiceConfigW(service, ServiceWin32OwnProcess, ServiceAutoStart, ServiceErrorNormal, path, null, IntPtr.Zero,
                    null, "LocalSystem", null, DisplayName))
                throw new Win32Exception();
            Describe(service);
            KeepOnlyPrivileges(service, "SeSecurityPrivilege", "SeChangeNotifyPrivilege");
            RestartOnFailure(service);
        }
        finally
        {
            CloseServiceHandle(service);
        }
    }

    /// <summary>Starts the service and waits for it to run; <c>false</c> when it stopped again instead.</summary>
    public static bool Start()
    {
        WithService(ServiceStart | ServiceQueryStatus, service =>
        {
            if (!StartServiceW(service, 0, IntPtr.Zero) && Marshal.GetLastPInvokeError() != ErrorServiceAlreadyRunning)
                throw new Win32Exception();
        });
        return WaitFor(running: true, TimeSpan.FromSeconds(15));
    }

    public static void Stop()
    {
        WithService(ServiceStop, service =>
        {
            if (!ControlService(service, ServiceControlStop, out _) && Marshal.GetLastPInvokeError() != ErrorServiceNotActive)
                throw new Win32Exception();
        });
        if (!WaitFor(running: false, TimeSpan.FromSeconds(30)))
            throw new TimeoutException("The admin tier's service didn't stop within 30 seconds.");
    }

    public static void Delete() => WithService(Delete_, service =>
    {
        if (!DeleteService(service) && Marshal.GetLastPInvokeError() != ErrorServiceMarkedForDelete)
            throw new Win32Exception();
    });

    /// <summary>Waits for the service to run or to stop. Waiting to run, a stop means it failed: a start pending is never stopped.</summary>
    static bool WaitFor(bool running, TimeSpan timeout)
    {
        var wanted = running ? ServiceRunning : ServiceStopped;
        var until = DateTime.UtcNow + timeout;
        while (true)
        {
            uint state = 0;
            WithService(ServiceQueryStatus, service => state = Status(service).CurrentState);
            if (state == wanted)
                return true;
            if (state == ServiceStopped || DateTime.UtcNow > until)
                return false;
            Thread.Sleep(250);
        }
    }

    static ServiceStatusProcess Status(IntPtr service) =>
        QueryServiceStatusEx(service, ScStatusProcessInfo, out var status, sizeof(ServiceStatusProcess), out _) ? status : throw new Win32Exception();

    static void Describe(IntPtr service)
    {
        fixed (char* text = "Tiresias's optional admin tier: holds what an ordinary account can't (docs/admin-tier.md). Remove it from the Tiresias app's About page.")
        {
            var info = (IntPtr)text;
            Config2(service, ServiceConfigDescription, &info);
        }
    }

    /// <summary>The service's token keeps only these; LocalSystem's others are removed when it starts (<c>sc privs</c>).</summary>
    static void KeepOnlyPrivileges(IntPtr service, params string[] privileges)
    {
        fixed (char* list = string.Join('\0', privileges) + "\0\0")
        {
            var info = (IntPtr)list;
            Config2(service, ServiceConfigRequiredPrivilegesInfo, &info);
        }
    }

    /// <summary>Restarts after 5 s, 30 s, then every minute, the count reset after a day; also when it stops with an error.</summary>
    static void RestartOnFailure(IntPtr service)
    {
        var actions = stackalloc ScAction[] { new(ScActionRestart, 5_000), new(ScActionRestart, 30_000), new(ScActionRestart, 60_000) };
        var failure = new ServiceFailureActions { ResetPeriod = 86_400, Actions = 3, ActionList = actions };
        Config2(service, ServiceConfigFailureActions, &failure);
        var onNonCrash = 1;
        Config2(service, ServiceConfigFailureActionsFlag, &onNonCrash);
    }

    static void Config2(IntPtr service, uint level, void* info)
    {
        if (!ChangeServiceConfig2W(service, level, info))
            throw new Win32Exception();
    }

    static void WithService(uint access, Action<IntPtr> act)
    {
        using var scm = Manager(ScManagerConnect);
        var service = OpenServiceW(scm.Handle, AdminWire.ServiceName, access);
        if (service == IntPtr.Zero)
            throw new Win32Exception();
        try
        {
            act(service);
        }
        finally
        {
            CloseServiceHandle(service);
        }
    }

    static ScmHandle Manager(uint access)
    {
        var handle = OpenSCManagerW(null, null, access);
        return handle == IntPtr.Zero ? throw new Win32Exception() : new(handle);
    }

    readonly struct ScmHandle(IntPtr handle) : IDisposable
    {
        public IntPtr Handle => handle;
        public void Dispose() => CloseServiceHandle(handle);
    }

    const string DisplayName = "Tiresias admin tier";

    const uint ScManagerConnect = 0x0001;
    const uint ScManagerAllAccess = 0xF003F;
    const uint ServiceQueryStatus = 0x0004;
    const uint ServiceStart = 0x0010;
    const uint ServiceStop = 0x0020;
    const uint Delete_ = 0x10000;
    const uint ServiceAllAccess = 0xF01FF;
    const uint ServiceWin32OwnProcess = 0x10;
    const uint ServiceAutoStart = 2;
    const uint ServiceErrorNormal = 1;
    const uint ServiceControlStop = 1;
    const uint ServiceStopped = 1;
    const uint ServiceRunning = 4;
    const int ScStatusProcessInfo = 0;
    const uint ServiceConfigDescription = 1;
    const uint ServiceConfigFailureActions = 2;
    const uint ServiceConfigFailureActionsFlag = 4;
    const uint ServiceConfigRequiredPrivilegesInfo = 6;
    const int ScActionRestart = 1;
    const int ErrorServiceAlreadyRunning = 1056;
    const int ErrorServiceDoesNotExist = 1060;
    const int ErrorServiceNotActive = 1062;
    const int ErrorServiceMarkedForDelete = 1072;

    [StructLayout(LayoutKind.Sequential)]
    struct ServiceStatusProcess
    {
        public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint, ProcessId, ServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    readonly struct ScAction(int type, uint delay)
    {
        readonly int type = type;
        readonly uint delay = delay;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ServiceFailureActions
    {
        public uint ResetPeriod;
        public IntPtr RebootMessage;
        public IntPtr Command;
        public uint Actions;
        public ScAction* ActionList;
    }

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial IntPtr OpenSCManagerW(string? machine, string? database, uint access);

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial IntPtr OpenServiceW(IntPtr manager, string name, uint access);

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial IntPtr CreateServiceW(IntPtr manager, string name, string displayName, uint access, uint type, uint start, uint errorControl,
        string binaryPath, string? loadOrderGroup, IntPtr tagId, string? dependencies, string? account, string? password);

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ChangeServiceConfigW(IntPtr service, uint type, uint start, uint errorControl, string binaryPath, string? loadOrderGroup,
        IntPtr tagId, string? dependencies, string? account, string? password, string displayName);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ChangeServiceConfig2W(IntPtr service, uint level, void* info);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryServiceStatusEx(IntPtr service, int level, out ServiceStatusProcess status, int size, out int needed);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool StartServiceW(IntPtr service, uint argCount, IntPtr args);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ControlService(IntPtr service, uint control, out ServiceStatusProcess status);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DeleteService(IntPtr service);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseServiceHandle(IntPtr handle);
}
