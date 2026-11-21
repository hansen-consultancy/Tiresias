using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using Tiresias.AdminTier;

namespace Tiresias.Admin;

/// <summary>The process on the other end of the pipe, as far as it could be read.</summary>
/// <param name="Caller"><c>null</c> when the caller can't be named: then it is refused.</param>
sealed record PipeClientInfo(AdminCaller? Caller, int? Pid, string? Image, string? Problem);

/// <summary>
/// Names the admin pipe's caller from the pipe and the client process's own token, never from
/// anything the client sends. The process must have existed before the connection was accepted:
/// a client that connects and exits can't hand its process id to another process that took it.
/// </summary>
static partial class PipeCallerIdentity
{
    const string ServiceGroupSid = "S-1-5-6";
    static readonly HashSet<string> ServiceAccounts = ["S-1-5-18", "S-1-5-19", "S-1-5-20"];

    public static PipeClientInfo Identify(NamedPipeServerStream pipe, DateTime connectedUtc)
    {
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var pid))
            return new(null, null, null, "the pipe's client process can't be told");
        using var process = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (process.IsInvalid)
            return new(null, (int)pid, null, $"process {pid} can't be opened ({Marshal.GetLastPInvokeError()})");
        // Holding the handle pins the process id; a process created after the connection isn't the client.
        if (!GetProcessTimes(process, out var created, out _, out _, out _) || DateTime.FromFileTimeUtc(created) > connectedUtc)
            return new(null, (int)pid, null, "the client process ended before it could be named");
        var image = Image(process);
        if (!OpenProcessToken(process, TokenQuery | TokenDuplicate, out var token))
            return new(null, (int)pid, image, $"process {pid}'s token can't be opened ({Marshal.GetLastPInvokeError()})");
        using (token)
        {
            try
            {
                return new(Caller(token), (int)pid, image, null);
            }
            catch (Exception e) when (e is Win32Exception or UnauthorizedAccessException or System.Security.SecurityException)
            {
                return new(null, (int)pid, image, $"process {pid}'s token can't be read ({e.GetType().Name})");
            }
        }
    }

    static AdminCaller Caller(SafeAccessTokenHandle token)
    {
        using var identity = new WindowsIdentity(token.DangerousGetHandle());
        var user = identity.User?.Value ?? throw new Win32Exception("The token has no user.");
        var isService = ServiceAccounts.Contains(user) || identity.Groups?.Any(g => g.Value == ServiceGroupSid) == true;
        var session = (int)TokenInt(token, TokenSessionId);
        return new(user, session, SessionUser(session), TokenInt(token, TokenElevation) != 0, isService);
    }

    static uint TokenInt(SafeAccessTokenHandle token, int infoClass) =>
        GetTokenInformation(token, infoClass, out var value, sizeof(uint), out _) ? value : throw new Win32Exception(Marshal.GetLastPInvokeError());

    /// <summary>The SID of the user signed in to the session, or <c>null</c> when nobody is.</summary>
    static string? SessionUser(int session)
    {
        var name = SessionString(session, WtsUserName);
        if (string.IsNullOrEmpty(name))
            return null;
        try
        {
            return new NTAccount(SessionString(session, WtsDomainName) ?? "", name).Translate(typeof(SecurityIdentifier)).Value;
        }
        catch (SystemException)
        {
            // NTAccount.Translate throws IdentityNotMappedException, or a bare SystemException when a domain can't be reached.
            // Can't be told: the caller is refused, as if nobody were signed in to its session.
            return null;
        }
    }

    static string? SessionString(int session, int infoClass)
    {
        if (!WTSQuerySessionInformationW(IntPtr.Zero, session, infoClass, out var buffer, out _))
            return null;
        try
        {
            return Marshal.PtrToStringUni(buffer);
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    static string? Image(SafeProcessHandle process)
    {
        var buffer = new char[1024];
        var size = buffer.Length;
        return QueryFullProcessImageNameW(process, 0, buffer, ref size) ? new string(buffer, 0, size) : null;
    }

    const uint ProcessQueryLimitedInformation = 0x1000;
    const uint TokenQuery = 0x0008;
    const uint TokenDuplicate = 0x0002;
    const int TokenSessionId = 12;
    const int TokenElevation = 20;
    const int WtsUserName = 5;
    const int WtsDomainName = 7;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, [Out] char[] name, ref int size);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetTokenInformation(SafeAccessTokenHandle token, int infoClass, out uint info, int length, out int returned);

    [LibraryImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WTSQuerySessionInformationW(IntPtr server, int session, int infoClass, out IntPtr buffer, out int bytes);

    [LibraryImport("wtsapi32.dll")]
    private static partial void WTSFreeMemory(IntPtr memory);
}
