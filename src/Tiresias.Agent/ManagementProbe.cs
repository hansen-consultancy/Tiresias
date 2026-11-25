using System.Runtime.InteropServices;
using Tiresias.Client;

namespace Tiresias.Agent;

/// <summary>Reads <see cref="Management"/> as any user can: netapi32 for domain and Entra ID join, the registry for device management.</summary>
static partial class ManagementProbe
{
    public static Management Read()
    {
        if (DemoMode.On)
            return Management.None;
        return new(Domain(), EntraJoined(), Management.Enrolled(Enrollments()));
    }

    const int NetSetupDomainName = 3;

    static string? Domain()
    {
        if (NetGetJoinInformation(null, out var name, out var status) != 0)
            return null;
        try
        {
            return status == NetSetupDomainName ? Marshal.PtrToStringUni(name) : null;
        }
        finally
        {
            _ = NetApiBufferFree(name);
        }
    }

    /// <summary>Joined (<c>DSREG_DEVICE_JOIN</c>), not just registered with a work account (<c>DSREG_WORKPLACE_JOIN</c>).</summary>
    static bool EntraJoined()
    {
        const int deviceJoin = 1;
        try
        {
            if (NetGetAadJoinInformation(null, out var info) != 0 || info == 0)
                return false;
            try
            {
                return Marshal.ReadInt32(info) == deviceJoin;
            }
            finally
            {
                NetFreeAadJoinInformation(info);
            }
        }
        catch (EntryPointNotFoundException)
        {
            return false;
        }
    }

    static IEnumerable<(string? Provider, int? State)> Enrollments()
    {
        using var root = UserMachine.LocalMachine?.OpenSubKey(@"SOFTWARE\Microsoft\Enrollments");
        if (root is null)
            return [];
        List<(string?, int?)> enrollments = [];
        foreach (var name in root.GetSubKeyNames())
        {
            using var key = root.OpenSubKey(name);
            enrollments.Add((key?.GetValue("ProviderID") as string, key?.GetValue("EnrollmentState") as int?));
        }
        return enrollments;
    }

    [LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int NetGetJoinInformation(string? server, out nint name, out int status);

    [LibraryImport("netapi32.dll")]
    private static partial int NetApiBufferFree(nint buffer);

    [LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int NetGetAadJoinInformation(string? tenantId, out nint joinInfo);

    [LibraryImport("netapi32.dll")]
    private static partial void NetFreeAadJoinInformation(nint joinInfo);
}
