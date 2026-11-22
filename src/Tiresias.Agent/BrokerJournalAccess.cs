using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Tiresias.Agent;

[SupportedOSPlatform("windows")]
internal static class BrokerJournalAccess
{
    internal static PipeSecurity For(SecurityIdentifier owner, SecurityIdentifier service)
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(service, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(owner, PipeAccessRights.Read | PipeAccessRights.Synchronize, AccessControlType.Allow));
        return security;
    }
}
