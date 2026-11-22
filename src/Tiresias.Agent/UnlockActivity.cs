using Tiresias.Audit;

namespace Tiresias.Agent;

internal static class UnlockActivity
{
    public static void Run(Action unlock, AuditLog activity)
    {
        try
        {
            unlock();
        }
        catch (HelloException e) when (e.PromptRefusal is { } reason)
        {
            activity.Append(new(AuditKind.Deny, Service: "Windows Hello unlock", Reason: reason));
            throw;
        }
    }
}
