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
        catch (HelloException e) when (e.Problem is HelloProblem.Cancelled or HelloProblem.Expired)
        {
            var reason = e.Problem == HelloProblem.Cancelled ? "Windows Hello prompt was cancelled." : "Windows Hello prompt expired.";
            activity.Append(new(AuditKind.Deny, Service: "Windows Hello unlock", Reason: reason));
            throw;
        }
    }
}
