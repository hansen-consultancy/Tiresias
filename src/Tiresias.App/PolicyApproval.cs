using System.Windows;
using Tiresias.Agent;
using Tiresias.App.Views;
using Tiresias.Policy;

namespace Tiresias.App;

/// <summary>
/// The app's one way to change the vault's services: shows what changes, then approves it with a
/// fresh Windows Hello prompt (<see cref="VaultEditor.Approve"/>), which rebinds the secrets the
/// change touches. A change made any other way leaves those secrets unusable.
/// </summary>
static class PolicyApproval
{
    /// <param name="confirmed">The caller already asked the user about this change in its own words (removing a service).</param>
    /// <returns>Whether the change was saved; <c>false</c> when the user said no.</returns>
    /// <exception cref="InvalidOperationException">A secret is missing, the Hello prompt was cancelled or failed, or the vault changed meanwhile.</exception>
    public static async Task<bool> ApplyAsync(Window? owner, IReadOnlyList<Service> set, IReadOnlyList<string> remove, bool confirmed = false)
    {
        var change = VaultEditor.Plan(set, remove);
        if (change.IsEmpty)
            return true;
        if (!confirmed && !AskWindow.Confirm(owner, Text.Get("Policy_Title"), Text.Format("Policy_Body", string.Join(Environment.NewLine, change.Lines)),
                Text.Get("Policy_Approve")))
            return false;
        await Task.Run(() =>
        {
            using var fresh = HelloKeyWrapper.Open(create: false);
            VaultEditor.Approve(change, fresh);
        });
        AppLog.Info($"policy approved: {change.Lines.Count} line(s), {change.Rebind.Count} secret(s) rebound");
        return true;
    }
}
