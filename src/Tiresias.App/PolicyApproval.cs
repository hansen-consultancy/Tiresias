using System.Windows;
using Tiresias.Agent;
using Tiresias.App.Logic;
using Tiresias.App.Views;
using Tiresias.Policy;
using Tiresias.Vault;

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
    public static Task<bool> ApplyAsync(Window? owner, IReadOnlyList<Service> set, IReadOnlyList<string> remove, bool confirmed = false) =>
        ApplyAsync(owner, VaultEditor.Plan(set, remove), confirmed ? null : ("Policy_Title", "Policy_Body"));

    /// <summary>
    /// Binds the secrets saved before policy binding, after showing their services as they are now.
    /// Until then the broker refuses them, so the app offers it after each unlock that finds some.
    /// </summary>
    /// <returns>Whether every secret is bound now.</returns>
    public static Task<bool> MigrateAsync(Window? owner) =>
        ApplyAsync(owner, VaultEditor.Migration(), ("Policy_MigrateTitle", "Policy_MigrateBody"));

    /// <param name="ask">The dialog's title and body resources, or <c>null</c> when the caller asked already.</param>
    static async Task<bool> ApplyAsync(Window? owner, PolicyChange change, (string Title, string Body)? ask)
    {
        if (change.IsEmpty)
            return true;
        if (ask is var (title, body) && !AskWindow.Confirm(owner, Text.Get(title), Text.Format(body, string.Join(Environment.NewLine, change.Lines)),
                Text.Get("Policy_Approve")))
            return false;
        using var because = HelloPrompts.Because(PromptReason.ApproveChange);
        await Task.Run(() =>
        {
            using var fresh = HelloKeyWrapper.Open(create: false);
            VaultEditor.Approve(change, fresh);
        });
        AppLog.Info($"policy approved: {change.Lines.Count} line(s), {change.Rebind.Count} secret(s) rebound");
        return true;
    }
}
