using System.Windows.Threading;
using Tiresias.App.Views;
using Tiresias.UserSecrets;

namespace Tiresias.App;

/// <summary>
/// Puts every consent question (user secrets from the pipe, placeholders from <c>tir</c>) on screen
/// one at a time: a second request waits until the first is answered, and the open dialog says how
/// many are waiting. Locking the session answers every open and waiting question with Deny.
/// </summary>
sealed class ConsentPresenter(Dispatcher dispatcher) : IUserSecretsConsentPrompt, IDisposable
{
    readonly SemaphoreSlim one = new(1, 1);
    CancellationTokenSource session = new();
    int waiting;

    /// <summary>Unlocks with Windows Hello, explaining any problem; completes with whether it worked. Set once the agent exists.</summary>
    public Func<Task<bool>>? Unlock { get; set; }

    /// <summary>Whether a consent dialog is on screen; an update never restarts the app under one.</summary>
    public bool Busy => one.CurrentCount == 0;

    public Task<ConsentAnswer> AskAsync(UserSecretsConsentRequest request, CancellationToken ct) =>
        ShowAsync(new ConsentView(
            // A non-breaking hyphen, so an id like my-app-1234 never wraps at its dashes.
            Text.Format("Consent_UserSecrets_Heading", request.UserSecretsId.Replace('-', '‑')),
            request.Executable,
            request.Keys.Count == 1 ? Text.Get("Consent_UserSecrets_KeysLabelOne") : Text.Format("Consent_UserSecrets_KeysLabel", request.Keys.Count),
            request.Keys,
            Text.Get("Consent_UserSecrets_Note"),
            AllowSession: true), UserSecretsService.ConsentTimeout, ct);

    /// <summary>Locked: the same dialog, naming the program, with "Unlock with Windows Hello" as the way to answer it.</summary>
    public async Task<bool> AskUnlockAsync(string? executable, string userSecretsId, CancellationToken ct)
    {
        if (Unlock is not { } unlock)
            return false;
        var answer = await ShowAsync(new ConsentView(
            Text.Format("Consent_UserSecrets_Heading", userSecretsId.Replace('-', '\u2011')),
            executable,
            Text.Get("Consent_Unlock_Label"),
            [],
            Text.Get("Consent_Unlock_Note"),
            AllowSession: false,
            Unlock: true), UserSecretsService.ConsentTimeout, ct);
        return answer != ConsentAnswer.Deny && await dispatcher.InvokeAsync(unlock).Task.Unwrap();
    }

    /// <summary>A placeholder or <c>tir exec</c> approval asked by <c>tir</c>; <c>tir</c> still asks for Windows Hello afterwards.</summary>
    public async Task<bool> AskPlaceholderAsync(string title, IReadOnlyList<string> lines, string? caller, CancellationToken ct) =>
        await ShowAsync(new ConsentView(
            Text.Format("Consent_Placeholder_Heading", title),
            caller,
            Text.Get("Consent_Placeholder_ListLabel"),
            lines,
            Text.Get("Consent_Placeholder_Note"),
            AllowSession: false), UserSecretsService.ConsentTimeout, ct) != ConsentAnswer.Deny;

    /// <summary>The session locked: deny what is open and what waits.</summary>
    public void DenyAll()
    {
        var old = Interlocked.Exchange(ref session, new CancellationTokenSource());
        // Not disposed: a request may be reading its token right now. Nothing unmanaged is left behind.
        old.Cancel();
    }

    async Task<ConsentAnswer> ShowAsync(ConsentView view, TimeSpan timeout, CancellationToken ct)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, session.Token);
        linked.CancelAfter(timeout);
        var deadline = DateTimeOffset.Now + timeout;
        Interlocked.Increment(ref waiting);
        try
        {
            await one.WaitAsync(linked.Token);
        }
        catch (OperationCanceledException)
        {
            Interlocked.Decrement(ref waiting);
            return ConsentAnswer.Deny;
        }
        try
        {
            var others = Interlocked.Decrement(ref waiting);
            var shown = await dispatcher.InvokeAsync(() => ConsentWindow.AskAsync(view, deadline - DateTimeOffset.Now, others, linked.Token));
            return await shown;
        }
        finally
        {
            one.Release();
        }
    }

    public void Dispose()
    {
        session.Dispose();
        one.Dispose();
    }
}
