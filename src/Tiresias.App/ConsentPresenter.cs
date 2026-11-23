using System.Windows.Threading;
using Tiresias.Alerts;
using Tiresias.App.Logic;
using Tiresias.App.Views;
using Tiresias.EnvironmentVariables;
using Tiresias.UserSecrets;

namespace Tiresias.App;

/// <summary>
/// Puts every consent question (user secrets from the pipe, placeholders from <c>tir</c>) on screen
/// one at a time: a second request waits until the first is answered, and the open dialog says how
/// many are waiting. Locking the session answers every open and waiting question with Deny.
/// Before a dialog shows, <see cref="Gate"/> may refuse it outright (lockdown, a blocked program);
/// "This wasn't me" answers Deny and hands the program to <see cref="NotMe"/>.
/// </summary>
sealed class ConsentPresenter(Dispatcher dispatcher) : IUserSecretsConsentPrompt, IDisposable
{
    readonly SemaphoreSlim one = new(1, 1);
    CancellationTokenSource session = new();
    int waiting;

    /// <summary>Unlocks with Windows Hello, explaining any problem; completes with whether it worked. Set once the agent exists.</summary>
    public Func<Task<bool>>? Unlock { get; set; }

    /// <summary>Whether a request may be shown at all; refused requests are answered Deny without a dialog.</summary>
    public Func<string?, GateDecision>? Gate { get; set; }

    /// <summary>The user chose "This wasn't me": called before the next waiting request is looked at, with the program, what it asked for and the secret or variable names, if any.</summary>
    public Action<Asker, string, IReadOnlyList<string>?>? NotMe { get; set; }

    /// <summary>Whether the Windows session is locked, so nobody can be at a dialog.</summary>
    public Func<bool>? SessionLocked { get; set; }

    /// <summary>
    /// A request the gate refused, or one shown while the session is locked (<see cref="AlertTriggers.Consent"/>):
    /// its kind, the program and the secret or variable names, never the heading, a command line or a value.
    /// </summary>
    public Action<AlertKind, Asker, IReadOnlyList<string>?>? Alert { get; set; }

    /// <summary>Whether a consent dialog is on screen; an update never restarts the app under one.</summary>
    public bool Busy => one.CurrentCount == 0;

    public Task<ConsentAnswer> AskAsync(UserSecretsConsentRequest request, CancellationToken ct) =>
        ShowAsync(request.IsEnvironment
            ? new ConsentView(
                Heading(request.UserSecretsId, request.Executable),
                request.Executable,
                Text.Format("Consent_Environment_ListLabel", request.Keys.Count),
                request.Keys,
                Text.Format("Consent_Configuration_Note", request.Folder),
                AllowSession: true)
            : new ConsentView(
                Heading(request.UserSecretsId, request.Executable),
                request.Executable,
                request.Keys.Count == 1 ? Text.Get("Consent_UserSecrets_KeysLabelOne") : Text.Format("Consent_UserSecrets_KeysLabel", request.Keys.Count),
                request.Keys,
                Text.Get("Consent_UserSecrets_Note"),
                AllowSession: true), new(request.Executable, null), request.Keys, UserSecretsService.ConsentTimeout, ct);

    /// <summary>A .NET app asking for sealed variables, or for a user-secrets file by its id.</summary>
    static string Heading(string userSecretsId, string? executable) =>
        userSecretsId == EnvironmentFile.Id
            ? Text.Format("Consent_Environment_Heading", Path.GetFileName(executable) ?? Text.Get("Consent_UnknownProgram"))
            // A non-breaking hyphen, so an id like my-app-1234 never wraps at its dashes.
            : Text.Format("Consent_UserSecrets_Heading", userSecretsId.Replace('-', '‑'));

    /// <summary>Locked: the same dialog, naming the program, with "Unlock with Windows Hello" as the way to answer it.</summary>
    public async Task<bool> AskUnlockAsync(string? executable, string userSecretsId, CancellationToken ct)
    {
        if (Unlock is not { } unlock)
            return false;
        var answer = await ShowAsync(new ConsentView(
            Heading(userSecretsId, executable),
            executable,
            Text.Get("Consent_Unlock_Label"),
            [],
            Text.Get("Consent_Unlock_Note"),
            AllowSession: false,
            Unlock: true), new(executable, null), null, UserSecretsService.ConsentTimeout, ct);
        // Cancelled (lock, time out) propagates: the service then says why rather than "unlock first".
        return answer != ConsentAnswer.Deny && await dispatcher.InvokeAsync(unlock).Task.Unwrap();
    }

    /// <summary><c>tir run</c> asking for the sealed environment variables for one program; <paramref name="commandLine"/> is the whole command, shown under the heading.</summary>
    /// <param name="asker">The program that ran <c>tir</c>, which "This wasn't me" blocks; <paramref name="caller"/> (<c>tir</c> itself) is what the dialog shows.</param>
    public async Task<bool> AskEnvironmentAsync(string program, IReadOnlyList<string>? commandLine, IReadOnlyList<string> names, string? caller, Asker asker, CancellationToken ct)
    {
        try
        {
            return await ShowAsync(ConsentView.ForEnvironment(program, commandLine, names, caller),
                asker, names, UserSecretsService.ConsentTimeout, ct) != ConsentAnswer.Deny;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    /// <summary>The terminal hook asking for the sealed variables for a shell session; <paramref name="shell"/> is its image path.</summary>
    public async Task<bool> AskShellAsync(string shell, int processId, string directory, IReadOnlyList<string> names, CancellationToken ct)
    {
        try
        {
            return await ShowAsync(new ConsentView(
                Text.Format("Consent_Shell_Heading", System.IO.Path.GetFileNameWithoutExtension(shell)),
                shell,
                Text.Format("Consent_Shell_ListLabel", names.Count, directory),
                names,
                Text.Get("Consent_Shell_Note"),
                AllowSession: false), new(shell, processId), names, UserSecretsService.ConsentTimeout, ct) != ConsentAnswer.Deny;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    /// <summary>A NuGet feed's token for one program (<paramref name="program"/> is its image path), allowed once or until the agent locks.</summary>
    public async Task<ConsentAnswer> AskNuGetAsync(string program, int processId, NuGetSource source, CancellationToken ct)
    {
        try
        {
            return await ShowAsync(new ConsentView(
                Text.Format("Consent_NuGet_Heading", System.IO.Path.GetFileNameWithoutExtension(program)),
                program,
                Text.Format("Consent_NuGet_ListLabel", source.Source, source.Username),
                [source.Variable],
                Text.Get("Consent_NuGet_Note"),
                AllowSession: true), new(program, processId), [source.Variable], UserSecretsService.ConsentTimeout, ct);
        }
        catch (OperationCanceledException)
        {
            return ConsentAnswer.Deny;
        }
    }

    /// <summary>A placeholder or <c>tir exec</c> approval asked by <c>tir</c>; <c>tir</c> still asks for Windows Hello afterwards.</summary>
    /// <param name="asker">The program that ran <c>tir</c>, which "This wasn't me" blocks; <paramref name="caller"/> (<c>tir</c> itself) is what the dialog shows.</param>
    public async Task<bool> AskPlaceholderAsync(string title, IReadOnlyList<string> lines, string? caller, Asker asker, CancellationToken ct)
    {
        try
        {
            return await ShowAsync(new ConsentView(
                Text.Format("Consent_Placeholder_Heading", title),
                caller,
                Text.Get("Consent_Placeholder_ListLabel"),
                lines,
                Text.Get("Consent_Placeholder_Note"),
                // The lines are tir's own text (a service, a command): no names an alert may carry.
                AllowSession: false), asker, null, UserSecretsService.ConsentTimeout, ct) != ConsentAnswer.Deny;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    /// <summary>The session locked: deny what is open and what waits.</summary>
    public void DenyAll()
    {
        var old = Interlocked.Exchange(ref session, new CancellationTokenSource());
        // Not disposed: a request may be reading its token right now. Nothing unmanaged is left behind.
        old.Cancel();
    }

    /// <exception cref="OperationCanceledException">
    /// Nobody answered: the session locked, the time ran out or the caller gave up. Only the Deny button
    /// returns <see cref="ConsentAnswer.Deny"/>, so the program is told the real reason, not "you declined".
    /// </exception>
    /// <param name="names">The secret or variable names asked for, for an alert; <c>null</c> when the request has none it may carry.</param>
    async Task<ConsentAnswer> ShowAsync(ConsentView view, Asker asker, IReadOnlyList<string>? names, TimeSpan timeout, CancellationToken ct)
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
            throw;
        }
        try
        {
            var others = Interlocked.Decrement(ref waiting);
            // Asked once it is this request's turn, so a "This wasn't me" on the dialog before it already counts.
            var decision = Gate?.Invoke(asker.Image) ?? GateDecision.Ask;
            if (AlertTriggers.Consent(decision, SessionLocked?.Invoke() == true) is { } alert)
                Alert?.Invoke(alert, asker, names);
            if (decision != GateDecision.Ask)
            {
                AppLog.Info($"refused without asking ({decision}): {asker.Image ?? "unknown program"}");
                return ConsentAnswer.Deny;
            }
            var shown = await dispatcher.InvokeAsync(() => ConsentWindow.AskAsync(view, deadline - DateTimeOffset.Now, others, linked.Token));
            var choice = await shown;
            if (choice == ConsentChoice.NotMe)
            {
                NotMe?.Invoke(asker, view.Heading, names);
                return ConsentAnswer.Deny;
            }
            if (choice == ConsentChoice.Deny && (linked.IsCancellationRequested || DateTimeOffset.Now >= deadline))
                throw new OperationCanceledException(linked.Token);
            return choice switch
            {
                ConsentChoice.AllowOnce => ConsentAnswer.AllowOnce,
                ConsentChoice.AllowForSession => ConsentAnswer.AllowForSession,
                _ => ConsentAnswer.Deny,
            };
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

/// <summary>The program a consent request is about, which "This wasn't me" blocks.</summary>
/// <param name="Image">Its image path, or <c>null</c> when unknown.</param>
/// <param name="ProcessId">The process, when the request came with one; a user-secrets caller is known by path only.</param>
sealed record Asker(string? Image, int? ProcessId);
