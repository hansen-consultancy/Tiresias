using Tiresias.UserSecrets;
using Tiresias.Vault;

namespace Tiresias.Agent;

/// <summary>
/// The agent's unlocked state: the Hello wrapper, opened with one Windows Hello prompt and kept
/// until <see cref="Lock"/>. While it is held, user secrets open without another prompt; that is
/// what "unlocked" means. The wrap key it derived lives in this process's memory until then.
/// </summary>
public sealed class AgentKeys : IUserSecretsKeys, IDisposable
{
    readonly Lock gate = new();
    HelloKeyWrapper? hello;

    public bool IsUnlocked
    {
        get
        {
            lock (gate)
                return hello is not null;
        }
    }

    /// <summary>The held wrapper, for an unlock that also opens the broker lease. <c>null</c> while locked.</summary>
    public HelloKeyWrapper? Hello
    {
        get
        {
            lock (gate)
                return hello;
        }
    }

    IKeyWrapper? IUserSecretsKeys.Unlocked => Hello;

    public IKeyWrapper? Recovery => RecoveryKey.Wrapper();

    /// <summary>Shows the Windows Hello prompt now (not at the first secret) and holds the result.</summary>
    /// <param name="create">Create the Hello credential if there is none: first run only.</param>
    /// <exception cref="InvalidOperationException">Hello isn't set up, was cancelled, or the credential is missing.</exception>
    public void Unlock(bool create = false)
    {
        if (IsUnlocked)
            return;
        var opened = HelloKeyWrapper.Open(create);
        try
        {
            // Deriving the wrap key is the one Hello prompt.
            Array.Clear(opened.Wrap(new byte[32], "tiresias/v1/unlock-probe"));
        }
        catch
        {
            opened.Dispose();
            throw;
        }
        lock (gate)
        {
            if (hello is null)
            {
                hello = opened;
                return;
            }
        }
        opened.Dispose();
    }

    public void Lock()
    {
        HelloKeyWrapper? held;
        lock (gate)
        {
            held = hello;
            hello = null;
        }
        held?.Dispose();
    }

    public void Dispose() => Lock();
}
