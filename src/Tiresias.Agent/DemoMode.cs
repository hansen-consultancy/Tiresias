using Microsoft.Win32;

namespace Tiresias.Agent;

/// <summary>
/// The app's demo mode, in Debug builds only (docs/testing-on-windows.md): the agent works on a
/// made-up machine instead of this one. The user's folders are a profile for <c>alice</c> under
/// <see cref="Profile"/>, <c>HKCU</c> is a key under <c>HKCU\Software\Tiresias\Demo</c>, and Windows
/// Hello is a fixed key that never prompts (<see cref="UserMachine"/> and <see cref="HelloKeyWrapper"/>
/// route to them). Both are emptied when it starts and when it ends, so what a demo changes lasts
/// until the app quits. Nothing reaches the real vault, profile, environment or Hello credential.
/// A Release build cannot turn it on: <see cref="On"/> is always <c>false</c> there.
/// </summary>
public static class DemoMode
{
    /// <summary>How long a demo's Hello or UAC "prompt" takes, so the reason card shown before it can be seen.</summary>
    public static readonly TimeSpan PromptPause = TimeSpan.FromSeconds(2);

#if DEBUG
    /// <summary>The made-up user's profile folder, while demo mode is on. No real user name in it, so it can be shown.</summary>
    public static string? Profile { get; private set; }

    public static bool On => Profile is not null;

    internal const string RegistryPath = @"Software\Tiresias\Demo";

    /// <summary>The demo's stand-in for <c>HKCU</c>, while on.</summary>
    internal static RegistryKey? CurrentUser { get; private set; }

    /// <summary>Whether the demo's Hello credential exists: from the scenario, or once something creates it.</summary>
    internal static bool HelloExists { get; set; }

    /// <summary>The fixed secret the demo's Hello "signs" with. Not a secret: everything it seals is made up.</summary>
    internal static readonly byte[] HelloKey = System.Security.Cryptography.SHA256.HashData("tiresias/demo/hello"u8);

    static string Root => Path.Combine(Environment.GetEnvironmentVariable("PUBLIC") ?? Path.GetTempPath(), "Tiresias-demo");

    /// <summary>Turns demo mode on with an empty machine, before anything reads a store.</summary>
    /// <param name="helloExists">The scenario's user has set up Windows Hello for Tiresias already.</param>
    public static void Start(bool helloExists)
    {
        Clear();
        Profile = Path.Combine(Root, "alice");
        System.IO.Directory.CreateDirectory(Profile);
        CurrentUser = Registry.CurrentUser.CreateSubKey(RegistryPath, writable: true);
        HelloExists = helloExists;
    }

    /// <summary>Deletes the made-up machine. Safe to call when demo mode is off.</summary>
    public static void End()
    {
        if (!On)
            return;
        CurrentUser?.Dispose();
        CurrentUser = null;
        Profile = null;
        Clear();
    }

    static void Clear()
    {
        if (System.IO.Directory.Exists(Root))
            System.IO.Directory.Delete(Root, recursive: true);
        Registry.CurrentUser.DeleteSubKeyTree(RegistryPath, throwOnMissingSubKey: false);
    }
#else
    public static bool On => false;
#endif
}
