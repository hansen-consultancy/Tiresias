using Tiresias.Client;

namespace Tiresias.Agent;

/// <summary>
/// The files behind <see cref="Doctor.Devcontainers"/>: each devcontainer file the project walk
/// found and the env files it names, read through <see cref="NameScan"/> so no value outlives the
/// scan; and VS Code's user settings for what Dev Containers forwards.
/// </summary>
static class DevcontainerProbe
{
    public static DevcontainerFile? Read(string path)
    {
        if (DevcontainerScan.Workspace(path) is not { } workspace || Scan(path, DevcontainerScan.Read) is not { } contents)
            return null;
        var sources = contents.Sources.ToList();
        foreach (var envFile in contents.EnvFiles)
            if (DevcontainerScan.EnvFileCandidates(envFile, workspace, Path.GetDirectoryName(path)!).FirstOrDefault(File.Exists) is { } found
                && Scan(found, NameScan.EnvLines) is { Count: > 0 } names)
                sources.Add(new(Path.GetRelativePath(workspace, found), names));
        return new(path, workspace, sources);
    }

    /// <summary><c>null</c> unless VS Code has the Dev Containers extension; its forwarding is on by default.</summary>
    public static DevcontainerForwarding? Forwarding()
    {
        var extensions = Path.Combine(UserMachine.Folder(Environment.SpecialFolder.UserProfile), ".vscode", "extensions");
        try
        {
            if (!Directory.Exists(extensions) || !Directory.EnumerateDirectories(extensions, "ms-vscode-remote.remote-containers-*").Any())
                return null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
        var settings = Path.Combine(UserMachine.Folder(Environment.SpecialFolder.ApplicationData), "Code", "User", "settings.json");
        return (File.Exists(settings) ? Scan(settings, DevcontainerScan.Forwarding) : null) ?? new(true, true);
    }

    static T? Scan<T>(string path, SpanScanner<T> scan) where T : class
    {
        try
        {
            using var stream = File.OpenRead(path);
            return NameScan.Read(stream, scan);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
