using Tiresias.EnvironmentVariables;

namespace Tiresias.Agent;

/// <summary>Which project folders' devcontainers ask Tiresias for a ticket (docs/devcontainers.md).</summary>
public static class DevcontainerFolders
{
    /// <summary>A devcontainer file is a page of JSON; anything bigger isn't one.</summary>
    const long MaxFileBytes = 1 << 20;

    /// <summary>Whether a devcontainer file in <paramref name="folder"/> hands the ticket in through <c>remoteEnv</c>.</summary>
    public static bool AsksForTicket(string folder) => DevcontainerProbe.In([folder]).Any(path =>
    {
        try
        {
            return new FileInfo(path).Length <= MaxFileBytes && DevcontainerTickets.Asks(File.ReadAllBytes(path));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    });
}
