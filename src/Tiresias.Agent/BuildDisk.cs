using System.Security.AccessControl;
using System.Security.Principal;
using Tiresias.Client;

namespace Tiresias.Agent;

/// <summary>This machine's disk as <see cref="OwnBuild.Looks"/> reads it: existence, folder listings and owners only, nothing started.</summary>
sealed class BuildDisk : IBuildDisk
{
    public static readonly BuildDisk Instance = new();

    const string DownloadsId = "{374DE290-123F-4565-9164-39C4925E467B}";

    public IReadOnlyCollection<string> DropFolders
    {
        get
        {
            var profile = UserMachine.Folder(Environment.SpecialFolder.UserProfile);
            using var shell = UserMachine.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders");
            string?[] folders =
            [
                Path.GetTempPath(),
                Path.Combine(profile, "Downloads"),
                shell?.GetValue(DownloadsId) is string downloads ? Environment.ExpandEnvironmentVariables(downloads) : null,
                // Roaming and Local, with the browsers' caches and Temp in them.
                Path.Combine(profile, "AppData"),
                UserMachine.Folder(Environment.SpecialFolder.ApplicationData),
                UserMachine.Folder(Environment.SpecialFolder.LocalApplicationData),
            ];
            return [.. folders.OfType<string>().Where(f => f.Length > 0)];
        }
    }

    public bool Exists(string path) => File.Exists(path) || Directory.Exists(path);

    public IEnumerable<string> FileNames(string folder)
    {
        try
        {
            return Directory.Exists(folder) ? [.. Directory.EnumerateFiles(folder).Select(Path.GetFileName).OfType<string>()] : [];
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    public bool OwnedByYou(string file)
    {
        try
        {
            using var you = WindowsIdentity.GetCurrent();
            return new FileInfo(file).GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier owner
                && owner == you.User;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException or IdentityNotMappedException)
        {
            return false;
        }
    }
}
