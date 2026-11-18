using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration.UserSecrets;
using Tiresias.Protocol;
using Tiresias.UserSecrets;
using Tiresias.Vault;

namespace Tiresias.Agent;

/// <summary>One project's user secrets folder, found by id.</summary>
public sealed record UserSecretsFolder(string Id, string Directory)
{
    public string FilePath => Path.Combine(Directory, SecretsFile.FileName);

    public SecretsFileKind Kind => SecretsFile.Classify(File.Exists(FilePath) ? File.ReadAllText(FilePath) : null);
}

/// <summary>
/// Opening and saving <c>secrets.json</c> files outside the pipe: <c>tir secrets</c> and the app's
/// editor. Saving always seals, so editing never writes plaintext back.
/// </summary>
public static partial class UserSecretsFiles
{
    /// <summary><c>%APPDATA%\Microsoft\UserSecrets</c>: where every project's folder lives.</summary>
    public static string Root { get; } = Path.GetDirectoryName(Path.GetDirectoryName(PathHelper.GetSecretsPathFromSecretsId("x")))!;

    public static UserSecretsFolder Folder(string id) => new(id, Path.GetDirectoryName(PathHelper.GetSecretsPathFromSecretsId(id))!);

    /// <summary>Every folder holding a <c>secrets.json</c>, by id.</summary>
    public static IReadOnlyList<UserSecretsFolder> All() =>
        System.IO.Directory.Exists(Root)
            ? System.IO.Directory.EnumerateDirectories(Root)
                .Where(d => File.Exists(Path.Combine(d, SecretsFile.FileName)))
                .Select(d => new UserSecretsFolder(Path.GetFileName(d), d))
                .OrderBy(f => f.Id, StringComparer.OrdinalIgnoreCase)
                .ToArray()
            : [];

    /// <summary>The <c>&lt;UserSecretsId&gt;</c> of a project file, or of the one project in a folder (as <c>dotnet user-secrets</c> finds it).</summary>
    /// <exception cref="InvalidOperationException">No project, several, or no UserSecretsId in it.</exception>
    public static string IdFromProject(string path)
    {
        if (System.IO.Directory.Exists(path))
        {
            var projects = System.IO.Directory.GetFiles(path, "*.csproj");
            path = projects.Length switch
            {
                1 => projects[0],
                0 => throw new InvalidOperationException($"No project file in {path}. Pass --project <file.csproj> or --id <UserSecretsId>."),
                _ => throw new InvalidOperationException($"Several project files in {path}. Pass --project <file.csproj>."),
            };
        }
        var match = UserSecretsIdElement().Match(File.ReadAllText(path));
        return match.Success
            ? match.Groups[1].Value
            : throw new InvalidOperationException($"{Path.GetFileName(path)} has no <UserSecretsId>. Run 'dotnet user-secrets init' in its folder first.");
    }

    /// <summary>Opens the document with the unlocked Hello wrapper. A missing file is an empty document.</summary>
    public static UserSecretsLoad Open(UserSecretsFolder folder, IKeyWrapper hello) =>
        UserSecretsVault.Open(folder.Id, File.Exists(folder.FilePath) ? File.ReadAllText(folder.FilePath) : null, hello);

    /// <summary>Seals <paramref name="document"/> into the folder as the next version.</summary>
    /// <exception cref="InvalidOperationException">No recovery key: a sealed file must not depend on the TPM alone.</exception>
    public static void Save(UserSecretsFolder folder, UserSecretsLoad loaded, JsonObject document, IKeyWrapper hello)
    {
        var recovery = RecoveryKey.Wrapper()
            ?? throw new InvalidOperationException("No recovery key yet, so the file can't be sealed. Create it first (first-run wizard, or tir recovery init).");
        var text = UserSecretsVault.Seal(folder.Id, loaded.Version + 1, document, [hello, recovery]);
        System.IO.Directory.CreateDirectory(folder.Directory);
        var temp = folder.FilePath + ".tiresias.tmp";
        File.WriteAllText(temp, text);
        File.Move(temp, folder.FilePath, overwrite: true);
    }

    /// <summary>
    /// Writes <paramref name="document"/> back as a plain <c>secrets.json</c>, for an app that can't use
    /// Tiresias.Extensions.Configuration. The only way to undo a seal; the caller confirms first.
    /// </summary>
    public static void StoreInClear(UserSecretsFolder folder, JsonObject document)
    {
        var temp = folder.FilePath + ".tiresias.tmp";
        File.WriteAllText(temp, document.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        File.Move(temp, folder.FilePath, overwrite: true);
    }

    [GeneratedRegex(@"<UserSecretsId>\s*([^<\s]+)\s*</UserSecretsId>")]
    private static partial Regex UserSecretsIdElement();
}
