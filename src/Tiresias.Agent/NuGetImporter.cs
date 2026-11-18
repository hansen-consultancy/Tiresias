using System.Text;
using Tiresias.EnvironmentVariables;
using Tiresias.Vault;

namespace Tiresias.Agent;

/// <summary>What <see cref="NuGetImporter.Apply"/> did: the variables it sealed, and the config files it changed.</summary>
public sealed record NuGetImportResult(IReadOnlyList<string> Sealed, IReadOnlyList<string> Files);

/// <summary>
/// Moves package-source credentials out of NuGet.Config into the sealed environment, for
/// <c>tir env nuget import</c> and the environment variables window alike.
/// </summary>
public static class NuGetImporter
{
    /// <summary>
    /// The steps for every credential in the config files NuGet reads for <paramref name="directory"/>,
    /// or in the user's own files only when it is null.
    /// </summary>
    public static IReadOnlyList<NuGetImportStep> Plan(SealedEnvironment sealedNow, string? directory)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var found = NuGetConfig.Files(directory, appData)
            .SelectMany(file => NuGetConfig.Read(File.ReadAllText(file)).Select(c => (file, c)));
        var windows = EnvironmentStore.UserVariables().Select(v => v.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return NuGetImport.Plan(found, sealedNow, windows.Contains,
            name => sealedNow.Global.FirstOrDefault(v => string.Equals(v.Name, name, StringComparison.OrdinalIgnoreCase))?.Value
                ?? Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.User));
    }

    /// <summary>
    /// Seals what the steps need (from Windows, or the file's plain text), maps each source, and only
    /// then takes the credentials out of the files, keeping each file's encoding and line endings.
    /// Steps that don't act are passed over.
    /// </summary>
    public static NuGetImportResult Apply(IEnumerable<NuGetImportStep> steps, IKeyWrapper hello)
    {
        var acting = steps.Where(s => s.Acts).ToArray();
        var sealing = new List<string>();
        var protecting = acting.Where(s => s.ProtectFirst).Select(s => s.Variable!).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (protecting.Length > 0)
            sealing.AddRange(EnvironmentStore.Protect(protecting, hello));
        foreach (var step in acting.Where(s => s.SealClearText))
        {
            EnvironmentStore.Set(new(step.Variable!, step.Credential.Password!), null, hello);
            sealing.Add(step.Variable!);
        }
        var (sealedNow, version) = EnvironmentStore.Open(hello);
        foreach (var step in acting)
            sealedNow = sealedNow.WithNuGetSource(new(step.Credential.Source!, step.Variable!, step.Username));
        EnvironmentStore.Save(sealedNow, version, hello);

        var files = new List<string>();
        foreach (var file in acting.GroupBy(s => s.File, StringComparer.OrdinalIgnoreCase))
        {
            var bytes = File.ReadAllBytes(file.Key);
            var bom = bytes.AsSpan().StartsWith(Encoding.UTF8.Preamble);
            var text = NuGetConfig.WithoutCredentials(Encoding.UTF8.GetString(bom ? bytes[3..] : bytes), file.Select(s => s.Credential.Key));
            File.WriteAllBytes(file.Key, [.. bom ? Encoding.UTF8.Preamble : [], .. Encoding.UTF8.GetBytes(text)]);
            files.Add(file.Key);
        }
        return new(sealing, files);
    }
}
