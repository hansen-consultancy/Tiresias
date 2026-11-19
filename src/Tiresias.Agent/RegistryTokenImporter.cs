using System.Text;
using Tiresias.EnvironmentVariables;
using Tiresias.Vault;

namespace Tiresias.Agent;

/// <summary>
/// Moves a registry credential out of an <c>.npmrc</c> or <c>.pypirc</c> into the sealed environment,
/// for <c>tir env import</c> and the status page's fix alike. The value is read once, sealed, and
/// never shown; the file is changed only after the seal succeeded, keeping its encoding and line endings.
/// </summary>
public static class RegistryTokenImporter
{
    /// <param name="entry">The <c>.npmrc</c> key (<c>//registry.npmjs.org/:_authToken</c>) or the <c>.pypirc</c> section.</param>
    /// <exception cref="InvalidOperationException">The entry holds no plain credential any more, or <paramref name="variable"/> is taken.</exception>
    public static void Import(string file, string entry, string variable, IKeyWrapper hello)
    {
        var npm = string.Equals(Path.GetFileName(file), ".npmrc", StringComparison.OrdinalIgnoreCase);
        if (!npm && !string.Equals(Path.GetFileName(file), ".pypirc", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"{file} is neither an .npmrc nor a .pypirc.");
        var bytes = File.ReadAllBytes(file);
        var bom = bytes.AsSpan().StartsWith(Encoding.UTF8.Preamble);
        var text = Encoding.UTF8.GetString(bom ? bytes[3..] : bytes);
        var value = npm
            ? NpmRc.Read(text).Any(c => c.Key == entry && c.Literal) ? NpmRc.ValueOf(text, entry) : null
            : PyPiRc.PasswordOf(text, entry);
        if (value is null)
            throw new InvalidOperationException($"{file} has no credential in plain text at {entry} any more.");
        if (EnvironmentStore.Open(hello).Environment.IsSealedAnywhere(variable)
            || EnvironmentStore.UserVariables().Any(v => string.Equals(v.Name, variable, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException($"{variable} is taken. Seal the credential under another name with tir env set, then edit {file} yourself.");

        EnvironmentStore.Set(new(variable, value), null, hello);
        var changed = npm ? NpmRc.WithReference(text, entry, variable) : PyPiRc.WithoutPassword(text, entry);
        File.WriteAllBytes(file, [.. bom ? Encoding.UTF8.Preamble : [], .. Encoding.UTF8.GetBytes(changed)]);
    }
}
