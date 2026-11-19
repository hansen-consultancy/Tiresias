using Tiresias.EnvironmentVariables;

namespace Tiresias.Client;

/// <summary>A package tool's own credential file the doctor read: a <c>NuGet.Config</c>, <c>.npmrc</c> or <c>.pypirc</c>.</summary>
/// <param name="Text"><c>null</c> when unreadable.</param>
/// <param name="InProfile">The user's own file, which the tool reads wherever it runs, rather than one in a project folder.</param>
public sealed record DoctorToolFile(string Path, string? Text, bool InProfile);

public static partial class Doctor
{
    /// <summary>
    /// Findings in the package tools' credential files: NuGet feed tokens in plain text or in a
    /// user environment variable, NuGet push keys, npm tokens and PyPI passwords. A file is read to
    /// see which entries hold a credential; lines name the entry, the registry and the file, never
    /// the value. A malformed file is no finding.
    /// </summary>
    /// <param name="userVariables">Names of the user's Windows environment variables: a feed naming one as <c>%NAME%</c> is readable by every program.</param>
    public static IEnumerable<DoctorCheck> PublishingKeys(IEnumerable<DoctorToolFile> files, IReadOnlyCollection<string> userVariables)
    {
        var windows = userVariables.ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var file in files)
        {
            if (file.Text is null)
                continue;
            var name = Path.GetFileName(file.Path);
            var checks = string.Equals(name, "nuget.config", StringComparison.OrdinalIgnoreCase) || (file.InProfile && name.EndsWith(".config", StringComparison.OrdinalIgnoreCase))
                ? NuGetFile(file, windows)
                : string.Equals(name, ".npmrc", StringComparison.OrdinalIgnoreCase) ? NpmFile(file)
                : string.Equals(name, ".pypirc", StringComparison.OrdinalIgnoreCase) ? PyPiFile(file)
                : [];
            foreach (var check in checks)
                yield return check;
        }
    }

    const string ReadableByAll = "any program running as you can read";

    static IEnumerable<DoctorCheck> NuGetFile(DoctorToolFile file, HashSet<string> windows)
    {
        var fix = file.InProfile || Quotable(file.Path) ? new ImportNuGetCredentials(file.Path, file.InProfile) : null;
        foreach (var credential in NuGetConfig.Read(file.Text!))
        {
            var source = credential.Source ?? credential.Key;
            var name = $"NuGet feed {source} in {file.Path}";
            var (detail, kind) = credential.Kind switch
            {
                NuGetPasswordKind.ClearText => ($"its token is in plain text, which {ReadableByAll}", "NuGet feeds with a token in plain text"),
                NuGetPasswordKind.Variable when windows.Contains(credential.Password!) =>
                    ($"its token is %{credential.Password}%, a user environment variable {ReadableByAll}", "NuGet feeds whose token is in a user environment variable"),
                _ => (null, null),
            };
            if (detail is null)
                continue;
            yield return credential.Source is { } url && url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                ? new(name, DoctorStatus.Warn, $"{detail}. Move it to Tiresias: NuGet then asks Tiresias for it, which asks you once per program", fix, Position.Plaintext, fix is null ? null : Position.SealedApproved, kind)
                : new(name, DoctorStatus.Warn, $"{detail}. Tiresias answers NuGet only for https sources defined in the same file; seal the token with tir env set and map the source with tir env nuget add", Now: Position.Plaintext, Kind: kind);
        }

        foreach (var source in NuGetConfig.ApiKeySources(file.Text!))
            yield return new($"NuGet push key for {source} in {file.Path}", DoctorStatus.Warn,
                $"NuGet encrypts it for your Windows account, which every program running as you can undo. Seal it as a variable instead (tir env set NUGET_API_KEY), pass it to dotnet nuget push --api-key from a command run with tir run, and delete its entry under <apikeys>"
                + (IsNuGetOrg(source) ? ". To publish to nuget.org, trusted publishing from CI needs no key at all: learn.microsoft.com/nuget/nuget-org/trusted-publishing" : ""),
                Now: Position.Plaintext, Kind: "NuGet push keys kept by NuGet");
    }

    static IEnumerable<DoctorCheck> NpmFile(DoctorToolFile file) =>
        NpmRc.Read(file.Text!).Where(c => c.Literal).Select(c => new DoctorCheck($"npm token for {c.Registry} in {file.Path}", DoctorStatus.Warn,
            $"in plain text, which {ReadableByAll}. Seal it as {c.Variable}: the file then says ${{{c.Variable}}}, which npm fills in from the environment tir run and the terminal hook give it. Sealing reads the token once"
            + (c.Registry == NpmRc.DefaultRegistry ? ". To publish to npmjs.org, trusted publishing from CI needs no token at all: docs.npmjs.com/trusted-publishers" : ""),
            SealRegistryToken.For(file.Path, c.Key, c.Variable), Position.Plaintext, Quotable(file.Path) ? Position.SealedApproved : null, "npm tokens in plain text"));

    static IEnumerable<DoctorCheck> PyPiFile(DoctorToolFile file) =>
        PyPiRc.Read(file.Text!).Select(c => string.Equals(c.Section, PyPiRc.DefaultSection, StringComparison.OrdinalIgnoreCase)
            ? new DoctorCheck($"PyPI password for {c.Section} in {file.Path}", DoctorStatus.Warn,
                $"in plain text, which {ReadableByAll}. Seal it as {PyPiRc.Variable}, which twine reads from the environment tir run and the terminal hook give it. Sealing reads the password once. "
                + "To publish to pypi.org, trusted publishing from CI needs no token at all: docs.pypi.org/trusted-publishers",
                SealRegistryToken.For(file.Path, c.Section, PyPiRc.Variable), Position.Plaintext, Quotable(file.Path) ? Position.SealedApproved : null, "PyPI passwords in plain text")
            : new DoctorCheck($"PyPI password for {c.Section} in {file.Path}", DoctorStatus.Warn,
                $"in plain text, which {ReadableByAll}. twine reads one {PyPiRc.Variable} for every repository, so Tiresias seals only {PyPiRc.DefaultSection}'s; for {c.Section}, seal it with tir env set, pass it with tir run, and delete it from the file",
                Now: Position.Plaintext, Kind: "PyPI passwords in plain text"));

    /// <summary>
    /// Whether <paramref name="text"/> stays literal inside double quotes in cmd, PowerShell and
    /// bash. A fix's command is copied into a shell, and a cloned project names its own folders.
    /// </summary>
    internal static bool Quotable(string text) => text.IndexOfAny(['"', '%', '$', '`', '!']) < 0;

    static bool IsNuGetOrg(string source) =>
        Uri.TryCreate(source, UriKind.Absolute, out var uri) && (uri.Host.Equals("api.nuget.org", StringComparison.OrdinalIgnoreCase) || uri.Host.Equals("www.nuget.org", StringComparison.OrdinalIgnoreCase));
}

/// <summary>Move a NuGet.Config file's feed credentials into the sealed environment, as <c>tir env nuget import</c> does.</summary>
/// <param name="InProfile">The user's own config, which the app's Environment variables window imports; one in a project needs the command run there.</param>
public sealed record ImportNuGetCredentials(string File, bool InProfile) : DoctorFix
{
    public override string Instruction => InProfile
        ? "tir env nuget import (or in the Tiresias app: Environment variables, NuGet feeds, Move to Tiresias)"
        : $"tir env nuget import, run in {Path.GetDirectoryName(File)}";
}

/// <summary>Seal the credential at <paramref name="Entry"/> of an <c>.npmrc</c> (a key) or <c>.pypirc</c> (a section) as <paramref name="Variable"/>, and take it out of the file.</summary>
public sealed record SealRegistryToken(string File, string Entry, string Variable) : DoctorFix
{
    public override string Instruction => $"tir env import \"{File}\" \"{Entry}\" {Variable}";

    /// <summary>The fix, or none when the file's path or the entry can't be printed in a command safely.</summary>
    internal static SealRegistryToken? For(string file, string entry, string variable) =>
        Doctor.Quotable(file) && Doctor.Quotable(entry) ? new(file, entry, variable) : null;
}
