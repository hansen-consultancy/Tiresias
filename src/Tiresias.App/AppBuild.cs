using System.Reflection;
using Tiresias.App.Logic;
using Velopack;
using Velopack.Sources;

namespace Tiresias.App;

/// <summary>This copy's <see cref="BuildInfo"/> (installed means Velopack put it in place) and what the About window shows about it.</summary>
static class AppBuild
{
    public const string Repository = "https://github.com/hansen-consultancy/Tiresias";

    public static BuildInfo Current { get; } = BuildInfo.From(
        typeof(AppBuild).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion,
        installed: new UpdateManager(new GithubSource(Repository, accessToken: null, prerelease: false)).IsInstalled,
        AppContext.BaseDirectory);

    public const string Configuration =
#if DEBUG
        "Debug";
#else
        "Release";
#endif

    /// <summary>When the main assembly was written: the build, for a development copy.</summary>
    public static DateTime BuiltAt => File.GetLastWriteTime(typeof(AppBuild).Assembly.Location);

    /// <summary>When this version arrived: Velopack replaces the folder on every install and update.</summary>
    public static DateTime Since => Directory.GetCreationTime(AppContext.BaseDirectory);

    public static string ReleasePage => $"{Repository}/releases/tag/app-v{Current.Version}";

    public static string? CommitPage => Current.Commit is { } commit ? $"{Repository}/commit/{commit}" : null;

    /// <summary>
    /// This version's changelog section, packed into the app; a development build shows the
    /// Unreleased section, which is what it has on top of the last release.
    /// </summary>
    public static string? Notes()
    {
        using var stream = typeof(AppBuild).Assembly.GetManifestResourceStream("CHANGELOG.md");
        if (stream is null)
            return null;
        using var reader = new StreamReader(stream);
        return ReleaseNotes.Section(reader.ReadToEnd(), Current.Installed ? Current.Version : "Unreleased");
    }
}
