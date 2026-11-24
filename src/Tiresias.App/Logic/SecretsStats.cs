using Tiresias.Protocol;
using Tiresias.UserSecrets;

namespace Tiresias.App.Logic;

/// <summary>How a project's user secrets stand, as the secrets editor marks it in its list.</summary>
public enum ProjectState
{
    /// <summary>Sealed by Tiresias.</summary>
    Sealed,

    /// <summary>Plain text holding at least one value that may be a credential.</summary>
    NotSealed,

    /// <summary>Plain text, but only settings and Tiresias references: nothing to seal.</summary>
    Settings,

    /// <summary>No keys, or no file.</summary>
    Empty,

    /// <summary>Not valid JSON.</summary>
    Invalid,
}

/// <summary>The counts above the secrets editor's list: what the side bar's single number is made of.</summary>
public sealed record SecretsStats(int Sealed, int NotSealed, int Settings, int Empty, int Invalid)
{
    public int Total => Sealed + NotSealed + Settings + Empty + Invalid;

    public static ProjectState StateOf(SecretsFileKind kind, SecretsContent content) => (kind, content) switch
    {
        (SecretsFileKind.Sealed, _) => ProjectState.Sealed,
        (_, SecretsContent.Invalid) or (SecretsFileKind.Invalid, _) => ProjectState.Invalid,
        (_, SecretsContent.Empty) => ProjectState.Empty,
        (_, SecretsContent.Settings) => ProjectState.Settings,
        _ => ProjectState.NotSealed,
    };

    public static SecretsStats Of(IEnumerable<ProjectState> states)
    {
        var all = states.ToArray();
        int Count(ProjectState state) => all.Count(s => s == state);
        return new(Count(ProjectState.Sealed), Count(ProjectState.NotSealed), Count(ProjectState.Settings), Count(ProjectState.Empty), Count(ProjectState.Invalid));
    }
}
