using System.Text;

namespace Tiresias.EnvironmentVariables;

/// <summary>
/// What <c>tir env hook</c> puts in a PowerShell profile, and the script <c>tir env shell</c> hands
/// the hook to bring a terminal's environment up to date. The names the hook set last are kept in
/// <see cref="NamesVariable"/> (names only, never a value), so leaving a folder removes what it added.
/// </summary>
public static class ShellScript
{
    /// <summary>The names the hook has set in this terminal, separated by <c>;</c>.</summary>
    public const string NamesVariable = "TIRESIAS_ENV_NAMES";

    /// <summary>
    /// The profile hook: wraps the prompt so the set is fetched when the terminal opens and again
    /// whenever the folder changes, never for each command. Works in PowerShell 7 and Windows
    /// PowerShell 5.1. Put it last in the profile, after anything else that replaces the prompt.
    /// </summary>
    public const string PowerShellHook = """
        # Tiresias: sealed environment variables for this terminal (tir env hook pwsh).
        function global:Update-TiresiasEnvironment {
            param([switch]$Ask)
            $arguments = @('env', 'shell', '--shell', $PID, '--directory', $PWD.ProviderPath)
            if ($Ask) { $arguments += '--ask' }
            $script = & tir @arguments
            if ($script) { Invoke-Expression ($script -join "`n") }
        }
        if (-not $global:TiresiasPrompt) {
            $global:TiresiasPrompt = $function:prompt
            $global:TiresiasDirectory = $null
            function global:prompt {
                if ($PWD.Provider.Name -eq 'FileSystem' -and $PWD.ProviderPath -ne $global:TiresiasDirectory) {
                    $global:TiresiasDirectory = $PWD.ProviderPath
                    Update-TiresiasEnvironment
                }
                & $global:TiresiasPrompt
            }
        }
        """;

    /// <summary>
    /// Statements that take a PowerShell session from <paramref name="previous"/> (what the hook set
    /// last) to <paramref name="variables"/>: stale names removed, the rest set, the list updated.
    /// </summary>
    public static string PowerShell(IEnumerable<string> previous, IReadOnlyList<SealedVariable> variables)
    {
        var now = variables.Select(v => v.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var script = new StringBuilder();
        foreach (var name in previous.Where(n => n.Length > 0 && !now.Contains(n)).Distinct(StringComparer.OrdinalIgnoreCase))
            script.Append("[Environment]::SetEnvironmentVariable(").Append(Quote(name)).Append(", $null, 'Process')\n");
        foreach (var variable in variables)
            script.Append("[Environment]::SetEnvironmentVariable(").Append(Quote(variable.Name)).Append(", ").Append(Decoded(variable.Value)).Append(", 'Process')\n");
        script.Append("[Environment]::SetEnvironmentVariable(").Append(Quote(NamesVariable)).Append(", ")
            .Append(now.Count == 0 ? "$null" : Quote(string.Join(';', variables.Select(v => v.Name)))).Append(", 'Process')\n");
        return script.ToString();
    }

    /// <summary>The names in <see cref="NamesVariable"/>'s value.</summary>
    public static IReadOnlyList<string> Names(string? list) =>
        list is null ? [] : list.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>
    /// A value as base64 decoded by PowerShell: the script crosses a console pipe, whose code page
    /// would mangle anything outside it, and nothing in a value can be read as PowerShell.
    /// </summary>
    static string Decoded(string value) =>
        $"[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{Convert.ToBase64String(Encoding.UTF8.GetBytes(value))}'))";

    /// <summary>
    /// A PowerShell single-quoted string, for names. PowerShell also ends one at the typographic single quotes,
    /// so each of those is doubled too; nothing else is special inside one.
    /// </summary>
    static string Quote(string text)
    {
        var quoted = new StringBuilder(text.Length + 2).Append('\'');
        foreach (var c in text)
        {
            if (c is '\'' or '‘' or '’' or '‚' or '‛')
                quoted.Append(c);
            quoted.Append(c);
        }
        return quoted.Append('\'').ToString();
    }
}
