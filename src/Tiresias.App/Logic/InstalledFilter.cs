using Tiresias.Client;

namespace Tiresias.App.Logic;

/// <summary>Which programs the Installed page shows for what the user typed and picked.</summary>
public static class InstalledFilter
{
    /// <summary>
    /// Every word typed must appear, in any case, in the program's name, version, folder or a
    /// service it used, so "github" finds what used GitHub and "program files x86" a folder.
    /// </summary>
    public static IEnumerable<InstalledProgram> Apply(IEnumerable<InstalledProgram> programs, string search, bool unusedOnly)
    {
        var words = search.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return programs.Where(p => (!unusedOnly || p.Use == ProgramUse.Unused) && words.All(w => Haystack(p).Any(h => h.Contains(w, StringComparison.OrdinalIgnoreCase))));
    }

    static IEnumerable<string> Haystack(InstalledProgram program) =>
        [program.Entry.Name, program.Entry.Version ?? "", program.Entry.Folder ?? "", .. program.Reached];
}
