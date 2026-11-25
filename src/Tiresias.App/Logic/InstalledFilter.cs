using Tiresias.Client;

namespace Tiresias.App.Logic;

/// <summary>Which programs the Installed page's Show picker keeps, or the extensions or global tools it lists instead (<see cref="InstalledAddOns"/>).</summary>
public enum InstalledView { All, Unused, Unsigned, New, Extensions, Tools }

/// <summary>Which programs the Installed page shows for what the user typed and picked.</summary>
public static class InstalledFilter
{
    /// <summary>How recent an install counts as new.</summary>
    public const int NewDays = 14;

    /// <summary>
    /// Every word typed must appear, in any case, in the program's name, version, folder or a
    /// service it used, so "github" finds what used GitHub and "program files x86" a folder.
    /// </summary>
    /// <param name="mark">A program file's mark (<see cref="ProgramMarks.Of"/>); <see cref="ProgramMark.None"/> while unchecked.</param>
    public static IEnumerable<InstalledProgram> Apply(IEnumerable<InstalledProgram> programs, string search, InstalledView view, DateOnly today, Func<string, ProgramMark> mark)
    {
        var words = search.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return programs.Where(p => view switch
            {
                InstalledView.Unused => p.Use == ProgramUse.Unused,
                InstalledView.Unsigned => IsUnsigned(p.Entry, mark),
                InstalledView.New => IsNew(p.Entry, today),
                _ => true,
            } && words.All(w => Haystack(p).Any(h => h.Contains(w, StringComparison.OrdinalIgnoreCase))));
    }

    /// <summary>Installed in the last <see cref="NewDays"/> days, today included.</summary>
    public static bool IsNew(UninstallEntry entry, DateOnly today) => entry.InstalledOn is { } on && on > today.AddDays(-NewDays);

    /// <summary>
    /// Its program file was checked and has no valid signature. One that couldn't be checked (a part
    /// of Windows, a Store app, no file) is not called unsigned, nor is the user's own build where
    /// developer tools show.
    /// </summary>
    public static bool IsUnsigned(UninstallEntry entry, Func<string, ProgramMark> mark) => Mark(entry, mark) == ProgramMark.Unsigned;

    /// <summary>The mark of the entry's program file; <see cref="ProgramMark.None"/> when it names none.</summary>
    public static ProgramMark Mark(UninstallEntry entry, Func<string, ProgramMark> mark) => entry.ProgramFile is { } file ? mark(file) : ProgramMark.None;

    static IEnumerable<string> Haystack(InstalledProgram program) =>
        [program.Entry.Name, program.Entry.Version ?? "", program.Entry.Folder ?? "", .. program.Reached];
}
