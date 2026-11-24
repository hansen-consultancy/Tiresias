using Tiresias.Client;

namespace Tiresias.App.Logic;

/// <summary>Which programs the Installed page's Show picker keeps.</summary>
public enum InstalledView { All, Unused, Unsigned, New }

/// <summary>Which programs the Installed page shows for what the user typed and picked.</summary>
public static class InstalledFilter
{
    /// <summary>How recent an install counts as new.</summary>
    public const int NewDays = 14;

    /// <summary>
    /// Every word typed must appear, in any case, in the program's name, version, folder or a
    /// service it used, so "github" finds what used GitHub and "program files x86" a folder.
    /// </summary>
    /// <param name="signed">A program file's signature verdict as <see cref="InstalledDetails.Signer"/> takes it; <c>null</c> while unchecked.</param>
    public static IEnumerable<InstalledProgram> Apply(IEnumerable<InstalledProgram> programs, string search, InstalledView view, DateOnly today, Func<string, bool?> signed)
    {
        var words = search.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return programs.Where(p => view switch
            {
                InstalledView.Unused => p.Use == ProgramUse.Unused,
                InstalledView.Unsigned => IsUnsigned(p.Entry, signed),
                InstalledView.New => IsNew(p.Entry, today),
                _ => true,
            } && words.All(w => Haystack(p).Any(h => h.Contains(w, StringComparison.OrdinalIgnoreCase))));
    }

    /// <summary>Installed in the last <see cref="NewDays"/> days, today included.</summary>
    public static bool IsNew(UninstallEntry entry, DateOnly today) => entry.InstalledOn is { } on && on > today.AddDays(-NewDays);

    /// <summary>
    /// Its program file was checked and has no valid signature. One that couldn't be checked (a part
    /// of Windows, a Store app, no file) is not called unsigned.
    /// </summary>
    public static bool IsUnsigned(UninstallEntry entry, Func<string, bool?> signed) => entry.ProgramFile is { } file && signed(file) == false;

    static IEnumerable<string> Haystack(InstalledProgram program) =>
        [program.Entry.Name, program.Entry.Version ?? "", program.Entry.Folder ?? "", .. program.Reached];
}
