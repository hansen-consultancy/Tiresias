using Tiresias.Client;

namespace Tiresias.App.Logic;

/// <summary>Which log-on entries the Startup page's Show picker keeps.</summary>
public enum StartupView { All, NotFromApp, Unsigned, Off }

/// <summary>Which log-on entries the Startup page shows for what the user typed and picked.</summary>
public static class StartupFilter
{
    /// <summary>
    /// Every word typed must appear, in any case, in the entry's name, program, installed app or a
    /// service it used.
    /// </summary>
    /// <param name="mark">The program's mark, as <see cref="ProgramMarks.Of"/> gives it.</param>
    public static IEnumerable<StartupProgram> Apply(IEnumerable<StartupProgram> programs, string search, StartupView view, Func<StartupEntry, ProgramMark> mark)
    {
        var words = search.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return programs.Where(p => view switch
            {
                StartupView.NotFromApp => p.App is null,
                StartupView.Unsigned => mark(p.Entry) == ProgramMark.Unsigned,
                StartupView.Off => !p.Entry.On,
                _ => true,
            } && words.All(w => Haystack(p).Any(h => h.Contains(w, StringComparison.OrdinalIgnoreCase))));
    }

    /// <summary>Whether the app can turn the entry off itself: one of the user's own that is on, named plainly; a machine-wide one needs Settings.</summary>
    public static DisableStartup? TurnOff(StartupEntry entry) =>
        entry is { On: true, Item: { } item, Where: StartupEntry.RunKey or StartupEntry.StartupFolder } && DisableStartup.IsSafeItem(item)
            ? new(entry.Name, entry.Where, item)
            : null;

    static IEnumerable<string> Haystack(StartupProgram program) =>
        [program.Entry.Name, program.Entry.Path ?? "", program.App ?? "", .. program.Reached];
}
