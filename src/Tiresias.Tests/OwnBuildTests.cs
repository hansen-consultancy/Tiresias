using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

/// <summary>#148: an unsigned program the user built themselves is information on a developer's PC; #98: the Startup list.</summary>
public class OwnBuildTests
{
    static readonly DateTimeOffset Now = new(2026, 11, 24, 10, 0, 0, TimeSpan.Zero);
    const string Repo = @"C:\src\Tray";
    const string Exe = Repo + @"\src\Tray\bin\Debug\net10.0\Tray.exe";

    /// <summary>A made-up disk: the paths that exist, files by folder, and who owns what.</summary>
    sealed class Disk(IEnumerable<string> paths, bool owned = true, params string[] drops) : IBuildDisk
    {
        readonly HashSet<string> exists = new(paths, StringComparer.OrdinalIgnoreCase);

        public IReadOnlyCollection<string> DropFolders => drops;

        public bool Exists(string path) => exists.Contains(path);

        public IEnumerable<string> FileNames(string folder) =>
            exists.Where(p => p.StartsWith(folder + @"\", StringComparison.OrdinalIgnoreCase) && !p[(folder.Length + 1)..].Contains('\\'))
                .Select(p => p[(folder.Length + 1)..]);

        public bool OwnedByYou(string file) => owned;
    }

    static Disk Built(string repo = Repo, string exe = Exe, bool owned = true, params string[] drops) =>
        new([repo + @"\.git", repo + @"\src\Tray\obj", exe], owned, drops);

    [Test]
    public void An_unsigned_program_in_a_work_tree_beside_its_obj_folder_is_your_build() =>
        Assert.That(OwnBuild.Looks(Exe, false, null, Built()), Is.True);

    [Test]
    public void A_project_file_above_it_counts_as_its_project_and_a_worktree_git_file_as_a_work_tree()
    {
        const string publish = Repo + @"\Tray\publish\Tray.exe";
        Assert.That(OwnBuild.Looks(publish, false, null, new Disk([Repo + @"\.git", Repo + @"\Tray\Tray.csproj", publish])), Is.True);
        Assert.That(OwnBuild.Looks(publish, false, null, new Disk([Repo + @"\.git", Repo + @"\Tray.slnx", publish])), Is.True);
    }

    [Test]
    public void Without_a_work_tree_a_project_or_your_ownership_it_is_not()
    {
        Assert.Multiple(() =>
        {
            Assert.That(OwnBuild.Looks(Exe, false, null, new Disk([Repo + @"\src\Tray\obj", Exe])), Is.False, "no .git");
            Assert.That(OwnBuild.Looks(Exe, false, null, new Disk([Repo + @"\.git", Exe])), Is.False, "no project: a cloned release binary");
            Assert.That(OwnBuild.Looks(Exe, false, null, Built(owned: false)), Is.False, "someone else's file");
            Assert.That(OwnBuild.Looks(@"C:\x.exe", false, null, new Disk([@"C:\.git", @"C:\x.csproj"], owned: true)), Is.True, "a repo at the drive's root");
        });
    }

    [Test]
    public void Only_a_program_with_no_signature_at_all_qualifies()
    {
        Assert.Multiple(() =>
        {
            Assert.That(OwnBuild.Looks(Exe, false, "Example Corp", Built()), Is.False, "a signature that doesn't verify keeps its warning");
            Assert.That(OwnBuild.Looks(Exe, true, "Example Corp", Built()), Is.False);
            Assert.That(OwnBuild.Looks(Exe, null, null, Built()), Is.False);
        });
    }

    [TestCase(@"C:\Users\alice\AppData\Local\Temp")]
    [TestCase(@"C:\Users\alice\Downloads")]
    [TestCase(@"C:\Users\alice\AppData\")]
    public void Nothing_in_a_drop_folder_is_your_build(string drop)
    {
        var repo = @"C:\Users\alice\" + (drop.Contains("Downloads", StringComparison.Ordinal) ? @"Downloads\tray" : @"AppData\Local\Temp\tray");
        var exe = repo + @"\src\Tray\bin\Debug\net10.0\Tray.exe";
        Assert.That(OwnBuild.Looks(exe, false, null, Built(repo, exe, drops: drop)), Is.False);
        Assert.That(OwnBuild.Looks(exe, false, null, Built(repo, exe)), Is.True, "the same tree elsewhere");
    }

    [TestCase(@"Tray.exe")]
    [TestCase(@"\\server\share\Tray.exe")]
    [TestCase(@"C:\src\Tray\..\Tray.exe")]
    public void Only_a_full_local_path_qualifies(string path) =>
        Assert.That(OwnBuild.Looks(path, false, null, new Disk([@"C:\src\.git", @"C:\src\Tray.csproj"])), Is.False);

    [TestCase(true, true, true, ProgramMark.None)]
    [TestCase(null, true, true, ProgramMark.None)]
    [TestCase(false, false, true, ProgramMark.Unsigned)]
    [TestCase(false, true, true, ProgramMark.BuiltByYou)]
    [TestCase(false, true, false, ProgramMark.Unsigned)]
    public void Both_lists_mark_a_program_the_same_way(bool? valid, bool builtByYou, bool developerTools, ProgramMark mark) =>
        Assert.That(ProgramMarks.Of(valid, builtByYou, developerTools), Is.EqualTo(mark));

    static StartupEntry Tray(bool builtByYou) => new("Tray", StartupEntry.RunKey, Exe, false, "Tray", BuiltByYou: builtByYou);

    [Test]
    public void The_doctor_lists_your_own_startup_build_as_information_that_opens_the_startup_list()
    {
        var check = Doctor.AttackSurface([], [Tray(true)], [], [], Now).Single();

        Assert.That(check.Status, Is.EqualTo(DoctorStatus.Ok));
        Assert.That(check.Kind, Is.EqualTo(Doctor.OwnBuildStartupKind));
        Assert.That(check.Fix, Is.InstanceOf<ReviewStartup>());
        Assert.That(FindingView.Button(check.Fix)?.Action, Is.EqualTo(FixAction.OpenStartupList));
        Assert.That(check.WithoutDeveloperTools, Is.EqualTo(Doctor.AttackSurface([], [Tray(false)], [], [], Now).Single()));
    }

    [Test]
    public void Without_developer_tools_your_own_build_is_an_unsigned_warning_like_any_other()
    {
        DoctorCheck[] checks = [.. Doctor.AttackSurface([], [Tray(true)], [], [], Now)];

        var developer = FindingView.Of(checks, Dismissals.Empty, developerTools: true).Open.Single().Single();
        var other = FindingView.Of(checks, Dismissals.Empty, developerTools: false).Open.Single().Single();

        Assert.That(developer.Status, Is.EqualTo(DoctorStatus.Ok));
        Assert.That((other.Status, other.Kind), Is.EqualTo((DoctorStatus.Warn, Doctor.UnsignedStartupKind)));
    }

    [Test]
    public void A_startup_entry_belongs_to_the_installed_app_whose_folder_holds_it()
    {
        UninstallEntry app = new(@"HKCU\x\Chat", "Chat", "1.0", null, false, true, Folder: @"C:\Users\alice\AppData\Local\Chat");
        UninstallEntry inner = new(@"HKCU\x\Helper", "Chat Helper", "1.0", null, false, true, Folder: @"C:\Users\alice\AppData\Local\Chat\helper");
        StartupEntry[] startup =
        [
            new("Chat", StartupEntry.RunKey, @"C:\Users\alice\AppData\Local\Chat\chat.exe", true, "Chat"),
            new("Helper", StartupEntry.ScheduledTask, @"C:\Users\alice\AppData\Local\Chat\helper\h.exe", true),
            new("Sync", StartupEntry.StartupFolder, @"C:\Tools\sync.exe", false, "Sync.lnk", On: false),
            new("Sync", StartupEntry.StartupFolder, @"C:\TOOLS\sync.exe", false, "Sync.lnk", On: false),
        ];
        ProgramRun[] runs = [new(@"C:\Tools\sync.exe", Now.AddDays(-3)), new(@"C:\Tools\sync.exe", Now.AddDays(-1), Opened: false)];
        CredentialUse[] uses = [new(@"C:\Tools\sync.exe", "github", Now.AddDays(-2)), new(@"C:\Tools\sync.exe", "old", Now.AddDays(-200))];

        var programs = Doctor.StartupPrograms(startup, [app, inner], runs, uses, Now);

        Assert.That(programs.Select(p => (p.Entry.Name, p.App)), Is.EqualTo(new (string, string?)[] { ("Sync", null), ("Chat", "Chat"), ("Helper", "Chat Helper") }),
            "not from an installed app first; the deepest folder wins; one entry once");
        Assert.That(programs[0].LastOpened, Is.EqualTo(Now.AddDays(-3)), "only what you opened yourself");
        Assert.That(programs[0].Reached, Is.EqualTo(new[] { "github" }));
    }

    [Test]
    public void The_startup_list_filters_and_offers_turning_off_only_your_own_entries_that_are_on()
    {
        StartupProgram[] list =
        [
            new(new("Chat", StartupEntry.RunKey, @"C:\a\chat.exe", true, "Chat"), "Chat", null, []),
            new(new("Sync", StartupEntry.StartupFolder, @"C:\b\sync.exe", false, "Sync.lnk", On: false), null, null, []),
            new(new("Tray", StartupEntry.RunKey, Exe, false, "Tray", BuiltByYou: true), null, null, []),
            new(new("Agent", StartupEntry.MachineRunKey, @"C:\c\agent.exe", true, "Agent"), "Agent", null, ["github"]),
            new(new("Update", StartupEntry.ScheduledTask, @"C:\d\update.exe", true), "Update", null, []),
        ];
        string[] Names(StartupView view, string search = "") =>
            [.. StartupFilter.Apply(list, search, view, e => ProgramMarks.Of(e.Signed, e.BuiltByYou, true)).Select(p => p.Entry.Name)];

        Assert.Multiple(() =>
        {
            Assert.That(Names(StartupView.NotFromApp), Is.EqualTo(new[] { "Sync", "Tray" }));
            Assert.That(Names(StartupView.Unsigned), Is.EqualTo(new[] { "Sync" }), "your own build isn't a caution");
            Assert.That(Names(StartupView.Off), Is.EqualTo(new[] { "Sync" }));
            Assert.That(Names(StartupView.All, "github"), Is.EqualTo(new[] { "Agent" }));
            Assert.That(list.Select(p => StartupFilter.TurnOff(p.Entry)?.Item), Is.EqualTo(new[] { "Chat", null, "Tray", null, null }),
                "off already, machine-wide and tasks go through Settings");
        });
    }
}
