using Tiresias.App.Logic;
using Tiresias.UserSecrets;

namespace Tiresias.Tests;

/// <summary>Naming user-secrets folders after the projects that use them.</summary>
public class ProjectScanTests
{
    string root = "";

    [SetUp]
    public void CreateTree() => root = Directory.CreateTempSubdirectory("tiresias-scan-").FullName;

    [TearDown]
    public void RemoveTree() => Directory.Delete(root, recursive: true);

    /// <summary>A path under the temporary tree; written with <c>\</c>, which this OS's separator replaces.</summary>
    string Under(string relative) => Path.Combine(root, relative.Replace('\\', Path.DirectorySeparatorChar));

    string Project(string relative, string? id)
    {
        var path = Under(relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, id is null
            ? "<Project Sdk=\"Microsoft.NET.Sdk\"></Project>"
            : $"<Project Sdk=\"Microsoft.NET.Sdk.Web\"><PropertyGroup>\n  <UserSecretsId> {id} </UserSecretsId>\n</PropertyGroup></Project>");
        return path;
    }

    [Test]
    public void A_scan_finds_projects_with_an_id_and_passes_over_build_output()
    {
        var api = Project(@"Shop\Api\Api.csproj", "aaa-1");
        Project(@"Shop\Lib\Lib.csproj", null);
        Project(@"Shop\Api\bin\Debug\Copy\Api.csproj", "aaa-1");
        Project(@"Shop\node_modules\x\X.csproj", "zzz");
        var worker = Project(@"Other\Worker\Worker.fsproj", "bbb-2");

        var found = ProjectScanner.Scan(root);

        Assert.That(found, Is.EquivalentTo(new[] { new ProjectFile(api, "aaa-1"), new ProjectFile(worker, "bbb-2") }));
    }

    [Test]
    public void The_program_asking_is_traced_back_to_its_project()
    {
        var api = Project(@"Shop\Api\Api.csproj", "aaa-1");
        var exe = Under(@"Shop\Api\bin\Debug\net10.0\Api.exe");

        Assert.That(ProjectScanner.FromExecutable(exe, "AAA-1"), Is.EqualTo(new ProjectFile(api, "aaa-1")));
        Assert.That(ProjectScanner.FromExecutable(exe, "another-id"), Is.Null, "a project with another id is not this program's");
        Assert.That(ProjectScanner.FromExecutable(Under(@"elsewhere\dotnet.exe"), "aaa-1"), Is.Null);
    }

    [Test]
    public void A_rescan_replaces_what_was_known_under_that_folder_only()
    {
        var index = new ProjectIndex([@"P:\src"], [
            new(@"P:\src\Old\Old.csproj", "1"),
            new(@"P:\srcother\Keep.csproj", "2"),
            new(@"D:\linked\Linked.csproj", "3"),
        ]);

        var after = index.Rescanned(@"P:\src\", [new(@"P:\src\New\New.csproj", "1")]);

        Assert.That(after.Projects.Select(p => p.Path), Is.EquivalentTo(new[] { @"P:\srcother\Keep.csproj", @"D:\linked\Linked.csproj", @"P:\src\New\New.csproj" }));
    }

    [Test]
    [Platform("Win")]
    public void A_project_on_a_drive_that_is_not_there_is_kept_one_that_was_deleted_is_not()
    {
        var index = new ProjectIndex([], [new(@"P:\gone\Gone.csproj", "1"), new(@"E:\usb\Usb.csproj", "2"), new(@"P:\here\Here.csproj", "3")]);

        var after = index.Pruned(path => path == @"P:\here\Here.csproj", root => root == @"P:\");

        Assert.That(after.Projects.Select(p => p.Id), Is.EquivalentTo(new[] { "2", "3" }));
    }

    [Test]
    public void Linking_a_project_again_updates_it_rather_than_adding_a_second()
    {
        var index = ProjectIndex.Empty.Linked(new(@"P:\a\A.csproj", "1")).Linked(new(@"p:\A\a.csproj", "2"));

        Assert.That(index.Projects, Has.Count.EqualTo(1));
        Assert.That(index.Projects[0].Id, Is.EqualTo("2"));
    }

    [Test]
    [Platform("Win")]
    public void Named_projects_come_first_and_a_copied_id_lists_every_project()
    {
        var index = new ProjectIndex([@"P:\"], [
            new(@"P:\shop\Shop.csproj", "s"),
            new(@"P:\copy\Shop.csproj", "s"),
            new(@"P:\api\Api.csproj", "a"),
        ]);

        var list = ProjectList.Build(["zz-unknown", "s", "a", "S"], index);

        Assert.That(list.Select(e => e.Name), Is.EqualTo(new[] { "Api", "Shop", "zz-unknown" }));
        Assert.That(list[1].Paths, Is.EqualTo(new[] { @"P:\copy\Shop.csproj", @"P:\shop\Shop.csproj" }));
        Assert.That(ProjectList.Unused(list, index), Is.EqualTo(new[] { "zz-unknown" }));
    }

    [Test]
    public void Nothing_is_offered_for_removal_before_a_folder_was_scanned()
    {
        var list = ProjectList.Build(["a", "b"], ProjectIndex.Empty);

        Assert.That(list.All(e => !e.Known), Is.True);
        Assert.That(ProjectList.Unused(list, ProjectIndex.Empty), Is.Empty);
    }

    [Test]
    public void Remembered_folders_are_kept_once_and_in_order()
    {
        var index = ProjectIndex.Empty.WithFolder(@"P:\").WithFolder(@"D:\src").WithFolder(@"p:\");

        Assert.That(index.Folders, Is.EqualTo(new[] { @"D:\src", @"P:\" }));
        Assert.That(index.WithoutFolder(@"d:\SRC").Folders, Is.EqualTo(new[] { @"P:\" }));
    }

    [Test]
    [Platform("Win")]
    public void Worktrees_of_one_project_sum_up_to_the_main_checkout_and_a_count()
    {
        var paths = ProjectPaths.Of([
            @"P:\.worktrees\Shop\fix-a\src\Shop\Shop.csproj",
            @"P:\Shop\src\Shop\Shop.csproj",
            @"P:\.worktrees\Shop\fix-b\src\Shop\Shop.csproj",
        ]);

        Assert.That(paths, Is.EqualTo(new ProjectPaths(@"P:\Shop\src\Shop\Shop.csproj", 2, 0)));
        Assert.That(paths.OnlyCheckouts, Is.True);
    }

    [Test]
    [Platform("Win")]
    public void Other_projects_sharing_an_id_are_counted_apart_from_checkouts()
    {
        var paths = ProjectPaths.Of([@"C:\Web\Web.csproj", @"C:\Web.Tests\Web.Tests.csproj"]);

        Assert.That(paths, Is.EqualTo(new ProjectPaths(@"C:\Web\Web.csproj", 0, 1)));
        Assert.That(paths.OnlyCheckouts, Is.False);
        Assert.That(paths.More, Is.EqualTo(1));
    }

    [Test]
    public void One_project_has_nothing_more() =>
        Assert.That(ProjectPaths.Of([@"C:\Web\Web.csproj"]).More, Is.Zero);
}
