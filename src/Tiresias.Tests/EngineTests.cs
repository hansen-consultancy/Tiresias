using System.Text;
using System.Text.Json;
using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

public class EngineTests
{
    const string Canary = "canary-91be4d";

    static byte[] Bytes(string text) => Encoding.UTF8.GetBytes(text);

    const string ContainerList = """
        [
          { "Id": "aaa111", "Names": ["/api-dev"], "Image": "shop-api", "ImageID": "sha256:img1", "State": "running",
            "Labels": { "devcontainer.local_folder": "C:\\src\\shop", "secret.label": "x" },
            "Mounts": [ { "Type": "bind", "Source": "/run/desktop/mnt/host/c/Users/alice/.ssh", "Destination": "/root/.ssh" },
                        { "Type": "bind", "Source": "C:\\src\\shop", "Destination": "/workspaces/shop" } ] },
          { "Id": "bbb222", "Names": ["/redis"], "ImageID": "sha256:img2", "State": "exited", "Labels": null, "Mounts": [] }
        ]
        """;

    static readonly string ApiInspect = $$"""
        { "Id": "aaa111", "Config": { "Hostname": "x", "Env": [ "PATH=/usr/bin", "NUGET_TOKEN={{Canary}}", "OPENAI_API_KEY={{Canary}}", "DATABASE_URL=postgres://app:{{Canary}}@db/shop", "PROXY_TOKEN=" ] } }
        """;

    static readonly string ImageInspect = $$"""
        { "Id": "sha256:img1", "Config": { "Env": [ "PATH=/usr/bin", "NUGET_TOKEN={{Canary}}" ] }, "ContainerConfig": { "Env": [ "LEAK_KEY={{Canary}}" ] } }
        """;

    static readonly EngineContents Docker = new("docker_engine",
        [
            Container(EngineScan.Containers(Bytes(ContainerList))[0], EngineScan.Env(Bytes(ApiInspect))),
            Container(EngineScan.Containers(Bytes(ContainerList))[1], EngineScan.Env(Bytes("""{ "Config": { "Env": ["REDIS_PASSWORD=x"] } }"""))),
        ],
        [new("sha256:img1", "shop-api:latest", EngineScan.Env(Bytes(ImageInspect))), new("sha256:img2", "redis:7", [])]);

    static EngineContainer Container(EngineScan.Listed c, IReadOnlyList<ScannedName> env) => new(c.Name, c.Running, c.ImageId, env, c.Mounts, c.Workspace);

    static readonly ReachFacts Open = new([new("docker_engine", EngineKind.Current, ["docker-users"])], [], HyperVAccess.NotInstalled);

    static DoctorCheck[] Checks(ReachContents? contents) => [.. Doctor.Contents(Open, contents)];

    [Test]
    public void The_container_list_yields_names_state_mounts_and_the_devcontainer_folder()
    {
        var listed = EngineScan.Containers(Bytes(ContainerList));
        Assert.Multiple(() =>
        {
            Assert.That(listed.Select(c => (c.Name, c.Running)), Is.EqualTo(new[] { ("api-dev", true), ("redis", false) }));
            Assert.That(listed[0].Workspace, Is.EqualTo(@"C:\src\shop"));
            Assert.That(listed[0].Mounts, Has.Count.EqualTo(2));
            Assert.That(listed[1].Workspace, Is.Null);
        });
    }

    [Test]
    public void Only_Config_Env_is_read_and_as_names()
    {
        Assert.That(EngineScan.Env(Bytes(ImageInspect)).Select(n => n.Name), Is.EqualTo(new[] { "PATH", "NUGET_TOKEN" }), "ContainerConfig is not the image's environment");
        Assert.That(EngineScan.Images(Bytes("""[{ "Id": "sha256:0123456789abcdef", "RepoTags": ["<none>:<none>"] }, { "Id": "sha256:b", "RepoTags": ["redis:7"] }]""")),
            Is.EqualTo(new[] { ("sha256:0123456789abcdef", "0123456789ab"), ("sha256:b", "redis:7") }));
    }

    [TestCase("")]
    [TestCase("{")]
    [TestCase("[{ \"Id\": ")]
    [TestCase("{\"message\":\"page not found\"}")]
    public void Malformed_engine_JSON_yields_nothing(string json) => Assert.Multiple(() =>
    {
        Assert.That(EngineScan.Containers(Bytes(json)), Is.Empty);
        Assert.That(EngineScan.Images(Bytes(json)), Is.Empty);
        Assert.That(EngineScan.Env(Bytes(json)), Is.Empty);
    });

    [Test]
    public void No_value_reaches_the_facts_or_the_findings()
    {
        var checks = Checks(new(Docker));
        var everything = JsonSerializer.Serialize(Docker)
            + string.Concat(checks.Select(c => c.Name + c.Detail + c.Fix?.Instruction + (c.Fix as InjectAtRunTime)?.Commands));
        Assert.That(everything, Does.Not.Contain(Canary));
    }

    [Test]
    public void A_container_s_own_secrets_are_a_finding_and_the_image_s_are_the_image_s()
    {
        var checks = Checks(new(Docker)).ToDictionary(c => c.Name);
        Assert.Multiple(() =>
        {
            Assert.That(checks.Keys, Is.EquivalentTo(new[] { "container api-dev", "mounts of api-dev", "container redis", "image shop-api:latest" }));
            var api = checks["container api-dev"];
            Assert.That(api.Detail, Does.StartWith("OPENAI_API_KEY, DATABASE_URL (password in URL): in the environment of this running container, the devcontainer for C:\\src\\shop"));
            Assert.That(api.Detail, Does.Not.Contain("NUGET_TOKEN"), "set by the image, reported there");
            Assert.That(FindingView.Moves(api), Is.EqualTo("E5/C3 → E4/C1"));
            var fix = (InjectAtRunTime)api.Fix!;
            Assert.That(fix.Commands.Split('\n'), Is.EqualTo(new[]
            {
                "tir env set OPENAI_API_KEY --folder \"C:\\src\\shop\"", "tir env set DATABASE_URL --folder \"C:\\src\\shop\"",
                "docker rm api-dev", "cd \"C:\\src\\shop\"", "tir run -- code .",
            }));
            Assert.That(checks["container redis"].Detail, Does.Contain("stopped container"));
            Assert.That(((InjectAtRunTime)checks["container redis"].Fix!).Commands, Does.EndWith("tir run --only REDIS_PASSWORD -- docker run --rm -e REDIS_PASSWORD redis:7"));
            var image = checks["image shop-api:latest"];
            Assert.That((image.Detail, image.Kind, FindingView.Moves(image)), Is.EqualTo((
                "NUGET_TOKEN: set by the image's ENV lines, so every container made from it and anyone holding a copy has them", "images with secrets baked in", "E5/C3")));
            Assert.That(image.Fix!.Instruction, Does.StartWith("rebuild shop-api:latest without the ENV lines"));
            Assert.That(checks["mounts of api-dev"].Detail, Does.StartWith("/run/desktop/mnt/host/c/Users/alice/.ssh is mounted"));
            Assert.That(FindingView.Button(checks["mounts of api-dev"].Fix), Is.EqualTo((FixAction.OpenGuide, "Finding_FixReachGuide")));
            Assert.That(FindingView.Button(api.Fix), Is.EqualTo((FixAction.CopyCommand, "Finding_FixCopy")));
        });
    }

    [TestCase("C:\\src\\shop\" & calc & \"")]
    [TestCase("C:\\src\\$(calc)")]
    [TestCase("C:\\src\\%PATH%")]
    public void An_engine_label_that_would_break_out_of_a_pasted_command_is_left_out(string label)
    {
        var listed = EngineScan.Containers(Bytes(JsonSerializer.Serialize(new[]
        {
            new { Id = "c1", Names = new[] { "/a;calc" }, ImageID = "i1", State = "running", Labels = new Dictionary<string, string> { ["devcontainer.local_folder"] = label } },
        })))[0];
        var docker = new EngineContents("docker_engine", [Container(listed, [new("API_TOKEN", false, false, false, false)])], [new("i1", "evil:1\"&calc", [new("BAKED_TOKEN", false, false, false, false)])]);
        var fixes = Checks(new(docker)).Select(c => c.Fix).OfType<InjectAtRunTime>().ToArray();
        Assert.Multiple(() =>
        {
            Assert.That(fixes.Select(f => f.Commands + f.Instruction), Has.All.Not.Contain("calc").And.All.Not.Contain("%PATH%"));
            Assert.That(fixes[0].Commands, Does.EndWith("docker run --rm -e API_TOKEN <image>"));
            Assert.That(fixes[1].Instruction, Does.StartWith("rebuild the image without"));
        });
    }

    [Test]
    public async Task An_engine_label_that_would_break_out_is_not_scanned_for_devcontainer_files()
    {
        var probe = new ContentsProbe();
        var docker = new EngineContents("docker_engine", [new("a", true, "i", [], [], "C:\\x\" & calc & \""), new("b", true, "i", [], [], @"C:\src\shop")], []);
        await Doctor.RunAsync(probe, new(docker));
        Assert.That(probe.Workspaces, Is.EqualTo(new[] { @"C:\src\shop" }));
    }

    [Test]
    public void Not_asked_says_how_to_look_only_while_an_engine_is_open()
    {
        Assert.That(Checks(null).Single().Detail, Does.StartWith("not looked inside: tir doctor --reach"));
        Assert.That(Doctor.Contents(ReachFacts.None, null), Is.Empty);
        Assert.That(Checks(new(null)).Single().Detail, Does.StartWith("Docker didn't answer"));
        Assert.That(Checks(new(new("docker_engine", [], []))).Single(), Has.Property("Status").EqualTo(DoctorStatus.Ok));
    }

    [Test]
    public async Task The_doctor_looks_inside_only_with_contents_and_adds_the_containers_devcontainer_folders()
    {
        var probe = new ContentsProbe();
        var without = await Doctor.RunAsync(probe);
        Assert.That(probe.Workspaces, Is.Empty);
        Assert.That(without.Single(c => c.Name == Doctor.DockerContentsCheck).Detail, Does.StartWith("not looked inside"));

        var with = await Doctor.RunAsync(probe, new(Docker));
        Assert.That(probe.Workspaces, Is.EqualTo(new[] { @"C:\src\shop" }));
        Assert.That(with.Select(c => c.Name), Does.Contain("container api-dev"));
    }

    sealed class ContentsProbe : IDoctorProbe
    {
        public IReadOnlyCollection<string> Workspaces = [];

        public bool Enrolled => true;
        public bool HasDeviceKey => true;
        public bool RecoveryKeySet => true;
        public DoctorVault? Vault => new(2, [], []);
        public Task<int?> BrokerStatusAsync() => Task.FromResult<int?>(401);
        public Task<bool> ForwarderListeningAsync() => Task.FromResult(true);
        public IEnumerable<DoctorFile> UserSecretsFiles() => [];
        public IEnumerable<DoctorFile> Projects() => [];
        public ReachFacts Reach => Open;

        public IEnumerable<DevcontainerFile> Devcontainers(IReadOnlyCollection<string> workspaces)
        {
            Workspaces = workspaces;
            return [];
        }
    }

    [TestCase(ReachScan.Off, null, false, ReachStep.Skip)]
    [TestCase(ReachScan.Off, null, true, ReachStep.Look)]
    [TestCase(ReachScan.Once, null, false, ReachStep.Skip)]
    [TestCase(ReachScan.Once, 2.0, false, ReachStep.Reuse)]
    [TestCase(ReachScan.Daily, null, false, ReachStep.Look)]
    [TestCase(ReachScan.Daily, 2.0, false, ReachStep.Reuse)]
    [TestCase(ReachScan.Daily, 25.0, false, ReachStep.Look)]
    [TestCase(ReachScan.Once, 2.0, true, ReachStep.Look)]
    public void The_app_looks_when_asked_or_daily_and_otherwise_reuses_the_last_look(ReachScan setting, double? hoursAgo, bool asked, ReachStep step)
    {
        var now = new DateTimeOffset(2026, 11, 22, 12, 0, 0, TimeSpan.Zero);
        Assert.That(ReachLook.Decide(setting, hoursAgo is { } h ? now.AddHours(-h) : null, now, asked), Is.EqualTo(step));
    }

    [Test]
    public void Looking_turns_the_setting_on_once_and_keeps_daily() => Assert.Multiple(() =>
    {
        Assert.That(ReachLook.AfterLooking(ReachScan.Off), Is.EqualTo(ReachScan.Once));
        Assert.That(ReachLook.AfterLooking(ReachScan.Daily), Is.EqualTo(ReachScan.Daily));
        Assert.That(JsonSerializer.Serialize(ReachScan.Daily), Is.EqualTo("\"Daily\""));
    });
}
