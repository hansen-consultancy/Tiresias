using System.Buffers.Binary;
using System.Text;
using System.Text.Json.Nodes;
using Tiresias.AdminTier;
using Tiresias.Client;
using Tiresias.Protocol;

namespace Tiresias.Tests;

public class AdminLastRunTests
{
    const string Alice = "S-1-5-21-1000-1000-1000-1001";
    static readonly DateTimeOffset T0 = new(2026, 11, 21, 9, 0, 0, TimeSpan.Zero);
    static readonly Dictionary<string, string> Devices = new(StringComparer.OrdinalIgnoreCase)
    {
        [@"\Device\HarddiskVolume3"] = "C:",
        [AdminLastRun.VolumeKey(0x1A2B3C4D)] = "C:",
    };

    const string Device = @"\VOLUME{01d6a8b4c2e3f123-1a2b3c4d}";

    /// <summary>A version 30 Prefetch file as Windows writes it once decompressed: the fields read, the rest zero.</summary>
    static byte[] Pf(string exe, string[] files, int count, DateTimeOffset[] runs, uint version = 30, uint metrics = 0x130)
    {
        var names = Encoding.Unicode.GetBytes(string.Concat(files.Select(f => f + "\0")));
        var data = new byte[304 + names.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(data, version);
        "SCCA"u8.CopyTo(data.AsSpan(4));
        Encoding.Unicode.GetBytes(exe).CopyTo(data, 16);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(84), metrics);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(100), 304);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(104), (uint)names.Length);
        for (var i = 0; i < runs.Length; i++)
            BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(128 + i * 8), runs[i].ToFileTime());
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(metrics == 0x128 ? 200 : 208), (uint)count);
        names.CopyTo(data, 304);
        return data;
    }

    static byte[] Tool => Pf("TOOL.EXE", [$@"{Device}\WINDOWS\SYSTEM32\NTDLL.DLL", $@"{Device}\TOOLS\TOOL.EXE"], 7, [T0, T0.AddDays(-1)]);

    [Test]
    public void A_prefetch_file_reads_its_program_count_and_last_runs()
    {
        var file = Prefetch.Parse(Tool)!;

        Assert.That(file.Executable, Is.EqualTo("TOOL.EXE"));
        Assert.That(file.RunCount, Is.EqualTo(7));
        Assert.That(file.LastRuns, Is.EqualTo(new[] { T0, T0.AddDays(-1) }));
        Assert.That(file.ProgramPath, Is.EqualTo($@"{Device}\TOOLS\TOOL.EXE"));
        Assert.That(AdminLastRun.DrivePath(file.ProgramPath!, Devices), Is.EqualTo(@"C:\TOOLS\TOOL.EXE"));
    }

    [Test]
    public void Both_layouts_and_version_31_read_the_count()
    {
        Assert.That(Prefetch.Parse(Pf("A.EXE", [], 3, [T0], metrics: 0x128))!.RunCount, Is.EqualTo(3));
        Assert.That(Prefetch.Parse(Pf("A.EXE", [], 4, [T0], version: 31))!.RunCount, Is.EqualTo(4));
    }

    [Test]
    public void A_long_name_matches_on_its_first_29_characters()
    {
        var name = new string('A', 29);
        var file = Prefetch.Parse(Pf(name, [$@"{Device}\X\{name}LONGER.EXE"], 1, [T0]))!;
        Assert.That(file.ProgramPath, Is.EqualTo($@"{Device}\X\{name}LONGER.EXE"));
    }

    [Test]
    public void Another_version_or_signature_is_not_read()
    {
        Assert.That(Prefetch.Parse(Pf("A.EXE", [], 1, [T0], version: 23)), Is.Null);
        var bad = Tool;
        bad[5] = (byte)'X';
        Assert.That(Prefetch.Parse(bad), Is.Null);
    }

    [Test]
    public void Names_past_the_end_are_refused()
    {
        var data = Tool;
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(104), uint.MaxValue);
        Assert.That(Prefetch.Parse(data), Is.Null);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(100), uint.MaxValue);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(104), 16);
        Assert.That(Prefetch.Parse(data), Is.Null);
    }

    [Test]
    public void Damaged_files_never_throw()
    {
        var random = new Random(91);
        var good = Tool;
        for (var i = 0; i < 5000; i++)
        {
            var data = i % 3 == 0 ? good[..random.Next(good.Length)] : (byte[])good.Clone();
            for (var flips = random.Next(1, 12); flips > 0 && data.Length > 0; flips--)
                data[random.Next(data.Length)] = (byte)random.Next(256);
            Assert.DoesNotThrow(() =>
            {
                Prefetch.Parse(data);
                AdminLastRun.Unwrap(data);
            });
        }
    }

    [Test]
    public void A_compressed_file_is_found_with_its_size_and_a_checksum_skipped()
    {
        byte[] plain = [(byte)'M', (byte)'A', (byte)'M', 0x04, 0x00, 0x10, 0, 0, 0xAA];
        byte[] checksummed = [(byte)'M', (byte)'A', (byte)'M', 0x84, 0x00, 0x10, 0, 0, 1, 2, 3, 4, 0xAA];
        byte[] huge = [(byte)'M', (byte)'A', (byte)'M', 0x04, 0xFF, 0xFF, 0xFF, 0x7F, 0xAA];

        Assert.That(AdminLastRun.Unwrap(plain), Is.EqualTo((true, 8, 0x1000)));
        Assert.That(AdminLastRun.Unwrap(checksummed), Is.EqualTo((true, 12, 0x1000)));
        Assert.That(AdminLastRun.Unwrap(huge), Is.Null);
        Assert.That(AdminLastRun.Unwrap(Tool), Is.EqualTo((false, 0, Tool.Length)));
        Assert.That(AdminLastRun.Unwrap([1, 2, 3]), Is.Null);
    }

    [TestCase(@"\Device\HarddiskVolume3\Tools\tool.exe", @"C:\Tools\tool.exe")]
    [TestCase(@"\Device\HarddiskVolume9\Tools\tool.exe", null)]
    [TestCase(@"\VOLUME{01d6a8b4c2e3f123-1A2B3C4D}\TOOLS\TOOL.EXE", @"C:\TOOLS\TOOL.EXE")]
    [TestCase(@"\VOLUME{01d6a8b4c2e3f123-FFFFFFFF}\TOOLS\TOOL.EXE", null)]
    [TestCase(@"\VOLUME{broken\TOOLS", null)]
    [TestCase("Microsoft.WindowsTerminal_8wekyb3d8bbwe", null)]
    [TestCase(@"\", null)]
    public void Device_paths_become_drive_paths(string device, string? drive) =>
        Assert.That(AdminLastRun.DrivePath(device, Devices), Is.EqualTo(drive));

    static byte[] Bam(DateTimeOffset at)
    {
        var data = new byte[24];
        BinaryPrimitives.WriteInt64LittleEndian(data, at.ToFileTime());
        return data;
    }

    [Test]
    public void The_bam_key_reads_programs_and_skips_the_rest()
    {
        var runs = AdminLastRun.Bam([
            (@"\Device\HarddiskVolume3\Tools\tool.exe", Bam(T0)),
            ("Version", [1, 0, 0, 0]),
            ("SequenceNumber", new byte[8]),
            ("Microsoft.WindowsTerminal_8wekyb3d8bbwe", Bam(T0)),
            (@"\Device\HarddiskVolume3\Tools\short.exe", [1, 2]),
            (@"\Device\HarddiskVolume3\Tools\null.exe", null),
        ], Devices).ToArray();

        Assert.That(runs, Is.EqualTo(new[] { new BamRun(@"C:\Tools\tool.exe", T0) }));
    }

    [Test]
    public void Only_the_users_runs_under_the_paths_asked_are_answered()
    {
        BamRun[] bam = [new(@"C:\TOOLS\TOOL.EXE", T0.AddDays(-3)), new(@"C:\Other\secret.exe", T0), new(@"C:\Tools2\x.exe", T0)];
        var prefetch = new[] { (@"C:\TOOLS\TOOL.EXE", Prefetch.Parse(Tool)!), (@"C:\Elsewhere\only-another-user.exe", Prefetch.Parse(Tool)!) };

        var answer = AdminLastRun.Answer([@"C:\Tools\"], bam, prefetch);

        Assert.That(answer, Has.Count.EqualTo(1));
        Assert.That(answer[0].Path, Is.EqualTo(@"C:\TOOLS\TOOL.EXE"));
        Assert.That(answer[0].Runs, Is.EqualTo(7));
        Assert.That(answer[0].LastRun, Is.EqualTo(T0), "Prefetch's later run");
        Assert.That(answer[0].Recent, Is.EqualTo(new[] { T0, T0.AddDays(-1) }));
        Assert.That(AdminLastRun.Answer([@"C:\Elsewhere\only-another-user.exe"], bam, prefetch), Is.Empty);
    }

    [TestCase(1, true)]
    [TestCase(AdminArgs.MaxRunPaths, true)]
    [TestCase(AdminArgs.MaxRunPaths + 1, false)]
    [TestCase(0, false)]
    public void Lastrun_takes_a_few_hundred_full_paths(int count, bool allowed)
    {
        var args = new JsonObject { ["paths"] = new JsonArray([.. Enumerable.Range(0, count).Select(i => (JsonNode)$@"C:\Tools\{i}.exe")]) };
        var caller = new AdminCaller(Alice, 1, Alice, Elevated: false, IsService: false);
        Assert.That(AdminCallerPolicy.Decide(new(AdminWire.ProtocolVersion, AdminOps.LastRun, args), caller).Allowed, Is.EqualTo(allowed));
    }

    [TestCase(@"\\server\share\x.exe")]
    [TestCase(@"C:\Tools\..\x.exe")]
    [TestCase("x.exe")]
    public void Lastrun_refuses_anything_but_a_drive_path(string path) =>
        Assert.That(AdminArgs.RunPaths(new JsonArray(path)), Is.False);

    [Test]
    public void The_answer_crosses_the_wire()
    {
        var back = AdminWire.FromNode<AdminLastRuns>(AdminWire.ToNode(new AdminLastRuns([new(@"C:\x.exe", T0, 3, [T0])])))!;
        Assert.That(back.Runs.Single().Runs, Is.EqualTo(3));
        Assert.That(back.Runs.Single().Recent, Is.EqualTo(new[] { T0 }));
    }

    [Test]
    public void The_doctor_asks_about_startup_programs_installed_folders_and_blocked_programs()
    {
        var asked = Doctor.RunsAsked(
            [new StartupEntry("Tool", StartupEntry.RunKey, @"C:\Tools\tool.exe", true)],
            [new UninstallEntry("App", "App", "1", null, false, true, Folder: @"C:\Program Files\App")],
            [@"C:\Users\alice\evil.exe", @"\\server\x.exe"]);
        Assert.That(asked, Is.EquivalentTo(new[] { @"C:\Tools\tool.exe", @"C:\Program Files\App", @"C:\Users\alice\evil.exe" }));
    }

    [Test]
    public void A_run_only_the_admin_tier_saw_does_not_make_a_startup_program_opened()
    {
        var startup = new StartupEntry("Tool", StartupEntry.RunKey, @"C:\Tools\tool.exe", true, "Tool");
        var now = T0;
        ProgramRun[] runs = [new(@"C:\Tools\tool.exe", now.AddDays(-200)), new(@"C:\Tools\tool.exe", now.AddHours(-1), Opened: false)];
        Assert.That(Doctor.AttackSurface([], [startup], [], [], now, runs).Count(c => c.Kind == Doctor.IdleStartupKind), Is.EqualTo(1));
    }

    [Test]
    public void A_decoy_finding_says_when_windows_last_saw_the_program_run()
    {
        const string evil = @"C:\Users\alice\evil.exe";
        var finding = Doctor.Decoys([new(evil, "the decoy API key", T0)], [evil], T0, [new(evil, T0.AddDays(-2), Opened: false)]).Single();
        Assert.That(finding.Detail, Does.Contain("Windows last saw it run on"));
    }
}
