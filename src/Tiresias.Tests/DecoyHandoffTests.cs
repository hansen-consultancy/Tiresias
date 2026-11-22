using Microsoft.Extensions.Logging.Abstractions;
using Tiresias.Admin;
using Tiresias.AdminTier;
using Tiresias.Agent;
using Tiresias.Decoys;

namespace Tiresias.Tests;

[Platform("Win"), System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class DecoyHandoffTests
{
    const string Sid = "S-1-5-21-1000-1000-1000-1001";
    string directory = "";

    [SetUp]
    public void SetUp() => directory = Directory.CreateTempSubdirectory("tir-handoff-").FullName;

    [TearDown]
    public void TearDown() => Directory.Delete(directory, recursive: true);

    [Test]
    public void The_manifest_stays_bound_to_the_same_file_until_its_transfer_finishes()
    {
        var path = Path.Combine(directory, DecoySet.FileName);
        var other = Path.Combine(directory, "replacement.json");
        File.WriteAllText(path, "verified snapshot");
        File.WriteAllText(other, "different snapshot");
        using (var manifest = SourceHandle.Open(path, directory: false, allowDelete: true))
        {
            Assert.That(manifest.ReadText(path, 100), Is.EqualTo("verified snapshot"));
            Assert.That(manifest.ReadText(other, 100), Is.Null);
            Assert.That(manifest.ReadText(path, 4), Is.Null);
            Assert.That(() => File.Move(other, path, overwrite: true), Throws.InstanceOf<IOException>().Or.InstanceOf<UnauthorizedAccessException>());
        }
        Assert.That(File.ReadAllText(other), Is.EqualTo("different snapshot"));
    }

    [TestCase(true)]
    [TestCase(false)]
    public async Task A_handoff_retains_the_original_registration_until_its_matching_receipt_commits(bool verified)
    {
        var set = DecoySet.Mint(_ => true).With(new(DecoyKind.Variables, "user environment", DateTimeOffset.UtcNow));
        var original = new AdminHeldDecoys(set, [], verified);
        var folder = Directory.CreateDirectory(Path.Combine(directory, "decoys"));
        var path = Path.Combine(folder.FullName, Sid + ".json");
        File.WriteAllText(path, original.ToJson());

        string receipt;
        await using (var first = new DecoyHold(directory, new Freezer(directory, NullLogger.Instance), NullLogger.Instance))
        {
            receipt = first.PrepareRelease(Sid).Receipt!;
            // The caller can disconnect or find its local manifest occupied without consuming the record.
            Assert.That(first.Status(Sid).NeedsVerification, Is.EqualTo(!verified));
            Assert.That(File.ReadAllText(path), Is.EqualTo(original.ToJson()));
        }
        await using var restarted = new DecoyHold(directory, new Freezer(directory, NullLogger.Instance), NullLogger.Instance);
        Assert.That(restarted.PrepareRelease(Sid).Receipt, Is.EqualTo(receipt));
        Assert.That(await restarted.CommitReleaseAsync(Sid, new string('0', 64)), Is.False);
        using (File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            Assert.That(async () => await restarted.CommitReleaseAsync(Sid, receipt), Throws.InstanceOf<IOException>());
        Assert.That(restarted.Status(Sid).Held, Is.EqualTo(verified));
        Assert.That(restarted.Status(Sid).NeedsVerification, Is.EqualTo(!verified));
        Assert.That(await restarted.CommitReleaseAsync(Sid, receipt), Is.True);
        Assert.That(File.Exists(path), Is.False);
        Assert.That(await restarted.CommitReleaseAsync(Sid, receipt), Is.True);
    }
}
