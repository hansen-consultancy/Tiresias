using Tiresias.Audit;

namespace Tiresias.Tests;

public class AuditLogTests
{
    string path = "";

    [SetUp]
    public void SetUp() => path = Path.Combine(Path.GetTempPath(), $"tir-audit-{Guid.NewGuid():N}.jsonl");

    [TearDown]
    public void TearDown() => File.Delete(path);

    void Write(int count)
    {
        var log = new AuditLog(path, new ManualTime(new(2026, 11, 17, 9, 0, 0, TimeSpan.Zero)));
        for (var i = 0; i < count; i++)
            log.Append(new(AuditKind.Allow, "L1", "claude:test", "llm", "read", "GET", $"/v1/models/{i}", 200));
    }

    [Test]
    public void A_valid_chain_verifies()
    {
        Write(4);
        Assert.That(AuditLog.Verify(path), Is.Null);
    }

    [Test]
    public void The_first_line_chains_from_genesis()
    {
        Write(1);
        Assert.That(File.ReadAllText(path), Does.StartWith($"{{\"prevHash\":\"{AuditLog.Genesis}\""));
    }

    [Test]
    public async Task A_complete_snapshot_round_trips_and_an_interrupted_snapshot_is_unavailable()
    {
        Write(2);
        using var log = new AuditLog(path, TimeProvider.System);
        using var frame = new MemoryStream();
        await AuditSnapshot.WriteAsync(log, frame, CancellationToken.None);
        frame.Position = 0;
        var lines = await AuditSnapshot.ReadAsync(frame, CancellationToken.None);
        Assert.That(lines, Is.EqualTo(File.ReadAllLines(path)));
        Assert.That(AuditLog.Verify(lines), Is.Null);

        frame.SetLength(frame.Length - 1);
        frame.Position = 0;
        Assert.ThrowsAsync<EndOfStreamException>(async () => await AuditSnapshot.ReadAsync(frame, CancellationToken.None));
    }

    [Test]
    public void A_snapshot_keeps_its_record_boundary_while_the_service_continues_writing()
    {
        Write(1);
        using var log = new AuditLog(path, TimeProvider.System);
        var (file, length) = log.OpenSnapshot();
        using (file)
        {
            log.Append(new(AuditKind.Deny));
            Assert.That(file.Length, Is.GreaterThan(length));
            Assert.That(AuditLog.Verify(path), Is.Null);
        }
    }

    [Test]
    public void Reopening_continues_the_chain()
    {
        Write(2);
        Write(2);
        Assert.That(AuditLog.Verify(path), Is.Null);
    }

    [Test]
    public void An_edited_line_breaks_the_chain_after_it()
    {
        Write(4);
        var lines = File.ReadAllLines(path);
        lines[1] = lines[1].Replace("\"status\":200", "\"status\":403", StringComparison.Ordinal);
        File.WriteAllLines(path, lines);
        Assert.That(AuditLog.Verify(path), Is.EqualTo(3));
    }

    [Test]
    public void A_deleted_line_is_detected()
    {
        Write(4);
        var lines = File.ReadAllLines(path).ToList();
        lines.RemoveAt(1);
        File.WriteAllLines(path, lines);
        Assert.That(AuditLog.Verify(path), Is.EqualTo(2));
    }

    [Test]
    public void Reordered_lines_are_detected()
    {
        Write(4);
        var lines = File.ReadAllLines(path);
        (lines[1], lines[2]) = (lines[2], lines[1]);
        File.WriteAllLines(path, lines);
        Assert.That(AuditLog.Verify(path), Is.EqualTo(2));
    }

    [Test]
    public void A_token_reference_is_a_short_hash_prefix() =>
        Assert.That(AuditLog.TokenRef(new byte[32]), Is.EqualTo("00000000"));
}
