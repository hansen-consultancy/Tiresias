namespace Tiresias.Audit;

/// <summary>
/// Follows another process's audit log through snapshots of it (the broker service's journal):
/// each snapshot gives the records written since the last one. The first snapshot, and one that
/// no longer extends the last (rewritten, replaced, or a chain that doesn't verify), only sets the
/// starting point, so nothing older is reported as new.
/// </summary>
public sealed class AuditTail
{
    int count = -1;
    string? last;

    public IReadOnlyList<(AuditRecord Record, DateTimeOffset At)> Next(IReadOnlyList<string> snapshot)
    {
        var extends = count >= 0 && snapshot.Count >= count
            && (count == 0 || AuditLog.Hash(snapshot[count - 1]) == last)
            && AuditLog.Verify(snapshot) is null;
        var from = extends ? count : snapshot.Count;
        count = snapshot.Count;
        last = count > 0 ? AuditLog.Hash(snapshot[^1]) : null;
        var found = new List<(AuditRecord, DateTimeOffset)>();
        for (var i = from; i < snapshot.Count; i++)
            if (AuditLog.Parse(snapshot[i]) is { } parsed)
                found.Add(parsed);
        return found;
    }
}
