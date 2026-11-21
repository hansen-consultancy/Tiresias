using Tiresias.AdminTier;
using Tiresias.Decoys;
using Tiresias.Protocol;

namespace Tiresias.Tests;

public class AdminIncidentHistoryTests
{
    static AdminEvent Event(long id) =>
        new(id, new(DecoyUse.ApiKey, "loopback", null, null, DateTimeOffset.UnixEpoch.AddSeconds(id)), []);

    [Test]
    public void A_missing_or_unreadable_service_page_is_distinct_from_empty_history()
    {
        Assert.That(AdminIncidentHistory.Page(AdminReply.Ok(new AdminEvents([], 0, 0)))?.Events, Is.Empty);
        Assert.That(AdminIncidentHistory.Page(AdminReply.Ok(new { events = Array.Empty<AdminEvent>() })), Is.Null);
        Assert.That(AdminIncidentHistory.Page(AdminReply.Ok(new { lastId = 3L, reviewedThrough = 0L, events = new[] { "broken" } })), Is.Null);
        Assert.That(AdminIncidentHistory.Page(AdminReply.Ok(new AdminEvents([Event(2)], 0, 1))), Is.Null);
    }

    [Test]
    public async Task A_review_uses_only_the_incidents_in_the_displayed_snapshot()
    {
        var requested = new List<long>();
        var history = await AdminIncidentHistory.ReadAsync(after =>
        {
            requested.Add(after);
            return Task.FromResult<AdminEvents?>(after switch
            {
                0 => new([Event(1)], 0, 2),
                1 => new([Event(2), Event(3)], 1, 3),
                _ => throw new InvalidOperationException()
            });
        });
        Assert.That(requested, Is.EqualTo(new[] { 0L, 1L }));
        Assert.That(history!.Events.Select(e => e.Id), Is.EqualTo(new[] { 1L, 2L }));
        Assert.That(history.LastId, Is.EqualTo(2));
        Assert.That(history.ReviewedThrough, Is.EqualTo(1));
    }

    [TestCase(true)]
    [TestCase(false)]
    public async Task An_interrupted_or_repeated_page_is_not_a_reviewable_history(bool interrupted)
    {
        var history = await AdminIncidentHistory.ReadAsync(after =>
            Task.FromResult<AdminEvents?>(after > 0 && interrupted ? null : new([Event(1)], 0, 2)));
        Assert.That(history, Is.Null);
    }
}
