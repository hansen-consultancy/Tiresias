using System.Text;
using Tiresias.Protocol;

namespace Tiresias.Tests;

public class AlertPayloadTests
{
    static string Shape(Type type) => string.Join(", ", type.GetProperties()
        .Where(p => p.Name != "EqualityContract")
        .Select(p => $"{p.PropertyType.Name} {p.Name}"));

    /// <summary>A new field fails here until someone decides it may leave the machine (docs/alerts.md, <i>Tests</i>).</summary>
    [Test]
    public void The_payload_carries_exactly_the_designed_fields()
    {
        Assert.That(Shape(typeof(AlertPayload)), Is.EqualTo(
            "String Id, String Event, AlertSeverity Severity, String Title, String Machine, DateTimeOffset At, Int32 Count, "
            + "String Key, TrustedDetail Detail, String Schema"));
        Assert.That(Shape(typeof(TrustedDetail)), Is.EqualTo(
            "String Program, Nullable`1 ProcessId, IReadOnlyList`1 Parents, String What, String Service, "
            + "IReadOnlyList`1 Names, IReadOnlyList`1 Findings"));
    }

    static readonly AlertPayload Sample = new(
        "01JD2K8Q4X9V7M3N5P6R8S0T2W", "decoy.used", AlertSeverity.Critical, "Decoy credential used", "workstation",
        new DateTimeOffset(2026, 11, 21, 11, 15, 0, TimeSpan.FromHours(1)), 1, "decoy.used:5e1f0c9a2b7d4e86",
        new(Program: "C:\\Users\\alice\\AppData\\Local\\Temp\\x.exe", ProcessId: 4242, What: "the decoy admin token"));

    static readonly string Golden =
        """{"schema":"tiresias.alert/v1","id":"01JD2K8Q4X9V7M3N5P6R8S0T2W","event":"decoy.used","severity":"critical",""" +
        """ "title":"Decoy credential used","machine":"workstation","at":"2026-11-21T10:15:00Z","count":1,""".TrimStart() +
        """ "key":"decoy.used:5e1f0c9a2b7d4e86","detail":{"program":"C:\\Users\\alice\\AppData\\Local\\Temp\\x.exe",""".TrimStart() +
        """ "processId":4242,"what":"the decoy admin token"}}""".TrimStart();

    [Test]
    public void The_golden_document_pins_the_json()
    {
        Assert.That(Encoding.UTF8.GetString(AlertWire.Serialize(Sample)), Is.EqualTo(Golden));
    }

    [Test]
    public void A_public_payload_has_no_detail_at_all()
    {
        var json = Encoding.UTF8.GetString(AlertWire.Serialize(Sample with { Detail = null }));
        Assert.That(json, Does.EndWith("\"key\":\"decoy.used:5e1f0c9a2b7d4e86\"}"));
    }

    [Test]
    public void The_golden_document_reads_back()
    {
        var parsed = AlertWire.Parse(Encoding.UTF8.GetBytes(Golden));
        Assert.That(parsed with { Detail = null }, Is.EqualTo(Sample with { Detail = null }));
        Assert.That(parsed.Detail, Is.EqualTo(Sample.Detail));
    }

    [TestCase("""{"schema":"tiresias.alert/v2","id":"x"}""")]
    [TestCase("""{"id":"x"}""")]
    [TestCase("""{"schema":1}""")]
    [TestCase("""[]""")]
    public void Another_schema_is_refused(string json)
    {
        Assert.Throws<InvalidDataException>(() => AlertWire.Parse(Encoding.UTF8.GetBytes(json)));
    }
}
