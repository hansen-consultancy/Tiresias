using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

public class RavenExpiryTests
{
    static readonly DateTimeOffset Now = new(2026, 11, 19, 10, 0, 0, TimeSpan.Zero);

    static DoctorCheck[] Checks(params DoctorRavenCertificate[] certificates) => [.. Doctor.RavenExpiry(certificates, Now)];

    static DoctorRavenCertificate Expiring(double days, string thumbprint = "ABCDEF0123456789") =>
        new("orders", "orders-app", thumbprint, Now.AddDays(days));

    [Test]
    public void A_certificate_expiring_within_30_days_warns_with_its_replacement()
    {
        var check = Checks(Expiring(29)).Single();

        Assert.That(check.Status, Is.EqualTo(DoctorStatus.Warn));
        Assert.That(check.Name, Is.EqualTo("RavenDB certificate orders-app for orders (ABCDEF01)"));
        Assert.That(check.Detail, Does.StartWith("expires on 2026-12-18"));
        Assert.That(check.Fix, Is.EqualTo(new ReplaceRavenCertificate("orders")));
        Assert.That((check.Now, check.Better), Is.EqualTo(((Position?)null, (Position?)null)));
        Assert.That(check.IsFinding);
        Assert.That(FindingView.Button(check.Fix)?.Action, Is.EqualTo(FixAction.ReplaceRaven));
    }

    [Test]
    public void A_certificate_31_days_out_is_no_line() =>
        Assert.That(Checks(Expiring(31)), Is.Empty);

    [TestCase(0)]
    [TestCase(-3)]
    public void An_expired_certificate_fails(double days) =>
        Assert.That(Checks(Expiring(days)).Single().Status, Is.EqualTo(DoctorStatus.Fail));

    [Test]
    public void A_new_certificate_is_a_new_finding() =>
        Assert.That(Dismissals.KeyOf(Checks(Expiring(10, "1111111122")).Single()), Is.Not.EqualTo(Dismissals.KeyOf(Checks(Expiring(10, "2222222211")).Single())));

    [Test]
    public void A_certificate_set_up_before_recording_is_skipped_without_a_finding()
    {
        var check = Checks(new DoctorRavenCertificate("orders", null, null, null)).Single();

        Assert.That(check.Detail, Does.StartWith("expiry unknown"));
        Assert.That(check.IsFinding, Is.False);
    }
}
