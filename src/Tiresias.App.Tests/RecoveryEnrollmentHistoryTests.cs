using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
using NSec.Cryptography;
using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;
using Tiresias.Agent;

namespace Tiresias.App.Tests;

public class RecoveryEnrollmentHistoryTests
{
    const string Owner = "S-1-5-21-1-2-3-1001";
    const string Admin = "S-1-5-21-1-2-3-1002";

    [Test]
    public void The_desktop_account_must_match_even_when_another_administrator_confirms()
    {
        Assert.DoesNotThrow(() => RecoveryEnrollmentAuthority.RequireDesktop(Owner, Owner));
        Assert.Throws<UnauthorizedAccessException>(() => RecoveryEnrollmentAuthority.RequireDesktop(Admin, Owner));
        Assert.Throws<UnauthorizedAccessException>(() => RecoveryEnrollmentAuthority.RequireDesktop("S-1-5-18", "S-1-5-18"));
    }

    [TestCase("S-1-12-1-100-200-300-400", true)]
    [TestCase("S-1-5-21-1-2-3-4294967295", true)]
    [TestCase("S-1-5-21-1-2-3-4294967296", false)]
    [TestCase("S-1-5-21-1-2-3-04", false)]
    [TestCase("S-1-5-21-1-2-3-4\n", false)]
    [TestCase("S-1-5-32-544", false)]
    public void Only_canonical_local_domain_and_Entra_account_SIDs_are_accepted(string sid, bool valid) =>
        Assert.That(RecoveryRecipient.UserSid(sid), Is.EqualTo(valid));

    [Test]
    public void An_ordinary_token_cannot_run_the_elevated_helper()
    {
        using var account = WindowsIdentity.GetCurrent();
        if (new WindowsPrincipal(account).IsInRole(WindowsBuiltInRole.Administrator))
            Assert.Ignore("Requires a non-elevated process.");
        Assert.Throws<UnauthorizedAccessException>(() => RecoveryEnrollmentAuthority.ApplyElevated(Owner, "new", NewKey()));
    }

    [Test]
    public void Ordinary_accounts_have_only_read_access_and_cannot_own_the_store()
    {
        var acl = RecoveryEnrollmentHistory.Security(Owner);
        Assert.DoesNotThrow(() => RecoveryEnrollmentHistory.RequireProtected(acl, Owner));
        var owner = new SecurityIdentifier(Owner);
        var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<RegistryAccessRule>();
        Assert.That(rules.Single(r => r.IdentityReference.Equals(owner)).RegistryRights, Is.EqualTo(RegistryRights.ReadKey));
        Assert.That(rules.Select(r => r.IdentityReference.Value), Is.EquivalentTo(new[] { Owner, "S-1-5-18", "S-1-5-32-544" }));
        Assert.Throws<UnauthorizedAccessException>(() => RecoveryEnrollmentHistory.RequireProtected(acl, Admin));
        acl.AddAccessRule(new RegistryAccessRule(owner, RegistryRights.SetValue, AccessControlType.Allow));
        Assert.Throws<UnauthorizedAccessException>(() => RecoveryEnrollmentHistory.RequireProtected(acl, Owner));
        acl = RecoveryEnrollmentHistory.Security(Owner);
        acl.SetOwner(owner);
        Assert.Throws<UnauthorizedAccessException>(() => RecoveryEnrollmentHistory.RequireProtected(acl, Owner));
    }

    [Test]
    public void Windows_preserves_the_protected_registry_descriptor()
    {
        using var account = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(account).IsInRole(WindowsBuiltInRole.Administrator))
            Assert.Ignore("Assigning Administrators as the owner requires an already elevated runner.");
        WithIsolatedKey(state =>
        {
            using var key = state.CreateSubKey("protected", RegistryKeyPermissionCheck.ReadWriteSubTree,
                RegistryOptions.Volatile, RecoveryEnrollmentHistory.Security(Owner));
            var acl = key.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            Assert.DoesNotThrow(() => RecoveryEnrollmentHistory.RequireProtected(acl, Owner));
            Assert.Throws<UnauthorizedAccessException>(() => RecoveryEnrollmentHistory.RequireProtected(acl, Admin));
        });
    }

    [Test]
    public void Each_committed_enrollment_appears_once_in_allowed_activity()
    {
        WithIsolatedKey(state =>
        {
            using var pending = state.CreateSubKey("pending-" + Guid.NewGuid().ToString("N"), true, RegistryOptions.Volatile);
            Append(state, null, NewKey());
            var first = Latest(state)!;
            Append(state, first.Binding.Revision, NewKey());
            var times = RecoveryEnrollmentHistory.ApprovalTimes(state, Owner, protectedStore: false);
            var history = ActivityHistory.From([], [], BrokerServiceState.NotInstalled, null, times);
            var rows = ActivityQuery.Filter(history.Entries, new("Recovery key enrollment", ActivityOutcome.Allowed), DateTimeOffset.Now);
            Assert.That(rows.Select(r => r.Time), Is.EquivalentTo(new[] { first.At, Latest(state)!.At }));
            Assert.That(rows.Select(r => r.Reason), Is.All.EqualTo("The administrator approved recovery key enrollment."));
        });
    }

    [Test]
    public void Initial_enrollment_and_rotation_record_each_authorized_revision()
    {
        WithIsolatedKey(state =>
        {
            Assert.That(Latest(state), Is.Null);
            string first = NewKey(), second = NewKey();
            Append(state, null, first);
            var initial = Latest(state)!;
            Assert.That(initial.Binding.PublicKey, Is.EqualTo(first));
            Assert.That(initial.Binding.Revision, Is.Not.EqualTo(Guid.Empty));
            Assert.That(initial.PreviousRevision, Is.Null);
            Assert.That(initial.OwnerSid, Is.EqualTo(Owner));
            Assert.That(initial.AuthorizedBy, Is.EqualTo(Admin));
            Assert.That(initial.At, Is.Not.EqualTo(default(DateTimeOffset)));
            Append(state, initial.Binding.Revision, second);
            var rotated = Latest(state)!;
            Assert.That(rotated.Binding.PublicKey, Is.EqualTo(second));
            Assert.That(rotated.Binding.Revision, Is.Not.EqualTo(initial.Binding.Revision));
            Assert.That(rotated.PreviousRevision, Is.EqualTo(initial.Binding.Revision));
            Assert.That(state.GetSubKeyNames(), Is.EquivalentTo(new[] { "1", "2" }));
            Assert.Throws<InvalidOperationException>(() => Append(state, initial.Binding.Revision, first));
            Assert.That(Latest(state), Is.EqualTo(rotated));
        });
    }

    [Test]
    public void Concurrent_changes_from_the_same_revision_commit_only_one_audit_entry()
    {
        WithIsolatedKey(state =>
        {
            Append(state, null, NewKey());
            var approvedFrom = Latest(state)!.Binding.Revision;
            using var ready = new Barrier(2);
            var candidates = new[] { NewKey(), NewKey() };
            var attempts = candidates.Select(candidate => Task.Run(() =>
            {
                ready.SignalAndWait(TimeSpan.FromSeconds(10));
                try
                {
                    Append(state, approvedFrom, candidate);
                    return true;
                }
                catch (InvalidOperationException) { return false; }
            })).ToArray();
            var outcomes = Task.WhenAll(attempts).GetAwaiter().GetResult();
            Assert.That(outcomes.Count(ok => ok), Is.EqualTo(1));
            Assert.That(Latest(state)!.Binding.PublicKey, Is.EqualTo(candidates[Array.IndexOf(outcomes, true)]));
            Assert.That(state.GetSubKeyNames(), Is.EquivalentTo(new[] { "1", "2" }));
        });
    }

    [TestCase("1", "")]
    [TestCase("1", "{}")]
    [TestCase("1", "{")]
    [TestCase("2", "{}")]
    [TestCase("unexpected", "")]
    public void An_invalid_committed_entry_cannot_be_replaced_as_an_empty_enrollment(string name, string data)
    {
        WithIsolatedKey(state =>
        {
            using var key = state.CreateSubKey(name, writable: true, RegistryOptions.Volatile);
            key.SetValue("change", data);
            Assert.Throws<InvalidOperationException>(() => Latest(state));
            Assert.Throws<InvalidOperationException>(() => Append(state, null, NewKey()));
            Assert.That(state.GetSubKeyNames(), Is.EqualTo(new[] { name }));
        });
    }

    [Test]
    public void An_interrupted_staging_entry_never_becomes_the_recipient()
    {
        WithIsolatedKey(state =>
        {
            using var staged = state.CreateSubKey("pending-" + Guid.NewGuid().ToString("N"), writable: true, RegistryOptions.Volatile);
            Assert.That(Latest(state), Is.Null);
            Append(state, null, NewKey());
            Assert.That(Latest(state)!.Number, Is.EqualTo(1));
        });
    }

    [Test]
    public void An_unused_replacement_rechecks_after_confirmation_before_publishing()
    {
        WithIsolatedKey(state =>
        {
            Append(state, null, NewKey());
            var previous = Latest(state)!;
            Assert.Throws<InvalidOperationException>(() =>
                RecoveryEnrollmentHistory.Append(state, Owner, Admin, previous.Binding.Revision, NewKey(), protectedStore: false,
                    beforePublish: () =>
                    {
                        Assert.That(state.GetSubKeyNames().Any(n => n.StartsWith("pending-", StringComparison.Ordinal)), Is.True);
                        throw new InvalidOperationException("The enrollment is now in use.");
                    }));
            Assert.That(Latest(state), Is.EqualTo(previous));
            Assert.That(state.GetSubKeyNames(), Is.EqualTo(new[] { "1" }));
        });
    }

    [Test]
    public void Unusable_keys_cannot_be_enrolled()
    {
        Assert.Throws<InvalidOperationException>(() => RecoveryRecipient.ValidateKey("invalid"));
        Assert.Throws<InvalidOperationException>(() => RecoveryRecipient.ValidateKey(Convert.ToBase64String(new byte[32])));
        Assert.DoesNotThrow(() => RecoveryRecipient.ValidateKey(NewKey()));
    }

    [TestCase("0100000000000000000000000000000000000000000000000000000000000000")]
    [TestCase("E0EB7A7C3B41B8AE1656E3FAF19FC46ADA098DEB9C32B1FD866205165F49B800")]
    [TestCase("5F9C95BCA3508C24B1D0B1559C83EF5B04445CC4581C8E86D8224EDDD09F1157")]
    [TestCase("ECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F")]
    [TestCase("EDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F")]
    [TestCase("0900000000000000000000000000000000000000000000000000000000000080")]
    public void Small_order_or_noncanonical_encodings_are_rejected(string hex)
    {
        Assert.Throws<InvalidOperationException>(() => RecoveryRecipient.ValidateKey(Convert.ToBase64String(Convert.FromHexString(hex))));
    }

    static string NewKey()
    {
        using var key = Key.Create(KeyAgreementAlgorithm.X25519);
        return Convert.ToBase64String(key.PublicKey.Export(KeyBlobFormat.RawPublicKey));
    }

    static void Append(RegistryKey state, Guid? expected, string key) =>
        RecoveryEnrollmentHistory.Append(state, Owner, Admin, expected, key, protectedStore: false);

    static RecoveryChange? Latest(RegistryKey state) => RecoveryEnrollmentHistory.Latest(state, Owner, protectedStore: false);

    static void WithIsolatedKey(Action<RegistryKey> test)
    {
        using var user = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
        var path = @"Software\Tiresias-Tests-" + Guid.NewGuid().ToString("N");
        try
        {
            using var state = user.CreateSubKey(path, writable: true, RegistryOptions.Volatile);
            test(state);
        }
        finally { user.DeleteSubKeyTree(path, throwOnMissingSubKey: false); }
    }
}
