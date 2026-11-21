using Tiresias.AdminTier;
using Tiresias.Decoys;
using Tiresias.Protocol;

namespace Tiresias.Tests;

public class AdminAuditTests
{
    const string Alice = "S-1-5-21-1000-1000-1000-1001";
    const string Bob = "S-1-5-21-1000-1000-1000-1002";
    const string Decoy = @"C:\Users\alice\.aws\credentials";

    static string Event(string objectName = Decoy, string mask = "0x1", string pid = "0x1a2c", string image = @"C:\Tools\reader.exe",
        string id = "4663", string provider = "Microsoft-Windows-Security-Auditing", string record = "81234") => $"""
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="{provider}" />
            <EventID>{id}</EventID>
            <TimeCreated SystemTime="2026-11-21T10:15:30.1234567Z" />
            <EventRecordID>{record}</EventRecordID>
            <Channel>Security</Channel>
          </System>
          <EventData>
            <Data Name="SubjectUserSid">{Alice}</Data>
            <Data Name="ObjectType">File</Data>
            <Data Name="ObjectName">{objectName}</Data>
            <Data Name="AccessList">%%4416</Data>
            <Data Name="AccessMask">{mask}</Data>
            <Data Name="ProcessId">{pid}</Data>
            <Data Name="ProcessName">{image}</Data>
          </EventData>
        </Event>
        """;

    static readonly IReadOnlyDictionary<string, string> Held = new Dictionary<string, string>
    {
        [AdminAudit.Normal(Decoy)] = Alice,
        [AdminAudit.Normal(@"C:\Users\bob\.ssh\id_ed25519")] = Bob,
    };

    [Test]
    public void An_object_access_reads_as_its_file_mask_and_process()
    {
        var access = AdminAudit.Parse(Event())!;

        Assert.That(access.RecordId, Is.EqualTo(81234));
        Assert.That(access.At, Is.EqualTo(new DateTimeOffset(2026, 11, 21, 10, 15, 30, TimeSpan.Zero).AddTicks(1234567)));
        Assert.That(access.ObjectName, Is.EqualTo(Decoy));
        Assert.That(access.AccessMask, Is.EqualTo(0x1u));
        Assert.That(access.ProcessId, Is.EqualTo(0x1a2c));
        Assert.That(access.ProcessName, Is.EqualTo(@"C:\Tools\reader.exe"));
    }

    [TestCase("not xml")]
    [TestCase("<Event/>")]
    public void Anything_but_an_event_is_nothing(string xml) => Assert.That(AdminAudit.Parse(xml), Is.Null);

    [Test]
    public void Another_event_or_provider_is_nothing()
    {
        Assert.That(AdminAudit.Parse(Event(id: "4656")), Is.Null);
        Assert.That(AdminAudit.Parse(Event(provider: "Someone-Else")), Is.Null, "only Windows writes the Security log, but the check is cheap");
    }

    [TestCase("1")]
    [TestCase("0xzz")]
    [TestCase("")]
    public void A_mask_or_id_that_isnt_hex_is_nothing(string value)
    {
        Assert.That(AdminAudit.Parse(Event(mask: value)), Is.Null);
        Assert.That(AdminAudit.Parse(Event(pid: value)), Is.Null);
    }

    [Test]
    public void A_read_of_a_held_file_is_its_users()
    {
        var (sid, hit) = AdminAudit.Read(AdminAudit.Parse(Event())!, Held)!.Value;

        Assert.That(sid, Is.EqualTo(Alice));
        Assert.That(hit.Use, Is.EqualTo(DecoyUse.Read));
        Assert.That(hit.Endpoint, Is.EqualTo(Decoy));
        Assert.That(hit.ProcessId, Is.EqualTo(0x1a2c));
        Assert.That(hit.Program, Is.EqualTo(@"C:\Tools\reader.exe"));
    }

    [TestCase(@"\??\C:\Users\alice\.aws\credentials")]
    [TestCase(@"c:\users\ALICE\.aws\CREDENTIALS")]
    public void The_file_is_found_however_the_event_writes_it(string objectName) =>
        Assert.That(AdminAudit.Read(AdminAudit.Parse(Event(objectName))!, Held)?.UserSid, Is.EqualTo(Alice));

    [Test]
    public void An_access_without_read_data_or_of_another_file_is_no_read()
    {
        Assert.That(AdminAudit.Read(AdminAudit.Parse(Event(mask: "0x80"))!, Held), Is.Null, "read attributes only");
        Assert.That(AdminAudit.Read(AdminAudit.Parse(Event(@"C:\Users\alice\notes.txt"))!, Held), Is.Null);
    }

    [TestCase("-")]
    [TestCase("")]
    public void An_unknown_image_is_no_program(string image) =>
        Assert.That(AdminAudit.Read(AdminAudit.Parse(Event(image: image))!, Held)!.Value.Hit.Program, Is.Null);

    [Test]
    public void Process_zero_is_no_process() =>
        Assert.That(AdminAudit.Read(AdminAudit.Parse(Event(pid: "0x0"))!, Held)!.Value.Hit.ProcessId, Is.Null);

    [Test]
    public void The_query_reads_on_from_the_last_record_handled() =>
        Assert.That(AdminAudit.Query(81234), Is.EqualTo("*[System[(EventID=4663) and (EventRecordID>81234)]]"));

    [Test]
    public void A_regular_file_of_the_users_own_may_carry_a_rule() =>
        Assert.That(AdminAudit.RuleRefusal(FileAttributes.Archive, 1, Alice, Alice.ToLowerInvariant()), Is.Null);

    [TestCase(FileAttributes.ReparsePoint, 1u, Alice, "is a link")]
    [TestCase(FileAttributes.Directory, 1u, Alice, "is a folder")]
    [TestCase(FileAttributes.Normal, 2u, Alice, "has 2 hard links")]
    [TestCase(FileAttributes.Normal, 1u, Bob, "isn't owned by the user whose decoy it is")]
    [TestCase(FileAttributes.Normal, 1u, null, "isn't owned by the user whose decoy it is")]
    public void Anything_else_may_not(FileAttributes attributes, uint links, string? owner, string why) =>
        Assert.That(AdminAudit.RuleRefusal(attributes, links, owner, Alice), Is.EqualTo(why));

    [Test]
    public void Parents_only_for_the_process_that_read()
    {
        var read = new DateTimeOffset(2026, 11, 21, 10, 15, 30, TimeSpan.Zero);
        Assert.That(AdminAudit.SameProcess(read.UtcDateTime.AddMinutes(-5), read), Is.True);
        Assert.That(AdminAudit.SameProcess(read.UtcDateTime.AddMinutes(5), read), Is.False, "an id reused since");
    }

    [Test]
    public void The_users_own_Tiresias_is_routine_and_nothing_else_in_its_folder()
    {
        var folders = AdminAudit.Routine(@"C:\Windows", [@"C:\Program Files"], @"C:\ProgramData", @"C:\Users\alice");

        Assert.That(DecoyReads.RoutineOpener(@"C:\Users\alice\AppData\Local\Tiresias\current\Tiresias.exe", folders), Is.EqualTo("Tiresias"));
        Assert.That(DecoyReads.RoutineOpener(@"C:\Users\alice\AppData\Local\Tiresias\current\other.exe", folders), Is.Null);
        Assert.That(DecoyReads.RoutineOpener(@"C:\Users\bob\AppData\Local\Tiresias\current\Tiresias.exe", folders), Is.Null, "another user's");
        Assert.That(DecoyReads.RoutineOpener(@"C:\Windows\explorer.exe", folders), Is.EqualTo("File Explorer"));
    }

    [Test]
    public void A_user_without_a_profile_has_no_Tiresias_folder() =>
        Assert.That(AdminAudit.Routine(@"C:\Windows", [], @"C:\ProgramData", null).Tiresias, Is.Null);

    [Test]
    public void Success_auditing_is_turned_on_only_when_off_and_off_only_by_who_turned_it_on()
    {
        var (turnOn, on) = AdminAuditState.Initial.Enable(successOn: false);
        Assert.That(turnOn, Is.True);
        Assert.That(on.Enable(successOn: true), Is.EqualTo((false, on)), "a second set changes nothing");
        Assert.That(on.Release(setsLeft: 1).TurnOff, Is.False, "another set is still held");
        var (turnOff, off) = on.Release(setsLeft: 0);
        Assert.That(turnOff, Is.True);
        Assert.That(off.EnabledPolicy, Is.False);

        var (already, kept) = AdminAuditState.Initial.Enable(successOn: true);
        Assert.That(already, Is.False);
        Assert.That(kept.Release(0).TurnOff, Is.False, "it was on before Tiresias: it stays on");
    }

    [Test]
    public void Records_are_handled_only_forward()
    {
        var state = AdminAuditState.Initial.Handled(10).Handled(7);
        Assert.That(state.LastRecordId, Is.EqualTo(10));
    }

    [Test]
    public void The_state_survives_a_restart()
    {
        var state = AdminAuditState.Initial.Enable(false).State.Handled(81234);
        Assert.That(AdminAuditState.Parse(state.ToJson()), Is.EqualTo(state));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("{")]
    [TestCase("{\"v\":2,\"enabledPolicy\":true,\"lastRecordId\":5}")]
    [TestCase("{\"v\":1,\"enabledPolicy\":true,\"lastRecordId\":-5}")]
    public void A_damaged_or_newer_state_is_the_initial_one(string? json) =>
        Assert.That(AdminAuditState.Parse(json), Is.EqualTo(AdminAuditState.Initial));

    [Test]
    public void A_routine_read_crosses_the_wire_as_the_app_reads_it()
    {
        var hit = new DecoyHit(DecoyUse.Read, Decoy, 4242, @"C:\Windows\explorer.exe", DateTimeOffset.UnixEpoch);
        var (queue, added) = AdminEventQueue.Empty.Add(hit, [], "File Explorer");

        var back = AdminReply.Ok(new AdminEvents([added])).ResultAs<AdminEvents>()!.Events.Single();

        Assert.That(back.Routine, Is.EqualTo("File Explorer"));
        Assert.That(back.Hit, Is.EqualTo(hit));
        Assert.That(AdminEventQueue.Parse(queue.ToJson()).Pending.Single().Routine, Is.EqualTo("File Explorer"), "and a restart");
    }

    [Test]
    public void Auditing_is_in_the_held_sets_status()
    {
        var set = DecoySet.Mint(_ => true).With(new(DecoyKind.Project, @"C:\Users\alice\source\billing-api-old", DateTimeOffset.UnixEpoch));
        Assert.That(new AdminHeldDecoys(set, [Decoy]).Status(listening: true, auditing: true).Auditing, Is.True);
    }
}
