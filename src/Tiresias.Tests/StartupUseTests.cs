using System.Text;
using NUnit.Framework;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.Tests;

public class StartupUseTests
{
    static readonly DateTimeOffset Now = new(2026, 11, 19, 10, 0, 0, TimeSpan.Zero);
    const string Chat = @"C:\Users\alice\AppData\Local\Chat\chat.exe";

    static StartupEntry Entry(string where = StartupEntry.RunKey, string item = "Chat", string path = Chat) => new("Chat", where, path, true, item);

    static DoctorCheck[] Run(IEnumerable<StartupEntry> startup, IEnumerable<ProgramRun> runs, IEnumerable<CredentialUse>? uses = null) =>
        [.. Doctor.AttackSurface([], startup, uses ?? [], [], Now, runs)];

    [Test]
    public void A_log_on_program_not_opened_in_90_days_is_turned_off_keeping_the_program()
    {
        var check = Run([Entry()], [new(Chat, Now.AddDays(-120))]).Single();

        Assert.That(check.Name, Is.EqualTo("Chat starts at log-on, unused"));
        Assert.That(check.Detail, Does.Contain("2026-07-22"));
        Assert.That(check.Fix, Is.EqualTo(new DisableStartup("Chat", StartupEntry.RunKey, "Chat")));
        Assert.That(check.Kind, Is.EqualTo(Doctor.IdleStartupKind));
        Assert.That(check.Now, Is.Null);
    }

    [Test]
    public void A_program_whose_last_use_is_unknown_is_never_unused()
    {
        Assert.That(Run([Entry()], []), Is.Empty);
    }

    [Test]
    public void A_program_opened_recently_or_that_used_a_credential_is_in_use()
    {
        Assert.That(Run([Entry()], [new(Chat, Now.AddDays(-120)), new(Chat, Now.AddDays(-5))]), Is.Empty);
        Assert.That(Run([Entry()], [new(Chat, Now.AddDays(-120))], [new(Chat, "github", Now.AddDays(-2))]), Is.Empty);
    }

    [Test]
    public void A_program_with_a_tray_icon_is_used_from_there_so_its_use_is_unknown()
    {
        Assert.That(Run([Entry() with { InTray = true }], [new(Chat, Now.AddDays(-120))]), Is.Empty);
    }

    [Test]
    public void Tiresias_never_suggests_turning_itself_off()
    {
        Assert.That(Run([Entry(item: "Tiresias")], [new(Chat, Now.AddDays(-120))]), Is.Empty);
    }

    [Test]
    public void A_machine_wide_entry_opens_the_startup_settings()
    {
        var fix = new DisableStartup("Chat", StartupEntry.MachineRunKey, "Chat");

        Assert.That(fix.Instruction, Does.EndWith("(needs an administrator)"));
        Assert.That(FindingView.Button(fix)?.Action, Is.EqualTo(FixAction.OpenStartupSettings));
        Assert.That(FindingView.Button(fix with { Where = StartupEntry.StartupFolder })?.Action, Is.EqualTo(FixAction.DisableStartup));
    }

    [TestCase("Chat", true)]
    [TestCase("Chat.lnk", true)]
    [TestCase(@"..\Run\Other", false)]
    [TestCase("", false)]
    public void Only_a_single_value_name_is_turned_off(string item, bool safe) => Assert.That(DisableStartup.IsSafeItem(item), Is.EqualTo(safe));

    [Test]
    public void An_unsafe_item_raises_no_fix()
    {
        Assert.That(Run([Entry(item: @"a\b")], [new(Chat, Now.AddDays(-120))]), Is.Empty);
    }

    [TestCase(new byte[] { 2, 0, 0, 0 }, false)]
    [TestCase(new byte[] { 6, 0, 0, 0 }, false)]
    [TestCase(new byte[] { 3, 0, 0, 0 }, true)]
    [TestCase(new byte[0], false)]
    public void Startup_approved_says_whether_an_entry_is_off(byte[] value, bool off) => Assert.That(Doctor.StartupTurnedOff(value), Is.EqualTo(off));

    static string Rot13(string text) => new([.. text.Select(c => c switch
    {
        >= 'a' and <= 'z' => (char)('a' + (c - 'a' + 13) % 26),
        >= 'A' and <= 'Z' => (char)('A' + (c - 'A' + 13) % 26),
        _ => c,
    })]);

    static byte[] Data(DateTimeOffset? lastRun)
    {
        var data = new byte[72];
        BitConverter.GetBytes(4).CopyTo(data, 4);
        BitConverter.GetBytes(lastRun?.ToFileTime() ?? 0).CopyTo(data, 60);
        return data;
    }

    [Test]
    public void UserAssist_names_are_rot13_with_known_folders_resolved()
    {
        var programFiles = new Guid("6D809377-6AF0-444B-8957-A3773F02200E");
        var unknown = Guid.NewGuid();
        var at = new DateTimeOffset(2026, 3, 1, 8, 30, 0, TimeSpan.Zero);
        (string, byte[]?)[] values =
        [
            (Rot13(Chat), Data(at)),
            (Rot13($@"{{{programFiles}}}\Acme\acme.exe"), Data(at)),
            (Rot13($@"{{{unknown}}}\x.exe"), Data(at)),
            (Rot13("Microsoft.Windows.Explorer"), Data(at)),
            (Rot13(@"C:\never\run.exe"), Data(null)),
            (Rot13(@"C:\short\data.exe"), new byte[16]),
            ("UEME_CTLSESSION", Data(at)),
        ];

        var runs = Doctor.UserAssistRuns(values, id => id == programFiles ? @"C:\Program Files" : null).ToArray();

        Assert.That(runs, Is.EqualTo(new ProgramRun[] { new(Chat, at), new(@"C:\Program Files\Acme\acme.exe", at) }));
    }
}
