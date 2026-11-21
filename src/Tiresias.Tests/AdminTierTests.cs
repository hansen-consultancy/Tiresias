using System.Text.Json.Nodes;
using Tiresias.AdminTier;
using Tiresias.App.Logic;
using Tiresias.Decoys;
using Tiresias.Protocol;

namespace Tiresias.Tests;

public class AdminCallerPolicyTests
{
    const string Alice = "S-1-5-21-1000-1000-1000-1001";
    const string Bob = "S-1-5-21-1000-1000-1000-1002";

    static readonly AdminCaller User = new(Alice, 1, Alice, Elevated: false, IsService: false);
    static readonly AdminCaller ElevatedUser = User with { Elevated = true };

    static AdminRequest Ask(string op, JsonObject? args = null) => new(AdminWire.ProtocolVersion, op, args);

    [Test]
    public void Status_is_open_to_the_user_signed_in_to_the_callers_session() =>
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.Status), User).Allowed, Is.True);

    [TestCase(0)]
    [TestCase(3)]
    public void Another_protocol_version_is_refused(int version)
    {
        var decision = AdminCallerPolicy.Decide(new AdminRequest(version, AdminOps.Status), User);
        Assert.That(decision.Allowed, Is.False);
        Assert.That(decision.Reason, Does.Contain("protocol version"));
    }

    [TestCase("run")]
    [TestCase("Status")]
    [TestCase("")]
    [TestCase(null)]
    public void An_unknown_op_is_refused_without_repeating_it(string? op)
    {
        var decision = AdminCallerPolicy.Decide(new AdminRequest(AdminWire.ProtocolVersion, op!), User);
        Assert.That(decision.Allowed, Is.False);
        Assert.That(decision.Reason, Is.EqualTo("unknown op"));
    }

    [Test]
    public void Services_are_refused_even_elevated()
    {
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.Status), ElevatedUser with { IsService = true }).Allowed, Is.False);
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.Status), new("S-1-5-18", 0, null, true, true)).Allowed, Is.False);
    }

    [Test]
    public void Session_zero_is_refused() =>
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.Status), User with { SessionId = 0, SessionUserSid = Alice }).Allowed, Is.False);

    [Test]
    public void A_caller_in_another_users_session_is_refused()
    {
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.Status), User with { SessionUserSid = Bob }).Allowed, Is.False);
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.Status), User with { SessionUserSid = null }).Allowed, Is.False);
    }

    [Test]
    public void The_session_user_compares_without_case() =>
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.Status), User with { SessionUserSid = Alice.ToLowerInvariant() }).Allowed, Is.True);

    [TestCase(AdminOps.Thaw)]
    [TestCase(AdminOps.DecoysRelease)]
    [TestCase(AdminOps.DecoysReleaseCommit)]
    [TestCase(AdminOps.DecoysAdopt)]
    [TestCase(AdminOps.EventsReview)]
    [TestCase(AdminOps.BlocksUnblock)]
    [TestCase(AdminOps.Teardown)]
    public void Ops_that_weaken_protection_need_an_elevated_caller(string op)
    {
        Assert.That(AdminCallerPolicy.NeedsElevation(op), Is.True);
        var decision = AdminCallerPolicy.Decide(Ask(op), User);
        Assert.That(decision.Allowed, Is.False);
        Assert.That(decision.Reason, Does.Contain("elevated"));
    }

    [Test]
    public void Only_the_ops_that_weaken_protection_need_elevation() =>
        Assert.That(AdminOps.All.Where(AdminCallerPolicy.NeedsElevation),
            Is.EquivalentTo(new[] { AdminOps.Thaw, AdminOps.DecoysRelease, AdminOps.DecoysReleaseCommit, AdminOps.DecoysAdopt, AdminOps.EventsReview, AdminOps.BlocksUnblock, AdminOps.Teardown }));

    static readonly string[] Built = [AdminOps.Status, AdminOps.EventsWait, AdminOps.EventsHistory, AdminOps.EventsReview,
        AdminOps.BlocksCheck, AdminOps.BlocksList, AdminOps.BlocksUnblock, AdminOps.DecoysAdopt, AdminOps.DecoysStatus, AdminOps.DecoysRelease, AdminOps.DecoysReleaseCommit];

    [Test]
    public void Ops_not_built_yet_are_refused_even_when_the_caller_qualifies()
    {
        foreach (var op in AdminOps.All.Except(Built))
        {
            var decision = AdminCallerPolicy.Decide(Ask(op), ElevatedUser);
            Assert.That(decision.Allowed, Is.False, op);
            Assert.That(decision.Reason, Does.Contain("isn't available"), op);
        }
    }

    [Test]
    public void An_extra_argument_is_refused()
    {
        var decision = AdminCallerPolicy.Decide(Ask(AdminOps.Status, new JsonObject { ["path"] = "C:\\Windows" }), User);
        Assert.That(decision.Allowed, Is.False);
        Assert.That(decision.Reason, Is.EqualTo("unexpected argument"), "the argument's name and value are not repeated");
    }

    [Test]
    public void Empty_arguments_are_no_arguments() =>
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.Status, []), User).Allowed, Is.True);

    [Test]
    public void An_allowed_caller_acts_for_itself()
    {
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.DecoysStatus), User).ActingFor, Is.EqualTo(Alice));
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.DecoysRelease), ElevatedUser).ActingFor, Is.EqualTo(Alice));
    }

    [Test]
    public void An_administrator_elevated_over_the_shoulder_acts_for_the_sessions_user()
    {
        var administrator = new AdminCaller(Bob, 1, Alice, Elevated: true, IsService: false);

        var decision = AdminCallerPolicy.Decide(Ask(AdminOps.DecoysRelease), administrator);

        Assert.That(decision.Allowed, Is.True);
        Assert.That(decision.ActingFor, Is.EqualTo(Alice), "the session's user's set, never the administrator's own");
    }

    [Test]
    public void Only_an_elevated_caller_acts_for_someone_else() =>
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.DecoysStatus), new AdminCaller(Bob, 1, Alice, false, false)).Allowed, Is.False);

    [Test]
    public void A_session_user_that_isnt_a_users_sid_is_refused() =>
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.Status), ElevatedUser with { SessionUserSid = "S-1-5-18" }).Allowed, Is.False);

    static DecoySet Placed() => DecoySet.Mint(_ => true)
        .With(new(DecoyKind.PasswordsFile, @"C:\Users\alice\Documents\passwords.txt", new(2026, 11, 21, 9, 0, 0, TimeSpan.Zero)))
        .With(new(DecoyKind.Variables, "user environment", new(2026, 11, 21, 9, 0, 0, TimeSpan.Zero)));

    [Test]
    public void The_agents_adopt_arguments_pass_and_read_back_as_the_set()
    {
        var set = Placed();
        var args = AdminArgs.Adopt(set, Alice);

        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.DecoysAdopt, args), User).Allowed, Is.False);
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.DecoysAdopt, args), ElevatedUser).Allowed, Is.True);
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.DecoysAdopt, args), ElevatedUser with { UserSid = Bob }).Allowed, Is.True);
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.DecoysAdopt, AdminArgs.Adopt(set, Bob)), ElevatedUser).Allowed, Is.False);
        var back = AdminWire.FromNode<DecoySet>(args["set"])!;
        Assert.That((back.HttpPort, back.SqlPort, back.Values), Is.EqualTo((set.HttpPort, set.SqlPort, set.Values)));
        Assert.That(back.Placed, Is.EqualTo(set.Placed));
        Assert.That(AdminWire.FromNode<string[]>(args["files"]), Is.EqualTo(new[] { @"C:\Users\alice\Documents\passwords.txt" }));
    }

    static readonly Func<JsonObject, JsonObject>[] BadAdopts =
    [
        a => { a.Remove("files"); return a; },
        a => { a["extra"] = 1; return a; },
        a => { a["set"]!["httpPort"] = 80; return a; },
        a => { a["set"]!["sqlPort"] = 70000; return a; },
        a => { a["set"]!["sqlPort"] = a["set"]!["httpPort"]!.GetValue<int>(); return a; },
        a => { a["set"]!["httpPort"] = "31000"; return a; },
        a => { a["set"]!["connectionString"] = "x"; return a; },
        a => { a["set"]!["values"]!["apiKey"] = "line\nbreak"; return a; },
        a => { a["set"]!["values"]!["apiKey"] = new string('k', AdminArgs.MaxValue + 1); return a; },
        a => { a["set"]!["placed"] = new JsonArray(); return a; },
        a => { a["set"]!["placed"]![0]!["kind"] = "script"; return a; },
        a => { a["set"]!["placed"]![0]!["placed"] = "yesterday"; return a; },
        a => { a["set"]!["placed"]![0]!["where"] = new string('x', AdminArgs.MaxPath + 1); return a; },
        a => { a["files"] = new JsonArray("passwords.txt"); return a; },
        a => { a["files"] = new JsonArray(@"\\203.0.113.5\share\x.txt"); return a; },
        a => { a["files"] = new JsonArray(@"C:\Users\alice\..\bob\x.txt"); return a; },
        a => { a["files"] = new JsonArray([.. Enumerable.Range(0, AdminArgs.MaxFiles + 1).Select(i => (JsonNode)$@"C:\x{i}.txt")]); return a; },
    ];

    [Test]
    public void Adopt_arguments_out_of_shape_or_range_are_refused_without_their_values()
    {
        for (var i = 0; i < BadAdopts.Length; i++)
        {
            var decision = AdminCallerPolicy.Decide(Ask(AdminOps.DecoysAdopt, BadAdopts[i](AdminArgs.Adopt(Placed(), Alice))), ElevatedUser);
            Assert.That(decision.Allowed, Is.False, $"case {i}");
            Assert.That(decision.Reason, Does.Not.Contain("C:\\").And.Not.Contain("31000"), $"case {i}");
        }
    }

    [TestCase("0", 30, true)]
    [TestCase("17", 0, true)]
    [TestCase("-1", 30, false)]
    [TestCase("[]", 30, false)]
    [TestCase("1.5", 30, false)]
    [TestCase("0", 31, false)]
    [TestCase("0", -1, false)]
    public void Events_wait_takes_a_read_position_and_a_bounded_wait(string after, int wait, bool allowed) =>
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.EventsWait, new JsonObject { ["after"] = JsonNode.Parse(after), ["wait"] = wait }), User).Allowed,
            Is.EqualTo(allowed));

    [Test]
    public void Read_progress_and_protection_changes_are_separate_operations()
    {
        var after = new JsonObject { ["after"] = 1L };
        var review = new JsonObject { ["through"] = 1L };
        var program = new JsonObject { ["program"] = @"C:\Tools\a.exe" };
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.EventsHistory, after), User).Allowed, Is.True);
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.EventsWait, new() { ["ack"] = new JsonArray(), ["wait"] = 0 }), User).Allowed, Is.False);
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.EventsReview, review), User).Allowed, Is.False);
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.EventsReview, review), ElevatedUser).ActingFor, Is.EqualTo(Alice));
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.BlocksUnblock, program), User).Allowed, Is.False);
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.BlocksUnblock, program), ElevatedUser).ActingFor, Is.EqualTo(Alice));
        Assert.That(AdminCallerPolicy.Decide(Ask(AdminOps.BlocksCheck, new() { ["program"] = null, ["sha256"] = null }), User).Allowed, Is.True);
    }

    [TestCase("S-1-5-21-1000-1000-1000-1001", true)]
    [TestCase("S-1-12-1-1000-1000-1000-1001", true)]
    [TestCase("S-1-5-18", false)]
    [TestCase(@"S-1-5-21-1-2-3-4\..\x", false)]
    [TestCase("", false)]
    public void Only_a_users_sid_names_a_file(string sid, bool user) => Assert.That(AdminArgs.UserSid(sid), Is.EqualTo(user));

    [Test]
    public void Only_known_ops_reach_the_log()
    {
        Assert.That(AdminCallerPolicy.KnownOp(AdminOps.Freeze), Is.EqualTo(AdminOps.Freeze));
        Assert.That(AdminCallerPolicy.KnownOp("rm -rf"), Is.Null);
        Assert.That(AdminCallerPolicy.KnownOp(null), Is.Null);
    }
}

public class AdminInstallPlanTests
{
    [Test]
    public void A_fresh_install_creates_the_service()
    {
        Assert.That(AdminInstallPlan.Install(new(Exists: false, Running: false)), Is.EqualTo(new[]
        {
            AdminInstallStep.CopyFiles, AdminInstallStep.SecureStateFolder, AdminInstallStep.CreateService, AdminInstallStep.StartService,
        }));
    }

    [Test]
    public void An_update_stops_the_running_service_before_replacing_its_files()
    {
        Assert.That(AdminInstallPlan.Install(new(Exists: true, Running: true)), Is.EqualTo(new[]
        {
            AdminInstallStep.StopService, AdminInstallStep.CopyFiles, AdminInstallStep.SecureStateFolder,
            AdminInstallStep.ConfigureService, AdminInstallStep.StartService,
        }));
    }

    [Test]
    public void A_repair_of_a_stopped_service_configures_and_starts_it()
    {
        Assert.That(AdminInstallPlan.Install(new(Exists: true, Running: false)), Is.EqualTo(new[]
        {
            AdminInstallStep.CopyFiles, AdminInstallStep.SecureStateFolder, AdminInstallStep.ConfigureService, AdminInstallStep.StartService,
        }));
    }

    [Test]
    public void Remove_leaves_nothing_whatever_it_finds()
    {
        Assert.That(AdminInstallPlan.Remove(new(Exists: true, Running: true)), Is.EqualTo(new[]
        {
            AdminInstallStep.StopService, AdminInstallStep.HandBackDecoys, AdminInstallStep.DeleteService, AdminInstallStep.DeleteFiles,
            AdminInstallStep.DeleteStateFolder,
        }));
        Assert.That(AdminInstallPlan.Remove(new(Exists: false, Running: false)), Is.EqualTo(new[]
        {
            AdminInstallStep.HandBackDecoys, AdminInstallStep.DeleteFiles, AdminInstallStep.DeleteStateFolder,
        }));
    }

    [TestCase(false, AdminFolders.SystemSid, true)]
    [TestCase(false, AdminFolders.AdministratorsSid, true)]
    [TestCase(false, "S-1-5-21-1000-1000-1000-1001", false)]
    [TestCase(false, null, false)]
    [TestCase(true, AdminFolders.SystemSid, false)]
    public void Only_a_real_folder_owned_by_SYSTEM_or_Administrators_is_trusted(bool reparse, string? owner, bool trusted) =>
        Assert.That(AdminFolders.Trusted(reparse, owner), Is.EqualTo(trusted));
}

public class AdminCopySourceTests
{
    const string Root = @"C:\Users\alice\AppData\Local\TiresiasApp\current\admin";

    [Test]
    public void A_plain_file_in_the_source_folder_is_copied()
    {
        Assert.That(AdminCopySource.Refusal(Root, FileAttributes.Archive, 1, $@"\\?\{Root}\tiresias-admin.exe"), Is.Null);
        Assert.That(AdminCopySource.Refusal(Root + "\\", FileAttributes.Normal, 1, $@"{Root}\sub\x.dll"), Is.Null);
        Assert.That(AdminCopySource.Refusal($@"\\?\{Root}", FileAttributes.Normal, 1, Root.ToUpperInvariant() + @"\x.dll"), Is.Null);
    }

    [Test]
    public void A_link_is_refused() =>
        Assert.That(AdminCopySource.Refusal(Root, FileAttributes.ReparsePoint | FileAttributes.Archive, 1, $@"{Root}\x.dll"), Is.EqualTo("is a link"));

    [TestCase(0u)]
    [TestCase(2u)]
    public void A_file_with_other_hard_links_is_refused(uint links) =>
        Assert.That(AdminCopySource.Refusal(Root, FileAttributes.Normal, links, $@"{Root}\x.dll"), Does.Contain("hard links"));

    [TestCase(@"\\?\C:\Windows\System32\config\SAM")]
    [TestCase(@"C:\Users\alice\AppData\Local\TiresiasApp\current\admin2\x.dll")]
    [TestCase(@"\\?\UNC\host\share\x.dll")]
    public void A_file_resolving_outside_the_source_folder_is_refused(string final) =>
        Assert.That(AdminCopySource.Refusal(Root, FileAttributes.Normal, 1, final), Is.EqualTo("resolves outside the source folder"));

    [Test]
    public void A_folder_is_walked_only_when_it_is_no_link()
    {
        Assert.That(AdminCopySource.FolderRefusal(FileAttributes.Directory), Is.Null);
        Assert.That(AdminCopySource.FolderRefusal(FileAttributes.Directory | FileAttributes.ReparsePoint), Is.EqualTo("is a link"));
        Assert.That(AdminCopySource.Refusal(Root, FileAttributes.Directory, 1, Root + @"\x"), Does.Contain("folder"));
    }
}

public class AdminTierStateTests
{
    static AdminStatusResult Answer(string version) => new(version, AdminWire.ProtocolVersion, new());

    [Test]
    public void State_follows_install_run_answer_and_version()
    {
        Assert.That(new AdminTierFacts(false, false, null, "0.3.0").State, Is.EqualTo(AdminTierState.NotInstalled));
        Assert.That(new AdminTierFacts(true, false, null, "0.3.0").State, Is.EqualTo(AdminTierState.Stopped));
        Assert.That(new AdminTierFacts(true, true, null, "0.3.0").State, Is.EqualTo(AdminTierState.NotAnswering));
        Assert.That(new AdminTierFacts(true, true, Answer("0.2.1"), "0.3.0").State, Is.EqualTo(AdminTierState.Older));
        Assert.That(new AdminTierFacts(true, true, Answer("0.3.0"), "0.3.0").State, Is.EqualTo(AdminTierState.Running));
        Assert.That(new AdminTierFacts(true, true, Answer("0.4.0"), "0.3.0").State, Is.EqualTo(AdminTierState.Running), "a newer service serves an older app");
    }

    [Test]
    public void Features_are_named_or_none()
    {
        Assert.That(new AdminTierFacts(true, true, Answer("1.0.0"), "1.0.0").Features, Is.EqualTo("none yet"));
        var on = new AdminStatusResult("1.0.0", 1, new(DecoysHeld: true, Auditing: true));
        Assert.That(new AdminTierFacts(true, true, on, "1.0.0").Features, Is.EqualTo("decoys held, auditing"));
    }

    [TestCase("0.2.1", "0.2.1", 0)]
    [TestCase("0.2.1", "0.2.0", 1)]
    [TestCase("0.2.1", "0.10.0", -1)]
    [TestCase("0.2.1-preview.3", "0.2.1", -1)]
    [TestCase("0.2.1-preview.10", "0.2.1-preview.9", 1)]
    [TestCase("0.2.1-preview.1", "0.2.1-rc.1", -1)]
    [TestCase("0.2.1-dev", "0.2.1-dev", 0)]
    [TestCase("0.2.1+5f91cdf", "0.2.1", 0)]
    [TestCase("1.2", "1.2.0", 0)]
    [TestCase("0.2.1-preview", "0.2.1-preview.1", -1)]
    public void Versions_order_as_releases_do(string a, string b, int expected)
    {
        Assert.That(Math.Sign(AppVersions.Compare(a, b)), Is.EqualTo(expected));
        Assert.That(Math.Sign(AppVersions.Compare(b, a)), Is.EqualTo(-expected));
    }
}

public class AdminTierCardTests
{
    static AdminTierFacts Tier(bool installed, bool running, string? version, string app = "0.3.0") =>
        new(installed, running, version is null ? null : new(version, AdminWire.ProtocolVersion, new()), app);

    [Test]
    public void Each_state_offers_what_can_be_done_about_it()
    {
        Assert.That(AdminTierCard.Actions(AdminTierState.NotInstalled), Is.EqualTo(new[] { AdminTierAction.SetUp }));
        Assert.That(AdminTierCard.Actions(AdminTierState.Running), Is.EqualTo(new[] { AdminTierAction.Remove }));
        Assert.That(AdminTierCard.Actions(AdminTierState.Older), Is.EqualTo(new[] { AdminTierAction.Update, AdminTierAction.Remove }));
        Assert.That(AdminTierCard.Actions(AdminTierState.Stopped), Is.EqualTo(new[] { AdminTierAction.SetUp, AdminTierAction.Remove }));
        Assert.That(AdminTierCard.Actions(AdminTierState.NotAnswering), Is.EqualTo(new[] { AdminTierAction.SetUp, AdminTierAction.Remove }));
    }

    [Test]
    public void The_state_is_described_with_its_versions()
    {
        Assert.That(AdminTierCard.Describe(Tier(false, false, null)).Key, Is.EqualTo("About_AdminTier_NotInstalled"));
        Assert.That(AdminTierCard.Describe(Tier(true, true, "0.3.0")).Args, Is.EqualTo(new object[] { "0.3.0" }));
        var older = AdminTierCard.Describe(Tier(true, true, "0.2.1"));
        Assert.That(older.Key, Is.EqualTo("About_AdminTier_Older"));
        Assert.That(older.Args, Is.EqualTo(new object[] { "0.2.1", "0.3.0" }));
    }

    [Test]
    public void The_outcome_says_what_happened()
    {
        Assert.That(AdminTierCard.Outcome(null, removing: false).Key, Is.EqualTo("AdminTier_Declined"));
        Assert.That(AdminTierCard.Outcome(AdminSetupResult.Done, removing: false).Key, Is.EqualTo("AdminTier_SetUp"));
        Assert.That(AdminTierCard.Outcome(AdminSetupResult.Done, removing: true).Key, Is.EqualTo("AdminTier_Removed"));
        Assert.That(AdminTierCard.Outcome(AdminSetupResult.FilesMissing, removing: false).Key, Is.EqualTo("AdminTier_FilesMissing"));
        Assert.That(AdminTierCard.Outcome(AdminSetupResult.Failed, removing: true).Args, Is.EqualTo(new object[] { 1 }));
    }

    [Test]
    public void First_run_offers_the_tier_once_after_the_vault_unless_it_is_there()
    {
        var notThere = new SetupFacts(HelloReady: true, RecoverySet: true, Enrolled: false, Skipped: false, AdminTierInstalled: false);
        Assert.That(FirstRunPlan.Next(FirstRunStep.Mode, notThere, SetupMode.Solo, haveRecoveryKey: true), Is.EqualTo(FirstRunStep.AdminTier));
        Assert.That(FirstRunPlan.Next(FirstRunStep.Mode, notThere, SetupMode.SecretsOnly), Is.EqualTo(FirstRunStep.AdminTier));
        Assert.That(FirstRunPlan.Next(FirstRunStep.AdminTier, notThere), Is.EqualTo(FirstRunStep.Done));
        Assert.That(FirstRunPlan.Next(FirstRunStep.RecoveryConfirm, notThere with { Enrolled = true }), Is.EqualTo(FirstRunStep.AdminTier));
        Assert.That(FirstRunPlan.Next(FirstRunStep.Mode, notThere with { AdminTierInstalled = true }, SetupMode.Solo, haveRecoveryKey: true),
            Is.EqualTo(FirstRunStep.Done));
        Assert.That(FirstRunPlan.Needed(notThere with { Enrolled = true }), Is.False, "declining it never brings the wizard back");
    }
}

public class AdminActionLogTests
{
    static readonly DateTimeOffset At = new(2026, 11, 21, 9, 30, 0, TimeSpan.Zero);
    static readonly AdminCaller Alice = new("S-1-5-21-1000-1000-1000-1001", 1, "S-1-5-21-1000-1000-1000-1001", false, false);

    [Test]
    public void A_line_names_op_caller_process_and_result()
    {
        var line = AdminAction.Of(At, AdminOps.Status, Alice, 4242, @"C:\Users\alice\app.exe", "ok", null).ToLine();
        var json = JsonNode.Parse(line)!.AsObject();
        Assert.That((int)json["v"]!, Is.EqualTo(1));
        Assert.That((string)json["op"]!, Is.EqualTo("status"));
        Assert.That((string)json["callerSid"]!, Is.EqualTo(Alice.UserSid));
        Assert.That((int)json["pid"]!, Is.EqualTo(4242));
        Assert.That((string)json["image"]!, Is.EqualTo(@"C:\Users\alice\app.exe"));
        Assert.That((string)json["result"]!, Is.EqualTo("ok"));
        Assert.That(json.ContainsKey("reason"), Is.False);
        Assert.That(line, Does.Not.Contain("\n"));
    }

    [Test]
    public void An_unknown_op_is_logged_as_unknown_never_as_sent() =>
        Assert.That(AdminAction.Of(At, "secret-looking\nop", Alice, 1, null, "refused", "unknown op").ToLine(),
            Does.Contain("\"op\":\"unknown\"").And.Not.Contain("secret-looking"));

    [TestCase(AdminOps.DecoysAdopt)]
    [TestCase(AdminOps.DecoysRelease)]
    [TestCase(AdminOps.DecoysReleaseCommit)]
    [TestCase(AdminOps.EventsReview)]
    [TestCase(AdminOps.BlocksUnblock)]
    public void Authorized_changes_distinguish_the_elevated_account_from_the_session_owner(string op)
    {
        var elevated = Alice with { UserSid = "S-1-5-21-1000-1000-1000-1002", Elevated = true };
        var action = AdminAction.Of(At, op, elevated, 42, null, "ok", null, elevated.SessionUserSid);
        var row = JsonNode.Parse(action.ToLine())!;
        Assert.That((string?)row["callerSid"], Is.EqualTo(elevated.UserSid));
        Assert.That((string?)row["actingFor"], Is.EqualTo(Alice.UserSid));
        var refused = AdminAction.Of(At, op, Alice, 42, null, "refused", "needs elevation");
        Assert.That(refused.ActingFor, Is.Null);
        Assert.That(refused.Reason, Is.EqualTo("needs elevation"));
    }
}

public class AdminWireTests
{
    sealed class StalledWriter : MemoryStream
    {
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            new(Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken));
    }

    [Test]
    public void A_stalled_reader_cannot_hold_its_service_reply_open()
    {
        using var stalled = new StalledWriter();
        Assert.CatchAsync<OperationCanceledException>(() => AdminWire.WriteReplyAsync(stalled, AdminReply.Ok(new { }),
            TimeSpan.FromMilliseconds(25), CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Test]
    public async Task A_request_and_a_reply_round_trip_in_the_agent_pipes_framing()
    {
        using var stream = new MemoryStream();
        await AdminWire.WriteAsync(stream, new AdminRequest(AdminWire.ProtocolVersion, AdminOps.Status), CancellationToken.None);
        var reply = AdminReply.Ok(new AdminStatusResult("0.3.0", AdminWire.ProtocolVersion, new(Listening: true)));
        await AdminWire.WriteAsync(stream, reply, CancellationToken.None);

        stream.Position = 0;
        var length = BitConverter.ToInt32(stream.GetBuffer(), 0);
        var firstJson = System.Text.Encoding.UTF8.GetString(stream.GetBuffer(), 4, length);
        Assert.That(firstJson, Is.EqualTo("{\"version\":2,\"op\":\"status\",\"args\":null}"));

        var request = await AdminWire.ReadAsync<AdminRequest>(stream, CancellationToken.None);
        var back = await AdminWire.ReadAsync<AdminReply>(stream, CancellationToken.None);
        Assert.That(request.Op, Is.EqualTo(AdminOps.Status));
        Assert.That(back.Status, Is.EqualTo(AdminStatus.Ok));
        Assert.That(back.ResultAs<AdminStatusResult>(), Is.EqualTo(new AdminStatusResult("0.3.0", AdminWire.ProtocolVersion, new(Listening: true))));
    }

    [Test]
    public async Task A_refusal_carries_its_status_as_a_word()
    {
        using var stream = new MemoryStream();
        await AdminWire.WriteAsync(stream, AdminReply.Refused("unknown op"), CancellationToken.None);
        var json = System.Text.Encoding.UTF8.GetString(stream.ToArray(), 4, (int)stream.Length - 4);
        Assert.That(json, Does.Contain("\"status\":\"refused\"").And.Contain("\"message\":\"unknown op\""));
        stream.Position = 0;
        Assert.That((await AdminWire.ReadAsync<AdminReply>(stream, CancellationToken.None)).ResultAs<AdminStatusResult>(), Is.Null);
    }

    [Test]
    public void An_oversized_message_is_refused_before_it_is_read()
    {
        using var stream = new MemoryStream(BitConverter.GetBytes(AdminWire.MaxMessageBytes + 1));
        Assert.ThrowsAsync<InvalidDataException>(() => AdminWire.ReadAsync<AdminRequest>(stream, CancellationToken.None));
    }

    [Test]
    public async Task The_agent_pipe_still_speaks_its_own_format()
    {
        using var stream = new MemoryStream();
        await AgentWire.WriteAsync(stream, new AgentReply(AgentStatus.Denied, Message: "no"), CancellationToken.None);
        var json = System.Text.Encoding.UTF8.GetString(stream.ToArray(), 4, (int)stream.Length - 4);
        Assert.That(json, Is.EqualTo("{\"status\":\"denied\",\"json\":null,\"message\":\"no\",\"refreshAt\":null}"));
        stream.Position = 0;
        Assert.That((await AgentWire.ReadAsync<AgentReply>(stream, CancellationToken.None)).Status, Is.EqualTo(AgentStatus.Denied));
    }
}

public class AdminHeldDecoysTests
{
    static readonly DateTimeOffset Now = new(2026, 11, 21, 9, 0, 0, TimeSpan.Zero);

    static DecoySet Set() => DecoySet.Mint(_ => true)
        .With(new(DecoyKind.Project, @"C:\Users\alice\source\billing-api-old", Now))
        .With(new(DecoyKind.Variables, "user environment", Now));

    [Test]
    public void Verified_enrollment_requires_each_claimed_file_and_variable_to_match()
    {
        var set = Set();
        var candidate = new AdminHeldDecoys(set, AdminHeldDecoys.FilesFor(set));
        var checkedSteps = new List<DecoyStep>();
        Assert.That(candidate.IsPlaced(step => { checkedSteps.Add(step); return true; }), Is.True);
        Assert.That(checkedSteps.OfType<WriteDecoyFile>().Count(), Is.EqualTo(2));
        Assert.That(checkedSteps.OfType<SetDecoyVariable>().Count(), Is.EqualTo(2));
        foreach (var missing in checkedSteps)
            Assert.That(candidate.IsPlaced(step => step != missing), Is.False);
        Assert.That((candidate with { Files = [] }).IsPlaced(_ => true), Is.False);
        Assert.That((candidate with { Files = [candidate.Files[0], candidate.Files[0]] }).MatchesManifest(), Is.False);
        var variables = set with { Placed = [set.Placed.Single(p => p.Kind == DecoyKind.Variables)] };
        Assert.That(new AdminHeldDecoys(variables, []).IsPlaced(step => step is SetDecoyVariable), Is.True);
        Assert.That(new AdminHeldDecoys(variables with { HttpPort = DecoySet.MinPort - 1 }, []).MatchesManifest(), Is.False);
        Assert.That(new AdminHeldDecoys(variables with { SqlPort = DecoySet.MaxPort + 1 }, []).MatchesManifest(), Is.False);
    }

    [Test]
    public void A_previous_registration_waits_for_verification_before_reporting_any_protection()
    {
        var legacy = new AdminHeldDecoys(Set(), [], Verified: false);
        var record = AdminHeldDecoys.Parse(legacy.ToJson())!;
        var status = record.Status(listening: true);
        Assert.That(status.NeedsVerification, Is.True);
        Assert.That(status.Held || status.Listening, Is.False);
        Assert.That(status.Kinds, Is.Empty);
        Assert.That(new AdminDecoysStatus(true, true, [DecoyKind.Project], 2).ConfirmedStatus(), Is.EqualTo(status));
    }

    [Test]
    public void A_held_set_reads_back_and_tells_kinds_and_file_count_only()
    {
        var held = new AdminHeldDecoys(Set(), [@"C:\Users\alice\source\billing-api-old\.env", @"C:\Users\alice\source\billing-api-old\appsettings.Production.json"]);

        var back = AdminHeldDecoys.Parse(held.ToJson())!;
        var status = back.Status(listening: true);

        Assert.That(back.Set.Values, Is.EqualTo(held.Set.Values));
        Assert.That(back.Files, Is.EqualTo(held.Files));
        Assert.That(status, Is.EqualTo(status with { Held = true, Listening = true, Files = 2 }));
        Assert.That(status.Kinds, Is.EqualTo(new[] { DecoyKind.Project, DecoyKind.Variables }));
        var wire = System.Text.Json.JsonSerializer.Serialize(status);
        Assert.That(wire, Does.Not.Contain("billing-api-old").And.Not.Contain(held.Set.Values.AdminToken).And.Not.Contain(held.Set.HttpPort.ToString(System.Globalization.CultureInfo.InvariantCulture)));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("{")]
    [TestCase("{\"v\":2,\"set\":{},\"files\":[]}")]
    [TestCase("{\"v\":1,\"set\":null,\"files\":[]}")]
    public void A_damaged_or_newer_file_holds_nothing(string? json) => Assert.That(AdminHeldDecoys.Parse(json), Is.Null);



    [TestCase(@"C:\Users\alice\AppData\Local\Tiresias\decoys.json", @"\\?\C:\Users\alice\AppData\Local\Tiresias\decoys.json", true)]
    [TestCase(@"C:\Users\alice\AppData\Local\Tiresias\decoys.json", @"\\?\c:\users\ALICE\appdata\local\tiresias\decoys.json", true)]
    [TestCase(@"C:\Users\alice\AppData\Local\Tiresias\decoys.json", @"\\?\C:\Windows\System32\decoys.json", false)]
    [TestCase(@"C:\Users\alice\AppData\Local\Tiresias\decoys.json", @"\\?\UNC\203.0.113.5\share\decoys.json", false)]
    public void A_set_goes_back_only_to_the_path_asked_for(string asked, string final, bool ok) =>
        Assert.That(AdminHandBack.IsWhereAsked(asked, final), Is.EqualTo(ok));

    [Test]
    public void Another_users_keyring_folder_is_in_their_profile() =>
        Assert.That(AdminHandBack.KeyringFolder(@"C:\Users\bob\"), Is.EqualTo(@"C:\Users\bob\AppData\Local\Tiresias"));
}
