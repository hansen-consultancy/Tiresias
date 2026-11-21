using System.Text.Json.Nodes;
using Tiresias.AdminTier;
using Tiresias.App.Logic;
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
    [TestCase(2)]
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
            Is.EquivalentTo(new[] { AdminOps.Thaw, AdminOps.DecoysRelease, AdminOps.Teardown }));

    [Test]
    public void Ops_not_built_yet_are_refused_even_when_the_caller_qualifies()
    {
        foreach (var op in AdminOps.All.Where(o => o != AdminOps.Status))
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
            AdminInstallStep.StopService, AdminInstallStep.DeleteService, AdminInstallStep.DeleteFiles, AdminInstallStep.DeleteStateFolder,
        }));
        Assert.That(AdminInstallPlan.Remove(new(Exists: false, Running: false)), Is.EqualTo(new[]
        {
            AdminInstallStep.DeleteFiles, AdminInstallStep.DeleteStateFolder,
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
}

public class AdminWireTests
{
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
        Assert.That(firstJson, Is.EqualTo("{\"version\":1,\"op\":\"status\",\"args\":null}"));

        var request = await AdminWire.ReadAsync<AdminRequest>(stream, CancellationToken.None);
        var back = await AdminWire.ReadAsync<AdminReply>(stream, CancellationToken.None);
        Assert.That(request.Op, Is.EqualTo(AdminOps.Status));
        Assert.That(back.Status, Is.EqualTo(AdminStatus.Ok));
        Assert.That(back.ResultAs<AdminStatusResult>(), Is.EqualTo(new AdminStatusResult("0.3.0", 1, new(Listening: true))));
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
