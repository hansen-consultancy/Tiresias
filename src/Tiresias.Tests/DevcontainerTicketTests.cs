using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Tiresias.Access;
using Tiresias.Agent;
using Tiresias.EnvironmentVariables;
using Tiresias.Protocol;
using Tiresias.Remote;

namespace Tiresias.Tests;

public class DevcontainerTicketTests
{
    sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 11, 23, 9, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }

    static byte[] Bytes(string text) => Encoding.UTF8.GetBytes(text);

    [TestCase("""{ "remoteEnv": { "TIRESIAS_TICKET": "${localEnv:TIRESIAS_TICKET}" } }""", true)]
    [TestCase("// comment\n{ \"name\": \"x\", \"remoteEnv\": { \"A\": \"b\", \"TIRESIAS_TICKET\": \"${localEnv:TIRESIAS_TICKET}\", }, }", true)]
    [TestCase("""{ "containerEnv": { "TIRESIAS_TICKET": "${localEnv:TIRESIAS_TICKET}" } }""", false)]
    [TestCase("""{ "remoteEnv": { "TIRESIAS_TICKET": "abc" } }""", false)]
    [TestCase("{ not json", false)]
    public void A_devcontainer_asks_through_remote_env_only(string json, bool asks) =>
        Assert.That(DevcontainerTickets.Asks(Bytes(json)), Is.EqualTo(asks));

    [Test]
    public void One_ticket_per_folder_until_it_ends()
    {
        var clock = new Clock();
        var tickets = new DevcontainerTickets(clock);
        var shop = tickets.Mint(@"C:\src\shop");
        Assert.That(tickets.Mint(@"C:\src\shop\"), Is.EqualTo(shop));
        Assert.That(tickets.Mint(@"C:\src\other"), Is.Not.EqualTo(shop));
        Assert.That(shop, Has.Length.EqualTo(43), "256 bits, base64url");
        Assert.That(tickets.Find(shop)!.Folder, Is.EqualTo(@"C:\src\shop"));
        Assert.That(tickets.Find("nope"), Is.Null);
        Assert.That(tickets.Find(null), Is.Null);

        clock.Now += Consent.MaxDuration;
        Assert.That(tickets.Find(shop), Is.Null);
        Assert.That(tickets.Mint(@"C:\src\shop"), Is.Not.EqualTo(shop));
    }

    [Test]
    public void Allowances_and_placeholders_end_with_the_ticket()
    {
        var tickets = new DevcontainerTickets(new Clock());
        var ticket = tickets.Mint(@"C:\src\shop");
        var key = new EnvironmentVariableAccess("OPENAI_API_KEY", @"C:\src\shop");
        Assert.That(tickets.AllAllowed(ticket, [key]), Is.False);
        tickets.Allow(ticket, [key]);
        Assert.That(tickets.AllAllowed(ticket, [key]), Is.True);
        Assert.That(tickets.AllAllowed(ticket, [key, new("GH_TOKEN", @"C:\src\shop")]), Is.False);
        Assert.That(tickets.Hold(ticket, ["tirph_a"]), Is.True);

        Assert.That(tickets.Clear(), Is.EqualTo(new[] { "tirph_a" }));
        Assert.That(tickets.Find(ticket), Is.Null);
        Assert.That(tickets.AllAllowed(ticket, [key]), Is.False);
        Assert.That(tickets.Hold(ticket, ["tirph_b"]), Is.False, "ended meanwhile: the caller revokes it");
    }

    [Test]
    public void Prune_ends_only_expired_tickets()
    {
        var clock = new Clock();
        var tickets = new DevcontainerTickets(clock);
        var old = tickets.Mint(@"C:\src\old");
        tickets.Hold(old, ["tirph_old"]);
        clock.Now += Consent.MaxDuration - TimeSpan.FromMinutes(1);
        var fresh = tickets.Mint(@"C:\src\new");
        clock.Now += TimeSpan.FromMinutes(1);
        Assert.That(tickets.Prune(), Is.EqualTo(new[] { "tirph_old" }));
        Assert.That(tickets.Find(fresh), Is.Not.Null);
    }

    [Test, Platform("Win")]
    public void The_folder_a_command_opens()
    {
        var folders = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { @"C:\src\shop", @"C:\work" };
        Assert.That(DevcontainerTickets.FolderFor(["code", @"C:\src\shop"], @"C:\work", folders.Contains), Is.EqualTo(@"C:\src\shop"));
        Assert.That(DevcontainerTickets.FolderFor(["code", "--new-window", "."], @"C:\work", folders.Contains), Is.EqualTo(@"C:\work"));
        Assert.That(DevcontainerTickets.FolderFor(["dotnet", "run"], @"C:\src\shop", folders.Contains), Is.EqualTo(@"C:\src\shop"));
    }

    [Test]
    public void A_placeholder_base_url_points_through_the_relay() =>
        Assert.That(DevcontainerTickets.ForContainer(new("http://127.0.0.1:7781")), Is.EqualTo(new Uri("http://host.docker.internal:7781/")));

    [TestCase("Tiresias abc", "abc")]
    [TestCase("Bearer abc", null)]
    [TestCase("Tiresias ", null)]
    [TestCase(null, null)]
    public void Ticket_header(string? header, string? ticket) => Assert.That(DevcontainerWire.Ticket(header), Is.EqualTo(ticket));

    static string Show(RemoteCommand? command) =>
        command is null ? "none" : command.Git is { } git ? $"git {git}" : $"{(command.Names is null ? "all" : string.Join(",", command.Names))} | {string.Join(" ", command.Command)}";

    [TestCase(new[] { "run", "--", "npm", "test" }, "all | npm test")]
    [TestCase(new[] { "run", "--only", "A, B", "--", "x" }, "A,B | x")]
    [TestCase(new[] { "env", "OPENAI_API_KEY" }, "OPENAI_API_KEY | ")]
    [TestCase(new[] { "git-credential", "get" }, "git get")]
    [TestCase(new[] { "git-credential" }, "none")]
    [TestCase(new[] { "run", "npm" }, "none")]
    [TestCase(new[] { "run", "--" }, "none")]
    [TestCase(new[] { "run", "--bogus", "--", "x" }, "none")]
    [TestCase(new string[0], "none")]
    public void Tir_remote_arguments(string[] args, string expected) => Assert.That(Show(RemoteCommand.Parse(args)), Is.EqualTo(expected));

    [Test, NonParallelizable, Platform("Win")]
    public async Task The_endpoint_refuses_without_a_live_ticket_and_names_the_folder_with_one()
    {
        var tickets = new DevcontainerTickets(TimeProvider.System);
        List<string> refusals = [];
        DevcontainerTicket? asked = null;
        DevcontainerGitRequest? askedGit = null;
        await using var endpoint = new DevcontainerEndpoint(tickets, (_, devcontainer, _, _) =>
        {
            asked = devcontainer;
            return Task.FromResult(new DevcontainerReply(true, new Dictionary<string, string> { ["A"] = "b" }));
        }, (_, _, git, _) =>
        {
            askedGit = git;
            return Task.FromResult(new DevcontainerGitReply(true, "tiresias", "t"));
        }, refusals.Add);
        await endpoint.EnsureStartedAsync();
        using var http = new HttpClient { BaseAddress = DevcontainerEndpoint.Url };

        Task<HttpResponseMessage> Post(string? ticket, bool git = false)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, git ? DevcontainerWire.GitPath : DevcontainerWire.EnvironmentPath)
            {
                Content = git
                    ? JsonContent.Create(new DevcontainerGitRequest("https", "github.com"), options: DevcontainerWire.Json)
                    : JsonContent.Create(new DevcontainerRequest(["A"]), options: DevcontainerWire.Json),
            };
            if (ticket is not null)
                request.Headers.TryAddWithoutValidation("Authorization", $"Tiresias {ticket}");
            return http.SendAsync(request);
        }

        Assert.That((await Post(null)).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That((await Post("guess")).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That((await Post("guess", git: true)).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(asked, Is.Null);
        Assert.That(askedGit, Is.Null);
        Assert.That(refusals, Has.Count.EqualTo(3).And.None.Contains("guess"));

        var ticket = tickets.Mint(@"C:\src\shop");
        var reply = await (await Post(ticket)).Content.ReadFromJsonAsync<DevcontainerReply>(DevcontainerWire.Json);
        Assert.That(reply!.Approved && reply.Variables!["A"] == "b");
        Assert.That(asked!.Folder, Is.EqualTo(@"C:\src\shop"));
        var credential = await (await Post(ticket, git: true)).Content.ReadFromJsonAsync<DevcontainerGitReply>(DevcontainerWire.Json);
        Assert.That(credential, Is.EqualTo(new DevcontainerGitReply(true, "tiresias", "t")));
        Assert.That(askedGit, Is.EqualTo(new DevcontainerGitRequest("https", "github.com")));
        tickets.Clear();
        Assert.That((await Post(ticket)).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [TestCase("github.com", "github.com")]
    [TestCase("GitHub.com", "github.com")]
    [TestCase("github.com:443", "github.com")]
    [TestCase("git.example.com:8443", "git.example.com:8443")]
    [TestCase("https://github.com", null)]
    [TestCase("github.com/org", null)]
    [TestCase("alice@github.com", null)]
    [TestCase("", null)]
    public void A_git_host_is_what_git_sends(string host, string? normalized) => Assert.That(GitHost.Normalize(host), Is.EqualTo(normalized));

    [Test]
    public void Git_hosts_are_sealed_with_the_rest_and_match_https_only()
    {
        var environment = SealedEnvironment.Empty.WithGitHost(new("GitHub.com", "GH_TOKEN", GitHost.DefaultUsername))
            .WithGitHost(new("git.example.com:8443", "CORP_TOKEN", "alice"));
        var read = SealedEnvironment.FromDocument(environment.ToDocument());
        Assert.That(read.GitHosts, Is.EqualTo(environment.GitHosts));
        Assert.That(read.GitHostFor("https", "github.com")!.Variable, Is.EqualTo("GH_TOKEN"));
        Assert.That(read.GitHostFor("https", "git.example.com:8443")!.Username, Is.EqualTo("alice"));
        Assert.That(read.GitHostFor("http", "github.com"), Is.Null, "never over plain http");
        Assert.That(read.GitHostFor("https", "git.example.com"), Is.Null, "another port is another host");
        Assert.That(read.GitHostFor("https", null), Is.Null);
        Assert.That(read.WithGitHost(new("github.com", "OTHER", "x")).GitHosts, Has.Count.EqualTo(2), "replaces the mapping for the same host");
        Assert.That(read.WithoutGitHost("GITHUB.COM").GitHosts.Select(h => h.Host), Is.EqualTo(new[] { "git.example.com:8443" }));
        Assert.Throws<ArgumentException>(() => read.WithGitHost(new("https://github.com", "GH_TOKEN", "x")));
    }

    [Test]
    public void The_credential_helper_reads_until_a_blank_line_and_answers_in_kind()
    {
        Assert.That(GitCredential.Read(["protocol=https", "host=github.com", "host=example.com", "path", "", "username=ignored"]),
            Is.EqualTo(new Dictionary<string, string> { ["protocol"] = "https", ["host"] = "example.com" }));
        Assert.That(GitCredential.Answer("tiresias", "t0k"), Is.EqualTo("username=tiresias\npassword=t0k\n"));
        Assert.That(GitCredential.Answer("tiresias", "a\nprotocol=http"), Is.Null, "a line break would let a value add attributes");
    }

    [Test]
    public void Tir_remote_writes_the_wire_as_the_app_reads_it()
    {
        var request = new DevcontainerGitRequest("https", "github.com");
        Assert.That(JsonSerializer.Serialize(request, RemoteJson.Default.DevcontainerGitRequest), Is.EqualTo(JsonSerializer.Serialize(request, DevcontainerWire.Json)));
        var names = new DevcontainerRequest(["A"]);
        Assert.That(JsonSerializer.Serialize(names, RemoteJson.Default.DevcontainerRequest), Is.EqualTo(JsonSerializer.Serialize(names, DevcontainerWire.Json)));
        var reply = new DevcontainerReply(true, new Dictionary<string, string> { ["A"] = "b" }, "note");
        var back = JsonSerializer.Deserialize(JsonSerializer.Serialize(reply, DevcontainerWire.Json), RemoteJson.Default.DevcontainerReply)!;
        Assert.That((back.Approved, back.Variables!["A"], back.Message), Is.EqualTo((true, "b", "note")));
        var git = new DevcontainerGitReply(true, "tiresias", "t");
        Assert.That(JsonSerializer.Deserialize(JsonSerializer.Serialize(git, DevcontainerWire.Json), RemoteJson.Default.DevcontainerGitReply), Is.EqualTo(git));
    }
}
