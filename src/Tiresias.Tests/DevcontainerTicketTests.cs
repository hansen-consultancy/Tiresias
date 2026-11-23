using System.Net;
using System.Net.Http.Json;
using System.Text;
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
        command is null ? "none" : $"{(command.Names is null ? "all" : string.Join(",", command.Names))} | {string.Join(" ", command.Command)}";

    [TestCase(new[] { "run", "--", "npm", "test" }, "all | npm test")]
    [TestCase(new[] { "run", "--only", "A, B", "--", "x" }, "A,B | x")]
    [TestCase(new[] { "env", "OPENAI_API_KEY" }, "OPENAI_API_KEY | ")]
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
        await using var endpoint = new DevcontainerEndpoint(tickets, (_, devcontainer, _, _) =>
        {
            asked = devcontainer;
            return Task.FromResult(new DevcontainerReply(true, new Dictionary<string, string> { ["A"] = "b" }));
        }, refusals.Add);
        await endpoint.EnsureStartedAsync();
        using var http = new HttpClient { BaseAddress = DevcontainerEndpoint.Url };

        Task<HttpResponseMessage> Post(string? ticket)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, DevcontainerWire.EnvironmentPath)
            {
                Content = JsonContent.Create(new DevcontainerRequest(["A"]), options: DevcontainerWire.Json),
            };
            if (ticket is not null)
                request.Headers.TryAddWithoutValidation("Authorization", $"Tiresias {ticket}");
            return http.SendAsync(request);
        }

        Assert.That((await Post(null)).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That((await Post("guess")).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(asked, Is.Null);
        Assert.That(refusals, Has.Count.EqualTo(2).And.None.Contains("guess"));

        var ticket = tickets.Mint(@"C:\src\shop");
        var reply = await (await Post(ticket)).Content.ReadFromJsonAsync<DevcontainerReply>(DevcontainerWire.Json);
        Assert.That(reply!.Approved && reply.Variables!["A"] == "b");
        Assert.That(asked!.Folder, Is.EqualTo(@"C:\src\shop"));
        tickets.Clear();
        Assert.That((await Post(ticket)).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }
}
