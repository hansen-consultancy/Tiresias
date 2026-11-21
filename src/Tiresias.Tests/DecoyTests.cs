using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using Microsoft.Data.SqlClient;
using Tiresias.Decoys;

namespace Tiresias.Tests;

public class DecoyTests
{
    static readonly DateTimeOffset Now = new(2026, 11, 21, 9, 0, 0, TimeSpan.Zero);

    static DecoySet Minted() => DecoySet.Mint(_ => true);

    static bool Free(int port)
    {
        try
        {
            var listener = new TcpListener(IPAddress.Loopback, port);
            listener.Start();
            listener.Stop();
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    [Test]
    public void Minting_picks_two_ports_and_values_that_look_real()
    {
        var set = Minted();

        Assert.That(set.HttpPort, Is.Not.EqualTo(set.SqlPort));
        Assert.That(set.Values.ApiKey, Does.StartWith("sk-proj-").And.Length.EqualTo(164));
        Assert.That(set.Values.AdminToken, Has.Length.EqualTo(48));
        Assert.That(set.Values.ApiKey + set.Values.AdminToken + set.Values.SqlPassword, Does.Not.Contain("tirph_"));
        Assert.That(Minted().Values.AdminToken, Is.Not.EqualTo(set.Values.AdminToken));
    }

    [Test]
    public void Minting_skips_ports_in_use()
    {
        var taken = new HashSet<int>();

        var set = DecoySet.Mint(port => !taken.Add(port) || taken.Count > 3);

        Assert.That(taken, Does.Contain(set.HttpPort));
    }

    [Test]
    public void The_file_round_trips_and_a_newer_or_damaged_one_reads_as_none()
    {
        var set = Minted().With(new(DecoyKind.PasswordsFile, @"C:\Users\alice\Documents\passwords.txt", Now));

        var read = DecoySet.Parse(set.ToJson())!;

        Assert.That(read.Values, Is.EqualTo(set.Values));
        Assert.That(read.Placed, Is.EqualTo(set.Placed));
        Assert.That(DecoySet.Parse(set.ToJson().Replace("\"v\": 1", "\"v\": 2")), Is.Null);
        Assert.That(DecoySet.Parse("{"), Is.Null);
        Assert.That(DecoySet.Parse(null), Is.Null);
    }

    [Test]
    public void Each_value_is_recognised_and_anything_else_is_not()
    {
        var set = Minted();

        Assert.That(set.Recognise($"Authorization: Bearer {set.Values.ApiKey}"), Is.EqualTo(DecoyUse.ApiKey));
        Assert.That(set.Recognise($"X-Api-Key: {set.Values.AdminToken}"), Is.EqualTo(DecoyUse.AdminToken));
        Assert.That(set.Recognise(set.Values.SqlPassword), Is.EqualTo(DecoyUse.SqlPassword));
        Assert.That(set.Recognise("Authorization: Bearer something-else"), Is.Null);
        Assert.That(set.Recognise(null), Is.Null);
    }

    [Test]
    public void Every_placed_file_names_a_loopback_endpoint()
    {
        var set = Minted();

        foreach (var text in new[] { DecoyPlan.DecoyListText(set), DecoyPlan.AppSettings(set), DecoyPlan.DotEnv(set) })
            Assert.That(text, Does.Contain($"127.0.0.1:{set.HttpPort}").Or.Contain($"127.0.0.1,{set.SqlPort}"));
        Assert.That(System.Text.Json.JsonDocument.Parse(DecoyPlan.AppSettings(set)).RootElement.GetProperty("ConnectionStrings").GetProperty("Billing").GetString(),
            Is.EqualTo(set.ConnectionString));
    }

    [Test]
    public void Placing_refuses_a_file_folder_or_variable_that_already_exists()
    {
        var set = Minted();
        var root = Path.GetFullPath("decoy-root");

        Assert.Throws<InvalidOperationException>(() => DecoyPlan.Steps(set, DecoyKind.PasswordsFile, Path.Combine(root, "passwords.txt"), _ => true));
        Assert.Throws<InvalidOperationException>(() => DecoyPlan.Steps(set, DecoyKind.Project, Path.Combine(root, "billing"), p => p == Path.Combine(root, "billing")));
        Assert.Throws<InvalidOperationException>(() => DecoyPlan.Steps(set, DecoyKind.Variables, "", n => n == "ADMIN_API_TOKEN"));
        Assert.That(DecoyPlan.Steps(set, DecoyKind.Project, Path.Combine(root, "billing"), _ => false), Has.Count.EqualTo(2));
        Assert.That(DecoyPlan.Steps(set, DecoyKind.Variables, "", _ => false).OfType<SetDecoyVariable>().Select(v => v.Name), Is.EqualTo(DecoyPlan.VariableNames));
    }

    [Test]
    public void Removal_takes_what_is_unchanged_and_keeps_what_the_user_changed()
    {
        var root = Path.GetFullPath("decoy-root");
        var project = new PlacedDecoy(DecoyKind.Project, Path.Combine(root, "billing"), Now);
        var set = Minted().With(project);
        var settings = Path.Combine(project.Where, "appsettings.Production.json");
        var env = Path.Combine(project.Where, ".env");
        var now = new Dictionary<string, string?> { [settings] = DecoyPlan.AppSettings(set), [env] = "OPENAI_API_KEY=mine" };

        var (remove, kept) = DecoyPlan.Undo(set, project, path => now.GetValueOrDefault(path));

        Assert.That(remove.OfType<WriteDecoyFile>().Select(f => f.Path), Is.EqualTo(new[] { settings }));
        Assert.That(kept, Is.EqualTo(new[] { env }));
        var gone = DecoyPlan.Undo(set, project, _ => null);
        Assert.That(gone.Remove, Is.Empty);
        Assert.That(gone.Kept, Is.Empty);
    }

    [Test]
    public void The_doctor_skips_decoy_files_and_everything_in_a_decoy_folder()
    {
        var root = Path.GetFullPath("decoy-root");
        var set = Minted()
            .With(new(DecoyKind.PasswordsFile, Path.Combine(root, "passwords.txt"), Now))
            .With(new(DecoyKind.Project, Path.Combine(root, "billing"), Now));

        Assert.That(set.Covers(Path.Combine(root, "passwords.txt")), Is.True);
        Assert.That(set.Covers(Path.Combine(root, "billing", "appsettings.Production.json")), Is.True);
        Assert.That(set.Covers(Path.Combine(root, "billing-real", "appsettings.json")), Is.False);
        Assert.That(set.Covers(Path.Combine(root, "other.txt")), Is.False);
    }

    [Test]
    public void Repeats_of_a_program_and_use_are_reported_once_a_minute()
    {
        var filter = new DecoyHitFilter();
        DecoyHit Hit(int pid, DecoyUse use, double seconds) => new(use, "SQL Server", pid, "x.exe", Now.AddSeconds(seconds));

        Assert.That(filter.ShouldReport(Hit(1, DecoyUse.SqlPassword, 0)), Is.True);
        Assert.That(filter.ShouldReport(Hit(1, DecoyUse.SqlPassword, 30)), Is.False);
        Assert.That(filter.ShouldReport(Hit(1, DecoyUse.Connected, 30)), Is.True);
        Assert.That(filter.ShouldReport(Hit(2, DecoyUse.SqlPassword, 30)), Is.True);
        Assert.That(filter.ShouldReport(Hit(1, DecoyUse.SqlPassword, 60)), Is.True);
    }

    [Test]
    public void A_login_reads_back_its_user_and_unobfuscated_password()
    {
        var login = Login7("billing_admin", "p@ss!word");

        Assert.That(DecoyTds.ReadLogin(login), Is.EqualTo(("billing_admin", "p@ss!word")));
        Assert.That(DecoyTds.ReadLogin(login.AsSpan(0, 40)), Is.Null);
    }

    /// <summary>A LOGIN7 body as a client builds it: fixed part, offset table, then host, user and obfuscated password.</summary>
    static byte[] Login7(string user, string password)
    {
        var host = Encoding.Unicode.GetBytes("host");
        var name = Encoding.Unicode.GetBytes(user);
        var secret = Encoding.Unicode.GetBytes(password).Select(b => (byte)(((b << 4) | (b >> 4)) ^ 0xA5)).ToArray();
        var login = new byte[48 + host.Length + name.Length + secret.Length];
        var at = 48;
        foreach (var (field, bytes, chars) in new[] { (36, host, 4), (40, name, user.Length), (44, secret, password.Length) })
        {
            BitConverter.GetBytes((ushort)at).CopyTo(login, field);
            BitConverter.GetBytes((ushort)chars).CopyTo(login, field + 2);
            bytes.CopyTo(login, at);
            at += bytes.Length;
        }
        return login;
    }

    static async Task<(DecoyHit Hit, T Result)> HitAsync<T>(DecoySet set, Func<Task<T>> call)
    {
        var hit = new TaskCompletionSource<DecoyHit>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var listener = new DecoyListener(set, (client, port) => (4242, $"seen {port}"), TimeProvider.System);
        listener.Hit += h => hit.TrySetResult(h);
        listener.Start();
        var result = await call();
        return (await hit.Task.WaitAsync(TimeSpan.FromSeconds(10)), result);
    }

    [Test]
    public async Task An_api_call_with_the_decoy_key_is_refused_and_names_the_key_and_caller()
    {
        var set = DecoySet.Mint(Free);
        using var http = new HttpClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", set.Values.ApiKey);

        var (hit, response) = await HitAsync(set, () => http.PostAsync($"{set.HttpUrl}/v1/chat/completions?x={set.Values.AdminToken}", new StringContent("{}")));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(await response.Content.ReadAsStringAsync(), Does.Contain("invalid_api_key"));
        Assert.That(hit.Use, Is.EqualTo(DecoyUse.ApiKey));
        Assert.That(hit.Endpoint, Is.EqualTo("HTTP POST /v1/chat/completions"));
        Assert.That((hit.ProcessId, hit.Program), Is.EqualTo(((int?)4242, $"seen {set.HttpPort}")));
    }

    [Test]
    public async Task A_bare_connection_to_a_decoy_port_is_still_a_hit()
    {
        var set = DecoySet.Mint(Free);

        var (hit, _) = await HitAsync(set, async () =>
        {
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(IPAddress.Loopback, set.SqlPort);
            return 0;
        });

        Assert.That(hit.Use, Is.EqualTo(DecoyUse.Connected));
        Assert.That(hit.Endpoint, Is.EqualTo("SQL Server"));
    }

    [Test]
    public async Task Sql_client_with_the_decoy_connection_string_gets_login_failed_and_is_seen()
    {
        var set = DecoySet.Mint(Free);

        var (hit, error) = await HitAsync(set, async () =>
        {
            await using var connection = new SqlConnection(set.ConnectionString + ";Pooling=False;Connect Timeout=10");
            return Assert.ThrowsAsync<SqlException>(() => connection.OpenAsync())!;
        });

        Assert.That(error.Number, Is.EqualTo(18456));
        Assert.That(error.Message, Does.Contain("Login failed for user 'billing_admin'"));
        Assert.That(hit.Use, Is.EqualTo(DecoyUse.SqlPassword));
    }

    [Test]
    [Platform("Win")]
    public async Task The_owner_of_a_loopback_connection_is_this_process()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, port);
            using var accepted = await listener.AcceptTcpClientAsync();

            var owner = Tiresias.Forwarder.WindowsClientProcessLookup.Owner((IPEndPoint)accepted.Client.RemoteEndPoint!, port);

            Assert.That(owner?.Pid, Is.EqualTo(Environment.ProcessId));
            Assert.That(owner?.Image, Is.EqualTo(Environment.ProcessPath).IgnoreCase);
        }
        finally
        {
            listener.Stop();
        }
    }
}
