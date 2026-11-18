using Tiresias.Policy;
using Tiresias.Vault;

namespace Tiresias.Tests;

public class SqlServerSetupPlanTests
{
    static readonly VaultDocument Empty = new([], []);

    static SqlServerSetupPlan Plan(string slug = "appdb", string server = "sql.example.com", string database = "AppDb", VaultDocument? vault = null) =>
        SqlServerSetupPlanner.Plan(new(slug, server, database), vault ?? Empty);

    [Test]
    public void A_database_becomes_an_mssql_service_whose_two_grants_hand_out_logins_from_one_provisioner_secret()
    {
        var plan = Plan();
        var service = plan.Service!;
        Assert.That(service.Upstream, Is.EqualTo(new Uri("mssql://sql.example.com/AppDb")));
        Assert.That(service.Grants.Select(g => (g.Name, g.SecretSlug, g.IssuesLogins, g.RequiresElevation)),
            Is.EqualTo(new[] { ("read", "appdb-provisioner", true, false), ("write", "appdb-provisioner", true, false) }));
        Assert.That((plan.ProvisionerSecret, plan.SigningSecret, plan.Replaces), Is.EqualTo(("appdb-provisioner", "appdb-signing", false)));
    }

    [TestCase("sql.example.com,1433", "sql.example.com")]
    [TestCase(@"SQL.example.com\SQLEXPRESS", "sql.example.com")]
    [TestCase(@".\SQLEXPRESS", "localhost")]
    [TestCase("(local)", "localhost")]
    public void The_upstream_names_the_host_however_the_server_was_typed(string server, string host)
    {
        var plan = Plan(server: server);
        Assert.That(plan.Service!.Upstream.Host, Is.EqualTo(host));
        Assert.That(plan.Server, Is.EqualTo(server));
    }

    [TestCase("", "Type the server's name")]
    [TestCase("sql.example.com,0", "isn't a server name")]
    [TestCase("sql.example.com,port", "isn't a server name")]
    [TestCase(@"sql.example.com\", "isn't a server name")]
    [TestCase("tcp:sql.example.com", "isn't a server name")]
    public void A_server_that_isnt_one_is_refused_with_examples(string server, string message) =>
        Assert.That(Plan(server: server).Problems.Single(), Has.Property("Field").EqualTo(SqlServerSetupField.Server).And.Property("Message").Contains(message));

    [TestCase("")]
    [TestCase("master")]
    [TestCase("msdb")]
    [TestCase("App]Db")]
    [TestCase("App'Db")]
    public void A_system_database_or_one_the_script_cant_quote_is_refused(string database) =>
        Assert.That(Plan(database: database).Problems.Single().Field, Is.EqualTo(SqlServerSetupField.Database));

    [Test]
    public void A_database_name_with_spaces_is_escaped_in_the_upstream() =>
        Assert.That(Plan(database: "App Db").Service!.Upstream.AbsolutePath, Is.EqualTo("/App%20Db"));

    [Test]
    public void The_same_service_for_the_same_database_is_set_up_again_and_another_is_refused()
    {
        var vault = Empty with { Services = [Plan().Service!] };
        Assert.That(Plan(server: "SQL.example.com,1433", database: "appdb", vault: vault).Replaces, Is.True);

        var other = Plan(database: "Other", vault: vault);
        Assert.That(other.Service, Is.Null);
        Assert.That(other.Problems.Single().Message, Does.Contain("exists already for mssql://sql.example.com/AppDb"));
    }

    [Test]
    public void An_https_service_with_the_name_is_never_replaced()
    {
        var vault = Empty with { Services = [new Service("appdb", new Uri("https://sql.example.com/AppDb"), [])] };
        Assert.That(Plan(vault: vault).Problems.Single().Field, Is.EqualTo(SqlServerSetupField.Slug));
    }

    [Test]
    public void Batches_split_on_go_substitute_variables_and_drop_on_error_exit()
    {
        var script = ":on error exit\r\nSET NOCOUNT ON;\r\nGO\r\nUSE [$(Database)];\r\n  go  \r\nPRINT N'$(Database)';\r\n";
        Assert.That(SqlServerSetupPlanner.Batches(script, new Dictionary<string, string> { ["Database"] = "AppDb" }).Select(b => b.Trim()),
            Is.EqualTo(new[] { "SET NOCOUNT ON;", "USE [AppDb];", "PRINT N'AppDb';" }));
    }

    [Test]
    public void A_missing_variable_or_another_sqlcmd_command_stops_before_anything_runs()
    {
        Assert.That(() => SqlServerSetupPlanner.Batches("USE [$(Db)];", new Dictionary<string, string>()),
            Throws.TypeOf<InvalidDataException>().With.Message.Contains("$(Db)"));
        Assert.That(() => SqlServerSetupPlanner.Batches(":r other.sql", new Dictionary<string, string>()),
            Throws.TypeOf<InvalidDataException>().With.Message.Contains(":r other.sql"));
    }

    [TestCase("01-tiresias-setup.sql")]
    [TestCase("02-tiresias-cleanup-job.sql")]
    public void The_shipped_scripts_split_with_the_variables_the_app_sets(string name)
    {
        var path = Path.Combine(RepoRoot(), "src", "Tiresias.Broker", "sql", name);
        var variables = new Dictionary<string, string> { ["Database"] = "AppDb", ["ProvisionerPassword"] = "p", ["SigningCertPassword"] = "s" };
        var batches = SqlServerSetupPlanner.Batches(File.ReadAllText(path), variables);
        Assert.That(batches, Has.Count.GreaterThan(1));
        Assert.That(string.Concat(batches), Does.Not.Contain("$("));
    }

    static string RepoRoot()
    {
        var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
        while (directory is not null && !Directory.Exists(Path.Combine(directory.FullName, "src", "Tiresias.Broker")))
            directory = directory.Parent;
        return directory?.FullName ?? throw new DirectoryNotFoundException("repository root");
    }
}
