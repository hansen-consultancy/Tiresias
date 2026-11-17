using Tiresias.Broker;

BrokerHost.Build(WebApplication.CreateBuilder(args)).Run();

/// <summary>The entry point, public so tests can host the broker with <c>WebApplicationFactory</c>.</summary>
public partial class Program;
