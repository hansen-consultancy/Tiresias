using Tiresias.Forwarder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

var builder = WebApplication.CreateBuilder(args);

if (LoopbackGuard.NonLoopback(builder.Configuration) is { Count: > 0 } exposed)
    throw new InvalidOperationException($"The forwarder listens on loopback only; refusing to start on: {string.Join(", ", exposed)}");

builder.Services.Configure<ForwarderOptions>(builder.Configuration.GetSection("Forwarder"));
builder.Services.AddSingleton<IClientProcessLookup>(OperatingSystem.IsWindows() ? new WindowsClientProcessLookup() : new NoClientProcessLookup());
builder.Services.AddSingleton<SvcForwarder>();
builder.Services.AddHttpClient(SvcForwarder.ClientName)
    .ConfigureHttpClient(c => c.Timeout = TimeSpan.FromMinutes(10))
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false });

var app = builder.Build();

// Belt and braces: whatever configuration source the guard didn't know about, the addresses
// actually bound must be loopback too.
app.Lifetime.ApplicationStarted.Register(() =>
{
    var bound = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?.Addresses ?? [];
    if (bound.FirstOrDefault(a => !LoopbackGuard.IsLoopback(a)) is { } open)
    {
        app.Logger.LogCritical("Bound to non-loopback address {Address}; stopping.", open);
        app.Lifetime.StopApplication();
    }
});

app.Map("/svc/{**rest}", (HttpContext context, SvcForwarder forwarder) => forwarder.HandleAsync(context));
app.Map("/raven/{**rest}", (HttpContext context, SvcForwarder forwarder) => forwarder.HandleAsync(context));
app.MapPost("/sql/{**rest}", (HttpContext context, SvcForwarder forwarder) => forwarder.HandleAsync(context));

app.Run();

public partial class Program;
