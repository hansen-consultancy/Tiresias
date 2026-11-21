using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Tiresias.Admin;
using Tiresias.Protocol;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = AdminWire.ServiceName);
builder.Services.AddHostedService<AdminPipeService>();
await builder.Build().RunAsync();
