// WebApplication.CreateBuilder adds user secrets in Development; Tiresias reroutes that call at
// compile time, so this file has no Tiresias code at all.
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Says whether the secret arrived, never what it is.
app.MapGet("/", (IConfiguration config) => config["Demo:ApiKey"] is { Length: > 0 } key
    ? $"Demo:ApiKey is set ({key.Length} characters)."
    : "Demo:ApiKey is not set. Run: dotnet user-secrets set Demo:ApiKey example-value");

app.Run();
