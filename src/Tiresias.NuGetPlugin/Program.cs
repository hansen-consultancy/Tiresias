using System.Text;
using Tiresias.Agent;
using Tiresias.EnvironmentVariables;

// NuGet starts the plugin with -Plugin and talks over standard input and output, so nothing else
// may be written there. Started by hand, it explains itself instead.
if (!args.Contains("-Plugin", StringComparer.OrdinalIgnoreCase))
{
    Console.WriteLine("""
        Tiresias's NuGet credential plugin. NuGet starts it; you don't need to.
        It answers for package sources mapped to a sealed environment variable (tir env nuget add),
        after you allow the program asking in the Tiresias app.
        """);
    return 0;
}

var utf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
Console.InputEncoding = utf8;
Console.OutputEncoding = utf8;

// Long enough for the user to answer the app's dialog, which denies one nobody answers well before this.
var consentWait = TimeSpan.FromMinutes(10);

var plugin = new NuGetCredentialPlugin(Console.In, Console.Out, async (uri, isRetry, ct) =>
{
    ControlReply? reply;
    try
    {
        reply = await ControlClient.TryAsync(new(ControlRequest.NuGetCredential, Title: uri.ToString(), AskAgain: isRetry), consentWait);
    }
    catch (Exception e) when (e is IOException or OperationCanceledException)
    {
        reply = null;
    }
    return reply switch
    {
        null => new(null, null, "Tiresias: the app isn't running, so sealed NuGet credentials are unavailable."),
        { Approved: true, Password: { } password } => new(reply.Username, password),
        _ => new(null, null, reply.Message is { } note ? $"Tiresias: {note}" : null),
    };
});
await plugin.RunAsync(CancellationToken.None);
return 0;
