using System.ComponentModel;
using System.Diagnostics;
using System.Net.Http.Json;
using Tiresias.Protocol;

namespace Tiresias.Remote;

static class Program
{
    static async Task<int> Main(string[] args)
    {
        if (RemoteCommand.Parse(args) is not { } command)
        {
            Console.Error.WriteLine(RemoteCommand.Usage);
            return 2;
        }
        if (Environment.GetEnvironmentVariable(DevcontainerWire.TicketVariable) is not { Length: > 0 } ticket)
        {
            Console.Error.WriteLine($"No {DevcontainerWire.TicketVariable}: add \"{DevcontainerWire.TicketVariable}\": \"${{localEnv:{DevcontainerWire.TicketVariable}}}\" to remoteEnv in devcontainer.json, and start VS Code with tir run -- code <folder>.");
            return 1;
        }
        var reply = await AskAsync(ticket, command.Names);
        if (reply.Message is { } message)
            Console.Error.WriteLine(message);
        if (!reply.Approved || reply.Variables is not { } variables)
            return 1;
        if (command.Command.Count == 0)
        {
            if (!variables.TryGetValue(command.Names![0], out var value))
                return 1;
            Console.WriteLine(value);
            return 0;
        }
        var start = new ProcessStartInfo(command.Command[0]) { UseShellExecute = false };
        foreach (var arg in command.Command.Skip(1))
            start.ArgumentList.Add(arg);
        foreach (var (name, value) in variables)
            start.Environment[name] = value;
        // The ticket opens nothing the command needs.
        start.Environment.Remove(DevcontainerWire.TicketVariable);
        try
        {
            using var child = Process.Start(start)!;
            await child.WaitForExitAsync();
            return child.ExitCode;
        }
        catch (Win32Exception e)
        {
            // 127, as a shell answers for a command it can't run.
            Console.Error.WriteLine($"Could not start {command.Command[0]} ({e.Message}). For a shell command, run it through the shell: tir-remote run -- sh -c \"{string.Join(' ', command.Command)}\"");
            return 127;
        }
    }

    static async Task<DevcontainerReply> AskAsync(string ticket, IReadOnlyList<string>? names)
    {
        // Consent waits for the user, so no short timeout.
        using var http = new HttpClient { BaseAddress = new($"http://{DevcontainerWire.Host}:{DevcontainerWire.Port}"), Timeout = TimeSpan.FromMinutes(3) };
        using var request = new HttpRequestMessage(HttpMethod.Post, DevcontainerWire.EnvironmentPath)
        {
            Content = JsonContent.Create(new DevcontainerRequest(names), options: DevcontainerWire.Json),
        };
        request.Headers.TryAddWithoutValidation("Authorization", $"{DevcontainerWire.Scheme} {ticket}");
        try
        {
            using var response = await http.SendAsync(request);
            return await response.Content.ReadFromJsonAsync<DevcontainerReply>(DevcontainerWire.Json)
                ?? new(false, Message: "The Tiresias app sent an empty reply.");
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException)
        {
            return new(false, Message: $"Can't reach the Tiresias app at {DevcontainerWire.Host}:{DevcontainerWire.Port}: is it running, with Docker Desktop? ({e.Message})");
        }
    }
}
