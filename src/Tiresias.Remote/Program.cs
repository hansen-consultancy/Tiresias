using System.ComponentModel;
using System.Diagnostics;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
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
        if (command.Git is { } action)
            return await GitAsync(action);
        if (Ticket() is not { } ticket)
            return 1;
        var reply = await AskAsync(ticket, DevcontainerWire.EnvironmentPath, new DevcontainerRequest(command.Names), RemoteJson.Default.DevcontainerRequest, RemoteJson.Default.DevcontainerReply)
            ?? new(false, Message: Unreachable);
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

    /// <summary>
    /// git's credential helper. Only <c>get</c> asks; <c>store</c> and <c>erase</c> keep nothing to
    /// change. Answering nothing, with exit 0, lets git try its next helper or prompt, as the
    /// protocol expects of a helper that has no credential.
    /// </summary>
    static async Task<int> GitAsync(string action)
    {
        var input = GitCredential.Read(ReadLines(Console.In));
        if (action != "get" || Environment.GetEnvironmentVariable(DevcontainerWire.TicketVariable) is not { Length: > 0 } ticket)
            return 0;
        var reply = await AskAsync(ticket, DevcontainerWire.GitPath,
            new DevcontainerGitRequest(input.GetValueOrDefault("protocol"), input.GetValueOrDefault("host")), RemoteJson.Default.DevcontainerGitRequest, RemoteJson.Default.DevcontainerGitReply)
            ?? new(false, Message: Unreachable);
        if (reply.Message is { } message)
            Console.Error.WriteLine($"tir-remote: {message}");
        if (reply is { Approved: true, Username: { } username, Password: { } password })
        {
            if (GitCredential.Answer(username, password) is { } answer)
                Console.Out.Write(answer);
            else
                Console.Error.WriteLine("tir-remote: the token holds a line break, which git can't take.");
        }
        return 0;

        static IEnumerable<string> ReadLines(TextReader reader)
        {
            while (reader.ReadLine() is { } line)
                yield return line;
        }
    }

    static string? Ticket()
    {
        if (Environment.GetEnvironmentVariable(DevcontainerWire.TicketVariable) is { Length: > 0 } ticket)
            return ticket;
        Console.Error.WriteLine($"No {DevcontainerWire.TicketVariable}: add \"{DevcontainerWire.TicketVariable}\": \"${{localEnv:{DevcontainerWire.TicketVariable}}}\" to remoteEnv in devcontainer.json, and start VS Code with tir run -- code <folder>.");
        return null;
    }

    static readonly string Unreachable = $"Can't reach the Tiresias app at {DevcontainerWire.Host}:{DevcontainerWire.Port}: is it running, with Docker Desktop?";

    /// <returns><c>null</c> when the app can't be reached or sent no reply.</returns>
    static async Task<TReply?> AskAsync<TRequest, TReply>(string ticket, string path, TRequest body, JsonTypeInfo<TRequest> requestType, JsonTypeInfo<TReply> replyType)
        where TReply : class
    {
        // Consent waits for the user, so no short timeout.
        using var http = new HttpClient { BaseAddress = new($"http://{DevcontainerWire.Host}:{DevcontainerWire.Port}"), Timeout = TimeSpan.FromMinutes(3) };
        using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body, requestType) };
        request.Headers.TryAddWithoutValidation("Authorization", $"{DevcontainerWire.Scheme} {ticket}");
        try
        {
            using var response = await http.SendAsync(request);
            return await response.Content.ReadFromJsonAsync(replyType);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or JsonException)
        {
            Console.Error.WriteLine($"tir-remote: {e.Message}");
            return null;
        }
    }
}

/// <summary>The wire's JSON, generated so a trimmed build needs no reflection; the same options as <see cref="DevcontainerWire.Json"/>.</summary>
[JsonSourceGenerationOptions(JsonSerializerDefaults.Web, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(DevcontainerRequest))]
[JsonSerializable(typeof(DevcontainerReply))]
[JsonSerializable(typeof(DevcontainerGitRequest))]
[JsonSerializable(typeof(DevcontainerGitReply))]
sealed partial class RemoteJson : JsonSerializerContext;
