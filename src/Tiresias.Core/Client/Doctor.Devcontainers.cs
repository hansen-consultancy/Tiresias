using System.Text.Json;

namespace Tiresias.Client;

/// <summary>Names found in one place of a devcontainer: <c>containerEnv</c>, <c>remoteEnv</c>, <c>runArgs</c>, or an env file it names (relative to the workspace).</summary>
public sealed record DevcontainerSource(string Where, IReadOnlyList<ScannedName> Names);

/// <summary>A <c>devcontainer.json</c> in a project folder, the folder it opens, and the names in it and its env files. Never a value.</summary>
public sealed record DevcontainerFile(string Path, string Workspace, IReadOnlyList<DevcontainerSource> Sources);

/// <summary>What VS Code's Dev Containers forwards into the containers it starts, from the user's settings.</summary>
public sealed record DevcontainerForwarding(bool GitCredentials, bool DockerCredentials);

/// <summary>Reads a <c>devcontainer.json</c> (JSON with comments) for names, through <see cref="NameScan"/>'s rules.</summary>
public static class DevcontainerScan
{
    /// <param name="EnvFiles">The <c>--env-file</c> paths in <c>runArgs</c>, as written.</param>
    public sealed record Contents(IReadOnlyList<DevcontainerSource> Sources, IReadOnlyList<string> EnvFiles)
    {
        public static readonly Contents None = new([], []);
    }

    static readonly JsonReaderOptions Jsonc = new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    /// <summary>The names in <c>containerEnv</c>, <c>remoteEnv</c> and <c>runArgs</c>' <c>-e</c>, and the env files <c>runArgs</c> names. Malformed JSON has none.</summary>
    public static Contents Read(ReadOnlySpan<byte> json)
    {
        List<DevcontainerSource> sources = [];
        List<string> envFiles = [];
        try
        {
            var reader = new Utf8JsonReader(json, Jsonc);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
                return Contents.None;
            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                var property = reader.GetString();
                reader.Read();
                if (property is "containerEnv" or "remoteEnv" && reader.TokenType == JsonTokenType.StartObject)
                    sources.Add(new(property, Properties(ref reader)));
                else if (property is "runArgs" && reader.TokenType == JsonTokenType.StartArray)
                {
                    var env = RunArgs(ref reader, envFiles);
                    if (env.Count > 0)
                        sources.Add(new(property, env));
                }
                else
                    reader.Skip();
            }
        }
        catch (JsonException)
        {
            return Contents.None;
        }
        return new(sources, envFiles);
    }

    static List<ScannedName> Properties(ref Utf8JsonReader reader)
    {
        List<ScannedName> names = [];
        while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
        {
            var name = reader.GetString()!;
            reader.Read();
            switch (reader.TokenType)
            {
                case JsonTokenType.String:
                    names.Add(NameScan.Facts(name, reader.ValueSpan));
                    break;
                case JsonTokenType.Number or JsonTokenType.True or JsonTokenType.False:
                    names.Add(new(name, false, false, false, false));
                    break;
                default:
                    reader.Skip();
                    break;
            }
        }
        return names;
    }

    /// <summary><c>-e NAME=value</c>, <c>--env NAME=value</c>, <c>--env=NAME=value</c>, and <c>--env-file</c> in either form. <c>-e NAME</c> alone passes the host's value and holds none.</summary>
    static List<ScannedName> RunArgs(ref Utf8JsonReader reader, List<string> envFiles)
    {
        List<ScannedName> env = [];
        var next = "";
        while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
        {
            if (reader.TokenType != JsonTokenType.String)
            {
                reader.Skip();
                next = "";
                continue;
            }
            var arg = reader.ValueSpan;
            if (next == "env" && NameScan.Entry(arg) is { } entry)
                env.Add(entry);
            else if (next == "file")
                envFiles.Add(reader.GetString()!);
            else if (arg.StartsWith("--env="u8) && NameScan.Entry(arg[6..]) is { } inline)
                env.Add(inline);
            else if (arg.StartsWith("--env-file="u8))
                envFiles.Add(reader.GetString()!["--env-file=".Length..]);
            next = next == "" && (arg.SequenceEqual("-e"u8) || arg.SequenceEqual("--env"u8)) ? "env"
                : next == "" && arg.SequenceEqual("--env-file"u8) ? "file"
                : "";
        }
        return env;
    }

    /// <summary>
    /// The folder a devcontainer file opens: the one holding <c>.devcontainer.json</c> or the
    /// <c>.devcontainer</c> folder; <c>null</c> for a <c>devcontainer.json</c> anywhere else, which VS Code doesn't use.
    /// </summary>
    public static string? Workspace(string path)
    {
        var folder = Path.GetDirectoryName(path);
        if (folder is null)
            return null;
        if (Path.GetFileName(path).Equals(".devcontainer.json", StringComparison.OrdinalIgnoreCase))
            return folder;
        if (!Path.GetFileName(path).Equals("devcontainer.json", StringComparison.OrdinalIgnoreCase))
            return null;
        if (IsDevcontainerFolder(folder))
            return Path.GetDirectoryName(folder);
        var parent = Path.GetDirectoryName(folder);
        return parent is not null && IsDevcontainerFolder(parent) ? Path.GetDirectoryName(parent) : null;

        static bool IsDevcontainerFolder(string folder) => Path.GetFileName(folder).Equals(".devcontainer", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Where an <c>--env-file</c> may be, in order: <c>${localWorkspaceFolder}</c> filled in, a relative path against the workspace, then against the file's folder.</summary>
    public static IEnumerable<string> EnvFileCandidates(string envFile, string workspace, string configFolder)
    {
        envFile = envFile.Replace("${localWorkspaceFolder}", workspace, StringComparison.Ordinal);
        if (Path.IsPathFullyQualified(envFile))
            return [Path.GetFullPath(envFile)];
        return [Path.GetFullPath(Path.Combine(workspace, envFile)), Path.GetFullPath(Path.Combine(configFolder, envFile))];
    }

    /// <summary>VS Code's user <c>settings.json</c>: forwarding stays on unless the setting turns it off.</summary>
    public static DevcontainerForwarding Forwarding(ReadOnlySpan<byte> json)
    {
        bool git = true, docker = true;
        try
        {
            var reader = new Utf8JsonReader(json, Jsonc);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
                return new(git, docker);
            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                var gitSetting = reader.ValueTextEquals("dev.containers.gitCredentialHelperConfigLocation"u8);
                var dockerSetting = reader.ValueTextEquals("dev.containers.dockerCredentialHelper"u8);
                reader.Read();
                if (gitSetting && reader.TokenType == JsonTokenType.String)
                    git = !reader.ValueTextEquals("none"u8);
                else if (dockerSetting)
                    docker = reader.TokenType != JsonTokenType.False;
                else
                    reader.Skip();
            }
        }
        catch (JsonException)
        {
            // VS Code reads what it can of a broken file too; the defaults stand.
        }
        return new(git, docker);
    }
}

public static partial class Doctor
{
    public const string ForwardingCheck = "devcontainer forwarding";

    /// <summary>
    /// A devcontainer file holding a secret-looking value is a finding per file, fixed by handing the
    /// value in at start (<see cref="InjectAtRunTime"/>). Dev Containers forwarding the host's git
    /// credentials or registry logins is a finding with steps; turned off, a passing line.
    /// </summary>
    public static IEnumerable<DoctorCheck> Devcontainers(IEnumerable<DevcontainerFile> files, DevcontainerForwarding? forwarding)
    {
        foreach (var file in files)
        {
            var found = file.Sources
                .Select(s => (s.Where, Names: s.Names.Where(n => n.LooksSecret).ToArray()))
                .Where(s => s.Names.Length > 0).ToArray();
            if (found.Length == 0)
                continue;
            var names = found.SelectMany(s => s.Names.Select(n => n.Name)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            yield return new($"devcontainer {file.Path}", DoctorStatus.Warn,
                $"{string.Join("; ", found.Select(s => $"{s.Where}: {string.Join(", ", s.Names.Select(n => n.Shown))}"))}: in plain text, which any program running as you can read. "
                + "Hand them in when the container starts instead",
                new InjectAtRunTime(file.Workspace, names), Position.Plaintext, Position.SealedApproved, "devcontainer files holding secrets");
        }

        if (forwarding is null)
            yield break;
        var what = (forwarding.GitCredentials, forwarding.DockerCredentials) switch
        {
            (true, true) => "your git credentials and Docker registry logins",
            (true, false) => "your git credentials",
            (false, true) => "your Docker registry logins",
            _ => null,
        };
        yield return what is null
            ? new(ForwardingCheck, DoctorStatus.Ok, "VS Code's Dev Containers forwards neither your git credentials nor your Docker registry logins")
            : new(ForwardingCheck, DoctorStatus.Warn,
                $"VS Code's Dev Containers forwards {what} into every container it starts: any program running inside one can ask your host for them",
                new ReachGuide(ReachTopic.DevcontainerForwarding));
    }
}

/// <summary>
/// Take secrets out of a devcontainer file and hand them in when VS Code starts it: sealed in the
/// workspace's folder set, given to VS Code by <c>tir run</c>, read by <c>remoteEnv</c>'s
/// <c>${localEnv:NAME}</c>. <c>remoteEnv</c> isn't in the container's config, so the engine doesn't show it either.
/// </summary>
public sealed record InjectAtRunTime(string Folder, IReadOnlyList<string> Names) : DoctorFix
{
    /// <summary>The commands to run, one per line, which the app copies.</summary>
    public string Commands => string.Join("\n",
        Names.Select(n => $"tir env set {n} --folder \"{Folder}\"").Append($"cd \"{Folder}\"").Append("tir run -- code ."));

    public override string Instruction =>
        $"in the devcontainer file, put each in remoteEnv as \"NAME\": \"${{localEnv:NAME}}\" and delete its value from containerEnv, runArgs and env files. "
        + $"Seal them, quit VS Code, and start it through tir run, which hands them over after you approve: {Commands.Replace("\n", "; ", StringComparison.Ordinal)}";
}
