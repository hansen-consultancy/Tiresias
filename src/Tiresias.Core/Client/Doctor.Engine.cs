using System.Text.Json;

namespace Tiresias.Client;

/// <summary>Which environments to look inside (docs/containers-and-vms.md, "Consent"). Only Docker so far.</summary>
[Flags]
public enum ReachScope { None = 0, Docker = 1 }

/// <summary>A container, running or stopped, as the engine lists it. Names only: <paramref name="Env"/> holds what <see cref="NameScan"/> kept.</summary>
/// <param name="ImageId">The image it was made from, to tell its own variables from the image's.</param>
/// <param name="Mounts">Host paths mounted into it, as the engine reports them.</param>
/// <param name="Workspace">The project folder VS Code's Dev Containers started it for (its <c>devcontainer.local_folder</c> label).</param>
public sealed record EngineContainer(string Name, bool Running, string ImageId, IReadOnlyList<ScannedName> Env, IReadOnlyList<string> Mounts, string? Workspace);

/// <summary>An image and the variables its <c>ENV</c> lines set, by name.</summary>
public sealed record EngineImage(string Id, string Tag, IReadOnlyList<ScannedName> Env);

/// <summary>What one engine holds, from read-only API calls through <paramref name="Pipe"/>.</summary>
public sealed record EngineContents(string Pipe, IReadOnlyList<EngineContainer> Containers, IReadOnlyList<EngineImage> Images);

/// <summary>What was found inside, when the user asked to look (<c>tir doctor --reach</c>, or Home's card).</summary>
/// <param name="Docker"><c>null</c> when no engine answered.</param>
public sealed record ReachContents(EngineContents? Docker);

/// <summary>
/// The Docker engine API's JSON, read for names: no value in <c>Config.Env</c> becomes a string.
/// Each method takes one response; malformed input yields nothing.
/// </summary>
public static class EngineScan
{
    /// <summary>One container from <c>GET /containers/json?all=1</c>, before its environment is read.</summary>
    public sealed record Listed(string Id, string Name, bool Running, string ImageId, IReadOnlyList<string> Mounts, string? Workspace);

    /// <summary><c>GET /containers/json?all=1</c>.</summary>
    public static IReadOnlyList<Listed> Containers(ReadOnlySpan<byte> json)
    {
        List<Listed> found = [];
        try
        {
            var reader = new Utf8JsonReader(json);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartArray)
                return [];
            while (reader.Read() && reader.TokenType == JsonTokenType.StartObject)
            {
                string? id = null, name = null, image = null, workspace = null;
                var running = false;
                List<string> mounts = [];
                while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
                {
                    var property = reader.GetString();
                    reader.Read();
                    switch (property)
                    {
                        case "Id" when reader.TokenType == JsonTokenType.String:
                            id = reader.GetString();
                            break;
                        case "ImageID" when reader.TokenType == JsonTokenType.String:
                            image = reader.GetString();
                            break;
                        case "State" when reader.TokenType == JsonTokenType.String:
                            running = reader.ValueTextEquals("running"u8);
                            break;
                        case "Names" when reader.TokenType == JsonTokenType.StartArray:
                            while (reader.Read() && reader.TokenType == JsonTokenType.String)
                                name ??= reader.GetString()!.TrimStart('/');
                            break;
                        case "Labels" when reader.TokenType == JsonTokenType.StartObject:
                            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
                            {
                                var folder = reader.ValueTextEquals("devcontainer.local_folder"u8);
                                reader.Read();
                                if (folder && reader.TokenType == JsonTokenType.String)
                                    workspace = reader.GetString();
                                else
                                    reader.Skip();
                            }
                            break;
                        case "Mounts" when reader.TokenType == JsonTokenType.StartArray:
                            while (reader.Read() && reader.TokenType == JsonTokenType.StartObject)
                                while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
                                {
                                    var source = reader.ValueTextEquals("Source"u8);
                                    reader.Read();
                                    if (source && reader.TokenType == JsonTokenType.String && reader.GetString() is { Length: > 0 } path)
                                        mounts.Add(path);
                                    else
                                        reader.Skip();
                                }
                            break;
                        default:
                            reader.Skip();
                            break;
                    }
                }
                if (id is not null)
                    found.Add(new(id, name ?? id[..Math.Min(12, id.Length)], running, image ?? "", mounts, workspace));
            }
        }
        catch (JsonException)
        {
            return [];
        }
        return found;
    }

    /// <summary><c>GET /images/json</c>: each image's id and first tag, or its short id when untagged.</summary>
    public static IReadOnlyList<(string Id, string Tag)> Images(ReadOnlySpan<byte> json)
    {
        List<(string, string)> found = [];
        try
        {
            var reader = new Utf8JsonReader(json);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartArray)
                return [];
            while (reader.Read() && reader.TokenType == JsonTokenType.StartObject)
            {
                string? id = null, tag = null;
                while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
                {
                    var property = reader.GetString();
                    reader.Read();
                    if (property == "Id" && reader.TokenType == JsonTokenType.String)
                        id = reader.GetString();
                    else if (property == "RepoTags" && reader.TokenType == JsonTokenType.StartArray)
                        while (reader.Read() && reader.TokenType == JsonTokenType.String)
                            tag ??= reader.GetString() is { } t && t != "<none>:<none>" ? t : null;
                    else
                        reader.Skip();
                }
                if (id is not null)
                    found.Add((id, tag ?? ShortId(id)));
            }
        }
        catch (JsonException)
        {
            return [];
        }
        return found;
    }

    /// <summary><c>Config.Env</c> of <c>GET /containers/{id}/json</c> or <c>GET /images/{id}/json</c>, as names.</summary>
    public static IReadOnlyList<ScannedName> Env(ReadOnlySpan<byte> json)
    {
        List<ScannedName> names = [];
        try
        {
            var reader = new Utf8JsonReader(json);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
                return [];
            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                var config = reader.ValueTextEquals("Config"u8);
                reader.Read();
                if (!config || reader.TokenType != JsonTokenType.StartObject)
                {
                    reader.Skip();
                    continue;
                }
                while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
                {
                    var env = reader.ValueTextEquals("Env"u8);
                    reader.Read();
                    if (env && reader.TokenType == JsonTokenType.StartArray)
                        while (reader.Read() && reader.TokenType == JsonTokenType.String)
                        {
                            if (NameScan.Entry(reader.ValueSpan) is { } entry)
                                names.Add(entry);
                        }
                    else
                        reader.Skip();
                }
            }
        }
        catch (JsonException)
        {
            return [];
        }
        return names;
    }

    static string ShortId(string id) => (id.StartsWith("sha256:", StringComparison.Ordinal) ? id[7..] : id) is var hex && hex.Length > 12 ? hex[..12] : hex;
}

public static partial class Doctor
{
    public const string DockerContentsCheck = "docker contents";

    /// <summary>Folders and files under a home that hold credentials: mounting one hands a container the keys.</summary>
    static readonly HashSet<string> CredentialFolders = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ssh", ".aws", ".azure", ".kube", ".docker", ".gnupg", "gcloud", ".git-credentials", ".netrc", ".npmrc", ".pypirc", ".nuget",
    };

    /// <summary>
    /// What is inside the Docker engine, when the user asked to look: a container's own secret-looking
    /// variables, an image's baked-in ones, and credential folders mounted into a container. Not asked,
    /// one passing line says how to look, while an engine is open.
    /// </summary>
    public static IEnumerable<DoctorCheck> Contents(ReachFacts facts, ReachContents? contents)
    {
        if (contents is null)
        {
            if (facts.Engines.Any(e => e.GrantedTo.Count > 0))
                yield return new(DockerContentsCheck, DoctorStatus.Ok,
                    "not looked inside: tir doctor --reach, or Check now on Home, lists the secret-looking names in your containers and images, never their values");
            yield break;
        }
        if (contents.Docker is not { } docker)
        {
            yield return new(DockerContentsCheck, DoctorStatus.Ok, "Docker didn't answer, so nothing was looked inside: start it and check again");
            yield break;
        }

        var images = docker.Images.ToDictionary(i => i.Id, StringComparer.Ordinal);
        var findings = 0;
        foreach (var container in docker.Containers)
        {
            var image = images.GetValueOrDefault(container.ImageId);
            var fromImage = new HashSet<string>(image?.Env.Select(n => n.Name) ?? [], StringComparer.Ordinal);
            var own = container.Env.Where(n => n.LooksSecret && !fromImage.Contains(n.Name)).ToArray();
            var state = container.Running ? "running" : "stopped";
            if (own.Length > 0)
            {
                findings++;
                var devcontainer = container.Workspace is null ? "" : $", the devcontainer for {container.Workspace}";
                yield return new($"container {container.Name}", DoctorStatus.Warn,
                    $"{string.Join(", ", own.Select(n => n.Shown))}: in the environment of this {state} container{devcontainer}, which the engine shows any program you run",
                    new InjectAtRunTime([.. own.Select(n => n.Name)], PastableFolder(container.Workspace), Word(container.Name), Word(image?.Tag)),
                    Position.Plaintext, Position.SealedApproved, "containers holding secrets");
            }
            var mounted = container.Mounts.Where(IsCredentialFolder).ToArray();
            if (mounted.Length > 0)
            {
                findings++;
                yield return new($"mounts of {container.Name}", DoctorStatus.Warn,
                    $"{string.Join(", ", mounted)} {(mounted.Length == 1 ? "is" : "are")} mounted into this {state} container: whatever runs in it can use those credentials",
                    new ReachGuide(ReachTopic.ContainerMounts), Kind: "containers with your credential folders mounted");
            }
        }
        foreach (var image in docker.Images)
        {
            var baked = image.Env.Where(n => n.LooksSecret).ToArray();
            if (baked.Length == 0)
                continue;
            findings++;
            yield return new($"image {image.Tag}", DoctorStatus.Warn,
                $"{string.Join(", ", baked.Select(n => n.Shown))}: set by the image's ENV lines, so every container made from it and anyone holding a copy has them",
                new InjectAtRunTime([.. baked.Select(n => n.Name)], Image: Word(image.Tag), Baked: true),
                Now: Position.Plaintext, Kind: "images with secrets baked in");
        }
        if (findings == 0)
            yield return new(DockerContentsCheck, DoctorStatus.Ok,
                $"looked inside {docker.Containers.Count} containers and {docker.Images.Count} images through {docker.Pipe}: no secret-looking names in their environments, and no credential folder mounted");
    }

    /// <summary>The last segment of a host path (Windows, or the engine's <c>/run/desktop/mnt/host/c/…</c>), as a credential folder.</summary>
    static bool IsCredentialFolder(string source) =>
        CredentialFolders.Contains(source.TrimEnd('/', '\\').Split('/', '\\')[^1]);

    /// <summary>
    /// A name or tag from the engine, only when it can go into a command the user pastes. The engine
    /// is anyone's to fill (an image pulled from a registry carries its own labels), so a value with a
    /// quote, <c>$</c> or <c>&amp;</c> is left out and the fix falls back to its generic form.
    /// </summary>
    static string? Word(string? value) => value is not null && Pastable(value) ? value : null;

    /// <summary>A <c>devcontainer.local_folder</c> label, only when it can go into a pasted command (see <see cref="Word"/>).</summary>
    internal static string? PastableFolder(string? folder) => folder is not null && Pastable(folder, path: true) ? folder : null;
}
