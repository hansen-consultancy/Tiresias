using System.Text;
using System.Text.Json;

namespace Tiresias.Client;

/// <summary>A credential file found in a distribution, by its Linux path; never its contents.</summary>
/// <param name="Names">What the file holds by name: AWS profiles, registries, secret-looking <c>.env</c> names. Empty when the file's presence is the finding.</param>
/// <param name="MayHold">Shell history: it holds secrets only if a command did, so it never makes a finding on its own.</param>
public sealed record WslFile(string Path, IReadOnlyList<string> Names, bool MayHold = false);

/// <summary>What one running distribution's homes hold.</summary>
public sealed record WslContents(string Distribution, IReadOnlyList<WslFile> Files);

/// <summary>How a known file in a home is read for <see cref="WslFile.Names"/>.</summary>
public enum HomeFileKind
{
    /// <summary>Holding a credential is what the file is for: its presence is the finding.</summary>
    Present,
    /// <summary>An INI file: the sections that set <see cref="HomeScan.IniSecretKeys"/>.</summary>
    IniSections,
    /// <summary>Docker's <c>config.json</c>: registries under <c>auths</c> with a stored login.</summary>
    DockerAuths,
    /// <summary>A file that holds a credential only when a line sets one of <see cref="HomeScan.TokenKeys"/>.</summary>
    TokenLine,
    /// <summary>Shell history (<see cref="WslFile.MayHold"/>).</summary>
    History,
    /// <summary>A <c>.env</c> file: its secret-looking names.</summary>
    Env,
}

/// <summary>
/// Which files in a Linux home hold credentials (docs/containers-and-vms.md, "WSL contents"), and
/// scanners that read them for names. Like <see cref="NameScan"/>, no value becomes a string.
/// </summary>
public static class HomeScan
{
    /// <summary>Files under a home, by path relative to it. SSH keys and <c>.env</c> files are found by <see cref="IsSshKey"/> and <see cref="EnvFile"/>.</summary>
    public static readonly IReadOnlyList<(string Path, HomeFileKind Kind)> Known =
    [
        (".aws/credentials", HomeFileKind.IniSections),
        (".azure/msal_token_cache.json", HomeFileKind.Present),
        (".config/gcloud/credentials.db", HomeFileKind.Present),
        (".config/gcloud/application_default_credentials.json", HomeFileKind.Present),
        (".kube/config", HomeFileKind.Present),
        (".docker/config.json", HomeFileKind.DockerAuths),
        (".git-credentials", HomeFileKind.Present),
        (".netrc", HomeFileKind.Present),
        (".npmrc", HomeFileKind.TokenLine),
        (".pypirc", HomeFileKind.TokenLine),
        (".config/gh/hosts.yml", HomeFileKind.TokenLine),
        (".bash_history", HomeFileKind.History),
        (".zsh_history", HomeFileKind.History),
    ];

    public const string EnvFile = ".env";

    /// <summary>Keys whose value, in an AWS credentials section, is a secret.</summary>
    public static readonly string[] IniSecretKeys = ["aws_secret_access_key", "aws_session_token"];

    /// <summary>A key ending in one of these holds a token: npm's <c>//host/:_authToken</c>, <c>.pypirc</c>'s <c>password</c>, <c>gh</c>'s <c>oauth_token</c>.</summary>
    public static readonly string[] TokenKeys = ["_authToken", "_auth", "_password", "password", "oauth_token"];

    /// <summary>A private key in <c>~/.ssh</c>, as <c>ssh-keygen</c> names one: <c>id_*</c>, not its <c>.pub</c>.</summary>
    public static bool IsSshKey(string fileName) =>
        fileName.StartsWith("id_", StringComparison.Ordinal) && !fileName.EndsWith(".pub", StringComparison.Ordinal);

    /// <summary>The names a file holds, read as <paramref name="kind"/>; <c>null</c> when it holds no credential.</summary>
    public static IReadOnlyList<string>? Names(HomeFileKind kind, ReadOnlySpan<byte> text) => kind switch
    {
        HomeFileKind.Present or HomeFileKind.History => [],
        HomeFileKind.IniSections => NonEmpty(IniSections(text)),
        HomeFileKind.DockerAuths => NonEmpty(DockerAuths(text)),
        HomeFileKind.TokenLine => HasToken(text) ? [] : null,
        _ => NonEmpty([.. NameScan.EnvLines(text).Where(n => n.LooksSecret).Select(n => n.Shown)]),
    };

    static IReadOnlyList<string>? NonEmpty(IReadOnlyList<string> names) => names.Count > 0 ? names : null;

    /// <summary>The <c>[section]</c>s in which a line sets a non-empty <see cref="IniSecretKeys"/>.</summary>
    public static IReadOnlyList<string> IniSections(ReadOnlySpan<byte> text)
    {
        List<string> found = [];
        string? section = null;
        foreach (var range in text.Split((byte)'\n'))
        {
            var line = text[range].Trim("\r \t"u8);
            if (line is [(byte)'[', .., (byte)']'])
                section = Encoding.UTF8.GetString(line[1..^1].Trim(" \t"u8));
            else if (section is not null && !found.Contains(section) && Setting(line, (byte)'=', out var key, out var value) && !value.IsEmpty
                && IsOneOf(key, IniSecretKeys, endsWith: false))
                found.Add(section);
        }
        return found;
    }

    static bool IsOneOf(ReadOnlySpan<byte> key, string[] names, bool endsWith)
    {
        foreach (var name in names)
        {
            var bytes = Encoding.UTF8.GetBytes(name);
            if (endsWith ? key.EndsWith(bytes) : key.SequenceEqual(bytes))
                return true;
        }
        return false;
    }

    /// <summary>Whether a line sets one of <see cref="TokenKeys"/> to a literal: npm's <c>${NPM_TOKEN}</c> is taken from the environment.</summary>
    public static bool HasToken(ReadOnlySpan<byte> text)
    {
        foreach (var range in text.Split((byte)'\n'))
        {
            var line = text[range].Trim("\r \t"u8);
            // npm's key holds a colon (//host/:_authToken=), YAML's value may hold an = (oauth_token: x=): try both.
            if (IsToken(line, (byte)'=') || IsToken(line, (byte)':'))
                return true;
        }
        return false;

        static bool IsToken(ReadOnlySpan<byte> line, byte separator) =>
            Setting(line, separator, out var key, out var value) && !value.IsEmpty && value[0] != (byte)'$' && IsOneOf(key, TokenKeys, endsWith: true);
    }

    /// <summary><c>key{separator}value</c>, comments skipped; the value unquoted.</summary>
    static bool Setting(ReadOnlySpan<byte> line, byte separator, out ReadOnlySpan<byte> key, out ReadOnlySpan<byte> value)
    {
        key = value = [];
        var at = line.IndexOf(separator);
        if (line.IsEmpty || line[0] is (byte)'#' or (byte)';' || at <= 0)
            return false;
        key = line[..at].Trim(" \t"u8);
        value = line[(at + 1)..].Trim(" \t"u8);
        if (value.Length >= 2 && value[0] is (byte)'"' or (byte)'\'' && value[^1] == value[0])
            value = value[1..^1];
        return true;
    }

    /// <summary>Registries in <c>auths</c> with a stored <c>auth</c> or <c>identitytoken</c>; one behind a credential helper stores neither.</summary>
    public static IReadOnlyList<string> DockerAuths(ReadOnlySpan<byte> json)
    {
        List<string> found = [];
        try
        {
            var reader = new Utf8JsonReader(json, new JsonReaderOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
                return [];
            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                var auths = reader.ValueTextEquals("auths"u8);
                reader.Read();
                if (!auths || reader.TokenType != JsonTokenType.StartObject)
                {
                    reader.Skip();
                    continue;
                }
                while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
                {
                    var registry = reader.GetString()!;
                    reader.Read();
                    if (reader.TokenType != JsonTokenType.StartObject)
                    {
                        reader.Skip();
                        continue;
                    }
                    var stored = false;
                    while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
                    {
                        var secret = reader.ValueTextEquals("auth"u8) || reader.ValueTextEquals("identitytoken"u8);
                        reader.Read();
                        stored |= secret && reader.TokenType == JsonTokenType.String && !reader.ValueSpan.IsEmpty;
                        reader.Skip();
                    }
                    if (stored)
                        found.Add(registry);
                }
            }
        }
        catch (JsonException)
        {
        }
        return found;
    }

    /// <summary>
    /// <c>wsl.exe --list --running --quiet</c>'s output: UTF-16LE from the inbox <c>wsl.exe</c>, UTF-8
    /// under <c>WSL_UTF8=1</c>. Only names in <paramref name="registered"/> are kept, so a message such
    /// as "no running distributions" is never taken for one.
    /// </summary>
    public static IReadOnlyList<string> Running(ReadOnlySpan<byte> output, IEnumerable<string> registered)
    {
        var text = output.Contains((byte)0) ? Encoding.Unicode.GetString(output) : Encoding.UTF8.GetString(output);
        var known = registered.ToHashSet(StringComparer.OrdinalIgnoreCase);
        return [.. text.TrimStart('﻿').Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Where(known.Contains).Distinct(StringComparer.OrdinalIgnoreCase)];
    }
}

public static partial class Doctor
{
    public const string WslContentsCheck = "wsl contents";

    /// <summary>
    /// What is in the homes of running WSL distributions, when the user asked to look: credential
    /// files, by path and the names they hold. A stopped distribution isn't read: opening its files
    /// would start it. Not asked, one passing line says how to look.
    /// </summary>
    public static IEnumerable<DoctorCheck> WslContents(ReachFacts facts, ReachContents? contents)
    {
        var registered = facts.Distributions.Select(d => d.Name).Where(n => !IsDockerDesktop(n)).ToArray();
        if (registered.Length == 0)
            yield break;
        if (contents is null)
        {
            yield return new(WslContentsCheck, DoctorStatus.Ok,
                "not looked inside: tir doctor --reach, or Check now on Home, lists the credential files in your running distributions, never their contents");
            yield break;
        }
        if (contents.Wsl is not { } distributions)
        {
            yield return new(WslContentsCheck, DoctorStatus.Ok, "WSL didn't answer, so no distribution was looked inside: check again");
            yield break;
        }

        var findings = 0;
        foreach (var distribution in distributions)
        {
            if (!distribution.Files.Any(f => !f.MayHold))
                continue;
            findings++;
            yield return new($"wsl {distribution.Distribution}", DoctorStatus.Warn,
                $"{string.Join(", ", distribution.Files.Select(Shown))}: in this running distribution, whose files any program you run can read through \\\\wsl.localhost",
                new ReachGuide(ReachTopic.Wsl, Distribution: Word(distribution.Distribution)),
                Position.Plaintext, Position.SealedApproved, "WSL distributions holding secrets");
        }
        var read = distributions.Select(d => d.Distribution).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var stopped = registered.Where(n => !read.Contains(n)).ToArray();
        var looked = $"looked inside {distributions.Count} running {(distributions.Count == 1 ? "distribution" : "distributions")}";
        var notRead = stopped.Length == 0 ? null
            : string.Join(", ", stopped) + (stopped.Length == 1
                ? " isn't running, so it was not read: opening its files would start it"
                : " aren't running, so they were not read: opening their files would start them");
        if (findings == 0)
            yield return new(WslContentsCheck, DoctorStatus.Ok,
                string.Join("; ", new[] { distributions.Count == 0 ? null : $"{looked}: no credential files in their homes", notRead }.OfType<string>()));
        else if (notRead is not null)
            yield return new(WslContentsCheck, DoctorStatus.Ok, $"{looked}; {notRead}");
    }

    static string Shown(WslFile file) =>
        file.MayHold ? $"{file.Path} (may hold commands with tokens)"
        : file.Names.Count > 0 ? $"{file.Path} [{string.Join(", ", file.Names)}]"
        : file.Path;

    /// <summary>Docker Desktop's own distributions: its engine, whose contents the Docker checks cover.</summary>
    public static bool IsDockerDesktop(string distribution) => distribution.StartsWith("docker-desktop", StringComparison.OrdinalIgnoreCase);
}
