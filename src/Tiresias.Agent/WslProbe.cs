using System.Diagnostics;
using Tiresias.Client;

namespace Tiresias.Agent;

/// <summary>
/// Looks in the homes of running WSL distributions for <see cref="Doctor.WslContents"/>, only when
/// the user asked. A stopped distribution is never touched: opening <c>\\wsl.localhost\name</c>
/// starts it. Known credential files are checked by existence; the few read for names go through
/// <see cref="NameScan"/>, so no value becomes a string.
/// </summary>
static class WslProbe
{
    /// <summary>More homes, or folders in a home searched for <c>.env</c>, than this are not looked at.</summary>
    const int MaxFolders = 200;

    static readonly TimeSpan ListTimeout = TimeSpan.FromSeconds(10);

    /// <summary><c>null</c> when there is no distribution or <c>wsl.exe</c> didn't answer; empty when none runs.</summary>
    public static async Task<IReadOnlyList<WslContents>?> ReadAsync(ReachFacts facts, CancellationToken ct)
    {
        var registered = facts.Distributions.Select(d => d.Name).Where(n => !Doctor.IsDockerDesktop(n) && IsPlainName(n)).ToArray();
        if (registered.Length == 0)
            return null;
        if (await RunningAsync(ct) is not { } output)
            return null;
        return await Task.Run(() => HomeScan.Running(output, registered).Select(Read).ToArray(), ct);
    }

    /// <summary>A name that stays one path segment under <c>\\wsl.localhost</c>.</summary>
    static bool IsPlainName(string name) =>
        name.Length > 0 && name is not ("." or "..") && name.IndexOfAny([.. Path.GetInvalidFileNameChars(), '/', '\\']) < 0;

    /// <summary><c>wsl.exe --list --running --quiet</c>'s bytes: listing starts nothing.</summary>
    static async Task<byte[]?> RunningAsync(CancellationToken ct)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "wsl.exe"))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in (string[])["--list", "--running", "--quiet"])
            start.ArgumentList.Add(argument);
        start.Environment["WSL_UTF8"] = "1";
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(ListTimeout);
        try
        {
            using var process = Process.Start(start);
            if (process is null)
                return null;
            try
            {
                using var output = new MemoryStream();
                var errors = process.StandardError.ReadToEndAsync(timeout.Token);
                await process.StandardOutput.BaseStream.CopyToAsync(output, timeout.Token);
                await process.WaitForExitAsync(timeout.Token);
                await errors;
                return output.ToArray();
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                process.Kill(entireProcessTree: true);
                return null;
            }
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return null;
        }
    }

    static WslContents Read(string distribution)
    {
        var root = $@"\\wsl.localhost\{distribution}";
        List<WslFile> files = [];
        foreach (var (home, shown) in Homes(root))
            files.AddRange(InHome(home, shown));
        return new(distribution, files);
    }

    /// <summary>Each <c>/home/*</c> and <c>/root</c>, with the Linux path a finding shows.</summary>
    static IEnumerable<(string Home, string Shown)> Homes(string root)
    {
        IEnumerable<string> users;
        try
        {
            users = Directory.EnumerateDirectories(Path.Combine(root, "home")).Take(MaxFolders).ToArray();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            users = [];
        }
        foreach (var user in users)
            yield return (user, $"/home/{Path.GetFileName(user)}");
        yield return (Path.Combine(root, "root"), "/root");
    }

    static IEnumerable<WslFile> InHome(string home, string shown)
    {
        foreach (var (path, kind) in HomeScan.Known)
            if (Found(Path.Combine(home, path), kind) is { } names)
                yield return new($"{shown}/{path}", names, kind == HomeFileKind.History);
        foreach (var key in Files(Path.Combine(home, ".ssh"), "id_*").Where(HomeScan.IsSshKey))
            if (Found(Path.Combine(home, ".ssh", key), HomeFileKind.Present) is not null)
                yield return new($"{shown}/.ssh/{key}", []);
        foreach (var folder in (string[])["", .. Folders(home)])
            if (Found(Path.Combine(home, folder, HomeScan.EnvFile), HomeFileKind.Env) is { } names)
                yield return new(folder.Length == 0 ? $"{shown}/{HomeScan.EnvFile}" : $"{shown}/{folder}/{HomeScan.EnvFile}", names);
    }

    /// <summary>
    /// The names <paramref name="path"/> holds, or <c>null</c> when it holds no credential. Only a
    /// regular, non-empty file counts: a link is not followed, and a FIFO is never opened, since a read
    /// from one would wait for a writer.
    /// </summary>
    static IReadOnlyList<string>? Found(string path, HomeFileKind kind)
    {
        try
        {
            var file = new FileInfo(path);
            if (!file.Exists || file.Length == 0 || file.Attributes.HasFlag(FileAttributes.ReparsePoint))
                return null;
            if (kind is HomeFileKind.Present or HomeFileKind.History)
                return [];
            if (file.Length > NameScan.MaxBytes)
                return null;
            using var stream = file.OpenRead();
            return NameScan.Read(stream, text => HomeScan.Names(kind, text));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    static string[] Files(string folder, string pattern)
    {
        try
        {
            return Directory.Exists(folder) ? [.. Directory.EnumerateFiles(folder, pattern).Select(Path.GetFileName).OfType<string>().Take(MaxFolders)] : [];
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    static string[] Folders(string home)
    {
        try
        {
            return [.. new DirectoryInfo(home).EnumerateDirectories()
                .Where(d => !d.Attributes.HasFlag(FileAttributes.ReparsePoint)).Select(d => d.Name).Take(MaxFolders)];
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }
}
