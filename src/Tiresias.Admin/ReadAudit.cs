using System.ComponentModel;
using System.Diagnostics.Eventing.Reader;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using Tiresias.Agent;
using Tiresias.AdminTier;
using Tiresias.Decoys;

namespace Tiresias.Admin;

/// <summary>
/// Sees every read of a held decoy file (docs/admin-tier.md, <i>Every read named</i>): an audit rule
/// on each file (<see cref="AuditRules"/>), File System success auditing on while a set is held, and
/// event 4663 read from the Security log, from the last record handled (<c>audit.json</c>), so reads
/// while the service was stopped are still reported. Each read of a held file is reported once a
/// minute per program and file, with the processes that started it and whether its opener is a
/// routine one.
/// </summary>
sealed class ReadAudit : IDisposable
{
    /// <summary>Events that aren't reads of a held file move the record id forward; saving it this often is enough.</summary>
    static readonly TimeSpan SaveEvery = TimeSpan.FromSeconds(30);

    readonly string statePath;
    readonly ILogger logger;
    readonly Action<string, DecoyHit, IReadOnlyList<string>, string?> report;
    readonly Lock gate = new();
    readonly DecoyHitFilter repeatedReads = new();
    readonly Dictionary<string, string> files = new(StringComparer.Ordinal);
    readonly HashSet<string> audited = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, RoutineFolders> routine = new(StringComparer.OrdinalIgnoreCase);
    readonly bool privileged;
    AdminAuditState state;
    DateTime saved = DateTime.UtcNow;
    EventLogWatcher? watcher;

    /// <param name="report">A read of a user's file: the user's SID, the read, who started the reader, and the routine opener it is, if one.</param>
    public ReadAudit(string stateFolder, ILogger logger, Action<string, DecoyHit, IReadOnlyList<string>, string?> report)
    {
        statePath = Path.Combine(stateFolder, "audit.json");
        this.logger = logger;
        this.report = report;
        state = AdminAuditState.Parse(File.Exists(statePath) ? File.ReadAllText(statePath) : null);
        try
        {
            AuditRules.EnablePrivilege();
            privileged = true;
        }
        catch (Win32Exception e)
        {
            logger.LogError("Reads of held decoy files can't be audited: SeSecurityPrivilege can't be enabled ({Code})", e.NativeErrorCode);
        }
    }

    /// <summary>Whether every file of the user's held set carries the rule and the log is read.</summary>
    public bool Auditing(string sid)
    {
        lock (gate)
            return watcher is not null && audited.Contains(sid);
    }

    /// <summary>Sets the rule on each of the user's files and turns success auditing on, if it is off. Again for a set held before: a rule is never doubled.</summary>
    public void Hold(string sid, IReadOnlyList<string> paths)
    {
        if (!privileged)
            return;
        lock (gate)
        {
            try
            {
                var (turnOn, next) = state.Enable(AuditRules.SuccessOn());
                if (turnOn)
                    AuditRules.SetSuccess(true);
                state = next;
                Save();
            }
            catch (Win32Exception e)
            {
                logger.LogError("File System auditing can't be turned on ({Code}); reads of held decoy files go unseen", e.NativeErrorCode);
                return;
            }
            var all = true;
            foreach (var path in paths)
            {
                if (AuditRules.Add(path, sid) is { } refusal)
                {
                    // Never the path: the Application log is readable by the user, and which files are decoys is what holding them hides.
                    logger.LogWarning("A decoy file of {Sid} carries no audit rule: it {Refusal}", sid, refusal);
                    all = false;
                    continue;
                }
                files[AdminAudit.Normal(path)] = sid;
            }
            if (all)
                audited.Add(sid);
            else
                audited.Remove(sid);
            Watch();
        }
    }

    /// <summary>Takes the rules off a released set's files, and success auditing off when no set is left and the service turned it on.</summary>
    public void Release(string sid, IReadOnlyList<string> paths, int setsLeft)
    {
        EventLogWatcher? stopped = null;
        lock (gate)
        {
            audited.Remove(sid);
            foreach (var path in paths)
            {
                files.Remove(AdminAudit.Normal(path));
                if (privileged && AuditRules.Remove(path) is { } refusal && File.Exists(path))
                    logger.LogWarning("A released decoy file of {Sid} keeps its audit rule: it {Refusal}", sid, refusal);
            }
            Settle(setsLeft);
            if (files.Count == 0)
                (stopped, watcher) = (watcher, null);
        }
        // Outside the lock: disposing waits for a callback that may be waiting for it.
        stopped?.Dispose();
    }

    /// <summary>With no set held, puts the policy back as it was: after a release, or at start after one that stopped midway.</summary>
    public void Settle(int setsHeld)
    {
        lock (gate)
        {
            var (turnOff, next) = state.Release(setsHeld);
            if (!turnOff || !privileged)
                return;
            try
            {
                AuditRules.SetSuccess(false);
                state = next;
                Save();
            }
            catch (Win32Exception e)
            {
                logger.LogError("File System auditing can't be turned off again ({Code})", e.NativeErrorCode);
            }
        }
    }

    void Watch()
    {
        if (watcher is not null || files.Count == 0)
            return;
        try
        {
            // The first time, the log's end is where reading starts: what came before held nothing.
            if (state.LastRecordId == 0)
            {
                state = state.Handled(NewestRecord());
                Save();
            }
            watcher = new(new EventLogQuery("Security", PathType.LogName, AdminAudit.Query(state.LastRecordId)), null, readExistingEvents: true);
            watcher.EventRecordWritten += (_, e) => Written(e);
            watcher.Enabled = true;
        }
        catch (Exception e) when (e is EventLogException or UnauthorizedAccessException)
        {
            watcher?.Dispose();
            watcher = null;
            logger.LogError("The Security log can't be read ({Kind}); reads of held decoy files go unseen", e.GetType().Name);
        }
    }

    static long NewestRecord()
    {
        using var reader = new EventLogReader(new EventLogQuery("Security", PathType.LogName) { ReverseDirection = true });
        using var newest = reader.ReadEvent();
        return newest?.RecordId ?? 0;
    }

    void Written(EventRecordWrittenEventArgs e)
    {
        if (e.EventException is { } failed)
        {
            logger.LogError("The Security log can't be read ({Kind})", failed.GetType().Name);
            return;
        }
        if (e.EventRecord is not { } record)
            return;
        AuditedAccess? access;
        using (record)
            access = AdminAudit.Parse(record.ToXml());
        if (access is null)
            return;
        (string Sid, DecoyHit Hit)? read;
        RoutineFolders folders;
        lock (gate)
        {
            read = AdminAudit.Read(access, files);
            state = state.Handled(access.RecordId);
            if (read is not null || DateTime.UtcNow - saved >= SaveEvery)
                Save();
            if (read is not { } found)
                return;
            folders = Routine(found.Sid);
        }
        var (sid, hit) = read.Value;
        if (!repeatedReads.ShouldReport(hit))
            return;
        report(sid, hit, Parents(hit), DecoyReads.RoutineOpener(hit.Program, folders));
    }

    /// <summary>Only when the process under the event's id is the reader: an event read late may name an id reused since.</summary>
    static IReadOnlyList<string> Parents(DecoyHit hit)
    {
        if (hit.ProcessId is not { } pid)
            return [];
        var chain = ProcessTree.Ancestry(pid);
        return chain.Count > 0 && AdminAudit.SameProcess(chain[0].Started, hit.At)
            ? [.. chain.Skip(1).Select(p => $"{p.Program} ({p.ProcessId})")]
            : [];
    }

    RoutineFolders Routine(string sid)
    {
        if (!routine.TryGetValue(sid, out var folders))
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}");
            var profile = key?.GetValue("ProfileImagePath") is string path ? Environment.ExpandEnvironmentVariables(path) : null;
            routine[sid] = folders = AdminAudit.Routine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                [Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)],
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                profile);
        }
        return folders;
    }

    void Save()
    {
        saved = DateTime.UtcNow;
        try
        {
            var temp = statePath + ".tmp";
            File.WriteAllText(temp, state.ToJson());
            File.Move(temp, statePath, overwrite: true);
        }
        catch (IOException e)
        {
            logger.LogError("audit.json can't be written: {Kind}", e.GetType().Name);
        }
    }

    public void Dispose()
    {
        EventLogWatcher? stopped;
        lock (gate)
            (stopped, watcher) = (watcher, null);
        stopped?.Dispose();
        lock (gate)
            Save();
    }
}
