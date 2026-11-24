using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace Tiresias.Agent;

internal sealed record RecoveryChange(int Number, string OwnerSid, string AuthorizedBy, DateTimeOffset At,
    Guid? PreviousRevision, RecoveryBinding Binding);

[JsonSerializable(typeof(RecoveryChange))]
internal partial class RecoveryChangeJson : JsonSerializerContext { }

/// <summary>A committed numbered entry is both the new binding and the audit of who changed it.</summary>
internal static partial class RecoveryEnrollmentHistory
{
    const string Root = @"SOFTWARE\Tiresias Recovery Enrollment";
    const AccessControlSections Permissions = AccessControlSections.Owner | AccessControlSections.Access;

    internal static InvalidOperationException Changed() => new("Recovery enrollment changed. Reopen it and verify the current recipient.");

    internal static RecoveryBinding? Current(string sid)
    {
        using var state = Open(sid, create: false);
        return Latest(state, sid)?.Binding;
    }

    internal static RegistrySecurity Security(string? ownerSid)
    {
        if (ownerSid is not null && !RecoveryRecipient.UserSid(ownerSid))
            throw new UnauthorizedAccessException("Recovery enrollment requires a Windows user account.");
        var security = new RegistrySecurity();
        security.SetSecurityDescriptorSddlForm($"O:BAD:P(A;;KA;;;BA)(A;;KA;;;SY)(A;;KR;;;{ownerSid ?? "AU"})");
        return security;
    }

    internal static void RequireProtected(RegistrySecurity security, string? ownerSid)
    {
        if (security.GetSecurityDescriptorSddlForm(Permissions) != Security(ownerSid).GetSecurityDescriptorSddlForm(Permissions))
            throw new UnauthorizedAccessException("Recovery enrollment permissions could not be verified.");
    }

    internal static RegistryKey? Open(string ownerSid, bool create)
    {
        if (!RecoveryRecipient.UserSid(ownerSid))
            throw new UnauthorizedAccessException("Recovery enrollment requires a Windows user account.");
        using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var root = OpenProtected(machine, Root, create, null);
        return root is null ? null : OpenProtected(root, ownerSid, create, ownerSid);
    }

    static RegistryKey? OpenProtected(RegistryKey parent, string name, bool create, string? ownerSid)
    {
        var key = create ? parent.CreateSubKey(name, RegistryKeyPermissionCheck.ReadWriteSubTree, Security(ownerSid)) : OpenRead(parent, name);
        try
        {
            if (key is not null)
                RequireProtected(key.GetAccessControl(Permissions), ownerSid);
            return key;
        }
        catch
        {
            key?.Dispose();
            throw;
        }
    }

    // Only ERROR_FILE_NOT_FOUND means there is no enrollment. Other registry failures must reach the caller.
    static RegistryKey? OpenRead(RegistryKey parent, string name)
    {
        int error = RegOpenKeyExW(parent.Handle, name, 0, (int)RegistryRights.ReadKey | (int)RegistryView.Registry64, out var handle);
        if (error == 0)
            return RegistryKey.FromHandle(handle, RegistryView.Registry64);
        handle.Dispose();
        if (error == 2)
            return null;
        throw new IOException($"Could not read recovery enrollment (Windows error {error}).");
    }

    internal static RecoveryChange? Latest(RegistryKey? state, string ownerSid, bool protectedStore = true)
    {
        if (state is null)
            return null;
        int count = 0, last = 0;
        foreach (var name in state.GetSubKeyNames())
        {
            if (name.StartsWith("pending-", StringComparison.Ordinal) && Guid.TryParseExact(name.AsSpan(8), "N", out _))
                continue;
            if (!int.TryParse(name, NumberStyles.None, CultureInfo.InvariantCulture, out var index) ||
                index < 1 || name != index.ToString(CultureInfo.InvariantCulture))
                throw InvalidRecord();
            last = Math.Max(last, index);
            count++;
        }
        if (last != count)
            throw InvalidRecord();
        if (count == 0)
            return null;
        return ReadChange(state, ownerSid, last, protectedStore);
    }

    internal static IReadOnlyList<DateTimeOffset> ApprovalTimes(RegistryKey? state, string ownerSid, bool protectedStore = true)
    {
        if (Latest(state, ownerSid, protectedStore) is not { } latest)
            return [];
        var times = new DateTimeOffset[latest.Number];
        for (int i = 1; i < latest.Number; i++)
            times[i - 1] = ReadChange(state!, ownerSid, i, protectedStore).At;
        times[^1] = latest.At;
        return times;
    }

    static RecoveryChange ReadChange(RegistryKey state, string ownerSid, int last, bool protectedStore)
    {
        var latest = last.ToString(CultureInfo.InvariantCulture);
        using var entry = protectedStore ? OpenProtected(state, latest, create: false, ownerSid) : OpenRead(state, latest);
        if (entry is null || entry.GetValue("change", null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string { Length: <= 1024 } json ||
            entry.GetValueKind("change") != RegistryValueKind.String)
            throw InvalidRecord();
        try
        {
            var change = JsonSerializer.Deserialize(json, RecoveryChangeJson.Default.RecoveryChange);
            if (change?.Binding is not { } binding || binding.Revision == Guid.Empty || change.Number != last ||
                change.OwnerSid != ownerSid || !RecoveryRecipient.UserSid(change.AuthorizedBy) || change.At == default ||
                (last == 1) != (change.PreviousRevision is null) || change.PreviousRevision == Guid.Empty || change.PreviousRevision == binding.Revision)
                throw InvalidRecord();
            RecoveryRecipient.ValidateKey(binding.PublicKey);
            return change;
        }
        catch (JsonException) { throw InvalidRecord(); }
    }

    internal static void Append(RegistryKey state, string ownerSid, string author, Guid? expected, string publicKey, bool protectedStore,
        Action? beforePublish = null)
    {
        var current = Latest(state, ownerSid, protectedStore);
        if (current?.Binding.Revision != expected)
            throw Changed();
        var number = checked((current?.Number ?? 0) + 1);
        var revision = Guid.NewGuid();
        var change = new RecoveryChange(number, ownerSid, author, DateTimeOffset.UtcNow, expected, new(revision, publicKey));
        var staging = "pending-" + revision.ToString("N");
        var committed = false;
        try
        {
            using (var key = protectedStore ? OpenProtected(state, staging, create: true, ownerSid)! :
                state.CreateSubKey(staging, writable: true, RegistryOptions.Volatile))
            {
                key.SetValue("change", JsonSerializer.Serialize(change, RecoveryChangeJson.Default.RecoveryChange), RegistryValueKind.String);
                if (RegFlushKey(key.Handle) != 0)
                    throw new IOException("The proposed recovery enrollment could not be flushed to disk.");
            }
            // The destination must be absent. Racing writers cannot replace each other's authorized transition.
            var destination = number.ToString(CultureInfo.InvariantCulture);
            beforePublish?.Invoke();
            int error = RegRenameKey(state.Handle, staging, destination);
            if (error != 0)
            {
                using var winner = OpenRead(state, destination);
                if (winner is not null)
                    throw Changed();
                throw new IOException($"Could not publish recovery enrollment (Windows error {error}).");
            }
            committed = true;
            if (RegFlushKey(state.Handle) != 0)
                throw new IOException("Recovery enrollment could not be flushed to disk.");
        }
        finally
        {
            if (!committed)
                state.DeleteSubKey(staging, throwOnMissingSubKey: false);
        }
    }

    static InvalidOperationException InvalidRecord() => new("The protected recovery enrollment is incomplete or invalid.");

    [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int RegOpenKeyExW(SafeRegistryHandle key, string name, uint options, int access, out SafeRegistryHandle result);
    [LibraryImport("advapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int RegRenameKey(SafeRegistryHandle key, string name, string newName);
    [LibraryImport("advapi32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int RegFlushKey(SafeRegistryHandle key);
}
