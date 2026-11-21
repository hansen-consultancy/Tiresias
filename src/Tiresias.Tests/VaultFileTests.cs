using System.Text;
using System.Text.RegularExpressions;
using System.Security.AccessControl;
using System.Security.Principal;
using Tiresias.Agent;
using Tiresias.Policy;
using Tiresias.Vault;

namespace Tiresias.Tests;

public class VaultFileTests
{
    string dir = "";

    [SetUp]
    public void SetUp() => dir = Directory.CreateTempSubdirectory("tir-vault-").FullName;

    [TearDown]
    public void TearDown() => Directory.Delete(dir, recursive: true);

    [Test]
    public void Round_trips_secrets_and_policy()
    {
        using var vault = TestVault.Create();
        var path = Path.Combine(dir, "vault.json");
        VaultFile.Save(path, vault.Document);

        var loaded = VaultFile.Load(path);
        var secret = loaded.FindSecret("llm-read")!;
        var dek = SecretEnvelope.UnwrapDek(secret, vault.Tpm)!;
        Assert.That(Encoding.UTF8.GetString(SecretEnvelope.Open(secret, dek)!), Is.EqualTo("Bearer sk-read"));

        var llm = loaded.FindService("llm")!;
        Assert.That(llm.Grants.Select(g => g.Name), Is.EqualTo(new[] { "read", "write", "admin" }));
        Assert.That(llm.Grants[2].RequiresElevation, Is.True);
        Assert.That(GrantSelector.Select(llm, new("GET", "/v1/models", 0), null, new HashSet<string>()).Grant?.Name, Is.EqualTo("read"));
        Assert.That(GrantSelector.Select(llm, new("GET", "/v1/admin/keys", 0), null, new HashSet<string>()).Reason, Is.EqualTo(DenyReason.NotCovered));
    }

    [Test]
    public void Regexes_are_culture_invariant_and_time_boxed()
    {
        using var vault = TestVault.Create();
        var path = Path.Combine(dir, "vault.json");
        VaultFile.Save(path, vault.Document);

        var allow = VaultFile.Load(path).FindService("llm")!.Grants[0].Rule.Allow[0];
        Assert.That(allow.Options, Is.EqualTo(RegexOptions.CultureInvariant));
        Assert.That(allow.MatchTimeout, Is.EqualTo(TimeSpan.FromMilliseconds(100)));
    }

    [Test]
    public void The_file_holds_no_plaintext()
    {
        using var vault = TestVault.Create();
        var path = Path.Combine(dir, "vault.json");
        VaultFile.Save(path, vault.Document);

        var text = File.ReadAllText(path);
        Assert.That(text, Does.Not.Contain("sk-read"));
        Assert.That(text, Does.Not.Contain(Convert.ToBase64String("Bearer sk-read"u8)));
    }

    [Test]
    public void Saving_over_an_existing_vault_leaves_no_temp_file()
    {
        using var vault = TestVault.Create();
        var path = Path.Combine(dir, "vault.json");
        VaultFile.Save(path, vault.Document);
        VaultFile.Save(path, vault.Document);
        Assert.That(Directory.GetFiles(dir).Select(Path.GetFileName), Is.EqualTo(new[] { "vault.json" }));
    }

    [Test, Platform("Win"), System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public void Service_read_access_stays_with_its_vault_across_saves_and_is_removed_on_uninstall()
    {
        var reader = new SecurityIdentifier("S-1-5-80-1234-5678-1234-5678-1234");
        var folder = new DirectoryInfo(dir);
        var folderAcl = folder.GetAccessControl();
        folderAcl.AddAccessRule(new FileSystemAccessRule(reader, FileSystemRights.Read,
            InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
        folder.SetAccessControl(folderAcl);
        var vault = new FileInfo(Path.Combine(dir, "vault.json"));
        var adjacent = new FileInfo(Path.Combine(dir, "other.json"));
        var document = new VaultDocument([], []);
        VaultFile.Save(vault.FullName, document);
        VaultFile.Save(adjacent.FullName, document);
        BrokerVaultAccess.Set(vault.FullName, reader, grant: true);
        VaultFile.Save(vault.FullName, document);

        FileSystemRights[] Rights(FileInfo file) => file.GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier))
            .OfType<FileSystemAccessRule>().Where(rule => rule.IdentityReference == reader).Select(rule => rule.FileSystemRights).ToArray();
        Assert.That(Rights(vault), Is.EqualTo(new[] { FileSystemRights.Read | FileSystemRights.Synchronize }));
        Assert.That(Rights(adjacent), Is.Empty);
        BrokerVaultAccess.Set(vault.FullName, reader, grant: false);
        Assert.That(Rights(vault), Is.Empty);
    }
}
