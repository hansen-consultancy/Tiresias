using System.IO;
using System.Reflection.PortableExecutable;
using NUnit.Framework;
using Tiresias.Agent;
using ReleaseImage = Tiresias.Agent.RecoveryHelperImage.ReleaseImage;

namespace Tiresias.App.Tests;

public class RecoveryHelperImageTests
{
    static readonly ReleaseImage Client = new("tir.dll", "tir", "1.2.3.0", "1.2.3+build", Machine.Amd64, "publisher-leaf", false);
    static readonly ReleaseImage Helper = Client with { OriginalName = "tiresias-recovery.dll", Product = "Tiresias recovery enrollment", NativeHelper = true };

    [Test]
    public void The_host_accepts_only_its_native_helper_from_the_same_signed_build()
    {
        Assert.That(RecoveryHelperImage.Matches("tir.exe", Client, Helper), Is.True);
        Assert.That(RecoveryHelperImage.Matches("TIR.EXE", Client, Helper), Is.True);
        Assert.That(RecoveryHelperImage.Matches("TIR.EXE", Client with { OriginalName = "TIR.DLL" }, Helper), Is.False);
        Assert.That(RecoveryHelperImage.Matches("Tiresias.exe", Client with { OriginalName = "Tiresias.dll", Product = "Tiresias" }, Helper), Is.True);
        Assert.That(RecoveryHelperImage.Matches("Tiresias.exe", Client, Helper), Is.False);
        Assert.That(RecoveryHelperImage.Matches("tir.exe", Client, Helper with { OriginalName = Client.OriginalName }), Is.False);
        Assert.That(RecoveryHelperImage.Matches("tir.exe", Client, Helper with { Product = "Another tool" }), Is.False);
        Assert.That(RecoveryHelperImage.Matches("tir.exe", Client, Helper with { NativeHelper = false }), Is.False);
        Assert.That(RecoveryHelperImage.Matches("tir.exe", Client, Helper with { Machine = Machine.Arm64 }), Is.False);
        Assert.That(RecoveryHelperImage.Matches("tir.exe", Client, Helper with { Signer = "another-leaf" }), Is.False);
        Assert.That(RecoveryHelperImage.Matches("tir.exe", Client, Helper with { ProductVersion = "1.2.3+earlier-build" }), Is.False);
        Assert.That(RecoveryHelperImage.Matches("tir.exe", Client, Helper with { FileVersion = "1.1.1.0" }), Is.False);
    }

    [Test]
    public void Missing_and_unsigned_files_are_refused_and_their_handles_are_released()
    {
        var directory = Directory.CreateTempSubdirectory();
        try
        {
            var client = Path.Combine(directory.FullName, "tir.exe");
            Assert.Throws<InvalidOperationException>(() => RecoveryHelperImage.OpenForClient(client));
            File.Copy(typeof(RecoveryHelperImage).Assembly.Location, client);
            File.Copy(client, Path.Combine(directory.FullName, RecoveryHelperImage.HelperName));
            Assert.Throws<InvalidOperationException>(() => RecoveryHelperImage.OpenForClient(client));
            using var reopened = File.Open(client, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Test]
    public void Managed_image_metadata_is_read_from_its_embedded_version_resource()
    {
        var image = RecoveryHelperImage.ReadMetadata(typeof(RecoveryHelperImage).Assembly.Location, "test");
        Assert.That(image.OriginalName, Is.EqualTo("Tiresias.Agent.dll"));
        Assert.That(image.FileVersion, Is.Not.Empty);
        Assert.That(image.ProductVersion, Is.Not.Empty);
        Assert.That(image.NativeHelper, Is.False);
    }

    [Test, Explicit("Requires a published native image.")]
    public void Published_native_helper_carries_the_required_identity_and_loader_flags()
    {
        var path = Environment.GetEnvironmentVariable("TIRESIAS_NATIVE_RECOVERY_IMAGE");
        Assert.That(path, Is.Not.Null.And.Not.Empty);
        var helper = RecoveryHelperImage.ReadMetadata(path!, "test");
        Assert.That(helper.OriginalName, Is.EqualTo(Helper.OriginalName));
        Assert.That(helper.Product, Is.EqualTo(Helper.Product));
        Assert.That(helper.NativeHelper, Is.True);
        if (Environment.GetEnvironmentVariable("TIRESIAS_RECOVERY_CLIENTS") is { Length: > 0 } clients)
            foreach (var name in new[] { "tir.exe", "Tiresias.exe" })
            {
                var client = RecoveryHelperImage.ReadMetadata(Path.Combine(clients, name), "test");
                Assert.That(RecoveryHelperImage.Matches(name, client, helper), Is.True, name);
            }
    }

    [Test, Explicit("Requires an independently verified embedded signature.")]
    public void Embedded_signature_returns_the_verified_leaf()
    {
        var path = Environment.GetEnvironmentVariable("TIRESIAS_SIGNED_TEST_IMAGE")!;
        using var held = SourceHandle.Open(path, directory: false);
        var leaf = RecoveryHelperImage.VerifiedSigner(path, held);
        Assert.That(leaf, Is.EqualTo(Environment.GetEnvironmentVariable("TIRESIAS_SIGNED_TEST_LEAF")));
    }

    [Test, Explicit("Requires an extracted, signed release.")]
    public void Signed_release_clients_verify_the_packaged_helper()
    {
        var directory = Environment.GetEnvironmentVariable("TIRESIAS_SIGNED_RECOVERY_CLIENT");
        Assert.That(directory, Is.Not.Null.And.Not.Empty);
        foreach (var name in new[] { "tir.exe", "Tiresias.exe" })
        {
            using var helper = RecoveryHelperImage.OpenForClient(Path.Combine(directory!, name));
            Assert.That(helper.Path, Is.EqualTo(Path.Combine(directory!, RecoveryHelperImage.HelperName)));
        }
    }
}
