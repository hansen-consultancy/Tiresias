using System.Security.Cryptography;
using Tiresias.Broker;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Tiresias.Tests;

public class IdentityKeyStoreTests
{
    string dir = "";
    string path = "";

    [SetUp]
    public void SetUp()
    {
        dir = Directory.CreateTempSubdirectory("tir-identity-").FullName;
        path = Path.Combine(dir, "identity.key");
    }

    [TearDown]
    public void TearDown() => TestDirectory.Delete(dir);

    [Test]
    public void No_file_is_no_key_and_a_saved_key_loads_back()
    {
        var store = IdentityKeyStore.ForPlatform(path, NullLogger.Instance);
        Assert.That(store.Load(), Is.Null);
        var raw = RandomNumberGenerator.GetBytes(32);
        store.Save(raw);
        Assert.That(IdentityKeyStore.ForPlatform(path, NullLogger.Instance).Load(), Is.EqualTo(raw));
    }

    [Test]

    [Platform("Win")]
    public void On_Windows_the_file_holds_only_a_DPAPI_blob()
    {
        var raw = RandomNumberGenerator.GetBytes(32);
        IdentityKeyStore.ForPlatform(path, NullLogger.Instance).Save(raw);
        var text = File.ReadAllText(path);
        Assert.That(text, Does.StartWith("dpapi:").And.Not.Contain(Convert.ToBase64String(raw)));
    }

    [Test]

    [Platform("Win")]
    public void On_Windows_a_plain_key_from_before_is_migrated_with_a_warning()
    {
        var raw = RandomNumberGenerator.GetBytes(32);
        File.WriteAllText(path, Convert.ToBase64String(raw));
        var logger = new CountingLogger();

        Assert.That(IdentityKeyStore.ForPlatform(path, logger).Load(), Is.EqualTo(raw));
        Assert.That(File.ReadAllText(path), Does.StartWith("dpapi:"));
        Assert.That(logger.Warnings, Is.EqualTo(1));
    }

    [Test]

    [Platform(Exclude = "Win")]
    public void Elsewhere_the_file_is_owner_only_and_a_wider_one_is_narrowed()
    {
        var store = IdentityKeyStore.ForPlatform(path, NullLogger.Instance);
        store.Save(RandomNumberGenerator.GetBytes(32));
        Assert.That(File.GetUnixFileMode(path), Is.EqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite));

        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        store.Load();
        Assert.That(File.GetUnixFileMode(path), Is.EqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite));
    }

    sealed class CountingLogger : ILogger
    {
        public int Warnings { get; private set; }
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning)
                Warnings++;
        }
    }
}
