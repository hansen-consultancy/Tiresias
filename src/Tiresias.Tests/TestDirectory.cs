namespace Tiresias.Tests;

static class TestDirectory
{
    /// <summary>
    /// Deletes a broker host's temp directory. With a top-level <c>Program</c>, the factory's
    /// <c>Dispose</c> can return before the app's own thread has disposed the services, and
    /// <c>BrokerState</c> appends its shutdown <c>LeaseEnd</c> during that disposal. Once the audit
    /// log is disposed nothing writes the file again, so a short retry is enough; a handle still
    /// open after it is a real leak and fails the test.
    /// </summary>
    public static void Delete(string dir)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                Directory.Delete(dir, recursive: true);
                return;
            }
            catch (IOException) when (attempt < 50)
            {
                Thread.Sleep(20);
            }
        }
    }
}
