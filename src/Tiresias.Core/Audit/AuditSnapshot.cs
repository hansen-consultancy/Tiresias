using System.Buffers.Binary;

namespace Tiresias.Audit;

/// <summary>A length-prefixed journal snapshot. A lost connection cannot turn a partial journal into a valid shorter one.</summary>
public static class AuditSnapshot
{
    public static async Task WriteAsync(AuditLog log, Stream destination, CancellationToken token)
    {
        var (file, remaining) = log.OpenSnapshot();
        using (file)
        {
            byte[] buffer = new byte[64 * 1024];
            BinaryPrimitives.WriteInt64LittleEndian(buffer, remaining);
            await destination.WriteAsync(buffer.AsMemory(0, sizeof(long)), token);
            while (remaining > 0)
            {
                var count = (int)Math.Min(buffer.Length, remaining);
                await file.ReadExactlyAsync(buffer.AsMemory(0, count), token);
                await destination.WriteAsync(buffer.AsMemory(0, count), token);
                remaining -= count;
            }
        }
    }

    public static async Task<IReadOnlyList<string>> ReadAsync(Stream source, CancellationToken token)
    {
        byte[] header = new byte[sizeof(long)];
        await source.ReadExactlyAsync(header, token);
        var length = BinaryPrimitives.ReadInt64LittleEndian(header);
        if (length < 0 || length > Array.MaxLength)
            throw new InvalidDataException("The journal exceeds the supported snapshot size.");
        byte[] bytes = new byte[(int)length];
        await source.ReadExactlyAsync(bytes, token);
        using var reader = new StreamReader(new MemoryStream(bytes));
        var lines = new List<string>();
        while (reader.ReadLine() is { } line)
            lines.Add(line);
        return lines;
    }
}
