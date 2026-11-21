using System.Buffers.Binary;
using System.Text;

namespace Tiresias.Decoys;

/// <summary>
/// Just enough of SQL Server's wire protocol (TDS) to read a login and refuse it the way SQL Server
/// refuses a wrong password: a pre-login answer without encryption, then error 18456.
/// </summary>
public static class DecoyTds
{
    public const byte PreLogin = 0x12;
    public const byte Login7 = 0x10;
    const byte TabularResult = 0x04;

    /// <summary>The pre-login answer: version, and "encryption not supported" so the login arrives readable.</summary>
    public static byte[] PreLoginResponse()
    {
        byte[] payload =
        [
            0x00, 0, 11, 0, 6, // VERSION at 11, 6 bytes
            0x01, 0, 17, 0, 1, // ENCRYPTION at 17, 1 byte
            0xFF,
            16, 0, 0x10, 0x00, 0, 0, // 16.0.4096 (SQL Server 2022)
            0x02, // ENCRYPT_NOT_SUP
        ];
        return Packet(TabularResult, payload);
    }

    /// <summary>The user name and password of a LOGIN7 message (without its packet header); <c>null</c> when it is too short to hold them.</summary>
    public static (string User, string Password)? ReadLogin(ReadOnlySpan<byte> login)
    {
        // Fixed part: 36 bytes, then (offset, length in characters) pairs: host name, user name, password.
        if (login.Length < 48)
            return null;
        var user = Field(login, 40, obfuscated: false);
        var password = Field(login, 44, obfuscated: true);
        return user is null || password is null ? null : (user, password);
    }

    static string? Field(ReadOnlySpan<byte> login, int at, bool obfuscated)
    {
        int offset = BinaryPrimitives.ReadUInt16LittleEndian(login[at..]), chars = BinaryPrimitives.ReadUInt16LittleEndian(login[(at + 2)..]);
        if (offset + chars * 2 > login.Length)
            return null;
        var bytes = login.Slice(offset, chars * 2).ToArray();
        if (obfuscated)
            for (var i = 0; i < bytes.Length; i++)
            {
                // The client swaps each byte's nibbles, then XORs it with 0xA5.
                var b = bytes[i] ^ 0xA5;
                bytes[i] = (byte)((b << 4) | (b >> 4));
            }
        return Encoding.Unicode.GetString(bytes);
    }

    /// <summary>SQL Server's own refusal: error 18456, state 1, class 14, then DONE with the error bit.</summary>
    public static byte[] LoginFailed(string user)
    {
        var message = $"Login failed for user '{user}'.";
        using var body = new MemoryStream();
        using var error = new MemoryStream();
        Write32(error, 18456);
        error.WriteByte(1); // state
        error.WriteByte(14); // class
        Write16(error, (ushort)message.Length);
        error.Write(Encoding.Unicode.GetBytes(message));
        error.WriteByte(0); // server name
        error.WriteByte(0); // procedure name
        Write32(error, 1); // line

        body.WriteByte(0xAA);
        Write16(body, (ushort)error.Length);
        error.WriteTo(body);
        body.WriteByte(0xFD);
        Write16(body, 0x0002); // DONE_ERROR
        Write16(body, 0);
        body.Write(new byte[8]);
        return Packet(TabularResult, body.ToArray());
    }

    /// <summary>One TDS packet: type, end of message, big-endian length, then the payload.</summary>
    static byte[] Packet(byte type, byte[] payload)
    {
        var packet = new byte[8 + payload.Length];
        packet[0] = type;
        packet[1] = 0x01;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)packet.Length);
        packet[6] = 1;
        payload.CopyTo(packet, 8);
        return packet;
    }

    static void Write16(Stream s, ushort value)
    {
        Span<byte> b = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(b, value);
        s.Write(b);
    }

    static void Write32(Stream s, int value)
    {
        Span<byte> b = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(b, value);
        s.Write(b);
    }
}
