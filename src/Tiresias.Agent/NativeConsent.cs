using System.Runtime.InteropServices;

namespace Tiresias.Agent;

/// <summary>A yes/no decision on the Windows desktop, including when a console's input is redirected.</summary>
public static partial class NativeConsent
{
    public static bool Ask(string caption, string message)
    {
        const uint yesNoDefaultNo = 0x0004 | 0x0020 | 0x0100 | 0x2000;
        return MessageBoxW(0, message, caption, yesNoDefaultNo) == 6;
    }

    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int MessageBoxW(nint owner, string text, string caption, uint options);
}
