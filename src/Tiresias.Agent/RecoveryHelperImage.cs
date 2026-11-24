using System.ComponentModel;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Tiresias.AdminTier;
using IOPath = System.IO.Path;

namespace Tiresias.Agent;

/// <summary>Holds the verified client, helper and their parent directories until the launch has completed.</summary>
internal sealed unsafe partial class RecoveryHelperImage : IDisposable
{
    internal const string HelperName = "tiresias-recovery.exe";
    const string Unavailable = "Recovery enrollment requires the matching helper from a signed Tiresias release. Install or repair the signed release and retry.";
    readonly List<SourceHandle> held = [];

    public string Path { get; }

    RecoveryHelperImage(string path) => Path = path;

    public static RecoveryHelperImage Open()
    {
        var client = Environment.ProcessPath ?? throw new InvalidOperationException(Unavailable);
        var verified = OpenForClient(client);
        try
        {
            // Query the running image again after locking the entire path. The cached ProcessPath
            // alone could still be the name of a directory that moved since startup.
            Span<char> current = stackalloc char[1024];
            var size = (uint)current.Length;
            fixed (char* buffer = current)
                if (!QueryFullProcessImageNameW(-1, 0, buffer, ref size) || !AdminHandBack.IsWhereAsked(client, new(current[..(int)size])))
                    throw new InvalidOperationException(Unavailable);
            return verified;
        }
        catch
        {
            verified.Dispose();
            throw;
        }
    }

    internal static RecoveryHelperImage OpenForClient(string client)
    {
        if (!IOPath.IsPathFullyQualified(client) || client.StartsWith(@"\\", StringComparison.Ordinal) ||
            ClientProduct(IOPath.GetFileName(client)) is null)
            throw new InvalidOperationException(Unavailable);
        var folder = new DirectoryInfo(IOPath.GetDirectoryName(client)!);
        var image = new RecoveryHelperImage(IOPath.Combine(folder.FullName, HelperName));
        try
        {
            var ancestors = new Stack<DirectoryInfo>();
            for (DirectoryInfo? next = folder; next is not null; next = next.Parent)
                ancestors.Push(next);
            foreach (var directory in ancestors)
                image.Hold(directory.FullName, directory: true);
            var host = image.Read(client);
            var helper = image.Read(image.Path);
            if (!Matches(IOPath.GetFileName(client), host, helper))
                throw new InvalidOperationException(Unavailable);
            return image;
        }
        catch (Exception e) when (e is Win32Exception or IOException or UnauthorizedAccessException or CryptographicException
            or BadImageFormatException or ArgumentException)
        {
            image.Dispose();
            throw new InvalidOperationException(Unavailable, e);
        }
        catch
        {
            image.Dispose();
            throw;
        }
    }

    SourceHandle Hold(string path, bool directory)
    {
        var source = SourceHandle.Open(path, directory);
        held.Add(source);
        if (!AdminHandBack.IsWhereAsked(path, source.FinalPath) || source.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            source.Attributes.HasFlag(FileAttributes.Directory) != directory || (!directory && source.Links != 1))
            throw new InvalidOperationException(Unavailable);
        return source;
    }

    public void Dispose()
    {
        for (var index = held.Count - 1; index >= 0; index--)
            held[index].Dispose();
        held.Clear();
    }

    internal sealed record ReleaseImage(string OriginalName, string Product, string FileVersion, string ProductVersion, Machine Machine, string Signer, bool NativeHelper);

    static string? ClientProduct(string filename) => filename.Equals("tir.exe", StringComparison.OrdinalIgnoreCase) ? "tir"
        : filename.Equals("Tiresias.exe", StringComparison.OrdinalIgnoreCase) ? "Tiresias" : null;

    internal static bool Matches(string clientName, ReleaseImage client, ReleaseImage helper) =>
        ClientProduct(clientName) is { } product && client.Product == product && client.OriginalName == product + ".dll"
        && helper.OriginalName == "tiresias-recovery.dll" && helper.Product == "Tiresias recovery enrollment"
        && client.FileVersion.Length > 0 && client.FileVersion == helper.FileVersion
        && client.ProductVersion.Length > 0 && client.ProductVersion == helper.ProductVersion
        && client.Machine == helper.Machine && helper.NativeHelper && client.Signer.Length > 0 && client.Signer == helper.Signer;

    ReleaseImage Read(string path)
    {
        var source = Hold(path, directory: false);
        return ReadMetadata(path, VerifiedSigner(path, source));
    }

    internal static string VerifiedSigner(string path, SourceHandle source)
    {
        string? signer = null;
        if (!SurfaceProbe.VerifyEmbeddedSignature(path, source.Handle.DangerousGetHandle(), state => (signer = MachineTrustedSigner(state)) is not null))
            throw new InvalidOperationException(Unavailable);
        return signer!;
    }

    internal static ReleaseImage ReadMetadata(string path, string signer)
    {
        using var stream = File.OpenRead(path);
        using var image = new PEReader(stream);
        var resource = VersionResource(image);
        fixed (byte* buffer = resource)
        {
            if (!VerQueryValueW(buffer, @"\VarFileInfo\Translation", out var translation, out var length) || length != 4)
                throw new BadImageFormatException("Missing version resource translation.");
            var pair = (ushort*)translation;
            var table = $@"\StringFileInfo\{pair[0]:x4}{pair[1]:x4}\";
            return new(Field(buffer, table + "OriginalFilename"), Field(buffer, table + "ProductName"), Field(buffer, table + "FileVersion"),
                Field(buffer, table + "ProductVersion"), image.PEHeaders.CoffHeader.Machine, signer, IsNativeHelper(image));
        }
    }

    static string Field(byte* resource, string field)
    {
        if (!VerQueryValueW(resource, field, out var data, out var length) || length is < 2 or > 512)
            throw new BadImageFormatException("Missing version resource field.");
        return new string((char*)data, 0, (int)length - 1);
    }

    // Read RT_VERSION from the locked, signed PE itself. FileVersionInfo can use a neighboring MUI file.
    static byte[] VersionResource(PEReader image)
    {
        var table = image.PEHeaders.PEHeader?.ResourceTableDirectory ?? default;
        if (table.Size < 16)
            throw new BadImageFormatException();
        var section = image.GetSectionData(table.RelativeVirtualAddress);
        int Child(int offset, int? id, bool directory)
        {
            var reader = section.GetReader(offset, section.Length - offset);
            reader.Offset = 12;
            var count = reader.ReadUInt16() + reader.ReadUInt16();
            while (count-- > 0)
            {
                var name = reader.ReadInt32();
                var target = reader.ReadInt32();
                if (name >= 0 && (id is null || name == id) && (target < 0) == directory)
                    return target & int.MaxValue;
            }
            throw new BadImageFormatException("Missing embedded version resource.");
        }
        var entry = Child(Child(Child(0, 16, true), 1, true), null, false);
        var leaf = section.GetReader(entry, 16);
        var rva = leaf.ReadInt32();
        var size = leaf.ReadInt32();
        if (size is < 6 or > 65535)
            throw new BadImageFormatException();
        return image.GetSectionData(rva).GetReader(0, size).ReadBytes(size);
    }

    static bool IsNativeHelper(PEReader image)
    {
        var headers = image.PEHeaders;
        if (headers.CorHeader is not null || headers.PEHeader is not { Magic: PEMagic.PE32Plus } pe ||
            headers.CoffHeader.Machine is not (Machine.Amd64 or Machine.Arm64) || pe.LoadConfigTableDirectory.Size < 80 ||
            pe.ExportTableDirectory.Size < 40)
            return false;
        var config = image.GetSectionData(pe.LoadConfigTableDirectory.RelativeVirtualAddress).GetReader(0, 80);
        if (config.ReadUInt32() < 80)
            return false;
        config.Offset = 78; // IMAGE_LOAD_CONFIG_DIRECTORY64.DependentLoadFlags
        if (config.ReadUInt16() != 0x800) // LOAD_LIBRARY_SEARCH_SYSTEM32
            return false;
        var exports = image.GetSectionData(pe.ExportTableDirectory.RelativeVirtualAddress).GetReader(0, 40);
        exports.Offset = 24;
        var count = exports.ReadInt32();
        exports.Offset = 32;
        if (count is < 1 or > 1024)
            return false;
        var names = image.GetSectionData(exports.ReadInt32()).GetReader(0, count * 4);
        ReadOnlySpan<byte> runtimeExport = "DotNetRuntimeContractDescriptor\0"u8;
        for (var index = 0; index < count; index++)
        {
            var name = image.GetSectionData(names.ReadInt32());
            if (name.Length >= runtimeExport.Length && name.GetContent(0, runtimeExport.Length).AsSpan().SequenceEqual(runtimeExport))
                return true;
        }
        return false;
    }

    static string? MachineTrustedSigner(nint state)
    {
        var provider = WTHelperProvDataFromStateData(state);
        var signer = provider == 0 ? null : WTHelperGetProvSignerFromChain(provider, 0, 0, 0);
        if (signer == null || signer->CertificateCount is < 2 or > 32)
            return null;
        var first = WTHelperGetProvCertFromChain(signer, 0);
        var last = WTHelperGetProvCertFromChain(signer, signer->CertificateCount - 1);
        if (first == null || last == null || first->Context == 0 || last->Context == 0)
            return null;
        using var leaf = new X509Certificate2(first->Context);
        using var root = new X509Certificate2(last->Context);
        if (leaf.SubjectName.RawData.AsSpan().SequenceEqual(leaf.IssuerName.RawData))
            return null;
        using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        return store.Certificates.FindByThumbprint(HashAlgorithmName.SHA256, root.GetCertHash(HashAlgorithmName.SHA256)).Count != 0
            ? leaf.GetCertHashString(HashAlgorithmName.SHA256) : null;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ProviderSigner
    {
        public uint Size, VerifyTimeLow, VerifyTimeHigh, CertificateCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ProviderCertificate
    {
        public uint Size;
        public nint Context;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryFullProcessImageNameW(nint process, uint flags, char* path, ref uint size);

    [LibraryImport("version.dll", StringMarshalling = StringMarshalling.Utf16)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool VerQueryValueW(byte* block, string subBlock, out nint value, out uint length);

    [LibraryImport("wintrust.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial nint WTHelperProvDataFromStateData(nint state);

    [LibraryImport("wintrust.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial ProviderSigner* WTHelperGetProvSignerFromChain(nint provider, uint index, int counterSigner, uint counterIndex);

    [LibraryImport("wintrust.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial ProviderCertificate* WTHelperGetProvCertFromChain(ProviderSigner* signer, uint index);
}
