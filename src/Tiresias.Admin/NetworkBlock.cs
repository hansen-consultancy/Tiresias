using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Tiresias.Admin;

/// <summary>
/// Blocks a program's network with Windows Filtering Platform filters (docs/admin-tier.md,
/// <i>Stopping the program</i>): connect and accept, IPv4 and IPv6, matched on the program's image
/// path, in Tiresias's own provider and sublayer. Filters are persistent, so they hold across a
/// restart of the service or the machine until lifted by id. Linked into the agent, whose elevated
/// removal lifts them with the service stopped.
/// </summary>
static unsafe partial class NetworkBlock
{
    static readonly Guid Provider = new("6f1c0e2a-5b7d-4e8f-9a3c-2d4b6e8f0a1c");
    static readonly Guid SubLayer = new("8a2e4c6b-1d3f-4a5c-b7e9-0c2d4f6a8b1e");

    static readonly Guid AppId = new("d78e1e87-8644-4ea5-9437-d809ecefc971");

    /// <summary>ALE connect and receive/accept, IPv4 and IPv6.</summary>
    static readonly Guid[] Layers =
    [
        new("c38d57d1-05a7-4c33-904f-7fbceee60e82"),
        new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4"),
        new("e1cd9fe7-f4b5-4273-96c0-592e487b8650"),
        new("a3b42c97-9f04-4672-b87e-cee9c483257f"),
    ];

    /// <returns>The filters' ids, to lift them by.</returns>
    public static IReadOnlyList<ulong> Block(string program)
    {
        using var engine = Engine.Open();
        Check(FwpmTransactionBegin0(engine.Handle, 0));
        var committed = false;
        var name = Marshal.StringToHGlobalUni("Tiresias: program frozen after using a decoy");
        IntPtr appId = IntPtr.Zero;
        try
        {
            AddProviderAndSubLayer(engine.Handle, name);
            Check(FwpmGetAppIdFromFileName0(program, out appId));
            var condition = new Condition { FieldKey = AppId, MatchType = MatchEqual, Value = new() { Type = ByteBlobType, Data = (ulong)appId } };
            var ids = new List<ulong>();
            var provider = Provider;
            foreach (var layer in Layers)
            {
                var filter = new Filter
                {
                    FilterKey = Guid.NewGuid(),
                    DisplayData = new() { Name = name },
                    Flags = FilterPersistent,
                    ProviderKey = (IntPtr)(&provider),
                    LayerKey = layer,
                    SubLayerKey = SubLayer,
                    NumConditions = 1,
                    Conditions = (IntPtr)(&condition),
                    Action = new() { Type = ActionBlock },
                };
                Check(FwpmFilterAdd0(engine.Handle, ref filter, IntPtr.Zero, out var id));
                ids.Add(id);
            }
            Check(FwpmTransactionCommit0(engine.Handle));
            committed = true;
            return ids;
        }
        finally
        {
            if (!committed)
                _ = FwpmTransactionAbort0(engine.Handle);
            if (appId != IntPtr.Zero)
                FwpmFreeMemory0(ref appId);
            Marshal.FreeHGlobal(name);
        }
    }

    static void AddProviderAndSubLayer(IntPtr engine, IntPtr name)
    {
        var provider = new ProviderInfo { Key = Provider, DisplayData = new() { Name = name }, Flags = Persistent };
        Exists(FwpmProviderAdd0(engine, ref provider, IntPtr.Zero));
        var key = Provider;
        var subLayer = new SubLayerInfo { Key = SubLayer, DisplayData = new() { Name = name }, Flags = Persistent, ProviderKey = (IntPtr)(&key), Weight = 0x8000 };
        Exists(FwpmSubLayerAdd0(engine, ref subLayer, IntPtr.Zero));
    }

    /// <summary>Lifts filters by id; one already gone is fine.</summary>
    /// <returns>Whether none is left.</returns>
    public static bool Lift(IEnumerable<ulong> ids)
    {
        using var engine = Engine.Open();
        var all = true;
        foreach (var id in ids)
            if (FwpmFilterDeleteById0(engine.Handle, id) is not (0 or FilterNotFound))
                all = false;
        return all;
    }

    /// <summary>Removes Tiresias's sublayer and provider; refused by Windows while a filter is still in them.</summary>
    public static bool RemoveProvider()
    {
        using var engine = Engine.Open();
        var subLayer = SubLayer;
        var provider = Provider;
        return FwpmSubLayerDeleteByKey0(engine.Handle, &subLayer) is 0 or SubLayerNotFound
            && FwpmProviderDeleteByKey0(engine.Handle, &provider) is 0 or ProviderNotFound;
    }

    static void Check(uint result)
    {
        if (result != 0)
            throw new Win32Exception((int)result);
    }

    static void Exists(uint result)
    {
        if (result is not (0 or AlreadyExists))
            throw new Win32Exception((int)result);
    }

    sealed class Engine : IDisposable
    {
        public IntPtr Handle { get; private init; }

        public static Engine Open()
        {
            Check(FwpmEngineOpen0(null, RpcAuthnDefault, IntPtr.Zero, IntPtr.Zero, out var handle));
            return new() { Handle = handle };
        }

        public void Dispose() => _ = FwpmEngineClose0(Handle);
    }

    const uint RpcAuthnDefault = 0xFFFFFFFF;
    const uint Persistent = 0x1;
    const uint FilterPersistent = 0x1;
    const uint MatchEqual = 0;
    const uint ByteBlobType = 12;
    const uint ActionBlock = 0x1001;
    const uint AlreadyExists = 0x80320009;
    const uint FilterNotFound = 0x80320003;
    const uint SubLayerNotFound = 0x80320007;
    const uint ProviderNotFound = 0x80320005;

    [StructLayout(LayoutKind.Sequential)]
    struct DisplayData
    {
        public IntPtr Name;
        public IntPtr Description;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ByteBlob
    {
        public uint Size;
        public IntPtr Data;
    }

    /// <summary><c>FWP_VALUE0</c> and <c>FWP_CONDITION_VALUE0</c>: a type and an 8-byte union.</summary>
    [StructLayout(LayoutKind.Sequential)]
    struct Value
    {
        public uint Type;
        public ulong Data;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct Condition
    {
        public Guid FieldKey;
        public uint MatchType;
        public Value Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct FilterAction
    {
        public uint Type;
        public Guid FilterType;
    }

    /// <summary>The <c>rawContext</c> / <c>providerContextKey</c> union: 16 bytes, aligned to 8.</summary>
    [StructLayout(LayoutKind.Sequential)]
    struct Context
    {
        public ulong Low;
        public ulong High;
    }

    /// <summary><c>FWPM_FILTER0</c>.</summary>
    [StructLayout(LayoutKind.Sequential)]
    struct Filter
    {
        public Guid FilterKey;
        public DisplayData DisplayData;
        public uint Flags;
        public IntPtr ProviderKey;
        public ByteBlob ProviderData;
        public Guid LayerKey;
        public Guid SubLayerKey;
        public Value Weight;
        public uint NumConditions;
        public IntPtr Conditions;
        public FilterAction Action;
        public Context ProviderContext;
        public IntPtr Reserved;
        public ulong FilterId;
        public Value EffectiveWeight;
    }

    /// <summary><c>FWPM_PROVIDER0</c>.</summary>
    [StructLayout(LayoutKind.Sequential)]
    struct ProviderInfo
    {
        public Guid Key;
        public DisplayData DisplayData;
        public uint Flags;
        public ByteBlob ProviderData;
        public IntPtr ServiceName;
    }

    /// <summary><c>FWPM_SUBLAYER0</c>.</summary>
    [StructLayout(LayoutKind.Sequential)]
    struct SubLayerInfo
    {
        public Guid Key;
        public DisplayData DisplayData;
        public uint Flags;
        public IntPtr ProviderKey;
        public ByteBlob ProviderData;
        public ushort Weight;
    }

    [LibraryImport("fwpuclnt.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint FwpmEngineOpen0(string? server, uint authn, IntPtr identity, IntPtr session, out IntPtr engine);

    [LibraryImport("fwpuclnt.dll")]
    private static partial uint FwpmEngineClose0(IntPtr engine);

    [LibraryImport("fwpuclnt.dll")]
    private static partial uint FwpmTransactionBegin0(IntPtr engine, uint flags);

    [LibraryImport("fwpuclnt.dll")]
    private static partial uint FwpmTransactionCommit0(IntPtr engine);

    [LibraryImport("fwpuclnt.dll")]
    private static partial uint FwpmTransactionAbort0(IntPtr engine);

    [LibraryImport("fwpuclnt.dll")]
    private static partial uint FwpmProviderAdd0(IntPtr engine, ref ProviderInfo provider, IntPtr descriptor);

    [LibraryImport("fwpuclnt.dll")]
    private static partial uint FwpmProviderDeleteByKey0(IntPtr engine, Guid* key);

    [LibraryImport("fwpuclnt.dll")]
    private static partial uint FwpmSubLayerAdd0(IntPtr engine, ref SubLayerInfo subLayer, IntPtr descriptor);

    [LibraryImport("fwpuclnt.dll")]
    private static partial uint FwpmSubLayerDeleteByKey0(IntPtr engine, Guid* key);

    [LibraryImport("fwpuclnt.dll")]
    private static partial uint FwpmFilterAdd0(IntPtr engine, ref Filter filter, IntPtr descriptor, out ulong id);

    [LibraryImport("fwpuclnt.dll")]
    private static partial uint FwpmFilterDeleteById0(IntPtr engine, ulong id);

    [LibraryImport("fwpuclnt.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);

    [LibraryImport("fwpuclnt.dll")]
    private static partial void FwpmFreeMemory0(ref IntPtr memory);
}
