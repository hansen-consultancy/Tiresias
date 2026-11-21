using System.Collections.Concurrent;
using System.Security.Cryptography;
using Tiresias.Trust;
using NSec.Cryptography;

namespace Tiresias.Tests;

/// <summary>Stand-in Windows Hello keys for trust-chain tests: RSA 2048 with PKCS#1, one per name, kept for the test run.</summary>
static class TestHello
{
    static readonly ConcurrentDictionary<string, RSA> Keys = new();

    public static HelloKey For(string name)
    {
        var rsa = Keys.GetOrAdd(name, _ => RSA.Create(2048));
        return new(rsa.ExportSubjectPublicKeyInfo(), data => rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    public static Signer Device(string id, Key key) => new(id, key, For(id));
}
