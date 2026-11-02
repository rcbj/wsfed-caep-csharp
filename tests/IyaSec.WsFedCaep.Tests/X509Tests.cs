// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Xunit;

namespace IyaSec.WsFed.Tests;

public class X509Tests
{
    static readonly byte[] SkiOid = { 0x06, 0x03, 0x55, 0x1d, 0x0e };
    static readonly byte[] AkiOid = { 0x06, 0x03, 0x55, 0x1d, 0x23 };

    static byte[]? KeyIdAfter(byte[] cert, byte[] oid)
    {
        var at = IndexOf(cert, oid);
        if (at < 0) return null;
        var restAt = at + oid.Length;
        var marker = Array.IndexOf(cert, (byte)0x14, restAt);
        if (marker < 0 || marker + 21 > cert.Length) return null;
        return cert[(marker + 1)..(marker + 21)];
    }

    static int IndexOf(byte[] hay, byte[] needle)
    {
        for (var i = 0; i + needle.Length <= hay.Length; i++)
        {
            var match = true;
            for (var j = 0; j < needle.Length; j++)
                if (hay[i + j] != needle[j]) { match = false; break; }
            if (match) return i;
        }
        return -1;
    }

    static void AssertSelfSigned(X509Certificate2 cert)
    {
        var der = cert.RawData;
        var tbsEnd = Skip(der, SkipHeader(der, 0));
        var tbs = der[SkipHeader(der, 0)..tbsEnd];
        var sigStart = Skip(der, tbsEnd);
        var sigBody = SkipHeader(der, sigStart);
        var signature = der[(sigBody + 1)..Skip(der, sigStart)];
        using var rsa = cert.GetRSAPublicKey();
        Assert.NotNull(rsa);
        Assert.True(rsa!.VerifyHash(SHA256.HashData(tbs), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    static int SkipHeader(byte[] data, int at)
    {
        var first = data[at + 1];
        if (first < 0x80) return at + 2;
        return at + 2 + (first & 0x7F);
    }

    static int Skip(byte[] data, int at)
    {
        var first = data[at + 1];
        if (first < 0x80) return at + 2 + first;
        var length = 0;
        var count = first & 0x7F;
        for (var i = 0; i < count; i++) length = length * 256 + data[at + 2 + i];
        return at + 2 + count + length;
    }

    [Fact]
    public void SignsItselfAndNamesItsKey()
    {
        var pair = X509Keys.CreateSelfSigned("rp", 30, 2048);
        AssertSelfSigned(pair.Certificate);
        var want = SHA1.HashData(pair.PrivateKey.ExportRSAPublicKey());
        var der = pair.Certificate.RawData;
        Assert.Equal(want, KeyIdAfter(der, SkiOid));
        Assert.Equal(want, KeyIdAfter(der, AkiOid));
    }

    [Fact]
    public void TwoCertificatesOfOneNameHaveDifferentKeyIdentifiers()
    {
        var one = X509Keys.CreateSelfSigned("localhost:3000", 30, 2048);
        var two = X509Keys.CreateSelfSigned("localhost:3000", 30, 2048);
        Assert.Equal(one.Certificate.Subject, two.Certificate.Subject);
        Assert.NotEqual(KeyIdAfter(one.Certificate.RawData, SkiOid), KeyIdAfter(two.Certificate.RawData, SkiOid));
    }

    [Fact]
    public void GenerateKeysNamesTheCertificateAfterTheRealm()
    {
        var dir = Directory.CreateTempSubdirectory("wsfed-x509-");
        try
        {
            var config = Path.Combine(dir.FullName, "wsfed.json");
            File.WriteAllText(config, JsonSerializer.Serialize(new Dictionary<string, string>
            {
                ["realm"] = "http://localhost:3000/",
                ["replyUrl"] = "http://localhost:3000/wsfed",
                ["idpMetadata"] = "x",
                ["privateKey"] = "k.pem",
                ["certificate"] = "c.pem",
            }));
            var code = Cli.Main(new[] { "generate-keys", "--config", config, "--bits", "2048" }, new StringWriter());
            Assert.Equal(0, code);
            var cert = X509Certificate2.CreateFromPem(File.ReadAllText(Path.Combine(dir.FullName, "c.pem")));
            const string want = "CN=wsfed-caep-nodejs relying party http://localhost:3000/";
            var cn = cert.GetNameInfo(X509NameType.SimpleName, false);
            Assert.Equal("wsfed-caep-nodejs relying party http://localhost:3000/", cn);
            Assert.Equal(want, cert.Subject);
        }
        finally { dir.Delete(true); }
    }
}
