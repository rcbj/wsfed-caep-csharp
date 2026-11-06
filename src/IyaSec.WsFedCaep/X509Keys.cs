// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace IyaSec.WsFed;

public sealed class KeyPair
{
    public string PrivateKeyPem { get; init; } = "";
    public string CertificatePem { get; init; } = "";
    public X509Certificate2 Certificate { get; init; } = null!;
    public RSA PrivateKey { get; init; } = null!;
}

public static class X509Keys
{
    public static KeyPair CreateSelfSigned(string commonName, int days = 0, int bits = 0)
    {
        if (days <= 0) days = 1095;
        if (bits == 0) bits = 3072;
        using var generated = RSA.Create(bits);
        var privateKey = RSA.Create();
        privateKey.ImportPkcs8PrivateKey(generated.ExportPkcs8PrivateKey(), out _);
        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;
        if (serial[0] == 0) serial[0] = 1;
        var notBefore = DateTime.UtcNow.AddSeconds(-60);
        notBefore = new DateTime(notBefore.Year, notBefore.Month, notBefore.Day, notBefore.Hour, notBefore.Minute, notBefore.Second, DateTimeKind.Utc);
        var notAfter = notBefore.AddDays(days);
        var spki = privateKey.ExportSubjectPublicKeyInfo();
        var keyBits = SubjectPublicKeyBits(spki);
        var keyId = SHA1.HashData(keyBits);
        var extensions = Tlv(0xA3, Seq(
            Seq(Oid("2.5.29.14"), Tlv(0x04, Tlv(0x04, keyId))),
            Seq(Oid("2.5.29.35"), Tlv(0x04, Seq(Tlv(0x80, keyId)))),
            Seq(Oid("2.5.29.19"), Tlv(0x01, new byte[] { 0xFF }), Tlv(0x04, Seq())),
            Seq(Oid("2.5.29.15"), Tlv(0x01, new byte[] { 0xFF }), Tlv(0x04, Tlv(0x03, new byte[] { 0x05, 0xA0 })))
        ));
        var sha256Rsa = Seq(Oid("1.2.840.113549.1.1.11"), new byte[] { 0x05, 0x00 });
        var tbs = Seq(
            Tlv(0xA0, Tlv(0x02, new byte[] { 0x02 })),
            Tlv(0x02, serial),
            sha256Rsa,
            DerName(commonName),
            Seq(DerTime(notBefore), DerTime(notAfter)),
            DerName(commonName),
            spki,
            extensions
        );
        var hashed = SHA256.HashData(tbs);
        var signature = privateKey.SignHash(hashed, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var der = Seq(tbs, sha256Rsa, Tlv(0x03, Join(new byte[] { 0 }, signature)));
        var certificate = X509CertificateLoader.LoadCertificate(der);
        var keyPem = new string(PemEncoding.Write("PRIVATE KEY", privateKey.ExportPkcs8PrivateKey()));
        var certPem = new string(PemEncoding.Write("CERTIFICATE", der));
        return new KeyPair { PrivateKeyPem = keyPem + "\n", CertificatePem = certPem + "\n", Certificate = certificate, PrivateKey = privateKey };
    }

    static byte[] SubjectPublicKeyBits(byte[] spki)
    {
        var (body, _) = DerHeader(spki, 0);
        var (_, algEnd) = DerHeader(spki, body);
        var (bitsBody, bitsEnd) = DerHeader(spki, algEnd);
        return spki[(bitsBody + 1)..bitsEnd];
    }

    static (int start, int end) DerHeader(byte[] data, int at)
    {
        var first = data[at + 1];
        if (first < 0x80)
        {
            var start = at + 2;
            return (start, start + first);
        }
        var count = first & 0x7F;
        var length = 0;
        for (var i = 0; i < count; i++) length = length * 256 + data[at + 2 + i];
        var body = at + 2 + count;
        return (body, body + length);
    }

    static byte[] DerLen(int n)
    {
        if (n < 0x80) return new[] { (byte)n };
        var raw = new List<byte>();
        var value = n;
        while (value > 0)
        {
            raw.Insert(0, (byte)(value & 0xFF));
            value >>= 8;
        }
        raw.Insert(0, (byte)(0x80 | raw.Count));
        return raw.ToArray();
    }

    static byte[] Tlv(byte tag, params byte[][] content)
    {
        var body = Join(content);
        return Join(new[] { tag }, DerLen(body.Length), body);
    }

    static byte[] Seq(params byte[][] content) => Tlv(0x30, content);

    static byte[] Oid(string dotted)
    {
        var parts = dotted.Split('.').Select(int.Parse).ToArray();
        var body = new List<byte> { (byte)(parts[0] * 40 + parts[1]) };
        foreach (var number in parts.Skip(2))
        {
            var chunk = new List<byte> { (byte)(number & 0x7F) };
            var value = number >> 7;
            while (value > 0)
            {
                chunk.Insert(0, (byte)((value & 0x7F) | 0x80));
                value >>= 7;
            }
            body.AddRange(chunk);
        }
        return Tlv(0x06, body.ToArray());
    }

    static byte[] DerTime(DateTime moment)
    {
        var utc = moment.ToUniversalTime();
        var iso = utc.ToString("yyyyMMddHHmmss") + "Z";
        if (utc.Year < 2050) return Tlv(0x17, Encoding.ASCII.GetBytes(iso[2..]));
        return Tlv(0x18, Encoding.ASCII.GetBytes(iso));
    }

    static byte[] DerName(string commonName) => Seq(Tlv(0x31, Seq(Oid("2.5.4.3"), Tlv(0x0C, Encoding.UTF8.GetBytes(commonName)))));

    static byte[] Join(params byte[][] parts)
    {
        var len = parts.Sum(p => p.Length);
        var raw = new byte[len];
        var at = 0;
        foreach (var part in parts)
        {
            Buffer.BlockCopy(part, 0, raw, at, part.Length);
            at += part.Length;
        }
        return raw;
    }
}
