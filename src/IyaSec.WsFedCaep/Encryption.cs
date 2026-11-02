// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace IyaSec.WsFed;

static class XmlEncryption
{
    sealed record CipherSpec(string Name, bool Gcm, int KeyLength);

    static readonly Dictionary<string, CipherSpec> Ciphers = new(StringComparer.Ordinal)
    {
        ["http://www.w3.org/2009/xmlenc11#aes128-gcm"] = new("aes-128-gcm", true, 16),
        ["http://www.w3.org/2009/xmlenc11#aes192-gcm"] = new("aes-192-gcm", true, 24),
        ["http://www.w3.org/2009/xmlenc11#aes256-gcm"] = new("aes-256-gcm", true, 32),
        ["http://www.w3.org/2001/04/xmlenc#aes128-cbc"] = new("aes-128-cbc", false, 16),
        ["http://www.w3.org/2001/04/xmlenc#aes192-cbc"] = new("aes-192-cbc", false, 24),
        ["http://www.w3.org/2001/04/xmlenc#aes256-cbc"] = new("aes-256-cbc", false, 32),
    };

    const string OaepMgf1p = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
    const string Oaep11 = "http://www.w3.org/2009/xmlenc11#rsa-oaep";

    static readonly Dictionary<string, string> Digests = new(StringComparer.Ordinal)
    {
        ["http://www.w3.org/2000/09/xmldsig#sha1"] = "sha1",
        ["http://www.w3.org/2001/04/xmlenc#sha256"] = "sha256",
        ["http://www.w3.org/2001/04/xmldsig-more#sha384"] = "sha384",
        ["http://www.w3.org/2001/04/xmlenc#sha512"] = "sha512",
    };

    static readonly Dictionary<string, string> Mgfs = new(StringComparer.Ordinal)
    {
        ["http://www.w3.org/2009/xmlenc11#mgf1sha1"] = "sha1",
        ["http://www.w3.org/2009/xmlenc11#mgf1sha256"] = "sha256",
        ["http://www.w3.org/2009/xmlenc11#mgf1sha384"] = "sha384",
        ["http://www.w3.org/2009/xmlenc11#mgf1sha512"] = "sha512",
    };

    static WsFedException Fail(string message) => new("decryption", message);

    static byte[] B64(string value)
    {
        var compact = string.Concat(value.Where(c => !char.IsWhiteSpace(c)));
        return Convert.FromBase64String(compact);
    }

    static RSAEncryptionPadding Padding(string name) => name switch
    {
        "sha256" => RSAEncryptionPadding.OaepSHA256,
        "sha384" => RSAEncryptionPadding.OaepSHA384,
        "sha512" => RSAEncryptionPadding.OaepSHA512,
        _ => RSAEncryptionPadding.OaepSHA1,
    };

    static byte[] UnwrapKey(XmlElement encryptedKey, RSA key)
    {
        var method = XmlDoc.Child(encryptedKey, Names.Xenc, "EncryptionMethod");
        var alg = method == null ? "" : XmlDoc.Attr(method, "Algorithm");
        if (alg != OaepMgf1p && alg != Oaep11)
        {
            var shown = alg == "" ? "(none)" : alg;
            throw Fail("the content key is wrapped with " + shown + "; only RSA-OAEP is accepted");
        }
        var digestName = "sha1";
        var digestMethod = method == null ? null : XmlDoc.Child(method, Names.Ds, "DigestMethod");
        if (digestMethod != null)
        {
            var digestAlg = XmlDoc.Attr(digestMethod, "Algorithm");
            if (digestAlg != "")
            {
                if (!Digests.TryGetValue(digestAlg, out var name))
                    throw Fail("the OAEP digest " + digestAlg + " is not supported");
                digestName = name!;
            }
        }
        var mgf = "sha1";
        if (alg == Oaep11 && method != null)
        {
            var mgfEl = XmlDoc.Child(method, Names.Xenc11, "MGF");
            if (mgfEl != null)
            {
                var mgfAlg = XmlDoc.Attr(mgfEl, "Algorithm");
                if (mgfAlg != "")
                {
                    if (!Mgfs.TryGetValue(mgfAlg, out var name))
                        throw Fail("the OAEP mask generation function " + mgfAlg + " is not supported");
                    mgf = name!;
                }
            }
        }
        if (mgf != digestName)
            throw Fail("OAEP with digest " + digestName + " and MGF1 " + mgf + " is not supported; node:crypto uses one hash for both");
        var values = XmlDoc.Descendants(encryptedKey, Names.Xenc, "CipherValue");
        var raw = values.Count == 0 ? "" : XmlDoc.Text(values[0]);
        byte[] blob;
        try { blob = B64(raw); }
        catch (Exception ex) { throw new WsFedException("decryption", "the content key could not be unwrapped with this relying party's key", ex); }
        try { return key.Decrypt(blob, Padding(digestName)); }
        catch (Exception ex) { throw new WsFedException("decryption", "the content key could not be unwrapped with this relying party's key", ex); }
    }

    public static string DecryptElement(XmlElement encrypted, RSA key)
    {
        var data = encrypted;
        if (!(encrypted.LocalName == "EncryptedData" && encrypted.NamespaceURI == Names.Xenc))
            data = XmlDoc.Child(encrypted, Names.Xenc, "EncryptedData") ?? throw Fail("<" + encrypted.LocalName + "> has no EncryptedData");
        var method = XmlDoc.Child(data, Names.Xenc, "EncryptionMethod");
        var alg = method == null ? "" : XmlDoc.Attr(method, "Algorithm");
        if (!Ciphers.TryGetValue(alg, out var spec))
        {
            var shown = alg == "" ? "(none)" : alg;
            throw Fail("the content is encrypted with " + shown + ", which is not supported");
        }
        var keys = XmlDoc.Descendants(encrypted, Names.Xenc, "EncryptedKey");
        if (keys.Count == 0) throw Fail("<" + encrypted.LocalName + "> carries no EncryptedKey");
        var contentKey = UnwrapKey(keys[0], key);
        if (contentKey.Length != spec.KeyLength)
            throw Fail("the content key is " + contentKey.Length + " bytes; " + spec.Name + " needs " + spec.KeyLength);
        var cipherData = XmlDoc.Child(data, Names.Xenc, "CipherData");
        var valueEl = cipherData == null ? null : XmlDoc.Child(cipherData, Names.Xenc, "CipherValue");
        byte[] raw;
        try { raw = B64(valueEl == null ? "" : XmlDoc.Text(valueEl)); }
        catch (Exception ex) { throw new WsFedException("decryption", "the content could not be decrypted", ex); }
        if (spec.Gcm)
        {
            if (raw.Length < 12 + 16) throw Fail("the ciphertext is too short");
            var nonce = raw.AsSpan(0, 12);
            var tag = raw.AsSpan(raw.Length - 16, 16);
            var ct = raw.AsSpan(12, raw.Length - 12 - 16);
            var plain = new byte[ct.Length];
            try
            {
                using var gcm = new AesGcm(contentKey, 16);
                gcm.Decrypt(nonce, ct, tag, plain);
            }
            catch (Exception ex) { throw new WsFedException("decryption", "the content could not be decrypted", ex); }
            return Encoding.UTF8.GetString(plain);
        }
        if (raw.Length < 32 || raw.Length % 16 != 0) throw Fail("the ciphertext is not a whole number of blocks");
        try
        {
            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = contentKey;
            aes.IV = raw[..16];
            using var dec = aes.CreateDecryptor();
            var plain = dec.TransformFinalBlock(raw, 16, raw.Length - 16);
            return Encoding.UTF8.GetString(plain);
        }
        catch (WsFedException) { throw; }
        catch (Exception ex) { throw new WsFedException("decryption", "the content could not be decrypted", ex); }
    }
}
