// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Text;

namespace IyaSec.WsFed.Tests;

public sealed class AssertionOptions
{
    public string? Audience { get; set; }
    public bool AudienceSet { get; set; }
    public string Recipient { get; set; } = StubIdp.Reply;
    public bool IncludeRecipient { get; set; } = true;
    public string InResponseTo { get; set; } = "";
    public TimeSpan NotOnOrAfter { get; set; } = TimeSpan.FromSeconds(300);
    public bool NotOnOrAfterSet { get; set; }
    public string Issuer { get; set; } = "";
    public string NameId { get; set; } = "";
    public string SessionIndex { get; set; } = "";
    public string ExtraAttributes { get; set; } = "";
    public bool BareConfirmation { get; set; }
    public bool NoConditionsExpiry { get; set; }
}

public sealed class Made
{
    public string Xml { get; set; } = "";
    public string Id { get; set; } = "";
}

public sealed class MetaOptions
{
    public string KeyIn { get; set; } = "";
    public string[]? TokenTypes { get; set; }
    public string FedPrefix { get; set; } = "";
    public bool NoSts { get; set; }
}

public sealed class WResultOptions
{
    public string? Token { get; set; }
    public bool TokenSet { get; set; }
    public string Trust { get; set; } = "";
    public string AppliesTo { get; set; } = "";
    public string TokenType { get; set; } = "";
    public TimeSpan Expires { get; set; } = TimeSpan.FromHours(1);
    public bool ExpiresSet { get; set; }
}

public static class StubIdp
{
    public const string IdPEntity = "https://idp.test";
    public const string Passive = "https://idp.test/wsfed";
    public const string Realm = "https://rp.test/";
    public const string Reply = "https://rp.test/wsfed";
    const string Ds = "http://www.w3.org/2000/09/xmldsig#";
    const string Xenc = "http://www.w3.org/2001/04/xmlenc#";
    const string Xenc11 = "http://www.w3.org/2009/xmlenc11#";
    const string Saml = "urn:oasis:names:tc:SAML:2.0:assertion";
    const string Claims = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims";

    public static string RpKey { get; }
    public static string RpCert { get; }
    public static string IdPKey { get; }
    public static string IdPCert { get; }
    static readonly RSA RpPublic;
    static readonly RSA IdpPrivate;

    static StubIdp()
    {
        var rp = X509Keys.CreateSelfSigned("rp", 30, 2048);
        var idp = X509Keys.CreateSelfSigned("idp", 30, 2048);
        RpKey = rp.PrivateKeyPem;
        RpCert = rp.CertificatePem;
        IdPKey = idp.PrivateKeyPem;
        IdPCert = idp.CertificatePem;
        RpPublic = RSA.Create();
        RpPublic.ImportParameters(rp.PrivateKey.ExportParameters(false));
        IdpPrivate = idp.PrivateKey;
    }

    static string PemBody(string value)
    {
        var b = new StringBuilder();
        foreach (var line in value.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Contains("-----") || trimmed == "") continue;
            b.Append(trimmed);
        }
        return b.ToString();
    }

    public static string IdPMetadata(MetaOptions? opts = null)
    {
        opts ??= new MetaOptions();
        var fed = opts.FedPrefix == "" ? "fed" : opts.FedPrefix;
        var key = "<md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>" + PemBody(IdPCert) + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>";
        var types = opts.TokenTypes ?? new[] { "urn:oasis:names:tc:SAML:1.0:assertion", "urn:oasis:names:tc:SAML:2.0:assertion" };
        var typeXml = string.Concat(types.Select(token => "<" + fed + ":TokenType Uri=\"" + token + "\"/>"));
        var keyIn = opts.KeyIn == "" ? "sts" : opts.KeyIn;
        var stsKey = keyIn == "idpsso" ? "" : key;
        var sts = "";
        if (!opts.NoSts)
        {
            sts = "\n  <md:RoleDescriptor xsi:type=\"" + fed + ":SecurityTokenServiceType\" protocolSupportEnumeration=\"http://docs.oasis-open.org/wsfed/federation/200706\">\n    " + stsKey + "\n    <" + fed + ":TokenTypesOffered>" + typeXml + "</" + fed + ":TokenTypesOffered>\n    <" + fed + ":SecurityTokenServiceEndpoint><wsa:EndpointReference><wsa:Address>https://idp.test/sts</wsa:Address></wsa:EndpointReference></" + fed + ":SecurityTokenServiceEndpoint>\n    <" + fed + ":PassiveRequestorEndpoint><wsa:EndpointReference><wsa:Address>" + Passive + "</wsa:Address></wsa:EndpointReference></" + fed + ":PassiveRequestorEndpoint>\n  </md:RoleDescriptor>";
        }
        return "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"" + Ds + "\" xmlns:" + fed + "=\"http://docs.oasis-open.org/wsfed/federation/200706\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" entityID=\"" + IdPEntity + "\">" + sts + "\n  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n    " + key + "\n    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp.test/saml2/sso\"/>\n  </md:IDPSSODescriptor>\n</md:EntityDescriptor>";
    }

    public static string Iso(TimeSpan offset)
    {
        var moment = DateTimeOffset.UtcNow.Add(offset);
        return moment.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'");
    }

    static string NewId() => "_" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static Made AssertionXml(AssertionOptions? opts = null)
    {
        opts ??= new AssertionOptions();
        var aid = NewId();
        var recipient = opts.IncludeRecipient ? opts.Recipient : "";
        var recipientAttr = recipient == "" ? "" : " Recipient=\"" + recipient + "\"";
        var irt = opts.InResponseTo == "" ? "" : " InResponseTo=\"" + opts.InResponseTo + "\"";
        var offset = opts.NotOnOrAfterSet ? opts.NotOnOrAfter : TimeSpan.FromSeconds(300);
        var confirmation = "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"/>";
        if (!opts.BareConfirmation)
            confirmation = "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData" + recipientAttr + " NotOnOrAfter=\"" + Iso(offset) + "\"" + irt + "/></saml:SubjectConfirmation>";
        var expiry = opts.NoConditionsExpiry ? "" : " NotOnOrAfter=\"" + Iso(offset) + "\"";
        var issuer = opts.Issuer == "" ? IdPEntity : opts.Issuer;
        var name = opts.NameId == "" ? "alice-1234" : opts.NameId;
        var session = opts.SessionIndex == "" ? "_session1" : opts.SessionIndex;
        var audience = opts.AudienceSet ? opts.Audience ?? "" : Realm;
        var xml = "<saml:Assertion xmlns:saml=\"" + Saml + "\" ID=\"" + aid + "\" Version=\"2.0\" IssueInstant=\"" + Iso(TimeSpan.Zero) + "\">" +
                  "<saml:Issuer>" + issuer + "</saml:Issuer>" +
                  "<saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">" + name + "</saml:NameID>" +
                  confirmation + "</saml:Subject>" +
                  "<saml:Conditions NotBefore=\"" + Iso(TimeSpan.FromSeconds(-5)) + "\"" + expiry + ">" +
                  "<saml:AudienceRestriction><saml:Audience>" + audience + "</saml:Audience></saml:AudienceRestriction></saml:Conditions>" +
                  "<saml:AttributeStatement><saml:Attribute Name=\"" + Claims + "/nameidentifier\"><saml:AttributeValue>urn:uuid:alice</saml:AttributeValue></saml:Attribute>" +
                  "<saml:Attribute Name=\"" + Claims + "/emailaddress\" FriendlyName=\"mail\"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute>" +
                  "<saml:Attribute Name=\"http://schemas.microsoft.com/ws/2008/06/identity/claims/role\"><saml:AttributeValue>staff</saml:AttributeValue><saml:AttributeValue>admins</saml:AttributeValue></saml:Attribute>" +
                  opts.ExtraAttributes + "</saml:AttributeStatement>" +
                  "<saml:AuthnStatement AuthnInstant=\"" + Iso(TimeSpan.FromSeconds(-1)) + "\" SessionIndex=\"" + session + "\">" +
                  "<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>" +
                  "</saml:Assertion>";
        return new Made { Xml = xml, Id = aid };
    }

    public static string SignXml(string xml, string elementId, string? keyPem = null, string? certPem = null)
    {
        keyPem = string.IsNullOrEmpty(keyPem) ? IdPKey : keyPem;
        certPem = string.IsNullOrEmpty(certPem) ? IdPCert : certPem;
        using var key = RSA.Create();
        key.ImportFromPem(keyPem);
        _ = IdpPrivate;
        return XmlSignature.SignEnveloped(xml, elementId, key, certPem);
    }

    public static Made SignedAssertion(AssertionOptions? opts = null)
    {
        var made = AssertionXml(opts);
        return new Made { Xml = SignXml(made.Xml, made.Id), Id = made.Id };
    }

    static byte[] Pkcs7(byte[] data)
    {
        var pad = 16 - (data.Length % 16);
        var raw = new byte[data.Length + pad];
        Buffer.BlockCopy(data, 0, raw, 0, data.Length);
        for (var i = 0; i < pad; i++) raw[data.Length + i] = (byte)pad;
        return raw;
    }

    public static string Encrypt(string plain, string cipherName = "", string transport = "", string wrapper = "")
    {
        if (cipherName == "") cipherName = "aes-256-gcm";
        if (transport == "") transport = "mgf1p";
        if (wrapper == "") wrapper = "EncryptedAssertion";
        byte[] key;
        byte[] value;
        string alg;
        if (cipherName == "aes-256-gcm")
        {
            key = RandomNumberGenerator.GetBytes(32);
            var iv = RandomNumberGenerator.GetBytes(12);
            var sealedBytes = new byte[Encoding.UTF8.GetByteCount(plain) + 16];
            var tag = sealedBytes.AsSpan(sealedBytes.Length - 16);
            using var gcm = new AesGcm(key, 16);
            gcm.Encrypt(iv, Encoding.UTF8.GetBytes(plain), sealedBytes.AsSpan(0, sealedBytes.Length - 16), tag);
            value = iv.Concat(sealedBytes).ToArray();
            alg = Xenc11 + "aes256-gcm";
        }
        else if (cipherName == "aes-128-cbc")
        {
            key = RandomNumberGenerator.GetBytes(16);
            var iv = RandomNumberGenerator.GetBytes(16);
            var padded = Pkcs7(Encoding.UTF8.GetBytes(plain));
            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            aes.IV = iv;
            using var enc = aes.CreateEncryptor();
            var outBytes = enc.TransformFinalBlock(padded, 0, padded.Length);
            value = iv.Concat(outBytes).ToArray();
            alg = Xenc + "aes128-cbc";
        }
        else throw new InvalidOperationException(cipherName);
        string keyMethod;
        byte[] wrapped;
        if (transport == "mgf1p")
        {
            wrapped = RpPublic.Encrypt(key, RSAEncryptionPadding.OaepSHA1);
            keyMethod = "<xenc:EncryptionMethod Algorithm=\"" + Xenc + "rsa-oaep-mgf1p\"/>";
        }
        else if (transport == "oaep256")
        {
            wrapped = RpPublic.Encrypt(key, RSAEncryptionPadding.OaepSHA256);
            keyMethod = "<xenc:EncryptionMethod Algorithm=\"" + Xenc11 + "rsa-oaep\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><xenc11:MGF xmlns:xenc11=\"" + Xenc11 + "\" Algorithm=\"" + Xenc11 + "mgf1sha256\"/></xenc:EncryptionMethod>";
        }
        else throw new InvalidOperationException(transport);
        var data = "<xenc:EncryptedData xmlns:xenc=\"" + Xenc + "\" Type=\"" + Xenc + "Element\">" +
                   "<xenc:EncryptionMethod Algorithm=\"" + alg + "\"/>" +
                   "<ds:KeyInfo xmlns:ds=\"" + Ds + "\"><xenc:EncryptedKey>" + keyMethod +
                   "<xenc:CipherData><xenc:CipherValue>" + Convert.ToBase64String(wrapped) + "</xenc:CipherValue></xenc:CipherData>" +
                   "</xenc:EncryptedKey></ds:KeyInfo>" +
                   "<xenc:CipherData><xenc:CipherValue>" + Convert.ToBase64String(value) + "</xenc:CipherValue></xenc:CipherData>" +
                   "</xenc:EncryptedData>";
        if (wrapper == "none") return data;
        return "<saml:" + wrapper + " xmlns:saml=\"" + Saml + "\">" + data + "</saml:" + wrapper + ">";
    }

    public static string WResult(WResultOptions? opts = null)
    {
        opts ??= new WResultOptions();
        string body;
        if (opts.TokenSet) body = opts.Token ?? "";
        else body = SignedAssertion().Xml;
        var ns = opts.Trust == "1.3" ? "http://docs.oasis-open.org/ws-sx/ws-trust/200512" : "http://schemas.xmlsoap.org/ws/2005/02/trust";
        const string wsu = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
        var applies = opts.AppliesTo == "" ? Realm : opts.AppliesTo;
        var expires = opts.ExpiresSet ? opts.Expires : TimeSpan.FromHours(1);
        var tokenType = opts.TokenType == "" ? "urn:oasis:names:tc:SAML:2.0:assertion" : opts.TokenType;
        var rstr = "<t:RequestSecurityTokenResponse xmlns:t=\"" + ns + "\">" +
                   "<t:Lifetime><wsu:Created xmlns:wsu=\"" + wsu + "\">" + Iso(TimeSpan.Zero) + "</wsu:Created>" +
                   "<wsu:Expires xmlns:wsu=\"" + wsu + "\">" + Iso(expires) + "</wsu:Expires></t:Lifetime>" +
                   "<wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">" +
                   "<wsa:EndpointReference xmlns:wsa=\"http://www.w3.org/2005/08/addressing\">" +
                   "<wsa:Address>" + applies + "</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>" +
                   "<t:RequestedSecurityToken>" + body + "</t:RequestedSecurityToken>" +
                   "<t:TokenType>" + tokenType + "</t:TokenType>" +
                   "<t:RequestType>" + ns + "/Issue</t:RequestType><t:KeyType>" + ns + "/Bearer</t:KeyType>" +
                   "</t:RequestSecurityTokenResponse>";
        if (opts.Trust == "1.3")
            return "<t:RequestSecurityTokenResponseCollection xmlns:t=\"" + ns + "\">" + rstr + "</t:RequestSecurityTokenResponseCollection>";
        return rstr;
    }

    public static string Saml11() =>
        "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" MajorVersion=\"1\" MinorVersion=\"1\" AssertionID=\"" + NewId() + "\" Issuer=\"" + IdPEntity + "\" IssueInstant=\"" + Iso(TimeSpan.Zero) + "\"><saml:AttributeStatement><saml:Subject><saml:NameIdentifier>alice</saml:NameIdentifier></saml:Subject></saml:AttributeStatement></saml:Assertion>";
}
