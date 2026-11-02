// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Text.RegularExpressions;
using Xunit;

namespace IyaSec.WsFed.Tests;

public class RpTests
{
    static RelyingParty MustRp(Dictionary<string, object?> config) => RelyingParty.Create(config, Path.GetTempPath());

    static void Rejects(Action act, string code, string pattern)
    {
        var ex = Assert.Throws<WsFedException>(act);
        Assert.Equal(code, ex.Code);
        if (pattern != "") Assert.Matches(pattern, ex.Message);
    }

    static Dictionary<string, object?> Cfg(Dictionary<string, object?>? extra = null, MetaOptions? meta = null)
    {
        var body = new Dictionary<string, object?>
        {
            ["realm"] = StubIdp.Realm,
            ["replyUrl"] = StubIdp.Reply,
            ["privateKey"] = StubIdp.RpKey,
            ["certificate"] = StubIdp.RpCert,
            ["idpMetadata"] = StubIdp.IdPMetadata(meta),
        };
        if (extra != null)
            foreach (var pair in extra) body[pair.Key] = pair.Value;
        return body;
    }

    static bool SameConfig(Resolved a, Resolved b) =>
        a.Realm == b.Realm && a.ReplyUrl == b.ReplyUrl && a.IdPMetadata == b.IdPMetadata &&
        a.ClockSkewMs == b.ClockSkewMs && a.WantAssertionsEncrypted == b.WantAssertionsEncrypted &&
        a.AllowUnsolicited == b.AllowUnsolicited && a.RequestTokenType == b.RequestTokenType &&
        a.IdPCa == b.IdPCa && a.IdPEntityId == b.IdPEntityId && a.PrivateKey == null && b.PrivateKey == null;

    static Login Post(RelyingParty rp, string result, string? requestId, string? wctx, IReadOnlyList<string>? ids)
    {
        var body = new Dictionary<string, string> { ["wa"] = "wsignin1.0", ["wresult"] = result };
        if (wctx == null && requestId != null) wctx = "id=" + requestId;
        if (wctx != null) body["wctx"] = wctx;
        ids ??= requestId == null ? null : new[] { requestId };
        return rp.HandleReply(new ReplyRequest { Method = "POST", Url = "/wsfed", Body = body }, ids);
    }

    static Dictionary<string, string> Qparams(string raw)
    {
        var q = raw.IndexOf('?');
        return RelyingParty.FirstMap(q < 0 ? "" : raw[(q + 1)..]);
    }

    [Fact]
    public void ConfigurationRequiresRealmReplyAndAMatchingKey()
    {
        Rejects(() => RelyingParty.Create(Cfg(new() { ["realm"] = "" }), ""), "config", "realm");
        Rejects(() => RelyingParty.Create(Cfg(new() { ["replyUrl"] = "/wsfed" }), ""), "config", "absolute");
        Rejects(() => RelyingParty.Create(Cfg(new() { ["certificate"] = StubIdp.IdPCert }), ""), "config", "not for the private key");
        Rejects(() => RelyingParty.Create(new Dictionary<string, object?>
        {
            ["realm"] = StubIdp.Realm, ["replyUrl"] = StubIdp.Reply, ["idpMetadata"] = StubIdp.IdPMetadata(), ["privateKey"] = StubIdp.RpKey,
        }, ""), "config", "together");
        Rejects(() => RelyingParty.Create(new Dictionary<string, object?>
        {
            ["realm"] = StubIdp.Realm, ["replyUrl"] = StubIdp.Reply, ["idpMetadata"] = StubIdp.IdPMetadata(), ["wantAssertionsEncrypted"] = true,
        }, ""), "config", "needs privateKey");
        var keyless = MustRp(new Dictionary<string, object?>
        {
            ["realm"] = StubIdp.Realm, ["replyUrl"] = StubIdp.Reply, ["idpMetadata"] = StubIdp.IdPMetadata(),
        });
        Assert.DoesNotContain("KeyDescriptor", keyless.MetadataXml());
    }

    [Fact]
    public void SignalsOmittedOrTrueIsLeftOff()
    {
        var baseConfig = new Dictionary<string, object?>
        {
            ["realm"] = StubIdp.Realm, ["replyUrl"] = StubIdp.Reply,
            ["idpMetadata"] = "https://idp.example/FederationMetadata/2007-06/FederationMetadata.xml",
        };
        var omitted = WsfedConfig.Resolve(baseConfig, "");
        Assert.False(omitted.SignalsSet);
        Assert.Equal(StubIdp.Realm, omitted.Realm);
        Assert.Equal(StubIdp.Reply, omitted.ReplyUrl);
        Assert.True(omitted.RequestTokenType);
        var on = new Dictionary<string, object?>(baseConfig) { ["signals"] = true };
        var resolved = WsfedConfig.Resolve(on, "");
        Assert.False(resolved.SignalsSet);
        Assert.True(SameConfig(resolved, omitted));
    }

    [Fact]
    public void SignalsFalseIsRecorded()
    {
        var baseConfig = new Dictionary<string, object?>
        {
            ["realm"] = StubIdp.Realm, ["replyUrl"] = StubIdp.Reply,
            ["idpMetadata"] = "https://idp.example/FederationMetadata/2007-06/FederationMetadata.xml",
        };
        var offMap = new Dictionary<string, object?>(baseConfig) { ["signals"] = false };
        var off = WsfedConfig.Resolve(offMap, "");
        Assert.True(off.SignalsSet);
        Assert.False(off.Signals);
        var omitted = WsfedConfig.Resolve(baseConfig, "");
        Assert.True(SameConfig(off, omitted));
        Assert.Equal(baseConfig["idpMetadata"], off.IdPMetadata);
    }

    [Fact]
    public void SignalsMustBeTrueOrFalse()
    {
        var ex = Assert.Throws<WsFedException>(() => WsfedConfig.Resolve(new Dictionary<string, object?>
        {
            ["realm"] = StubIdp.Realm, ["replyUrl"] = StubIdp.Reply, ["idpMetadata"] = "https://idp.example/metadata", ["signals"] = "no",
        }, ""));
        Assert.Equal("config", ex.Code);
        Assert.Equal("signals must be true or false", ex.Message);
    }

    [Fact]
    public void ReadsTheSecurityTokenServiceRole()
    {
        var rp = MustRp(Cfg());
        Assert.Equal(StubIdp.IdPEntity, rp.Idp!.EntityId);
        Assert.Equal(StubIdp.Passive, rp.Idp.PassiveRequestorEndpoint);
        Assert.Contains(Names.Saml2Token, rp.Idp.TokenTypesOffered);
        Assert.Single(rp.Idp.SigningCertificates);
    }

    [Fact]
    public void XsiTypeAndIdpRoleFallback()
    {
        Assert.Equal(StubIdp.Passive, MustRp(Cfg(null, new MetaOptions { FedPrefix = "wsfed" })).Idp!.PassiveRequestorEndpoint);
        Assert.Single(MustRp(Cfg(null, new MetaOptions { KeyIn = "idpsso" })).Idp!.SigningCertificates);
    }

    [Fact]
    public void RefusesMetadataWithoutAnStsOrSaml2()
    {
        Rejects(() => RelyingParty.Create(Cfg(null, new MetaOptions { NoSts = true }), ""), "metadata", "SecurityTokenServiceType");
        Rejects(() => RelyingParty.Create(Cfg(null, new MetaOptions { TokenTypes = new[] { "urn:oasis:names:tc:SAML:1.0:assertion" } }), ""), "metadata", "no SAML 2.0");
    }

    [Fact]
    public void WritesApplicationServiceMetadata()
    {
        var xml = MustRp(Cfg()).MetadataXml();
        Assert.Contains("entityID=\"" + StubIdp.Realm + "\"", xml);
        Assert.Contains("xsi:type=\"fed:ApplicationServiceType\"", xml);
        Assert.Contains("<fed:PassiveRequestorEndpoint><wsa:EndpointReference><wsa:Address>" + StubIdp.Reply + "</wsa:Address>", xml);
        Assert.Contains("<fed:TargetScopes><wsa:EndpointReference><wsa:Address>" + StubIdp.Realm + "</wsa:Address>", xml);
        Assert.Matches(new Regex("<md:KeyDescriptor use=\"encryption\">[\\s\\S]*xmlenc11#aes256-gcm[\\s\\S]*</md:KeyDescriptor>"), xml);
    }

    [Fact]
    public void SigninNamesRealmReplyWctxAndSaml2()
    {
        var rp = MustRp(Cfg());
        var req = rp.Login(new LoginOptions { RelayState = "/home é" });
        var parms = Qparams(req.Url);
        var parsed = new Uri(req.Url);
        Assert.Equal(StubIdp.Passive, parsed.GetLeftPart(UriPartial.Path));
        Assert.Equal("wsignin1.0", parms["wa"]);
        Assert.Equal(StubIdp.Realm, parms["wtrealm"]);
        Assert.Equal(StubIdp.Reply, parms["wreply"]);
        var wctx = RelyingParty.FirstMap(parms["wctx"]);
        Assert.Equal(req.Id, wctx["id"]);
        Assert.Equal("/home é", wctx["ru"]);
        Assert.Contains("<wst:TokenType>urn:oasis:names:tc:SAML:2.0:assertion</wst:TokenType>", parms["wreq"]);
        Assert.Matches(new Regex(@"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$"), parms["wct"]);
        Assert.False(parms.ContainsKey("wfresh"));
    }

    [Fact]
    public void ForceAuthnAndProtocolParams()
    {
        var rp = MustRp(Cfg(new() { ["requestTokenType"] = false }));
        var req = rp.Login(new LoginOptions
        {
            ForceAuthn = true,
            AuthenticationMethod = "http://schemas.microsoft.com/claims/multipleauthn",
            HomeRealm = "urn:partner",
            Params = new Dictionary<string, string> { ["login_hint"] = "alice" },
        });
        var parms = Qparams(req.Url);
        Assert.Equal("0", parms["wfresh"]);
        Assert.Equal("http://schemas.microsoft.com/claims/multipleauthn", parms["wauth"]);
        Assert.Equal("urn:partner", parms["whr"]);
        Assert.Equal("alice", parms["login_hint"]);
        Assert.False(parms.ContainsKey("wreq"));
        Rejects(() => rp.Login(new LoginOptions { Params = new Dictionary<string, string> { ["wtrealm"] = "urn:evil" } }), "config", "protocol's own");
        Rejects(() => rp.Login(new LoginOptions { RelayState = new string('x', 1025) }), "config", "1024 bytes");
    }

    [Fact]
    public void SignoutRequest()
    {
        var parms = Qparams(MustRp(Cfg()).Logout("https://rp.test/"));
        Assert.Equal("wsignout1.0", parms["wa"]);
        Assert.Equal(StubIdp.Realm, parms["wtrealm"]);
        Assert.Equal("https://rp.test/", parms["wreply"]);
    }

    [Fact]
    public void SignedAssertionInA2005Response()
    {
        var rp = MustRp(Cfg());
        var req = rp.Login(new LoginOptions { RelayState = "/home" });
        var who = Post(rp, StubIdp.WResult(), req.Id, req.Wctx, null);
        Assert.Equal("alice-1234", who.NameId);
        Assert.Equal("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", who.NameIdFormat);
        Assert.Equal("_session1", who.SessionIndex);
        Assert.Equal("/home", who.RelayState);
        Assert.Equal(req.Id, who.RequestId);
        Assert.Equal("2005/02", who.TrustVersion);
        Assert.Equal(StubIdp.Realm, who.Realm);
        Assert.False(who.Encrypted);
        Assert.Equal("staff,admins", string.Join(",", who.Attributes["http://schemas.microsoft.com/ws/2008/06/identity/claims/role"]));
        Assert.Equal("mail", who.AttributeFriendlyNames["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"]);
        Assert.Equal("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", who.AuthnContextClassRef);
    }

    [Fact]
    public void Trust13AndARawFormBody()
    {
        var rp = MustRp(Cfg());
        var who = Post(rp, StubIdp.WResult(new WResultOptions { Trust = "1.3" }), "_r", null, null);
        Assert.Equal("1.3", who.TrustVersion);
        var signed = StubIdp.WResult();
        var raw = "wa=" + Uri.EscapeDataString("wsignin1.0") + "&wresult=" + Uri.EscapeDataString(signed) + "&wctx=" + Uri.EscapeDataString("id=_s");
        who = rp.HandleReply(new ReplyRequest { Method = "POST", Url = "/wsfed", Body = raw }, new[] { "_x", "_s" });
        Assert.Equal("alice-1234", who.NameId);
    }

    [Fact]
    public void RecipientOptionalAndChecked()
    {
        var rp = MustRp(Cfg());
        var made = StubIdp.SignedAssertion(new AssertionOptions { IncludeRecipient = false, Recipient = "" });
        var token = made.Xml;
        var who = Post(rp, StubIdp.WResult(new WResultOptions { Token = token, TokenSet = true }), "_r", null, null);
        Assert.Equal("alice-1234", who.NameId);
        made = StubIdp.SignedAssertion(new AssertionOptions { Recipient = "https://other.test/wsfed" });
        token = made.Xml;
        Rejects(() => Post(rp, StubIdp.WResult(new WResultOptions { Token = token, TokenSet = true }), "_r", null, null), "validation", "Recipient");
    }

    [Fact]
    public void BareBearerConfirmation()
    {
        var rp = MustRp(Cfg());
        var made = StubIdp.SignedAssertion(new AssertionOptions { BareConfirmation = true });
        var who = Post(rp, StubIdp.WResult(new WResultOptions { Token = made.Xml, TokenSet = true }), "_r", null, null);
        Assert.Equal("alice-1234", who.NameId);
        Assert.True(who.NotOnOrAfter > DateTimeOffset.UtcNow);
        made = StubIdp.SignedAssertion(new AssertionOptions { BareConfirmation = true, NotOnOrAfter = TimeSpan.FromSeconds(-120), NotOnOrAfterSet = true });
        Rejects(() => Post(rp, StubIdp.WResult(new WResultOptions { Token = made.Xml, TokenSet = true }), "_r", null, null), "validation", "expired");
        made = StubIdp.SignedAssertion(new AssertionOptions { BareConfirmation = true, NoConditionsExpiry = true });
        Rejects(() => Post(rp, StubIdp.WResult(new WResultOptions { Token = made.Xml, TokenSet = true }), "_r", null, null), "validation", "nothing|no Conditions NotOnOrAfter");
    }

    [Fact]
    public void UnsignedAssertionIsRefused()
    {
        var made = StubIdp.AssertionXml();
        Rejects(() => Post(MustRp(Cfg()), StubIdp.WResult(new WResultOptions { Token = made.Xml, TokenSet = true }), "_r", null, null), "validation", "not signed");
    }

    [Fact]
    public void AlteredOrWrongKeyIsRefused()
    {
        var rp = MustRp(Cfg());
        var made = StubIdp.SignedAssertion();
        Rejects(() => Post(rp, StubIdp.WResult(new WResultOptions { Token = made.Xml.Replace("alice-1234", "mallory"), TokenSet = true }), "_r", null, null), "signature", "");
        var plain = StubIdp.AssertionXml();
        var signed = StubIdp.SignXml(plain.Xml, plain.Id, StubIdp.RpKey, StubIdp.RpCert);
        Rejects(() => Post(rp, StubIdp.WResult(new WResultOptions { Token = signed, TokenSet = true }), "_r", null, null), "signature", "does not verify");
    }

    [Fact]
    public void SignatureWrapping()
    {
        var rp = MustRp(Cfg());
        var signed = StubIdp.SignedAssertion();
        var forged = StubIdp.AssertionXml(new AssertionOptions { NameId = "mallory" });
        var both = forged.Xml + signed.Xml;
        Rejects(() => Post(rp, StubIdp.WResult(new WResultOptions { Token = both, TokenSet = true }), "_r", null, null), "message", "exactly one");
        var hidden = Regex.Replace(forged.Xml, "ID=\"[^\"]+\"", "ID=\"" + signed.Id + "\"");
        hidden = hidden.Replace("</saml:Assertion>", "<saml:Advice>" + signed.Xml + "</saml:Advice></saml:Assertion>");
        Rejects(() => Post(rp, StubIdp.WResult(new WResultOptions { Token = hidden, TokenSet = true }), "_r", null, null), "signature", "two elements");
        var decoy = StubIdp.WResult(new WResultOptions { Token = signed.Xml, TokenSet = true });
        decoy = decoy.Replace("<t:Lifetime>", "<t:Lifetime xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"" + signed.Id + "\">");
        Rejects(() => Post(rp, decoy, "_r", null, null), "signature", "two elements");
        var sig = Regex.Match(signed.Xml, "<Signature[\\s\\S]*</Signature>").Value;
        if (sig == "") sig = Regex.Match(signed.Xml, "<ds:Signature[\\s\\S]*</ds:Signature>").Value;
        var moved = Regex.Replace(forged.Xml, "(</saml:Issuer>)", "${1}" + sig);
        Rejects(() => Post(rp, StubIdp.WResult(new WResultOptions { Token = moved, TokenSet = true }), "_r", null, null), "signature", "refers to");
    }

    [Fact]
    public void WrongRealmIssuerOrExpiry()
    {
        var rp = MustRp(Cfg());
        var made = StubIdp.SignedAssertion(new AssertionOptions { Audience = "https://other.test/", AudienceSet = true });
        Rejects(() => Post(rp, StubIdp.WResult(new WResultOptions { Token = made.Xml, TokenSet = true }), "_r", null, null), "validation", "not for");
        made = StubIdp.SignedAssertion(new AssertionOptions { Issuer = "https://evil.test" });
        Rejects(() => Post(rp, StubIdp.WResult(new WResultOptions { Token = made.Xml, TokenSet = true }), "_r", null, null), "validation", "issued by");
        made = StubIdp.SignedAssertion(new AssertionOptions { NotOnOrAfter = TimeSpan.FromSeconds(-120), NotOnOrAfterSet = true });
        Rejects(() => Post(rp, StubIdp.WResult(new WResultOptions { Token = made.Xml, TokenSet = true }), "_r", null, null), "validation", "expired");
        Rejects(() => Post(rp, StubIdp.WResult(new WResultOptions { AppliesTo = "https://other.test/" }), "_r", null, null), "validation", "applies to");
        Rejects(() => Post(rp, StubIdp.WResult(new WResultOptions { Expires = TimeSpan.FromSeconds(-120), ExpiresSet = true }), "_r", null, null), "validation", "response expired");
    }

    [Fact]
    public void InResponseToIsRefused()
    {
        var made = StubIdp.SignedAssertion(new AssertionOptions { InResponseTo = "_samlreq" });
        Rejects(() => Post(MustRp(Cfg()), StubIdp.WResult(new WResultOptions { Token = made.Xml, TokenSet = true }), "_r", null, null), "validation", "InResponseTo");
    }

    [Fact]
    public void Saml11AndNonTrustAreRefused()
    {
        var rp = MustRp(Cfg());
        var token = StubIdp.Saml11();
        Rejects(() => Post(rp, StubIdp.WResult(new WResultOptions { Token = token, TokenSet = true, TokenType = "urn:oasis:names:tc:SAML:2.0:assertion" }), "_r", null, null), "message", "SAML 1\\.1");
        Rejects(() => Post(rp, StubIdp.WResult(new WResultOptions { TokenType = "urn:oasis:names:tc:SAML:1.0:assertion" }), "_r", null, null), "message", "SAML 2.0 assertions only");
        var made = StubIdp.SignedAssertion();
        Rejects(() => Post(rp, made.Xml, "_r", null, null), "message", "not a WS-Trust");
        Rejects(() => Post(rp, "<!DOCTYPE x [<!ENTITY e \"x\">]>" + StubIdp.WResult(), "_r", null, null), "xml", "DOCTYPE");
    }

    [Fact]
    public void UnsolicitedAndUnknownRequests()
    {
        var rp = MustRp(Cfg());
        var result = StubIdp.WResult();
        Rejects(() => Post(rp, result, "_other", "id=_r", null), "validation", "not a sign-in this browser");
        Rejects(() => Post(rp, result, null, "id=_r", Array.Empty<string>()), "validation", "not a sign-in this browser");
        Rejects(() => Post(rp, result, null, null, Array.Empty<string>()), "validation", "unsolicited");
        var open = MustRp(Cfg(new() { ["allowUnsolicited"] = true }));
        var who = Post(open, result, null, "ru=%2Fthere", Array.Empty<string>());
        Assert.Null(who.RequestId);
        Assert.Equal("/there", who.RelayState);
    }

    [Fact]
    public void Replay()
    {
        var rp = MustRp(Cfg());
        var result = StubIdp.WResult();
        Post(rp, result, "_r", null, null);
        Rejects(() => Post(rp, result, "_r", null, null), "replay", "");
    }

    [Fact]
    public void DecryptsEncryptedAssertions()
    {
        var rp = MustRp(Cfg());
        foreach (var name in new[] { "aes-256-gcm", "aes-128-cbc" })
        {
            var made = StubIdp.SignedAssertion();
            var enc = StubIdp.Encrypt(made.Xml, name);
            var who = Post(rp, StubIdp.WResult(new WResultOptions { Token = enc, TokenSet = true }), "_r", null, null);
            Assert.Equal("alice-1234", who.NameId);
            Assert.True(who.Encrypted);
        }
        var signed = StubIdp.SignedAssertion();
        var bare = StubIdp.Encrypt(signed.Xml, "aes-256-gcm", "oaep256", "none");
        var again = Post(rp, StubIdp.WResult(new WResultOptions { Token = bare, TokenSet = true }), "_r", null, null);
        Assert.True(again.Encrypted);
    }

    [Fact]
    public void WantAssertionsEncryptedAndTamperedCiphertext()
    {
        var rp = MustRp(Cfg(new() { ["wantAssertionsEncrypted"] = true }));
        Rejects(() => Post(rp, StubIdp.WResult(), "_r", null, null), "validation", "not encrypted");
        var plain = StubIdp.AssertionXml();
        var enc = StubIdp.Encrypt(plain.Xml);
        Rejects(() => Post(rp, StubIdp.WResult(new WResultOptions { Token = enc, TokenSet = true }), "_r", null, null), "validation", "not signed");
        var made = StubIdp.SignedAssertion();
        enc = StubIdp.Encrypt(made.Xml);
        var matches = Regex.Matches(enc, "<xenc:CipherValue>([^<]+)</xenc:CipherValue>");
        var last = matches[^1].Groups[1].Value;
        var raw = Convert.FromBase64String(last);
        raw[20] ^= 1;
        var replaced = enc.Replace(last, Convert.ToBase64String(raw));
        Rejects(() => Post(rp, StubIdp.WResult(new WResultOptions { Token = replaced, TokenSet = true }), "_r", null, null), "decryption", "");
    }

    [Fact]
    public void EncryptedAttributeAndMissingKey()
    {
        var keyless = MustRp(new Dictionary<string, object?>
        {
            ["realm"] = StubIdp.Realm, ["replyUrl"] = StubIdp.Reply, ["idpMetadata"] = StubIdp.IdPMetadata(),
        });
        var made = StubIdp.SignedAssertion();
        var enc = StubIdp.Encrypt(made.Xml);
        Rejects(() => Post(keyless, StubIdp.WResult(new WResultOptions { Token = enc, TokenSet = true }), "_r", null, null), "decryption", "no privateKey");
        var rp = MustRp(Cfg());
        var secret = StubIdp.Encrypt("<saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"employeeNumber\"><saml:AttributeValue>E-42</saml:AttributeValue></saml:Attribute>", "aes-256-gcm", "oaep256", "EncryptedAttribute");
        var plain = StubIdp.AssertionXml(new AssertionOptions { ExtraAttributes = secret });
        var signed = StubIdp.SignXml(plain.Xml, plain.Id);
        var who = Post(rp, StubIdp.WResult(new WResultOptions { Token = signed, TokenSet = true }), "_r", null, null);
        Assert.Equal("E-42", string.Join(",", who.Attributes["employeeNumber"]));
    }

    [Fact]
    public void ReplyUrlRefusesGetWrongWaAndWresultptr()
    {
        var rp = MustRp(Cfg());
        var result = StubIdp.WResult();
        Rejects(() => rp.HandleReply(new ReplyRequest { Method = "GET", Url = "/wsfed?wa=wsignin1.0&wresult=" + Uri.EscapeDataString(result) }, null), "message", "POSTed");
        Rejects(() => rp.HandleReply(new ReplyRequest { Method = "POST", Url = "/wsfed", Body = new Dictionary<string, string> { ["wa"] = "wattr1.0", ["wresult"] = result } }, null), "message", "not wsignin1.0");
        Rejects(() => rp.HandleReply(new ReplyRequest { Method = "POST", Url = "/wsfed", Body = new Dictionary<string, string> { ["wa"] = "wsignin1.0", ["wresultptr"] = "https://evil.test/" } }, null), "message", "wresultptr");
        Rejects(() => rp.HandleReply(new ReplyRequest { Method = "POST", Url = "/wsfed", Body = new Dictionary<string, string> { ["wa"] = "wsignin1.0" } }, null), "message", "no wresult");
    }

    [Fact]
    public void SignOutCleanup()
    {
        var rp = MustRp(Cfg());
        Assert.True(rp.IsSignOutCleanup(new ReplyRequest { Method = "GET", Url = "/wsfed?wa=wsignoutcleanup1.0" }));
        Assert.True(rp.IsSignOutCleanup(new ReplyRequest { Method = "POST", Url = "/wsfed", Body = "wa=wsignout1.0" }));
        Assert.False(rp.IsSignOutCleanup(new ReplyRequest { Method = "POST", Url = "/wsfed", Body = new Dictionary<string, string> { ["wa"] = "wsignin1.0" } }));
        Rejects(() => rp.HandleReply(new ReplyRequest { Method = "GET", Url = "/wsfed?wa=wsignoutcleanup1.0" }, null), "message", "sign-out");
    }

    [Fact]
    public void StatusSuccessConstant()
    {
        Assert.Equal("urn:oasis:names:tc:SAML:2.0:status:Success", Names.StatusSuccess);
        Assert.Equal("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", Names.RsaSha256);
        Assert.Equal("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", Names.DefaultSubjectAttribute);
    }
}
