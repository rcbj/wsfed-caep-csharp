// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Xml;

namespace IyaSec.WsFed;

public sealed class Login
{
    public string NameId { get; set; } = "";
    public string? NameIdFormat { get; set; }
    public string? NameQualifier { get; set; }
    public string? SpNameQualifier { get; set; }
    public DateTimeOffset AuthnInstant { get; set; }
    public Dictionary<string, List<string>> Attributes { get; set; } = new();
    public Dictionary<string, string> AttributeFriendlyNames { get; set; } = new();
    public string Issuer { get; set; } = "";
    public string Realm { get; set; } = "";
    public string TrustVersion { get; set; } = "";
    public bool Encrypted { get; set; }
    public string AssertionId { get; set; } = "";
    public DateTimeOffset NotOnOrAfter { get; set; }
    public string? SessionIndex { get; set; }
    public DateTimeOffset? SessionNotOnOrAfter { get; set; }
    public string? AuthnContextClassRef { get; set; }
    public string? RequestId { get; set; }
    public string? RelayState { get; set; }
}

sealed class TokenContext
{
    public string Realm { get; set; } = "";
    public string ReplyUrl { get; set; } = "";
    public string IdPEntityId { get; set; } = "";
    public List<X509Certificate2> IdPCertificates { get; set; } = new();
    public RSA? DecryptionKey { get; set; }
    public int ClockSkewMs { get; set; }
    public bool WantAssertionsEncrypted { get; set; }
    public MemoryReplayCache? Replay { get; set; }
    public DateTimeOffset Now { get; set; }
}

static class Token
{
    static readonly Regex UtcTime = new(@"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$", RegexOptions.Compiled);

    public static Login Validate(string wresult, TokenContext ctx)
    {
        var now = ctx.Now == default ? DateTimeOffset.UtcNow : ctx.Now;
        var nowMs = now.ToUnixTimeMilliseconds();
        var skew = (long)ctx.ClockSkewMs;
        var doc = XmlDoc.Parse(wresult, "wresult");
        XmlDoc.AssertUniqueIds(doc.DocumentElement!);
        var (rstr, trust, trustVersion) = ResponseOf(doc.DocumentElement!);
        var tokenTypeEl = XmlDoc.Child(rstr, trust, "TokenType");
        var tokenType = XmlDoc.Text(tokenTypeEl);
        if (tokenType != "" && !Names.IsSaml2Token(tokenType))
            throw new WsFedException("message", "the response carries a token of type " + tokenType + "; this relying party accepts SAML 2.0 assertions only");
        var applies = XmlDoc.Children(rstr, Names.Wsp, "AppliesTo").Concat(XmlDoc.Children(rstr, Names.Wsp15, "AppliesTo")).ToList();
        if (applies.Count > 1) throw new WsFedException("message", "the response has more than one AppliesTo");
        if (applies.Count == 1)
        {
            var scopes = XmlDoc.WsaAddresses(applies[0]);
            if (scopes.Count > 0 && !scopes.Contains(ctx.Realm))
                throw new WsFedException("validation", "the response applies to " + string.Join(", ", scopes) + ", not to " + ctx.Realm);
        }
        var lifetime = XmlDoc.Child(rstr, trust, "Lifetime");
        DateTimeOffset? expires = null;
        if (lifetime != null)
        {
            var raw = XmlDoc.Text(XmlDoc.First(lifetime, Names.Wsu, "Expires"));
            expires = ParseInstant(raw, "the response's Lifetime Expires");
        }
        if (expires != null && expires.Value.ToUnixTimeMilliseconds() <= nowMs - skew)
            throw new WsFedException("validation", "the response expired at " + Iso(expires.Value));
        var requested = XmlDoc.Children(rstr, trust, "RequestedSecurityToken");
        if (requested.Count != 1)
            throw new WsFedException("message", "the response holds " + requested.Count + " RequestedSecurityToken elements; exactly one is accepted");
        var tokens = XmlDoc.Elements(requested[0]);
        if (tokens.Count != 1)
            throw new WsFedException("message", "the RequestedSecurityToken holds " + tokens.Count + " tokens; exactly one is accepted");
        var token = tokens[0];
        var encrypted = false;
        XmlElement assertion;
        if (Is(token, Names.Saml, "Assertion"))
        {
            if (ctx.WantAssertionsEncrypted)
                throw new WsFedException("validation", "the assertion is not encrypted, and wantAssertionsEncrypted is on");
            assertion = token;
        }
        else if (Is(token, Names.Saml, "EncryptedAssertion") || Is(token, Names.Xenc, "EncryptedData"))
        {
            if (ctx.DecryptionKey == null)
                throw new WsFedException("decryption", "the assertion is encrypted, and this relying party has no privateKey to decrypt it with");
            encrypted = true;
            var plain = XmlEncryption.DecryptElement(token, ctx.DecryptionKey);
            var decrypted = XmlDoc.Parse(plain, "the decrypted assertion");
            XmlDoc.AssertUniqueIds(decrypted.DocumentElement!);
            assertion = decrypted.DocumentElement!;
            if (Is(assertion, Names.Saml1, "Assertion"))
                throw new WsFedException("message", "the encrypted token is a SAML 1.1 assertion; this relying party accepts SAML 2.0 assertions only");
            if (!Is(assertion, Names.Saml, "Assertion"))
                throw new WsFedException("validation", "the encrypted token does not hold a SAML 2.0 Assertion");
        }
        else if (Is(token, Names.Saml1, "Assertion"))
        {
            throw new WsFedException("message", "the token is a SAML 1.1 assertion; this relying party accepts SAML 2.0 assertions only. Ask for SAML 2.0 (requestTokenType, the default), or configure the identity provider to issue it to this realm");
        }
        else throw new WsFedException("message", "the RequestedSecurityToken holds a <" + token.LocalName + ">, not a SAML 2.0 assertion");
        var signed = XmlSignature.VerifySigned(assertion, ctx.IdPCertificates, "the assertion");
        if (signed == null)
            throw new WsFedException("validation", "the assertion is not signed; in WS-Federation its signature is the only one, so it is required");
        assertion = XmlDoc.Parse(signed, "the signed assertion").DocumentElement!;
        if (XmlDoc.Attr(assertion, "Version") != "2.0")
            throw new WsFedException("validation", "the assertion is not version 2.0");
        var assertionId = XmlDoc.Attr(assertion, "ID");
        if (assertionId == "") throw new WsFedException("validation", "the assertion has no ID");
        var issuer = XmlDoc.Child(assertion, Names.Saml, "Issuer") ?? throw new WsFedException("validation", "the assertion has no Issuer");
        var format = XmlDoc.Attr(issuer, "Format");
        if (XmlDoc.HasAttr(issuer, "Format") && format != "" && format != "urn:oasis:names:tc:SAML:2.0:nameid-format:entity")
            throw new WsFedException("validation", "the assertion's Issuer has the Format " + format);
        if (XmlDoc.Text(issuer) != ctx.IdPEntityId)
            throw new WsFedException("validation", "the assertion was issued by " + XmlDoc.Text(issuer) + ", not by " + ctx.IdPEntityId);
        var subject = XmlDoc.Child(assertion, Names.Saml, "Subject") ?? throw new WsFedException("validation", "the assertion has no Subject");
        var nameId = XmlDoc.Child(subject, Names.Saml, "NameID");
        var encryptedId = XmlDoc.Child(subject, Names.Saml, "EncryptedID");
        if (nameId == null && encryptedId != null)
        {
            if (ctx.DecryptionKey == null)
                throw new WsFedException("decryption", "the NameID is encrypted, and this relying party has no privateKey to decrypt it with");
            var plain = XmlEncryption.DecryptElement(encryptedId, ctx.DecryptionKey);
            nameId = XmlDoc.Parse(plain, "the decrypted NameID").DocumentElement;
            if (nameId == null || !Is(nameId, Names.Saml, "NameID"))
                throw new WsFedException("validation", "the EncryptedID does not hold a NameID");
        }
        if (nameId == null || XmlDoc.Text(nameId) == "")
            throw new WsFedException("validation", "the assertion's Subject has no NameID");
        var conditions = XmlDoc.Child(assertion, Names.Saml, "Conditions") ?? throw new WsFedException("validation", "the assertion has no Conditions, so it names no audience");
        var notBefore = AttrInstant(conditions, "NotBefore", "Conditions NotBefore");
        var notOnOrAfter = AttrInstant(conditions, "NotOnOrAfter", "Conditions NotOnOrAfter");
        var reasons = new List<string>();
        DateTimeOffset? confirmedUntil = null;
        foreach (var confirmation in XmlDoc.Children(subject, Names.Saml, "SubjectConfirmation"))
        {
            var method = XmlDoc.Attr(confirmation, "Method");
            if (method != Names.CmBearer)
            {
                reasons.Add("method " + method);
                continue;
            }
            var data = XmlDoc.Child(confirmation, Names.Saml, "SubjectConfirmationData");
            if (data == null)
            {
                if (notOnOrAfter == null)
                {
                    reasons.Add("no SubjectConfirmationData, and no Conditions NotOnOrAfter to bound it");
                    continue;
                }
                confirmedUntil = notOnOrAfter;
                break;
            }
            var recipient = XmlDoc.Attr(data, "Recipient");
            var hasRecipient = XmlDoc.HasAttr(data, "Recipient");
            var until = AttrInstant(data, "NotOnOrAfter", "SubjectConfirmationData NotOnOrAfter") ?? notOnOrAfter;
            if (hasRecipient && recipient != ctx.ReplyUrl) reasons.Add("Recipient " + recipient);
            else if (until == null) reasons.Add("no NotOnOrAfter, on the confirmation or the Conditions");
            else if (until.Value.ToUnixTimeMilliseconds() <= nowMs - skew) reasons.Add("expired at " + Iso(until.Value));
            else if (XmlDoc.HasAttr(data, "NotBefore")) reasons.Add("a NotBefore, which a bearer confirmation must not have");
            else if (XmlDoc.HasAttr(data, "InResponseTo")) reasons.Add("InResponseTo " + XmlDoc.Attr(data, "InResponseTo") + ", which answers a SAML request, not a WS-Federation sign-in");
            else
            {
                confirmedUntil = until;
                break;
            }
        }
        if (confirmedUntil == null)
        {
            var why = reasons.Count == 0 ? "there is none" : string.Join("; ", reasons);
            throw new WsFedException("validation", "no bearer SubjectConfirmation of the assertion fits: " + why);
        }
        if (notBefore != null && notBefore.Value.ToUnixTimeMilliseconds() > nowMs + skew)
            throw new WsFedException("validation", "the assertion is not valid before " + Iso(notBefore.Value));
        if (notOnOrAfter != null && notOnOrAfter.Value.ToUnixTimeMilliseconds() <= nowMs - skew)
            throw new WsFedException("validation", "the assertion expired at " + Iso(notOnOrAfter.Value));
        var restrictions = XmlDoc.Children(conditions, Names.Saml, "AudienceRestriction");
        if (restrictions.Count == 0) throw new WsFedException("validation", "the assertion has no AudienceRestriction");
        foreach (var restriction in restrictions)
        {
            var ok = XmlDoc.Children(restriction, Names.Saml, "Audience").Any(audience => XmlDoc.Text(audience) == ctx.Realm);
            if (!ok) throw new WsFedException("validation", "the assertion is not for " + ctx.Realm);
        }
        var authnAll = XmlDoc.Children(assertion, Names.Saml, "AuthnStatement");
        if (authnAll.Count == 0) throw new WsFedException("validation", "the assertion has no AuthnStatement");
        var authn = authnAll[0];
        var authnInstant = AttrInstant(authn, "AuthnInstant", "AuthnInstant") ?? throw new WsFedException("validation", "the AuthnStatement has no AuthnInstant");
        var sessionNot = AttrInstant(authn, "SessionNotOnOrAfter", "SessionNotOnOrAfter");
        if (sessionNot != null && sessionNot.Value.ToUnixTimeMilliseconds() <= nowMs - skew)
            throw new WsFedException("validation", "the identity provider's session has already ended");
        var contextEl = XmlDoc.Child(authn, Names.Saml, "AuthnContext");
        var classRef = contextEl == null ? "" : XmlDoc.Text(XmlDoc.First(contextEl, Names.Saml, "AuthnContextClassRef"));
        var attributes = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        var friendly = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var statement in XmlDoc.Children(assertion, Names.Saml, "AttributeStatement"))
        {
            var decrypted = new List<XmlElement>();
            foreach (var encryptedAttr in XmlDoc.Children(statement, Names.Saml, "EncryptedAttribute"))
            {
                if (ctx.DecryptionKey == null)
                    throw new WsFedException("decryption", "an attribute is encrypted, and this relying party has no privateKey to decrypt it with");
                var plain = XmlEncryption.DecryptElement(encryptedAttr, ctx.DecryptionKey);
                var element = XmlDoc.Parse(plain, "the decrypted attribute").DocumentElement!;
                if (!Is(element, Names.Saml, "Attribute"))
                    throw new WsFedException("validation", "an EncryptedAttribute does not hold an Attribute");
                decrypted.Add(element);
            }
            foreach (var attribute in XmlDoc.Children(statement, Names.Saml, "Attribute").Concat(decrypted))
            {
                var name = XmlDoc.Attr(attribute, "Name");
                if (name == "") continue;
                var values = XmlDoc.Children(attribute, Names.Saml, "AttributeValue").Select(XmlDoc.TextContent).ToList();
                if (!attributes.TryGetValue(name, out var existing))
                {
                    existing = new List<string>();
                    attributes[name] = existing;
                }
                existing.AddRange(values);
                var friendlyName = XmlDoc.Attr(attribute, "FriendlyName");
                if (friendlyName != "") friendly[name] = friendlyName;
            }
        }
        var keep = confirmedUntil.Value.ToUnixTimeMilliseconds();
        if (notOnOrAfter != null && notOnOrAfter.Value.ToUnixTimeMilliseconds() > keep) keep = notOnOrAfter.Value.ToUnixTimeMilliseconds();
        keep += skew;
        var replay = ctx.Replay ?? new MemoryReplayCache();
        var replayId = ctx.IdPEntityId + " " + assertionId;
        bool recorded;
        try { recorded = replay.CheckAndRecord(replayId, DateTimeOffset.FromUnixTimeMilliseconds(keep)); }
        catch (WsFedException ex) when (ex.Code == "replay") { throw; }
        catch (Exception ex) { throw new WsFedException("replay", ex.Message, ex); }
        if (recorded) throw new WsFedException("replay", "the assertion " + assertionId + " has been accepted before");
        var login = new Login
        {
            NameId = XmlDoc.Text(nameId),
            AuthnInstant = authnInstant,
            Attributes = attributes,
            AttributeFriendlyNames = friendly,
            Issuer = ctx.IdPEntityId,
            Realm = ctx.Realm,
            TrustVersion = trustVersion,
            Encrypted = encrypted,
            AssertionId = assertionId,
            NotOnOrAfter = confirmedUntil.Value,
        };
        var nameFormat = XmlDoc.Attr(nameId, "Format");
        if (nameFormat != "") login.NameIdFormat = nameFormat;
        var nq = XmlDoc.Attr(nameId, "NameQualifier");
        if (nq != "") login.NameQualifier = nq;
        var sp = XmlDoc.Attr(nameId, "SPNameQualifier");
        if (sp != "") login.SpNameQualifier = sp;
        var session = XmlDoc.Attr(authn, "SessionIndex");
        if (session != "") login.SessionIndex = session;
        if (sessionNot != null) login.SessionNotOnOrAfter = sessionNot;
        if (classRef != "") login.AuthnContextClassRef = classRef;
        return login;
    }

    static bool Is(XmlElement el, string ns, string local) => el.LocalName == local && el.NamespaceURI == ns;

    static (XmlElement rstr, string trust, string version) ResponseOf(XmlElement root)
    {
        if (Is(root, Names.Trust13, "RequestSecurityTokenResponseCollection"))
        {
            var all = XmlDoc.Children(root, Names.Trust13, "RequestSecurityTokenResponse");
            if (all.Count != 1)
                throw new WsFedException("message", "the RequestSecurityTokenResponseCollection holds " + all.Count + " responses; exactly one is accepted");
            return (all[0], Names.Trust13, "1.3");
        }
        if (Is(root, Names.Trust2005, "RequestSecurityTokenResponse")) return (root, Names.Trust2005, "2005/02");
        if (Is(root, Names.Trust13, "RequestSecurityTokenResponse")) return (root, Names.Trust13, "1.3");
        var ns = root.NamespaceURI == "" ? "no namespace" : root.NamespaceURI;
        throw new WsFedException("message", "wresult is a <" + root.LocalName + "> in " + ns + ", not a WS-Trust RequestSecurityTokenResponse");
    }

    static DateTimeOffset? ParseInstant(string value, string what)
    {
        if (value == "") return null;
        if (!UtcTime.IsMatch(value)) throw new WsFedException("validation", what + " is not a UTC dateTime: " + value);
        var normalized = value.Replace("Z", "+00:00");
        if (!DateTimeOffset.TryParse(normalized, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed))
            throw new WsFedException("validation", what + " is not a dateTime: " + value);
        return parsed;
    }

    static DateTimeOffset? AttrInstant(XmlElement? el, string name, string what)
    {
        if (el == null || !XmlDoc.HasAttr(el, name)) return null;
        return ParseInstant(XmlDoc.Attr(el, name), what);
    }

    public static string Iso(DateTimeOffset moment)
    {
        var utc = moment.ToUniversalTime();
        return utc.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
    }
}
