// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace IyaSec.WsFed;

public sealed class IdPMetadata
{
    public string EntityId { get; set; } = "";
    public string PassiveRequestorEndpoint { get; set; } = "";
    public List<string> TokenTypesOffered { get; set; } = new();
    public List<X509Certificate2> SigningCertificates { get; set; } = new();
}

public static class Metadata
{
    static readonly string[] EncryptionMethods =
    {
        "http://www.w3.org/2009/xmlenc11#aes256-gcm",
        "http://www.w3.org/2009/xmlenc11#aes128-gcm",
        "http://www.w3.org/2009/xmlenc11#rsa-oaep",
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
    };

    static bool IsStsRole(XmlElement el)
    {
        if (el.LocalName != "RoleDescriptor" || el.NamespaceURI != Names.Md) return false;
        return XmlDoc.TryXsiType(el, out var ns, out var local) && ns == Names.Fed && local == "SecurityTokenServiceType";
    }

    static List<X509Certificate2> CertificatesOf(XmlElement role, string use)
    {
        var list = new List<X509Certificate2>();
        foreach (var descriptor in XmlDoc.Children(role, Names.Md, "KeyDescriptor"))
        {
            var declared = XmlDoc.Attr(descriptor, "use");
            if (XmlDoc.HasAttr(descriptor, "use") && declared != "" && declared != use) continue;
            foreach (var data in XmlDoc.Descendants(descriptor, Names.Ds, "X509Data"))
            {
                var first = XmlDoc.Children(data, Names.Ds, "X509Certificate");
                if (first.Count == 0) continue;
                try { list.Add(WsfedConfig.LoadCert(XmlDoc.ToPem(XmlDoc.Text(first[0])))); }
                catch (Exception ex)
                {
                    throw new WsFedException("metadata", "a " + use + " certificate in the identity provider's metadata cannot be read", ex);
                }
            }
        }
        return list;
    }

    static List<string> FedAddresses(XmlElement role, string local)
    {
        var list = new List<string>();
        foreach (var endpoint in XmlDoc.Children(role, Names.Fed, local))
            list.AddRange(XmlDoc.WsaAddresses(endpoint));
        return list;
    }

    static bool HasSts(XmlElement element)
    {
        foreach (var role in XmlDoc.Children(element, Names.Md, "RoleDescriptor"))
            if (IsStsRole(role)) return true;
        return false;
    }

    public static IdPMetadata Read(string xml, string? entityId)
    {
        var doc = XmlDoc.Parse(xml, "the identity provider metadata");
        var root = doc.DocumentElement!;
        XmlElement entity;
        if (root.LocalName == "EntityDescriptor" && root.NamespaceURI == Names.Md) entity = root;
        else if (root.LocalName == "EntitiesDescriptor" && root.NamespaceURI == Names.Md)
        {
            var all = XmlDoc.Descendants(root, Names.Md, "EntityDescriptor").Where(HasSts).ToList();
            XmlElement? chosen = null;
            if (!string.IsNullOrEmpty(entityId))
            {
                foreach (var item in all)
                    if (XmlDoc.Attr(item, "entityID") == entityId) { chosen = item; break; }
            }
            else if (all.Count == 1) chosen = all[0];
            if (chosen == null)
            {
                if (!string.IsNullOrEmpty(entityId))
                    throw new WsFedException("metadata", "the metadata aggregate has no WS-Federation identity provider " + entityId);
                throw new WsFedException("metadata", "the metadata aggregate holds " + all.Count + " WS-Federation identity providers; name one with idpEntityId");
            }
            entity = chosen;
        }
        else throw new WsFedException("metadata", "the identity provider metadata is not an EntityDescriptor");
        var identifier = XmlDoc.Attr(entity, "entityID");
        if (identifier == "") throw new WsFedException("metadata", "the identity provider metadata has no entityID");
        if (!string.IsNullOrEmpty(entityId) && identifier != entityId)
            throw new WsFedException("metadata", "the metadata describes " + identifier + ", not " + entityId);
        XmlElement? role = null;
        foreach (var item in XmlDoc.Children(entity, Names.Md, "RoleDescriptor"))
            if (IsStsRole(item)) { role = item; break; }
        if (role == null)
            throw new WsFedException("metadata", identifier + "'s metadata has no fed:SecurityTokenServiceType RoleDescriptor, so it is not a WS-Federation identity provider");
        var passive = FedAddresses(role, "PassiveRequestorEndpoint");
        if (passive.Count == 0)
            throw new WsFedException("metadata", identifier + "'s metadata names no PassiveRequestorEndpoint");
        var endpoint = passive[0];
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var parsed) || (parsed.Scheme != "https" && parsed.Scheme != "http"))
            throw new WsFedException("metadata", identifier + "'s PassiveRequestorEndpoint " + endpoint + " is not an http(s) URL");
        var offered = new List<string>();
        foreach (var types in XmlDoc.Children(role, Names.Fed, "TokenTypesOffered"))
            foreach (var token in XmlDoc.Children(types, Names.Fed, "TokenType"))
            {
                var uri = XmlDoc.Attr(token, "Uri");
                if (uri != "") offered.Add(uri);
            }
        if (offered.Count > 0 && !offered.Any(Names.IsSaml2Token))
            throw new WsFedException("metadata", identifier + " offers no SAML 2.0 token (it offers " + string.Join(", ", offered) + ")");
        var signing = CertificatesOf(role, "signing");
        if (signing.Count == 0)
        {
            var idp = XmlDoc.Children(entity, Names.Md, "IDPSSODescriptor");
            if (idp.Count > 0) signing = CertificatesOf(idp[0], "signing");
        }
        if (signing.Count == 0)
            throw new WsFedException("metadata", identifier + "'s metadata names no signing certificate");
        return new IdPMetadata
        {
            EntityId = identifier,
            PassiveRequestorEndpoint = endpoint,
            TokenTypesOffered = offered,
            SigningCertificates = signing,
        };
    }

    public static string Write(string realm, string replyUrl, X509Certificate2? certificate)
    {
        var key = "";
        if (certificate != null)
        {
            var methods = new StringBuilder();
            foreach (var method in EncryptionMethods)
                methods.Append("\n      <md:EncryptionMethod Algorithm=\"").Append(method).Append("\"/>");
            key = "    <md:KeyDescriptor use=\"encryption\">\n" +
                  "      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>" + XmlDoc.PemBody(certificate.ExportCertificatePem()) + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>" +
                  methods + "\n" +
                  "    </md:KeyDescriptor>\n";
        }
        string Endpoint(string local, string address) =>
            "    <fed:" + local + "><wsa:EndpointReference><wsa:Address>" + XmlDoc.Escape(address) + "</wsa:Address></wsa:EndpointReference></fed:" + local + ">";
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
               "<md:EntityDescriptor xmlns:md=\"" + Names.Md + "\" xmlns:ds=\"" + Names.Ds + "\" xmlns:fed=\"" + Names.Fed + "\" " +
               "xmlns:wsa=\"" + Names.Wsa + "\" xmlns:xsi=\"" + Names.Xsi + "\" entityID=\"" + XmlDoc.Escape(realm) + "\">\n" +
               "  <md:RoleDescriptor xsi:type=\"fed:ApplicationServiceType\" protocolSupportEnumeration=\"" + Names.Fed + "\">\n" +
               key + "    <fed:TokenTypesOffered><fed:TokenType Uri=\"" + Names.Saml2Token + "\"/></fed:TokenTypesOffered>\n" +
               "    <fed:TargetScopes><wsa:EndpointReference><wsa:Address>" + XmlDoc.Escape(realm) + "</wsa:Address></wsa:EndpointReference></fed:TargetScopes>\n" +
               Endpoint("ApplicationServiceEndpoint", replyUrl) + "\n" +
               Endpoint("SingleSignOutNotificationEndpoint", replyUrl) + "\n" +
               Endpoint("PassiveRequestorEndpoint", replyUrl) + "\n" +
               "  </md:RoleDescriptor>\n" +
               "</md:EntityDescriptor>\n";
    }
}
