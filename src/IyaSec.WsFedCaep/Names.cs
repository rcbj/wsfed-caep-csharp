// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

namespace IyaSec.WsFed;

public static class Names
{
    public const string Saml = "urn:oasis:names:tc:SAML:2.0:assertion";
    public const string Saml1 = "urn:oasis:names:tc:SAML:1.0:assertion";
    public const string Md = "urn:oasis:names:tc:SAML:2.0:metadata";
    public const string Ds = "http://www.w3.org/2000/09/xmldsig#";
    public const string Xenc = "http://www.w3.org/2001/04/xmlenc#";
    public const string Xenc11 = "http://www.w3.org/2009/xmlenc11#";
    public const string Xsi = "http://www.w3.org/2001/XMLSchema-instance";
    public const string Fed = "http://docs.oasis-open.org/wsfed/federation/200706";
    public const string Trust2005 = "http://schemas.xmlsoap.org/ws/2005/02/trust";
    public const string Trust13 = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    public const string Wsa = "http://www.w3.org/2005/08/addressing";
    public const string Wsa2004 = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
    public const string Wsp = "http://schemas.xmlsoap.org/ws/2004/09/policy";
    public const string Wsp15 = "http://www.w3.org/ns/ws-policy";
    public const string Wsu = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    public const string Saml2Token = "urn:oasis:names:tc:SAML:2.0:assertion";
    public const string Saml2TokenWss = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
    public const string CmBearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    public const string StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success";
    public const string RsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    public const string DefaultSubjectAttribute = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";
    public const string ExcC14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
    public const string ExcC14NComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
    public const string C14N10 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    public const string C14N10Comments = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
    public const string Enveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

    public static bool IsSaml2Token(string? value) => value == Saml2Token || value == Saml2TokenWss;
}
