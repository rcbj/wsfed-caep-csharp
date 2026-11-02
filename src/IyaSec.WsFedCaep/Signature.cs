// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace IyaSec.WsFed;

public sealed class SamlSignedXml : SignedXml
{
    public SamlSignedXml(XmlDocument document) : base(document) { }

    public override XmlElement? GetIdElement(XmlDocument? document, string idValue)
    {
        if (document?.DocumentElement == null || string.IsNullOrEmpty(idValue)) return null;
        return XmlDoc.FindId(document.DocumentElement, idValue);
    }
}

public static class XmlSignature
{
    static readonly Dictionary<string, bool> SignatureAlgs = new(StringComparer.Ordinal)
    {
        [Names.RsaSha256] = true,
        ["http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"] = true,
        ["http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"] = true,
    };

    static readonly Dictionary<string, bool> DigestAlgs = new(StringComparer.Ordinal)
    {
        ["http://www.w3.org/2001/04/xmlenc#sha256"] = true,
        ["http://www.w3.org/2001/04/xmldsig-more#sha384"] = true,
        ["http://www.w3.org/2001/04/xmlenc#sha512"] = true,
    };

    static bool IsC14N(string alg) => alg is Names.ExcC14N or Names.ExcC14NComments or Names.C14N10 or Names.C14N10Comments;

    static bool IsTransform(string alg) => alg == Names.Enveloped || IsC14N(alg);

    static string AlgorithmOf(XmlElement parent, string local)
    {
        var el = XmlDoc.Child(parent, Names.Ds, local);
        return el == null ? "" : XmlDoc.Attr(el, "Algorithm");
    }

    public static string SignEnveloped(string xml, string elementId, RSA key, string certPem)
    {
        var doc = XmlDoc.Parse(xml, "the signed element");
        var target = XmlDoc.FindId(doc.DocumentElement, elementId) ?? throw new WsFedException("signature", "no element ID " + elementId);
        var signed = new SamlSignedXml(doc) { SigningKey = key };
        var reference = new Reference("#" + elementId);
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        reference.DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256";
        signed.AddReference(reference);
        signed.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signed.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
        var certificate = X509Certificate2.CreateFromPem(certPem);
        var info = new KeyInfo();
        info.AddClause(new KeyInfoX509Data(certificate));
        signed.KeyInfo = info;
        signed.ComputeSignature();
        var sig = doc.ImportNode(signed.GetXml(), true);
        var issuer = XmlDoc.Child(target, Names.Saml, "Issuer");
        if (issuer != null) target.InsertAfter(sig, issuer);
        else target.AppendChild(sig);
        return doc.OuterXml;
    }

    public static string? VerifySigned(XmlElement el, IReadOnlyList<X509Certificate2> certs, string what)
    {
        var sigEl = XmlDoc.Child(el, Names.Ds, "Signature");
        if (sigEl == null) return null;
        var elementId = XmlDoc.Attr(el, "ID");
        if (elementId == "")
            throw new WsFedException("signature", what + " is signed but has no ID for the signature to refer to");
        var signedInfo = XmlDoc.Child(sigEl, Names.Ds, "SignedInfo") ?? throw new WsFedException("signature", what + "'s signature has no SignedInfo");
        var c14n = AlgorithmOf(signedInfo, "CanonicalizationMethod");
        if (!IsC14N(c14n))
        {
            var shown = c14n == "" ? "(none)" : c14n;
            throw new WsFedException("signature", what + "'s signature uses the canonicalization " + shown + ", which is refused");
        }
        var sigAlg = AlgorithmOf(signedInfo, "SignatureMethod");
        if (!SignatureAlgs.ContainsKey(sigAlg))
        {
            var shown = sigAlg == "" ? "(none)" : sigAlg;
            throw new WsFedException("signature", what + "'s signature uses " + shown + ", which is refused (SHA-1 and non-RSA algorithms are not accepted)");
        }
        var refs = XmlDoc.Children(signedInfo, Names.Ds, "Reference");
        if (refs.Count != 1)
            throw new WsFedException("signature", what + "'s signature has " + refs.Count + " references; exactly one is accepted");
        var uri = XmlDoc.Attr(refs[0], "URI");
        if (uri != "#" + elementId)
        {
            var shown = uri == "" ? "(nothing)" : uri;
            throw new WsFedException("signature", what + "'s signature refers to " + shown + ", not to " + what + " itself (#" + elementId + ")");
        }
        var digestAlg = AlgorithmOf(refs[0], "DigestMethod");
        if (!DigestAlgs.ContainsKey(digestAlg))
        {
            var shown = digestAlg == "" ? "(none)" : digestAlg;
            throw new WsFedException("signature", what + "'s signature digests with " + shown + ", which is refused");
        }
        var transforms = XmlDoc.Child(refs[0], Names.Ds, "Transforms");
        if (transforms != null)
        {
            foreach (var transform in XmlDoc.Children(transforms, Names.Ds, "Transform"))
            {
                var alg = XmlDoc.Attr(transform, "Algorithm");
                if (!IsTransform(alg))
                {
                    var shown = alg == "" ? "(none)" : alg;
                    throw new WsFedException("signature", what + "'s signature uses the transform " + shown + ", which is refused");
                }
            }
        }
        if (certs.Count == 0)
            throw new WsFedException("signature", "no signing certificate is known for the identity provider, so " + what + " cannot be verified");
        var doc = el.OwnerDocument ?? throw new WsFedException("signature", what + " has no document");
        var checker = new SamlSignedXml(doc);
        checker.LoadXml(sigEl);
        var verified = false;
        foreach (var cert in certs)
        {
            if (checker.CheckSignature(cert, true))
            {
                verified = true;
                break;
            }
        }
        if (!verified)
            throw new WsFedException("signature", what + "'s signature does not verify against the identity provider's certificate: the signature does not verify");
        return CanonicalWithoutSignature(el);
    }

    static string CanonicalWithoutSignature(XmlElement el)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(el.OuterXml);
        var sig = XmlDoc.Child(doc.DocumentElement, Names.Ds, "Signature");
        sig?.ParentNode?.RemoveChild(sig);
        var transform = new XmlDsigExcC14NTransform();
        transform.LoadInput(doc);
        using var stream = (Stream)transform.GetOutput()!;
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }
}
