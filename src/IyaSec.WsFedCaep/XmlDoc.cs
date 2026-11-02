// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace IyaSec.WsFed;

static class XmlDoc
{
    static readonly Regex Doctype = new("<!DOCTYPE|<!ENTITY", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    static readonly HashSet<string> IdNames = new(StringComparer.Ordinal) { "ID", "Id", "id" };

    public static XmlDocument Parse(string text, string what)
    {
        if (Doctype.IsMatch(text))
            throw new WsFedException("xml", what + " carries a DOCTYPE or an entity declaration, which WS-Federation never needs");
        var doc = new XmlDocument { PreserveWhitespace = true };
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        try
        {
            using var reader = XmlReader.Create(new StringReader(text), settings);
            doc.Load(reader);
        }
        catch (Exception ex) when (ex is not WsFedException)
        {
            throw new WsFedException("xml", what + " is not well-formed XML: " + ex.Message, ex);
        }
        if (doc.DocumentElement == null)
            throw new WsFedException("xml", what + " is not well-formed XML: no document element");
        return doc;
    }

    public static List<XmlElement> Children(XmlNode? el, string ns, string local)
    {
        var list = new List<XmlElement>();
        if (el == null) return list;
        foreach (XmlNode node in el.ChildNodes)
        {
            if (node is XmlElement child && child.LocalName == local && child.NamespaceURI == ns)
                list.Add(child);
        }
        return list;
    }

    public static XmlElement? Child(XmlElement? el, string ns, string local)
    {
        var found = Children(el, ns, local);
        if (found.Count > 1)
            throw new WsFedException("validation", "<" + (el?.LocalName ?? "") + "> has more than one <" + local + ">");
        return found.Count == 0 ? null : found[0];
    }

    public static XmlElement? First(XmlElement? el, string ns, string local)
    {
        var found = Children(el, ns, local);
        return found.Count == 0 ? null : found[0];
    }

    public static List<XmlElement> Descendants(XmlElement? el, string ns, string local)
    {
        var list = new List<XmlElement>();
        if (el == null) return list;
        void Walk(XmlElement cur)
        {
            foreach (XmlNode node in cur.ChildNodes)
            {
                if (node is not XmlElement child) continue;
                if (child.LocalName == local && child.NamespaceURI == ns) list.Add(child);
                Walk(child);
            }
        }
        Walk(el);
        return list;
    }

    public static List<XmlElement> Elements(XmlElement? el)
    {
        var list = new List<XmlElement>();
        if (el == null) return list;
        foreach (XmlNode node in el.ChildNodes)
            if (node is XmlElement child) list.Add(child);
        return list;
    }

    public static string TextContent(XmlNode? el)
    {
        if (el == null) return "";
        var b = new StringBuilder();
        void Walk(XmlNode cur)
        {
            foreach (XmlNode node in cur.ChildNodes)
            {
                if (node is XmlText or XmlCDataSection) b.Append(node.Value);
                else if (node is XmlElement child) Walk(child);
            }
        }
        Walk(el);
        return b.Length == 0 ? el.InnerText : b.ToString();
    }

    public static string Text(XmlNode? el) => TextContent(el).Trim();

    public static string Attr(XmlElement? el, string name)
    {
        if (el == null) return "";
        var node = el.GetAttributeNode(name);
        if (node == null || node.NamespaceURI != "") return "";
        return node.Value;
    }

    public static bool HasAttr(XmlElement? el, string name)
    {
        if (el == null) return false;
        var node = el.GetAttributeNode(name);
        return node != null && node.NamespaceURI == "";
    }

    public static string AttrNs(XmlElement? el, string ns, string local)
    {
        if (el == null) return "";
        foreach (XmlAttribute a in el.Attributes)
        {
            if (a.LocalName != local) continue;
            if (a.NamespaceURI == ns || (ns == "" && a.NamespaceURI == "" && !a.Name.Contains(':')))
                return a.Value;
        }
        return "";
    }

    public static bool HasAttrNs(XmlElement? el, string ns, string local)
    {
        if (el == null) return false;
        foreach (XmlAttribute a in el.Attributes)
        {
            if (a.LocalName == local && a.NamespaceURI == ns) return true;
        }
        return false;
    }

    public static bool TryXsiType(XmlElement el, out string ns, out string local)
    {
        var value = el.GetAttribute("type", Names.Xsi);
        if (string.IsNullOrEmpty(value))
        {
            ns = "";
            local = "";
            return false;
        }
        var i = value.IndexOf(':');
        if (i >= 0)
        {
            var prefix = value[..i].Trim();
            local = value[(i + 1)..].Trim();
            ns = el.GetNamespaceOfPrefix(prefix);
            return true;
        }
        local = value.Trim();
        ns = el.GetNamespaceOfPrefix("");
        return true;
    }

    public static List<string> WsaAddresses(XmlElement? el)
    {
        var list = new List<string>();
        if (el == null) return list;
        foreach (var node in Descendants(el, Names.Wsa, "Address").Concat(Descendants(el, Names.Wsa2004, "Address")))
        {
            var value = Text(node);
            if (value != "") list.Add(value);
        }
        return list;
    }

    public static void AssertUniqueIds(XmlElement root)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        void Walk(XmlElement el)
        {
            foreach (XmlAttribute a in el.Attributes)
            {
                if (!IdNames.Contains(a.LocalName) || a.Value == "") continue;
                if (!seen.Add(a.Value))
                    throw new WsFedException("signature", "two elements carry the ID " + a.Value);
            }
            foreach (var child in Elements(el)) Walk(child);
        }
        Walk(root);
    }

    public static XmlElement? FindId(XmlElement? root, string id)
    {
        if (root == null) return null;
        if (Attr(root, "ID") == id && HasAttr(root, "ID")) return root;
        foreach (var child in Elements(root))
        {
            var found = FindId(child, id);
            if (found != null) return found;
        }
        return null;
    }

    public static string Escape(string value) =>
        value.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;").Replace("'", "&apos;");

    public static string PemBody(string pem)
    {
        var b = new StringBuilder();
        foreach (var line in pem.Split('\n'))
        {
            var trimmed = line.Trim().TrimEnd('\r');
            if (trimmed.Contains("-----") || trimmed == "") continue;
            b.Append(trimmed);
        }
        return b.ToString();
    }

    public static string ToPem(string b64)
    {
        var body = string.Concat(b64.Where(c => !char.IsWhiteSpace(c)));
        var lines = new List<string>();
        for (var i = 0; i < body.Length; i += 64)
        {
            var n = Math.Min(64, body.Length - i);
            lines.Add(body.Substring(i, n));
        }
        return "-----BEGIN CERTIFICATE-----\n" + string.Join("\n", lines) + "\n-----END CERTIFICATE-----\n";
    }
}
