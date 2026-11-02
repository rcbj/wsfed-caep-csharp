// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace IyaSec.WsFed;

public sealed class Resolved
{
    public string Realm { get; set; } = "";
    public string ReplyUrl { get; set; } = "";
    public string IdPMetadata { get; set; } = "";
    public int ClockSkewMs { get; set; }
    public bool WantAssertionsEncrypted { get; set; }
    public bool AllowUnsolicited { get; set; }
    public bool RequestTokenType { get; set; }
    public bool SignalsSet { get; set; }
    public bool Signals { get; set; }
    public RSA? PrivateKey { get; set; }
    public X509Certificate2? Certificate { get; set; }
    public string IdPCa { get; set; } = "";
    public string IdPEntityId { get; set; } = "";
}

public static class WsfedConfig
{
    public static Resolved Resolve(IDictionary<string, object?>? config, string? baseDir)
    {
        if (config == null) throw new WsFedException("config", "the configuration must be an object");
        if (string.IsNullOrEmpty(baseDir)) baseDir = Directory.GetCurrentDirectory();
        var realm = config.TryGetValue("realm", out var realmValue) ? realmValue as string ?? "" : "";
        if (string.IsNullOrWhiteSpace(realm)) throw new WsFedException("config", "realm is required");
        var reply = AbsoluteUrl(config.TryGetValue("replyUrl", out var replyValue) ? replyValue : null, "replyUrl");
        if (!config.TryGetValue("idpMetadata", out var rawMeta) || rawMeta is not string metaText || string.IsNullOrWhiteSpace(metaText))
            throw new WsFedException("config", "idpMetadata is required");
        var meta = IdpMetadataRef(metaText, baseDir);
        var skew = 60.0;
        var skewPresent = config.TryGetValue("clockSkewSeconds", out var skewValue) && skewValue != null;
        if (skewPresent)
        {
            if (!AsFloat(skewValue, out skew) || skew < 0 || skew > 600)
                throw new WsFedException("config", "clockSkewSeconds must be a number from 0 to 600");
        }
        int skewMs;
        if (!skewPresent) skewMs = 60 * 1000;
        else if (Whole(skewValue)) skewMs = (int)skew * 1000;
        else skewMs = (int)(skew * 1000);
        var signals = Flag(config, "signals", true, "signals");
        var want = Flag(config, "wantAssertionsEncrypted", false, "wantAssertionsEncrypted");
        var allow = Flag(config, "allowUnsolicited", false, "allowUnsolicited");
        var requestType = Flag(config, "requestTokenType", true, "requestTokenType");
        var resolved = new Resolved
        {
            Realm = realm,
            ReplyUrl = reply,
            IdPMetadata = meta,
            ClockSkewMs = skewMs,
            WantAssertionsEncrypted = want,
            AllowUnsolicited = allow,
            RequestTokenType = requestType,
        };
        if (!signals)
        {
            resolved.SignalsSet = true;
            resolved.Signals = false;
        }
        var keyPresent = config.TryGetValue("privateKey", out var keyValue) && keyValue != null;
        var certPresent = config.TryGetValue("certificate", out var certValue) && certValue != null;
        if (keyPresent != certPresent)
            throw new WsFedException("config", "privateKey and certificate go together: give both or neither");
        if (keyPresent && certPresent)
        {
            if (keyValue is not string keyText || certValue is not string certText)
                throw new WsFedException("config", "the private key or certificate cannot be read: not a string");
            var keyPem = Material(keyText, baseDir, "privateKey");
            var certPem = Material(certText, baseDir, "certificate");
            var privateKey = LoadPrivateKey(keyPem);
            var certificate = LoadCert(certPem);
            using var pub = certificate.GetRSAPublicKey() ?? throw new WsFedException("config", "the certificate is not for the private key");
            var a = pub.ExportParameters(false);
            var b = privateKey.ExportParameters(false);
            if (a.Modulus == null || b.Modulus == null || a.Exponent == null || b.Exponent == null || !a.Modulus.AsSpan().SequenceEqual(b.Modulus) || !a.Exponent.AsSpan().SequenceEqual(b.Exponent))
                throw new WsFedException("config", "the certificate is not for the private key");
            resolved.PrivateKey = privateKey;
            resolved.Certificate = certificate;
        }
        else if (resolved.WantAssertionsEncrypted)
        {
            throw new WsFedException("config", "wantAssertionsEncrypted needs privateKey and certificate: the assertion is encrypted to them");
        }
        if (config.TryGetValue("idpCa", out var ca) && ca is string caText && caText != "")
            resolved.IdPCa = Material(caText, baseDir, "idpCa");
        if (config.TryGetValue("idpEntityId", out var id) && id is string idText && idText != "")
            resolved.IdPEntityId = idText;
        return resolved;
    }

    public static Resolved ReadFile(string path, IDictionary<string, object?>? overrides)
    {
        string raw;
        try { raw = File.ReadAllText(path); }
        catch (Exception ex) { throw new WsFedException("config", path + " cannot be read as JSON: " + ex.Message, ex); }
        Dictionary<string, object?> parsed;
        try { parsed = JsonMaps.Parse(raw); }
        catch (WsFedException) { throw; }
        catch (Exception ex) { throw new WsFedException("config", path + " cannot be read as JSON: " + ex.Message, ex); }
        if (overrides != null)
        {
            foreach (var pair in overrides)
                if (pair.Value != null) parsed[pair.Key] = pair.Value;
        }
        var full = Path.GetFullPath(path);
        return Resolve(parsed, Path.GetDirectoryName(full) ?? "");
    }

    public static RSA LoadPrivateKey(string pemText)
    {
        try
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(pemText);
            return rsa;
        }
        catch (Exception ex)
        {
            throw new WsFedException("config", "the private key or certificate cannot be read: " + ex.Message, ex);
        }
    }

    public static X509Certificate2 LoadCert(string pemText)
    {
        try { return X509Certificate2.CreateFromPem(pemText); }
        catch (Exception ex)
        {
            throw new WsFedException("config", "the private key or certificate cannot be read: " + (pemText.Contains("-----BEGIN ") ? ex.Message : "not a PEM"), ex);
        }
    }

    static bool Flag(IDictionary<string, object?> config, string key, bool fallback, string what)
    {
        if (!config.TryGetValue(key, out var value) || value == null) return fallback;
        if (value is bool bit) return bit;
        throw new WsFedException("config", what + " must be true or false");
    }

    static string AbsoluteUrl(object? value, string what)
    {
        if (value is not string text || string.IsNullOrWhiteSpace(text))
            throw new WsFedException("config", what + " is required");
        if (!(text.StartsWith("https://", StringComparison.Ordinal) || text.StartsWith("http://", StringComparison.Ordinal)))
            throw new WsFedException("config", what + " must be an absolute http(s) URL, not " + text);
        var rest = text.StartsWith("https://", StringComparison.Ordinal) ? text[8..] : text[7..];
        if (rest.Length == 0 || rest.StartsWith('/'))
            throw new WsFedException("config", what + " must be an absolute http(s) URL, not " + text);
        return text;
    }

    static bool AsFloat(object? value, out double number)
    {
        switch (value)
        {
            case double d when !double.IsNaN(d): number = d; return true;
            case float f: number = f; return true;
            case int i: number = i; return true;
            case long l: number = l; return true;
            case JsonNumber n: number = n.Value; return true;
            default: number = 0; return false;
        }
    }

    static bool Whole(object? value) => value is int or long || (value is double d && d == Math.Truncate(d));

    static string Material(string value, string baseDir, string what)
    {
        if (value.StartsWith("env:", StringComparison.Ordinal))
        {
            var name = value[4..];
            var got = Environment.GetEnvironmentVariable(name);
            if (string.IsNullOrEmpty(got))
                throw new WsFedException("config", what + " environment variable " + name + " is not set");
            value = got;
        }
        if (value.StartsWith("file:", StringComparison.Ordinal)) value = value[5..];
        if (value.Contains("-----BEGIN ")) return value;
        var path = Path.IsPathRooted(value) ? value : Path.Combine(baseDir, value);
        try { return File.ReadAllText(path); }
        catch (Exception ex) { throw new WsFedException("config", what + " is neither a PEM nor a readable file (" + path + ")", ex); }
    }

    static string IdpMetadataRef(string value, string baseDir)
    {
        value = value.Trim();
        if (value.StartsWith("env:", StringComparison.Ordinal))
        {
            var name = value[4..];
            var got = Environment.GetEnvironmentVariable(name);
            if (string.IsNullOrEmpty(got))
                throw new WsFedException("config", "idpMetadata environment variable " + name + " is not set");
            value = got.Trim();
        }
        if (value.StartsWith("file:", StringComparison.Ordinal)) value = value[5..];
        if (value.StartsWith("http://", StringComparison.Ordinal) || value.StartsWith("https://", StringComparison.Ordinal) || value.StartsWith('<'))
            return value;
        if (Path.IsPathRooted(value)) return value;
        return Path.Combine(baseDir, value);
    }
}

sealed class JsonNumber
{
    public double Value { get; }
    public JsonNumber(double value) { Value = value; }
}
