// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace IyaSec.WsFed;

sealed class TlsMaterial
{
    public string? Ca { get; init; }
    public string? Cert { get; init; }
    public string? Key { get; init; }
}

sealed class HttpResult
{
    public int Status { get; init; }
    public string ContentType { get; init; } = "";
    public string Body { get; init; } = "";
}

static class HttpSend
{
    public const int MaxBytes = 2 * 1024 * 1024;

    public static HttpResult Send(string url, string? method, IDictionary<string, string>? headers, string? body, TlsMaterial? tls, string code)
    {
        method ??= "GET";
        if (!url.StartsWith("https://", StringComparison.Ordinal) && !url.StartsWith("http://", StringComparison.Ordinal))
            throw new WsFedException(code, url + " is not an http(s) URL");
        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        if (url.StartsWith("https://", StringComparison.Ordinal))
        {
            X509Certificate2Collection? ca = null;
            if (!string.IsNullOrEmpty(tls?.Ca))
            {
                try { ca = TrustStore(tls!.Ca); }
                catch { throw new WsFedException(code, url + ": the CA certificate cannot be read"); }
            }
            if (!string.IsNullOrEmpty(tls?.Cert) && !string.IsNullOrEmpty(tls?.Key))
            {
                try
                {
                    var clientCert = X509Certificate2.CreateFromPem(tls!.Cert, tls.Key);
                    handler.ClientCertificates.Add(clientCert);
                }
                catch (Exception ex) { throw new WsFedException(code, url + ": " + ex.Message, ex); }
            }
            if (ca != null)
            {
                var trusted = ca;
                var host = HostOf(url);
                handler.ServerCertificateCustomValidationCallback = (_, cert, _, errors) => Accept(cert, errors, trusted, host);
            }
        }
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
        using var request = new HttpRequestMessage(new HttpMethod(method), url);
        if (headers != null)
        {
            foreach (var pair in headers)
            {
                if (pair.Key.Equals("content-type", StringComparison.OrdinalIgnoreCase) ||
                    pair.Key.Equals("content-length", StringComparison.OrdinalIgnoreCase))
                    continue;
                request.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
            }
        }
        if (body != null)
        {
            var content = new StringContent(body);
            if (request.Content != null)
            {
                foreach (var header in request.Content.Headers)
                    content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
            request.Content = content;
            content.Headers.ContentType = null;
            if (headers != null && headers.TryGetValue("content-type", out var ctype))
                content.Headers.TryAddWithoutValidation("content-type", ctype);
            else if (headers != null)
            {
                foreach (var pair in headers)
                    if (pair.Key.Equals("content-type", StringComparison.OrdinalIgnoreCase))
                        content.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
            }
        }
        HttpResponseMessage response;
        try { response = client.Send(request, HttpCompletionOption.ResponseHeadersRead); }
        catch (Exception ex)
        {
            var text = ex.ToString();
            if (text.Contains("Timeout", StringComparison.OrdinalIgnoreCase) || text.Contains("timed out", StringComparison.OrdinalIgnoreCase) || ex is TaskCanceledException)
                throw new WsFedException(code, url + " did not answer within 15 s", ex);
            throw new WsFedException(code, url + ": " + ex.Message, ex);
        }
        using (response)
        {
            var stream = response.Content.ReadAsStream();
            var buffer = new byte[8192];
            using var raw = new MemoryStream();
            while (true)
            {
                int n;
                try { n = stream.Read(buffer, 0, buffer.Length); }
                catch (Exception ex) { throw new WsFedException(code, url + ": " + ex.Message, ex); }
                if (n == 0) break;
                if (raw.Length + n > MaxBytes)
                    throw new WsFedException(code, url + " answered more than " + MaxBytes + " bytes");
                raw.Write(buffer, 0, n);
            }
            var type = response.Content.Headers.ContentType?.ToString() ?? "";
            return new HttpResult { Status = (int)response.StatusCode, ContentType = type, Body = System.Text.Encoding.UTF8.GetString(raw.ToArray()) };
        }
    }

    // idpCa may be one certificate or a whole trust chain: iya-sts publishes its
    // listener chain (leaf, TLS issuing CA, intermediate, root) and the setup
    // script saves all of it. Every PEM block is read. The self-signed ones are
    // the trust anchors and the rest are intermediates the chain may be built
    // through. A file with no self-signed certificate keeps the old meaning:
    // every certificate in it is an anchor.
    internal static X509Certificate2Collection TrustStore(string pem)
    {
        var all = new X509Certificate2Collection();
        all.ImportFromPem(pem);
        if (all.Count == 0) throw new CryptographicException("no certificate");
        return all;
    }

    static bool SelfSigned(X509Certificate2 cert) => cert.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData);

    // The callback replaces the platform's whole decision, the name check
    // included, so it makes that check itself: a certificate that chains to the
    // configured anchors but names another host is refused. An IP literal must
    // match an IP address SAN.
    internal static bool Accept(X509Certificate? cert, SslPolicyErrors errors, X509Certificate2Collection ca, string host)
    {
        if (cert == null) return false;
        if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0) return false;
        if ((errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0) return false;
        using (var leaf = new X509Certificate2(cert))
        {
            if (!NameMatches(leaf, host)) return false;
        }
        return Trusted(cert, ca);
    }

    internal static string HostOf(string url)
    {
        var host = new Uri(url).IdnHost;
        if (host.StartsWith('[') && host.EndsWith(']')) host = host[1..^1];
        return host;
    }

    internal static bool NameMatches(X509Certificate2 leaf, string host)
    {
        if (string.IsNullOrEmpty(host)) return false;
        try { return leaf.MatchesHostname(host, allowWildcards: true, allowCommonName: false); }
        catch { return false; }
    }

    internal static bool Trusted(X509Certificate? cert, X509Certificate2Collection ca)
    {
        if (cert == null) return false;
        using var leaf = new X509Certificate2(cert);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        var anchors = ca.Where(SelfSigned).ToList();
        if (anchors.Count == 0) anchors = ca.ToList();
        foreach (var item in ca)
        {
            if (anchors.Contains(item)) chain.ChainPolicy.CustomTrustStore.Add(item);
            else chain.ChainPolicy.ExtraStore.Add(item);
        }
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(leaf);
    }
}
