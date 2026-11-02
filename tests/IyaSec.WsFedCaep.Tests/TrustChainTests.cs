// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using IyaSec.WsFed.Demo;
using Xunit;

namespace IyaSec.WsFed.Tests;

// iya-sts's TLS listener presents leaf, TLS issuing CA, intermediate and root, and
// GET /tls/server-certificate answers the same chain. The setup script saves the
// whole chain where idpCa names it; the library must take that file as its trust
// store. The server below sends only its leaf, so the chain can be built only
// through the intermediates in the file.
public class TrustChainTests
{
    sealed class Chain
    {
        public X509Certificate2 Leaf = null!;
        public string Pem = "";
        public string LeafKeyPem = "";
    }

    static Chain MakeChain(string name, Action<SubjectAlternativeNameBuilder>? names = null)
    {
        var now = DateTimeOffset.UtcNow;
        X509Certificate2 Ca(string cn, X509Certificate2? issuer, RSA key)
        {
            var req = new CertificateRequest("CN=" + cn, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
            if (issuer == null) return req.CreateSelfSigned(now.AddDays(-1), now.AddDays(30));
            req.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));
            return req.Create(issuer, now.AddDays(-1), now.AddDays(29), RandomNumberGenerator.GetBytes(12));
        }
        using var rootKey = RSA.Create(2048);
        using var midKey = RSA.Create(2048);
        using var issuingKey = RSA.Create(2048);
        // CreateSelfSigned already carries the key; the issued ones do not.
        using var rootWithKey = Ca(name + " Root CA", null, rootKey);
        var root = rootWithKey;
        using var mid = Ca(name + " Intermediate CA", rootWithKey, midKey);
        var midWithKey = mid.CopyWithPrivateKey(midKey);
        using var issuing = Ca(name + " TLS Issuing CA", midWithKey, issuingKey);
        var issuingWithKey = issuing.CopyWithPrivateKey(issuingKey);
        var leafKey = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=127.0.0.1", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        if (names == null) san.AddIpAddress(IPAddress.Loopback);
        else names(san);
        leafReq.CertificateExtensions.Add(san.Build());
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
        leafReq.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuingWithKey, true, false));
        using var leaf = leafReq.Create(issuingWithKey, now.AddDays(-1), now.AddDays(28), RandomNumberGenerator.GetBytes(12));
        var leafWithKey = leaf.CopyWithPrivateKey(leafKey);
        string Pem(X509Certificate2 cert) => new string(PemEncoding.Write("CERTIFICATE", cert.RawData)) + "\n";
        return new Chain
        {
            Leaf = new X509Certificate2(leafWithKey.Export(X509ContentType.Pkcs12)),
            Pem = Pem(leaf) + Pem(issuing) + Pem(mid) + Pem(root),
            LeafKeyPem = new string(PemEncoding.Write("PRIVATE KEY", leafKey.ExportPkcs8PrivateKey())) + "\n",
        };
    }

    // A one-connection-at-a-time HTTPS server that presents only the leaf.
    sealed class TlsServer : IDisposable
    {
        readonly TcpListener _tcp = new(IPAddress.Loopback, 0);
        public int Port => ((IPEndPoint)_tcp.LocalEndpoint).Port;

        public TlsServer(X509Certificate2 leaf, Func<string, (string type, string body)> answer)
        {
            _tcp.Start();
            new Thread(() =>
            {
                while (true)
                {
                    TcpClient client;
                    try { client = _tcp.AcceptTcpClient(); }
                    catch { return; }
                    try
                    {
                        using (client)
                        using (var tls = new SslStream(client.GetStream()))
                        {
                            tls.AuthenticateAsServer(leaf, false, false);
                            var head = new StringBuilder();
                            var one = new byte[1];
                            while (!head.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal) && tls.Read(one, 0, 1) == 1)
                                head.Append((char)one[0]);
                            var path = head.ToString().Split(' ', 3)[1];
                            var (type, body) = answer(path);
                            var bytes = Encoding.UTF8.GetBytes(body);
                            var status = type == "" ? "404 Not Found" : "200 OK";
                            tls.Write(Encoding.ASCII.GetBytes("HTTP/1.1 " + status + "\r\ncontent-type: " + (type == "" ? "text/plain" : type) + "\r\ncontent-length: " + bytes.Length + "\r\nconnection: close\r\n\r\n"));
                            tls.Write(bytes);
                        }
                    }
                    catch { }
                }
            }) { IsBackground = true }.Start();
        }

        public void Dispose() => _tcp.Stop();
    }

    static (string type, string body) Answer(string path, Chain chain) => path switch
    {
        "/tls/server-certificate" => ("text/plain", chain.Pem),
        "/wsfed/metadata" => ("application/samlmetadata+xml", StubIdp.IdPMetadata()),
        _ => ("", "Not found"),
    };

    static string ConfigFile(string dir, int port, string idpCa, string host = "127.0.0.1")
    {
        var path = Path.Combine(dir, "wsfed-https.json");
        File.WriteAllText(path, JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["realm"] = "https://rp.test/",
            ["replyUrl"] = "https://rp.test/wsfed",
            ["idpMetadata"] = "https://" + host + ":" + port + "/wsfed/metadata",
            ["idpCa"] = idpCa,
        }));
        return path;
    }

    [Fact]
    public void TheLibraryTakesTheWholeChainFileAsItsTrustStore()
    {
        var chain = MakeChain("sts");
        using var server = new TlsServer(chain.Leaf, path => Answer(path, chain));
        var dir = Directory.CreateTempSubdirectory("wsfed-chain-");
        try
        {
            Directory.CreateDirectory(Path.Combine(dir.FullName, "generated"));
            File.WriteAllText(Path.Combine(dir.FullName, "generated", "idp-ca.pem"), chain.Pem);
            var party = RelyingParty.FromFile(ConfigFile(dir.FullName, server.Port, "file:generated/idp-ca.pem"), null);
            Assert.Equal(StubIdp.IdPEntity, party.Idp?.EntityId);
        }
        finally { dir.Delete(true); }
    }

    [Fact]
    public void AChainFromAnotherRootIsRefused()
    {
        var chain = MakeChain("sts");
        var other = MakeChain("other");
        using var server = new TlsServer(chain.Leaf, path => Answer(path, chain));
        var dir = Directory.CreateTempSubdirectory("wsfed-chain-");
        try
        {
            File.WriteAllText(Path.Combine(dir.FullName, "idp-ca.pem"), other.Pem);
            var err = Assert.Throws<WsFedException>(() => RelyingParty.FromFile(ConfigFile(dir.FullName, server.Port, "idp-ca.pem"), null));
            Assert.Equal("metadata", err.Code);
        }
        finally { dir.Delete(true); }
    }

    // The names an iya-sts TLS listener certificate carries.
    static void IyaStsNames(SubjectAlternativeNameBuilder san)
    {
        san.AddDnsName("localhost");
        san.AddDnsName("sts");
        san.AddDnsName("sts-mock");
        san.AddDnsName("sts.example.com");
        san.AddIpAddress(IPAddress.Loopback);
    }

    static Exception? Fetch(Chain chain, string host)
    {
        using var server = new TlsServer(chain.Leaf, path => Answer(path, chain));
        var dir = Directory.CreateTempSubdirectory("wsfed-name-");
        try
        {
            File.WriteAllText(Path.Combine(dir.FullName, "idp-ca.pem"), chain.Pem);
            var party = RelyingParty.FromFile(ConfigFile(dir.FullName, server.Port, "idp-ca.pem", host), null);
            Assert.Equal(StubIdp.IdPEntity, party.Idp?.EntityId);
            return null;
        }
        catch (WsFedException err) { return err; }
        finally { dir.Delete(true); }
    }

    // The chain is good; the name is not. The custom callback replaces the
    // platform's decision, name check included, so it has to refuse this itself.
    [Fact]
    public void AListenerNamingAnotherHostIsRefusedThoughItChainsToTheAnchor()
    {
        var chain = MakeChain("sts", san => san.AddDnsName("other.example.com"));
        var err = Fetch(chain, "localhost");
        Assert.NotNull(err);
        Assert.Equal("metadata", ((WsFedException)err!).Code);
    }

    [Fact]
    public void AnIpLiteralMustMatchAnIpAddressSan()
    {
        var chain = MakeChain("sts", san => san.AddDnsName("localhost"));
        var err = Fetch(chain, "127.0.0.1");
        Assert.NotNull(err);
        Assert.Equal("metadata", ((WsFedException)err!).Code);
    }

    [Fact]
    public void TheIyaStsListenerIsAcceptedByItsDnsNameAndByItsIpAddress()
    {
        var chain = MakeChain("sts", IyaStsNames);
        Assert.Null(Fetch(chain, "localhost"));
        Assert.Null(Fetch(chain, "127.0.0.1"));
    }

    [Fact]
    public void TheIyaStsListenerIsRefusedUnderANameItDoesNotCarry()
    {
        var chain = MakeChain("sts", san => { san.AddDnsName("sts.example.com"); san.AddIpAddress(IPAddress.Parse("10.9.8.7")); });
        Assert.NotNull(Fetch(chain, "localhost"));
        Assert.NotNull(Fetch(chain, "127.0.0.1"));
    }

    [Fact]
    public void TheScriptWritesTheWholeChainWhereIdpCaPoints()
    {
        var chain = MakeChain("sts");
        using var server = new TlsServer(chain.Leaf, path => Answer(path, chain));
        var dir = Directory.CreateTempSubdirectory("wsfed-chain-");
        try
        {
            // files_of() wants the key pair as files, as demo/wsfed.json names them.
            var generated = Directory.CreateDirectory(Path.Combine(dir.FullName, "generated")).FullName;
            File.WriteAllText(Path.Combine(generated, "rp.key"), StubIdp.RpKey);
            File.WriteAllText(Path.Combine(generated, "rp.crt"), StubIdp.RpCert);
            // The demo's own shape: every path is a file the script may write.
            var config = Path.Combine(dir.FullName, "wsfed.json");
            File.WriteAllText(config, JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["realm"] = "https://rp.test/",
                ["replyUrl"] = "https://rp.test/wsfed",
                ["privateKey"] = "file:generated/rp.key",
                ["certificate"] = "file:generated/rp.crt",
                ["idpMetadata"] = "file:generated/idp-metadata.xml",
                ["idpCa"] = "file:generated/idp-ca.pem",
            }));
            var code = """
import sys
sys.path.insert(0, sys.argv[1])
from configure_iya_sts import files_of, save_idp_ca
files = files_of(sys.argv[2])
save_idp_ca(sys.argv[3], files["idp_ca"])
print("wrote " + files["idp_ca"])
""";
            var psi = new ProcessStartInfo { FileName = "python3", RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add(code);
            psi.ArgumentList.Add(Path.Combine(ConfigureTestsRoot(), "scripts"));
            psi.ArgumentList.Add(config);
            psi.ArgumentList.Add("https://127.0.0.1:" + server.Port);
            using var proc = Process.Start(psi)!;
            var stdout = proc.StandardOutput.ReadToEnd();
            var stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit();
            Assert.True(proc.ExitCode == 0, stdout + stderr);
            var saved = Path.Combine(dir.FullName, "generated", "idp-ca.pem");
            Assert.Contains("wrote " + saved, stdout);
            Assert.Contains("(4 certificate(s))", stdout);
            Assert.Contains("trust anchor CN=sts Root CA", stdout);
            var written = File.ReadAllText(saved);
            Assert.Equal(chain.Pem, written);
            Assert.Equal(4, written.Split("-----BEGIN CERTIFICATE-----").Length - 1);
            // The file the script wrote is the library's trust store as it stands.
            var party = RelyingParty.FromFile(ConfigFile(dir.FullName, server.Port, "file:generated/idp-ca.pem"), null);
            Assert.Equal(StubIdp.IdPEntity, party.Idp?.EntityId);
        }
        finally { dir.Delete(true); }
    }

    static string ConfigureTestsRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "scripts", "configure_iya_sts.py"))) return dir.FullName;
            dir = dir.Parent;
        }
        throw new InvalidOperationException("configure_iya_sts.py was not found");
    }
}

public class LiveStatusTests
{
    static App SignedIn(out string sid)
    {
        var rp = RelyingParty.Create(new Dictionary<string, object?>
        {
            ["realm"] = "https://rp.test/",
            ["replyUrl"] = "https://rp.test/wsfed",
            ["privateKey"] = StubIdp.RpKey,
            ["certificate"] = StubIdp.RpCert,
            ["idpMetadata"] = StubIdp.IdPMetadata(),
        }, Path.GetTempPath());
        var app = new App(rp, null);
        var (_, loginHeaders, _) = app.Handle("GET", "/login", new Dictionary<string, string>(), Array.Empty<byte>());
        var location = loginHeaders.First(h => h.Name == "location").Value;
        var pending = CookieOf(loginHeaders, "wsfed_pending");
        var wctx = RelyingParty.FirstMap(new Uri(location).Query.TrimStart('?'))["wctx"];
        var form = "wa=wsignin1.0&wresult=" + Uri.EscapeDataString(StubIdp.WResult(new WResultOptions { Token = StubIdp.SignedAssertion().Xml, TokenSet = true })) + "&wctx=" + Uri.EscapeDataString(wctx);
        var (status, headers, _) = app.Handle("POST", "/wsfed", new Dictionary<string, string> { ["cookie"] = "wsfed_pending=" + pending }, Encoding.UTF8.GetBytes(form));
        Assert.Equal(303, status);
        sid = CookieOf(headers, "sid");
        return app;
    }

    static string CookieOf(List<HeaderField> headers, string name)
    {
        foreach (var field in headers.Where(h => h.Name == "set-cookie"))
        {
            var pair = field.Value.Split(';', 2)[0];
            var cut = pair.IndexOf('=');
            if (cut > 0 && pair[..cut] == name) return pair[(cut + 1)..];
        }
        return "";
    }

    static JsonElement Status(App app, string sid)
    {
        var (status, headers, body) = app.Handle("GET", "/live-status", new Dictionary<string, string> { ["cookie"] = "sid=" + sid }, Array.Empty<byte>());
        Assert.Equal(200, status);
        Assert.Equal("application/json", headers.First(h => h.Name == "content-type").Value);
        var text = Encoding.UTF8.GetString(body);
        Assert.DoesNotContain("Assertion", text);
        return JsonDocument.Parse(text).RootElement;
    }

    [Fact]
    public void ReportsTheSignInAndTheEventsAndSessionRevokedEndsTheOneSession()
    {
        var app = SignedIn(out var sid);
        var first = Status(app, sid);
        Assert.True(first.GetProperty("signedIn").GetBoolean());
        Assert.Equal("alice-1234", first.GetProperty("subject").GetString());
        Assert.Equal("not configured", first.GetProperty("receiver").GetString());
        Assert.Equal(0, first.GetProperty("events").GetArrayLength());

        app.Remember(new SignalEvent { Type = Events.Catalog["credential_change"], Jti = "jti-1" });
        var second = Status(app, sid);
        Assert.True(second.GetProperty("signedIn").GetBoolean());
        Assert.Equal(Events.Catalog["credential_change"], second.GetProperty("events")[0].GetProperty("type").GetString());
        Assert.Equal("jti-1", second.GetProperty("events")[0].GetProperty("jti").GetString());

        // iya-sts main's SessionIndex is the assertion id, so the event matched nobody.
        app.Remember(new SignalEvent { Type = Events.Catalog["session_revoked"], Jti = "jti-2" });
        var third = Status(app, sid);
        Assert.False(third.GetProperty("signedIn").GetBoolean());
        Assert.Equal(JsonValueKind.Null, third.GetProperty("subject").ValueKind);
        Assert.Equal(2, third.GetProperty("events").GetArrayLength());
        Assert.Equal(Events.Catalog["session_revoked"], third.GetProperty("events")[1].GetProperty("type").GetString());
    }

    [Fact]
    public void ASessionRevokedThatMatchedASessionLeavesTheOthers()
    {
        var app = SignedIn(out var sid);
        app.Remember(new SignalEvent { Type = Events.Catalog["session_revoked"], Jti = "j", Sessions = new List<string> { "someone-else" } });
        Assert.True(Status(app, sid).GetProperty("signedIn").GetBoolean());
    }
}
