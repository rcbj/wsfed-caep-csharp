// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Net;
using System.Text;
using IyaSec.WsFed.Demo;
using Xunit;

namespace IyaSec.WsFed.Tests;

public class HttpTests
{
    [Fact]
    public void SignInCleanupAndLogout()
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
        var port = FreePort();
        var listener = new HttpListener();
        listener.Prefixes.Add("http://127.0.0.1:" + port + "/");
        listener.Start();
        var thread = new Thread(() =>
        {
            while (listener.IsListening)
            {
                HttpListenerContext ctx;
                try { ctx = listener.GetContext(); }
                catch { return; }
                using var raw = new MemoryStream();
                ctx.Request.InputStream.CopyTo(raw);
                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (string? name in ctx.Request.Headers)
                {
                    if (name == null) continue;
                    headers[name.ToLowerInvariant()] = ctx.Request.Headers[name] ?? "";
                }
                var (status, fields, payload) = app.Handle(ctx.Request.HttpMethod, ctx.Request.Url?.PathAndQuery ?? "/", headers, raw.ToArray());
                ctx.Response.StatusCode = status;
                foreach (var field in fields)
                {
                    if (field.Name.Equals("content-type", StringComparison.OrdinalIgnoreCase)) ctx.Response.ContentType = field.Value;
                    else ctx.Response.Headers.Add(field.Name, field.Value);
                }
                ctx.Response.ContentLength64 = payload.Length;
                if (payload.Length > 0) ctx.Response.OutputStream.Write(payload);
                ctx.Response.Close();
            }
        }) { IsBackground = true };
        thread.Start();
        try
        {
            var baseUrl = "http://127.0.0.1:" + port;
            using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false });
            var health = client.GetAsync(baseUrl + "/healthz").GetAwaiter().GetResult();
            Assert.Equal(200, (int)health.StatusCode);
            Assert.Equal("ok", health.Content.ReadAsStringAsync().GetAwaiter().GetResult());
            var login = client.GetAsync(baseUrl + "/login").GetAwaiter().GetResult();
            Assert.Equal(302, (int)login.StatusCode);
            var location = login.Headers.Location ?? throw new InvalidOperationException("no location");
            Assert.Equal(StubIdp.Passive, location.GetLeftPart(UriPartial.Path));
            var query = RelyingParty.FirstMap(location.Query.TrimStart('?'));
            Assert.Equal("wsignin1.0", query["wa"]);
            var pending = Cookie(login, "wsfed_pending");
            var made = StubIdp.SignedAssertion();
            var result = StubIdp.WResult(new WResultOptions { Token = made.Xml, TokenSet = true });
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["wa"] = "wsignin1.0",
                ["wresult"] = result,
                ["wctx"] = query["wctx"],
            });
            var post = new HttpRequestMessage(HttpMethod.Post, baseUrl + "/wsfed") { Content = form };
            post.Headers.TryAddWithoutValidation("cookie", "wsfed_pending=" + pending);
            var reply = client.SendAsync(post).GetAwaiter().GetResult();
            var replyBody = reply.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            Assert.Equal(303, (int)reply.StatusCode);
            Assert.True(replyBody == "" || reply.IsSuccessStatusCode || (int)reply.StatusCode == 303, replyBody);
            var sid = Cookie(reply, "sid");
            var home = client.SendAsync(Get(baseUrl + "/", "sid=" + sid)).GetAwaiter().GetResult();
            var page = home.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            Assert.Contains("Signed in as <strong>alice-1234</strong>", page);
            Assert.Contains(StubIdp.IdPEntity, page);
            var cleanup = client.SendAsync(Get(baseUrl + "/wsfed?wa=wsignoutcleanup1.0", "sid=" + sid)).GetAwaiter().GetResult();
            Assert.Equal("image/gif", cleanup.Content.Headers.ContentType?.MediaType);
            cleanup.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
            var after = client.SendAsync(Get(baseUrl + "/", "sid=" + sid)).GetAwaiter().GetResult();
            Assert.Contains("Sign in with WS-Federation", after.Content.ReadAsStringAsync().GetAwaiter().GetResult());
            var logout = client.SendAsync(new HttpRequestMessage(HttpMethod.Post, baseUrl + "/logout")).GetAwaiter().GetResult();
            logout.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
            var loc = logout.Headers.Location ?? throw new InvalidOperationException("no logout");
            Assert.Equal("wsignout1.0", RelyingParty.FirstMap(loc.Query.TrimStart('?'))["wa"]);
            var bad = new HttpRequestMessage(HttpMethod.Post, baseUrl + "/wsfed")
            {
                Content = new StringContent("wa=wsignin1.0&wresult=x&wctx=id%3Dabc", Encoding.UTF8, "application/x-www-form-urlencoded"),
            };
            var refused = client.SendAsync(bad).GetAwaiter().GetResult();
            refused.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
            Assert.Equal(400, (int)refused.StatusCode);
        }
        finally { listener.Close(); }
    }

    [Fact]
    public void LoopbackFollowsPortAndPublicUrlKeepsThePath()
    {
        var (realm, reply) = DemoHost.EndpointsFor("http://localhost:3000/", "http://localhost:3000/wsfed", "", false, 19142);
        Assert.Equal("http://localhost:19142/", realm);
        Assert.Equal("http://localhost:19142/wsfed", reply);
        var (stayRealm, stayReply) = DemoHost.EndpointsFor("https://idp.example/realm", "https://idp.example/wsfed", "", false, 19142);
        Assert.Equal("https://idp.example/realm", stayRealm);
        Assert.Equal("https://idp.example/wsfed", stayReply);
        var (pubRealm, pubReply) = DemoHost.EndpointsFor("http://127.0.0.1:3000/app/", "http://127.0.0.1:3000/app/wsfed", "https://rp.example", true, 19142);
        Assert.Equal("https://rp.example/app/", pubRealm);
        Assert.Equal("https://rp.example/app/wsfed", pubReply);
        var (v6, v6Reply) = DemoHost.EndpointsFor("http://[::1]:3000/", "http://[::1]:3000/wsfed", "", false, 19142);
        Assert.Equal("http://[::1]:19142/", v6);
        Assert.Equal("http://[::1]:19142/wsfed", v6Reply);
    }

    static HttpRequestMessage Get(string url, string cookie)
    {
        var message = new HttpRequestMessage(HttpMethod.Get, url);
        message.Headers.TryAddWithoutValidation("cookie", cookie);
        return message;
    }

    static string Cookie(HttpResponseMessage response, string name)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var values)) return "";
        foreach (var raw in values)
        {
            var pair = raw.Split(';', 2)[0];
            var cut = pair.IndexOf('=');
            if (cut > 0 && pair[..cut] == name) return pair[(cut + 1)..];
        }
        return "";
    }

    static int FreePort()
    {
        var tcp = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        tcp.Start();
        var port = ((IPEndPoint)tcp.LocalEndpoint).Port;
        tcp.Stop();
        return port;
    }
}
