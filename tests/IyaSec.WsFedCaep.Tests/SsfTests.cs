// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace IyaSec.WsFed.Tests;

public class SsfTests
{
    static string B64(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    static Dictionary<string, object?> JwkOf(RSA key, string kid)
    {
        var p = key.ExportParameters(false);
        return new Dictionary<string, object?>
        {
            ["kty"] = "RSA", ["kid"] = kid, ["alg"] = "RS256", ["use"] = "sig",
            ["n"] = B64(p.Modulus!), ["e"] = B64(p.Exponent!),
        };
    }

    static string SignJws(Dictionary<string, object?> payload, RSA key, Dictionary<string, object?>? header = null)
    {
        header ??= new Dictionary<string, object?> { ["alg"] = "RS256", ["kid"] = "k1", ["typ"] = "secevent+jwt" };
        var h = B64(JsonSerializer.SerializeToUtf8Bytes(header));
        var p = B64(JsonSerializer.SerializeToUtf8Bytes(payload));
        var data = Encoding.ASCII.GetBytes(h + "." + p);
        var sig = key.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return h + "." + p + "." + B64(sig);
    }

    sealed class MemLog : ISignalsLog
    {
        public List<string> Errors { get; } = new();
        public void Info(string message) { }
        public void Warn(string message) { }
        public void Error(string message) { lock (Errors) Errors.Add(message); }
    }

    sealed class Stub : IDisposable
    {
        readonly object _gate = new();
        readonly Dictionary<string, string> _queue = new();
        readonly HttpListener _listener = new();
        readonly Thread _thread;
        public List<string> Acked { get; } = new();
        public Dictionary<string, object?> Errs { get; } = new();
        public int Created;
        public List<Dictionary<string, object?>> Streams { get; } = new();
        public RSA Key { get; } = RSA.Create(2048);
        public RSA Other { get; } = RSA.Create(2048);
        public Dictionary<string, object?> Jwk { get; }
        public string Url { get; }

        public Stub()
        {
            Jwk = JwkOf(Key, "k1");
            var port = FreePort();
            Url = "http://127.0.0.1:" + port;
            _listener.Prefixes.Add(Url + "/");
            _listener.Start();
            _thread = new Thread(Loop) { IsBackground = true };
            _thread.Start();
        }

        static int FreePort()
        {
            var tcp = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            tcp.Start();
            var port = ((IPEndPoint)tcp.LocalEndpoint).Port;
            tcp.Stop();
            return port;
        }

        void Loop()
        {
            while (_listener.IsListening)
            {
                HttpListenerContext ctx;
                try { ctx = _listener.GetContext(); }
                catch { return; }
                try { Handle(ctx); }
                catch { try { ctx.Response.Abort(); } catch { } }
            }
        }

        void Handle(HttpListenerContext ctx)
        {
            using var reader = new StreamReader(ctx.Request.InputStream, ctx.Request.ContentEncoding);
            var text = reader.ReadToEnd();
            Dictionary<string, object?>? parsed = null;
            if (text != "")
            {
                try { parsed = JsonMaps.Parse(text); }
                catch { parsed = null; }
            }
            var path = ctx.Request.Url?.AbsolutePath ?? "";
            object body;
            var status = 200;
            lock (_gate)
            {
                if (path == "/.well-known/ssf-configuration")
                {
                    body = new Dictionary<string, object?>
                    {
                        ["issuer"] = Url,
                        ["jwks_uri"] = Url + "/jwks",
                        ["configuration_endpoint"] = Url + "/ssf/stream",
                        ["verification_endpoint"] = Url + "/ssf/verify",
                        ["delivery_methods_supported"] = new[] { "urn:ietf:rfc:8936" },
                    };
                }
                else if (path == "/jwks")
                {
                    body = new Dictionary<string, object?> { ["keys"] = new[] { Jwk } };
                }
                else if (path == "/ssf/stream" && ctx.Request.HttpMethod == "GET")
                {
                    body = Streams;
                }
                else if (path == "/ssf/stream" && ctx.Request.HttpMethod == "POST")
                {
                    Created++;
                    var delivery = parsed?.GetValueOrDefault("delivery") as Dictionary<string, object?>;
                    var stream = new Dictionary<string, object?>
                    {
                        ["stream_id"] = "s" + Created,
                        ["iss"] = Url,
                        ["aud"] = "my-app",
                        ["delivery"] = new Dictionary<string, object?>
                        {
                            ["method"] = delivery?.GetValueOrDefault("method"),
                            ["endpoint_url"] = Url + "/ssf/poll/s" + Created,
                        },
                        ["events_requested"] = parsed?.GetValueOrDefault("events_requested"),
                        ["events_delivered"] = parsed?.GetValueOrDefault("events_requested"),
                    };
                    Streams.Add(stream);
                    body = stream;
                    status = 201;
                }
                else if (path.StartsWith("/ssf/poll/", StringComparison.Ordinal))
                {
                    if (parsed?.GetValueOrDefault("ack") is List<object?> ack)
                    {
                        foreach (var item in ack)
                        {
                            var jti = item?.ToString() ?? "";
                            Acked.Add(jti);
                            _queue.Remove(jti);
                        }
                    }
                    if (parsed?.GetValueOrDefault("setErrs") is Dictionary<string, object?> errs)
                    {
                        foreach (var pair in errs)
                        {
                            Errs[pair.Key] = pair.Value;
                            _queue.Remove(pair.Key);
                        }
                    }
                    body = new Dictionary<string, object?>
                    {
                        ["sets"] = new Dictionary<string, string>(_queue),
                        ["moreAvailable"] = false,
                    };
                }
                else
                {
                    status = 404;
                    body = new Dictionary<string, object?> { ["err"] = "not found" };
                }
            }
            var raw = JsonSerializer.SerializeToUtf8Bytes(body);
            ctx.Response.StatusCode = status;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = raw.Length;
            ctx.Response.OutputStream.Write(raw);
            ctx.Response.Close();
        }

        public string Put(string eventType, Dictionary<string, object?> sub, Dictionary<string, object?>? extra, RSA? key, string aud, string iss)
        {
            var jti = B64(RandomNumberGenerator.GetBytes(16));
            extra ??= new Dictionary<string, object?>();
            extra["event_timestamp"] = 1;
            if (aud == "") aud = "my-app";
            if (iss == "") iss = Url;
            key ??= Key;
            var payload = new Dictionary<string, object?>
            {
                ["iss"] = iss, ["aud"] = aud, ["jti"] = jti, ["iat"] = 1,
                ["sub_id"] = sub, ["events"] = new Dictionary<string, object?> { [eventType] = extra },
            };
            lock (_gate) _queue[jti] = SignJws(payload, key, null);
            return jti;
        }

        public void Dispose()
        {
            _listener.Close();
            Key.Dispose();
            Other.Dispose();
        }
    }

    static Login LoginOf(string person, string session) => new()
    {
        NameId = person,
        Issuer = "x",
        Realm = "https://rp.test/",
        TrustVersion = "2005/02",
        NameIdFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        SessionIndex = session,
        Attributes = new Dictionary<string, List<string>>
        {
            [Names.DefaultSubjectAttribute] = new() { "urn:uuid:" + person },
            ["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"] = new() { person + "@example.com" },
        },
    };

    static Dictionary<string, object?> Complex(string iss, string person, string? session)
    {
        var user = new Dictionary<string, object?> { ["format"] = "iss_sub", ["iss"] = iss, ["sub"] = "urn:uuid:" + person };
        var sub = new Dictionary<string, object?> { ["format"] = "complex", ["user"] = user };
        if (session != null)
            sub["session"] = new Dictionary<string, object?> { ["format"] = "opaque", ["id"] = session };
        return sub;
    }

    [Fact]
    public void VerifiesASetAndRefusesTheWrongKey()
    {
        using var key = RSA.Create(2048);
        using var other = RSA.Create(2048);
        var jwk = JwkOf(key, "k1");
        var keys = new List<Dictionary<string, object?>> { jwk };
        var (_, payload) = Jws.Verify(SignJws(new Dictionary<string, object?> { ["a"] = 1 }, key), keys);
        Assert.True(payload["a"] is long one && one == 1 || payload["a"] is double d && Math.Abs(d - 1) < 0.001);
        var wrong = Assert.Throws<WsFedException>(() => Jws.Verify(SignJws(new Dictionary<string, object?> { ["a"] = 1 }, other), keys));
        Assert.Equal("signature", wrong.Code);
        Assert.Contains("does not verify", wrong.Message);
        var missing = Assert.Throws<WsFedException>(() => Jws.Verify(SignJws(new Dictionary<string, object?> { ["a"] = 1 }, key, new Dictionary<string, object?> { ["alg"] = "RS256", ["kid"] = "nope" }), keys));
        Assert.Equal("signature", missing.Code);
        Assert.Contains("no RSA signing key with kid nope", missing.Message);
        var none = Assert.Throws<WsFedException>(() => Jws.Verify(SignJws(new Dictionary<string, object?> { ["a"] = 1 }, key, new Dictionary<string, object?> { ["alg"] = "none" }), keys));
        Assert.Contains("does not verify", none.Message);
        var hmac = Assert.Throws<WsFedException>(() => Jws.Verify(SignJws(new Dictionary<string, object?> { ["a"] = 1 }, key, new Dictionary<string, object?> { ["alg"] = "HS256", ["kid"] = "k1" }), keys));
        Assert.Contains("does not verify", hmac.Message);
    }

    [Fact]
    public void Subjects()
    {
        var got = Events.SubjectOf(new Dictionary<string, object?>
        {
            ["format"] = "complex",
            ["user"] = new Dictionary<string, object?> { ["format"] = "iss_sub", ["iss"] = "https://i", ["sub"] = "urn:uuid:a" },
            ["session"] = new Dictionary<string, object?> { ["format"] = "opaque", ["id"] = "S1" },
        }, "https://i");
        Assert.Equal("urn:uuid:a", got["person"]);
        Assert.Equal("S1", got["idp_session"]);
        Assert.Empty(Events.SubjectOf(new Dictionary<string, object?> { ["format"] = "iss_sub", ["iss"] = "https://other", ["sub"] = "urn:uuid:a" }, "https://i"));
        var email = Events.SubjectOf(new Dictionary<string, object?> { ["format"] = "email", ["email"] = "A@x.com" }, "https://i");
        Assert.Equal("A@x.com", email["email"]);
    }

    [Fact]
    public void PollStreamEndsTheNamedSessions()
    {
        using var stub = new Stub();
        var ended = new List<List<string>>();
        var seen = new List<SignalEvent>();
        var receiver = new SignalsReceiver(stub.Url, (ids, _) => ended.Add(ids.ToList()), new ReceiverOptions { PollIntervalMs = 60000, Log = new MemLog() });
        receiver.On("*", evt => seen.Add(evt));
        receiver.Start();
        receiver.Stop();
        Assert.Equal(1, stub.Created);
        Assert.Equal("s1", receiver.Stream?["stream_id"] as string);
        receiver.Track("L-a1", LoginOf("alice", "IDP-A1"));
        receiver.Track("L-a2", LoginOf("alice", "IDP-A2"));
        receiver.Track("L-b1", LoginOf("bob", "IDP-B1"));
        var j1 = stub.Put(Events.Catalog["session_revoked"], Complex(stub.Url, "alice", "IDP-A1"), null, null, "", "");
        var j2 = stub.Put(Events.Catalog["credential_change"], Complex(stub.Url, "bob", null), new Dictionary<string, object?> { ["credential_type"] = "password", ["change_type"] = "update" }, null, "", "");
        receiver.PollOnce();
        Assert.Single(ended);
        Assert.Equal("L-a1", ended[0][0]);
        var change = seen.FirstOrDefault(evt => evt.Jti == j2);
        Assert.NotNull(change);
        Assert.False(change!.Ended);
        Assert.Equal(new[] { "L-b1" }, change.Sessions);
        var j3 = stub.Put(Events.Catalog["account_disabled"], new Dictionary<string, object?> { ["format"] = "iss_sub", ["iss"] = stub.Url, ["sub"] = "urn:uuid:alice" }, null, null, "", "");
        receiver.PollOnce();
        Assert.Equal(2, ended.Count);
        Assert.Equal("L-a2", ended[1][0]);
        Assert.Contains(j1, stub.Acked);
        Assert.Contains(j2, stub.Acked);
        stub.Put(Events.Catalog["credential_compromise"], new Dictionary<string, object?> { ["format"] = "email", ["email"] = "BOB@example.com" }, new Dictionary<string, object?> { ["credential_type"] = "password" }, null, "", "");
        receiver.PollOnce();
        Assert.Equal("L-b1", ended[2][0]);
        receiver.PollOnce();
        Assert.Contains(j3, stub.Acked);
        var again = new SignalsReceiver(stub.Url, (_, _) => { }, new ReceiverOptions { Log = new MemLog() });
        again.Start();
        again.Stop();
        Assert.Equal(1, stub.Created);
        Assert.Equal("s1", again.Stream?["stream_id"] as string);
    }

    [Fact]
    public void ForgedSetsAreReported()
    {
        using var stub = new Stub();
        var ended = new List<List<string>>();
        var index = new MemorySessionIndex();
        var receiver = new SignalsReceiver(stub.Url, (ids, _) => ended.Add(ids.ToList()), new ReceiverOptions { Index = index, Log = new MemLog() });
        receiver.Start();
        receiver.Stop();
        receiver.Track("L-c1", LoginOf("carol", "IDP-C1"));
        var subject = Complex(stub.Url, "carol", "IDP-C1");
        var forged = stub.Put(Events.Catalog["session_revoked"], subject, null, stub.Other, "", "");
        var mis = stub.Put(Events.Catalog["session_revoked"], subject, null, null, "someone-else", "");
        var foreign = stub.Put(Events.Catalog["session_revoked"], subject, null, null, "", "https://evil.example");
        receiver.PollOnce();
        Assert.Empty(ended);
        Assert.Equal(new[] { "L-c1" }, index.ByPerson("urn:uuid:carol"));
        receiver.PollOnce();
        Assert.True(stub.Errs.ContainsKey(forged), string.Join(",", stub.Errs.Keys));
        Assert.True(stub.Errs.ContainsKey(mis));
        Assert.True(stub.Errs.ContainsKey(foreign));
    }

    [Fact]
    public void EventCatalog()
    {
        Assert.Equal(8, Events.CaepEvents.Count);
        Assert.Equal(14, Events.RiscEvents.Count);
        Assert.Contains(Events.Catalog["risk_level_change"], Events.CaepEvents);
        Assert.Contains(Events.Catalog["opt_out_effective"], Events.RiscEvents);
    }

    [Fact]
    public void HandlerAndOnEndErrorsAreStillAcknowledged()
    {
        using var stub = new Stub();
        var log = new MemLog();
        var seen = new List<string>();
        var receiver = new SignalsReceiver(stub.Url, (_, _) => throw new InvalidOperationException("store down"), new ReceiverOptions { Log = log });
        receiver.On(Events.Catalog["credential_change"], _ => throw new InvalidOperationException("handler bug"));
        receiver.On("*", evt => seen.Add(evt.Jti));
        receiver.Start();
        receiver.Stop();
        receiver.Track("L-d1", LoginOf("dave", "IDP-D1"));
        var j1 = stub.Put(Events.Catalog["credential_change"], Complex(stub.Url, "dave", null), new Dictionary<string, object?> { ["credential_type"] = "password", ["change_type"] = "update" }, null, "", "");
        var j2 = stub.Put(Events.Catalog["session_revoked"], Complex(stub.Url, "dave", "IDP-D1"), null, null, "", "");
        for (var i = 0; i < 3; i++) receiver.PollOnce();
        Assert.Contains(j1, stub.Acked);
        Assert.Contains(j2, stub.Acked);
        Assert.False(stub.Errs.ContainsKey(j1));
        Assert.False(stub.Errs.ContainsKey(j2));
        Assert.Contains(j1, seen);
        Assert.Contains(j2, seen);
        var joined = string.Join("\n", log.Errors);
        Assert.Contains("handler for", joined);
        Assert.Contains("credential-change", joined);
        Assert.Contains("threw", joined);
        Assert.Contains("onEndSessions threw", joined);
    }

    [Fact]
    public void OverlappingPollsHandleASetOnce()
    {
        using var stub = new Stub();
        var seen = new List<string>();
        var gate = new object();
        var receiver = new SignalsReceiver(stub.Url, (_, _) => { }, new ReceiverOptions { Log = new MemLog() });
        receiver.On("*", evt => { lock (gate) seen.Add(evt.Jti); });
        receiver.Start();
        receiver.Stop();
        var jti = stub.Put(Events.Catalog["account_enabled"], new Dictionary<string, object?> { ["format"] = "iss_sub", ["iss"] = stub.Url, ["sub"] = "urn:uuid:erin" }, null, null, "", "");
        var threads = new Thread[3];
        for (var i = 0; i < 3; i++)
        {
            threads[i] = new Thread(() => { try { receiver.PollOnce(); } catch { } });
            threads[i].Start();
        }
        foreach (var thread in threads) thread.Join();
        receiver.PollOnce();
        Assert.Equal(1, seen.Count(item => item == jti));
    }

    [Fact]
    public void RefusesATransmitterWithoutPollDelivery()
    {
        var receiver = new SignalsReceiver("http://127.0.0.1:1", (_, _) => { }, new ReceiverOptions { Log = new MemLog() });
        var err = Assert.Throws<WsFedException>(() => receiver.Start());
        Assert.Equal("ssf", err.Code);
    }
}
