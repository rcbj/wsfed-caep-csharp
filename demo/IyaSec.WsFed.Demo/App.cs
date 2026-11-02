// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace IyaSec.WsFed.Demo;

public sealed class HeaderField
{
    public string Name { get; }
    public string Value { get; }
    public HeaderField(string name, string value) { Name = name; Value = value; }
}

// GET /live-status is JSON: signedIn, subject, receiver, and the accepted Shared
// Signals events (type and jti). It never includes tokens or assertions.
public sealed class App
{
    public const string Styles =
        "/* SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC */\n" +
        "/* SPDX-License-Identifier: MIT */\n" +
        "body { font-family: sans-serif; margin: 2rem; }\n" +
        "a.button, button { padding: 0.4rem 0.8rem; }\n";

    static readonly byte[] Gif = Convert.FromBase64String("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7");

    public RelyingParty Party { get; }
    public SignalsReceiver? Receiver { get; set; }
    readonly Dictionary<string, Login> _sessions = new();
    readonly List<(string Type, string Jti)> _events = new();
    string _receiverState = "not configured";
    readonly byte[] _secret = RandomNumberGenerator.GetBytes(32);
    readonly string _replyPath;
    readonly string _secure;

    public App(RelyingParty party, SignalsReceiver? receiver)
    {
        Party = party;
        Receiver = receiver;
        var path = "/wsfed";
        if (Uri.TryCreate(party.Config.ReplyUrl, UriKind.Absolute, out var reply) && reply.AbsolutePath != "")
            path = reply.AbsolutePath;
        _replyPath = path;
        _secure = replyScheme(party.Config.ReplyUrl) == "https" ? "; Secure" : "";
    }

    static string replyScheme(string url) => Uri.TryCreate(url, UriKind.Absolute, out var parsed) ? parsed.Scheme : "";

    static string B64(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    static string Sign(byte[] secret, string value)
    {
        using var hmac = new HMACSHA256(secret);
        return value + "." + B64(hmac.ComputeHash(Encoding.UTF8.GetBytes(value)));
    }

    static string Unsign(byte[] secret, string signed)
    {
        var cut = signed.LastIndexOf('.');
        if (cut <= 0) return "";
        var value = signed[..cut];
        var again = Sign(secret, value);
        var left = Encoding.ASCII.GetBytes(again);
        var right = Encoding.ASCII.GetBytes(signed);
        if (left.Length != right.Length || !CryptographicOperations.FixedTimeEquals(left, right)) return "";
        return value;
    }

    static Dictionary<string, string> Cookies(string header)
    {
        var jar = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var part in header.Split(';'))
        {
            var cut = part.IndexOf('=');
            if (cut < 0) continue;
            var name = part[..cut].Trim();
            var value = part[(cut + 1)..].Trim();
            if (name != "" && value != "" && !jar.ContainsKey(name)) jar[name] = value;
        }
        return jar;
    }

    static string Esc(string value) => value.Replace("&", "&amp;", StringComparison.Ordinal).Replace("<", "&lt;", StringComparison.Ordinal).Replace(">", "&gt;", StringComparison.Ordinal).Replace("\"", "&quot;", StringComparison.Ordinal);

    public void Drop(string id) { lock (_sessions) _sessions.Remove(id); }

    /// <summary>What GET /live-status reports as receiver.</summary>
    public void SetReceiverState(string state) { lock (_sessions) _receiverState = state; }

    /// <summary>Records an accepted Shared Signals event for GET /live-status.</summary>
    public void Remember(SignalEvent evt)
    {
        List<string> ended = new();
        lock (_sessions)
        {
            _events.Add((evt.Type, evt.Jti));
            // iya-sts main sets the WS-Federation assertion's SessionIndex to the
            // assertion id. The CAEP session-revoked subject names the sign-on
            // session instead, so the index finds nobody and the end callback is
            // not asked to drop this login. This demo has that one session.
            if (evt.Type == Events.Catalog["session_revoked"] && evt.Sessions.Count == 0)
            {
                ended.AddRange(_sessions.Keys);
                _sessions.Clear();
            }
        }
        foreach (var id in ended) Receiver?.Untrack(id);
    }

    (int, List<HeaderField>, byte[]) LiveStatus(string sid)
    {
        Login? who = null;
        List<Dictionary<string, string>> events;
        string state;
        lock (_sessions)
        {
            if (sid != "") _sessions.TryGetValue(sid, out who);
            events = _events.Select(item => new Dictionary<string, string> { ["type"] = item.Type, ["jti"] = item.Jti }).ToList();
            state = _receiverState;
        }
        var body = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object?>
        {
            ["signedIn"] = who != null,
            ["subject"] = who?.NameId,
            ["receiver"] = state,
            ["events"] = events,
        });
        return (200, new List<HeaderField> { new("content-type", "application/json"), new("cache-control", "no-store") }, body);
    }

    string Pending(string value, int age)
    {
        var secure = _secure == "" ? "; Secure" : _secure;
        return "wsfed_pending=" + value + "; Path=" + _replyPath + "; HttpOnly; SameSite=None" + secure + "; Max-Age=" + age;
    }

    // One request, as the handlers below see it.
    sealed record Req(string Method, string Target, Dictionary<string, string> Jar, string Sid, byte[] Body);

    // The handlers, keyed by "METHOD /path" ("* /path" for any method). A table lookup picks the
    // handler, so no handler is guarded by comparing the request's own path or method string in this
    // code (CodeQL cs/user-controlled-bypass).
    Dictionary<string, Func<Req, (int, List<HeaderField>, byte[])>>? _routes;

    Dictionary<string, Func<Req, (int, List<HeaderField>, byte[])>> Routes()
    {
        if (_routes != null) return _routes;
        var routes = new Dictionary<string, Func<Req, (int, List<HeaderField>, byte[])>>
        {
            ["GET /healthz"] = _ => (200, new List<HeaderField> { new("content-type", "text/plain") }, Encoding.UTF8.GetBytes("ok")),
            ["GET /live-status"] = req => LiveStatus(req.Sid),
            ["GET /login"] = StartLogin,
            ["POST /logout"] = EndSession,
            ["GET /FederationMetadata/2007-06/FederationMetadata.xml"] = _ => (200, new List<HeaderField> { new("content-type", "application/samlmetadata+xml") }, Encoding.UTF8.GetBytes(Party.MetadataXml())),
            ["GET /"] = HomePage,
            ["GET /styles.css"] = _ => (200, new List<HeaderField> { new("content-type", "text/css") }, Encoding.UTF8.GetBytes(Styles)),
        };
        // The reply path takes the sign-in response (POST) and wsignoutcleanup1 (any method).
        routes["POST " + _replyPath] = req => SignOutCleanup(req) ?? Reply(req);
        routes["* " + _replyPath] = req => SignOutCleanup(req) ?? NotFound(req);
        _routes = routes;
        return routes;
    }

    public (int status, List<HeaderField> headers, byte[] body) Handle(string method, string target, IDictionary<string, string> headers, byte[] body)
    {
        var path = target;
        var q = path.IndexOf('?');
        if (q >= 0) path = path[..q];
        if (path == "") path = "/";
        headers.TryGetValue("cookie", out var cookieHeader);
        var jar = Cookies(cookieHeader ?? "");
        jar.TryGetValue("sid", out var sidCookie);
        var sid = Unsign(_secret, sidCookie ?? "");
        method = method.ToUpperInvariant();
        var req = new Req(method, target, jar, sid, body);
        var table = Routes();
        var handler = table.GetValueOrDefault(method + " " + path) ?? table.GetValueOrDefault("* " + path) ?? NotFound;
        return handler(req);
    }

    static (int, List<HeaderField>, byte[]) NotFound(Req req) =>
        (404, new List<HeaderField> { new("content-type", "text/plain") }, Encoding.UTF8.GetBytes("Not found"));

    // An exception's message stays in the log: it can carry configuration and server details (CodeQL
    // cs/information-exposure-through-exception).
    static (int, List<HeaderField>, byte[]) Failed(string where, Exception ex)
    {
        Console.Error.WriteLine("demo: " + where + ": " + ex);
        return (500, new List<HeaderField> { new("content-type", "text/plain") }, Encoding.UTF8.GetBytes(where + " failed; the reason is in the demo's log."));
    }

    (int, List<HeaderField>, byte[]) StartLogin(Req req)
    {
        try
        {
            var request = Party.Login(new LoginOptions { RelayState = "/" });
            return (302, new List<HeaderField>
            {
                new("location", request.Url),
                new("set-cookie", Pending(Sign(_secret, request.Id), 600)),
            }, Array.Empty<byte>());
        }
        catch (Exception ex)
        {
            return Failed("sign-in", ex);
        }
    }

    (int, List<HeaderField>, byte[])? SignOutCleanup(Req req)
    {
        if (!Party.IsSignOutCleanup(new ReplyRequest { Method = req.Method, Url = req.Target })) return null;
        if (req.Sid != "")
        {
            Drop(req.Sid);
            Receiver?.Untrack(req.Sid);
        }
        return (200, new List<HeaderField>
        {
            new("content-type", "image/gif"),
            new("set-cookie", "sid=; Path=/; HttpOnly; Max-Age=0" + _secure),
        }, Gif);
    }

    (int, List<HeaderField>, byte[]) Reply(Req req)
    {
        req.Jar.TryGetValue("wsfed_pending", out var pendingCookie);
        var pending = Unsign(_secret, pendingCookie ?? "");
        IReadOnlyList<string>? ids = pending == "" ? null : new[] { pending };
        Login who;
        try { who = Party.HandleReply(new ReplyRequest { Method = "POST", Url = req.Target, Body = Encoding.UTF8.GetString(req.Body) }, ids); }
        catch { return (400, new List<HeaderField> { new("content-type", "text/plain") }, Encoding.UTF8.GetBytes("Sign-in failed.")); }
        var sessionId = B64(RandomNumberGenerator.GetBytes(24));
        lock (_sessions) _sessions[sessionId] = who;
        Receiver?.Track(sessionId, who);
        var next = "/";
        if (who.RelayState != null && who.RelayState.StartsWith('/') && !who.RelayState.StartsWith("//")) next = who.RelayState;
        return (303, new List<HeaderField>
        {
            new("location", next),
            new("set-cookie", Pending("", 0)),
            new("set-cookie", "sid=" + Sign(_secret, sessionId) + "; Path=/; HttpOnly; SameSite=Lax" + _secure),
        }, Array.Empty<byte>());
    }

    (int, List<HeaderField>, byte[]) EndSession(Req req)
    {
        if (req.Sid != "")
        {
            Drop(req.Sid);
            Receiver?.Untrack(req.Sid);
        }
        var origin = "/";
        if (Uri.TryCreate(Party.Config.ReplyUrl, UriKind.Absolute, out var reply))
            origin = reply.Scheme + "://" + reply.Authority + "/";
        try
        {
            var location = Party.Logout(origin);
            return (303, new List<HeaderField>
            {
                new("location", location),
                new("set-cookie", "sid=; Path=/; HttpOnly; Max-Age=0" + _secure),
            }, Array.Empty<byte>());
        }
        catch (Exception ex)
        {
            return Failed("sign-out", ex);
        }
    }

    (int, List<HeaderField>, byte[]) HomePage(Req req)
    {
        Login? who = null;
        if (req.Sid != "") { lock (_sessions) _sessions.TryGetValue(req.Sid, out who); }
        var page = "<p><a href=\"/login\">Sign in with WS-Federation</a></p>";
        if (who != null)
            page = "<p>Signed in as <strong>" + Esc(who.NameId) + "</strong> by " + Esc(who.Issuer) + ".</p><form method=\"post\" action=\"/logout\"><button>Sign out</button></form>";
        var html = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>WS-Federation</title><link rel=\"stylesheet\" href=\"/styles.css\"></head><body><main>" + page + "</main></body></html>";
        return (200, new List<HeaderField> { new("content-type", "text/html; charset=utf-8") }, Encoding.UTF8.GetBytes(html));
    }
}

public static class DemoHost
{
    public static int Serve(int port, Func<App> getApp)
    {
        var listener = new HttpListener();
        listener.Prefixes.Add("http://+:" + port + "/");
        listener.Start();
        Console.WriteLine("wsfed-caep demo on port " + port);
        App? holder = null;
        Exception? failed = null;
        while (listener.IsListening)
        {
            HttpListenerContext ctx;
            try { ctx = listener.GetContext(); }
            catch (HttpListenerException) { break; }
            catch (ObjectDisposedException) { break; }
            var path = ctx.Request.Url?.AbsolutePath ?? "/";
            if (path == "/healthz" && ctx.Request.HttpMethod.Equals("GET", StringComparison.OrdinalIgnoreCase))
            {
                Write(ctx, 200, new List<HeaderField> { new("content-type", "text/plain") }, Encoding.UTF8.GetBytes("ok"));
                continue;
            }
            if (holder == null && failed == null)
            {
                try { holder = getApp(); }
                catch (Exception ex)
                {
                    failed = ex;
                    Console.Error.WriteLine("demo: not ready: " + ex);
                }
            }
            if (holder == null)
            {
                Write(ctx, 503, new List<HeaderField> { new("content-type", "text/plain") }, Encoding.UTF8.GetBytes("not ready; the reason is in the demo's log\n"));
                continue;
            }
            using var raw = new MemoryStream();
            ctx.Request.InputStream.CopyTo(raw);
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string? name in ctx.Request.Headers)
            {
                if (name == null) continue;
                headers[name.ToLowerInvariant()] = ctx.Request.Headers[name] ?? "";
            }
            var target = ctx.Request.Url?.PathAndQuery ?? "/";
            var (status, fields, payload) = holder.Handle(ctx.Request.HttpMethod, target, headers, raw.ToArray());
            Write(ctx, status, fields, payload);
        }
        return 0;
    }

    static void Write(HttpListenerContext ctx, int status, List<HeaderField> fields, byte[] payload)
    {
        ctx.Response.StatusCode = status;
        foreach (var field in fields)
        {
            if (field.Name.Equals("content-type", StringComparison.OrdinalIgnoreCase))
                ctx.Response.ContentType = field.Value;
            else
                ctx.Response.Headers.Add(field.Name, field.Value);
        }
        ctx.Response.ContentLength64 = payload.Length;
        if (payload.Length > 0) ctx.Response.OutputStream.Write(payload);
        ctx.Response.Close();
    }

    public static (string realm, string reply) EndpointsFor(string realm, string reply, string publicUrl, bool given, int port)
    {
        if (given && publicUrl != "") return (MoveOrigin(realm, publicUrl), MoveOrigin(reply, publicUrl));
        if (port > 0) return (OnPort(realm, port), OnPort(reply, port));
        return (realm, reply);
    }

    static bool Loopback(string host)
    {
        host = host.Trim().TrimStart('[').TrimEnd(']');
        return host == "localhost" || host == "127.0.0.1" || host == "::1";
    }

    static string OnPort(string raw, int port)
    {
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var parsed)) return raw;
        if (!Loopback(parsed.Host)) return raw;
        var bare = parsed.Host.TrimStart('[').TrimEnd(']');
        var host = bare.Contains(':') ? "[" + bare + "]:" + port : bare + ":" + port;
        return parsed.Scheme + "://" + host + parsed.AbsolutePath + parsed.Query + parsed.Fragment;
    }

    static string MoveOrigin(string value, string publicUrl)
    {
        var text = publicUrl.EndsWith('/') ? publicUrl : publicUrl + "/";
        if (!Uri.TryCreate(text, UriKind.Absolute, out var baseUrl)) return value;
        if (!Uri.TryCreate(value, UriKind.Absolute, out var next)) return value;
        var builder = new UriBuilder(next) { Scheme = baseUrl.Scheme, Host = baseUrl.Host, Port = baseUrl.Port };
        return builder.Uri.ToString();
    }

    public static (RelyingParty party, Dictionary<string, object?> raw) LoadParty(string path, int port, string publicUrl, bool given)
    {
        var raw = JsonMaps.Parse(File.ReadAllText(path));
        var realm = raw.GetValueOrDefault("realm") as string ?? "";
        var reply = raw.GetValueOrDefault("replyUrl") as string ?? "";
        (realm, reply) = EndpointsFor(realm, reply, publicUrl, given, port);
        var overrides = new Dictionary<string, object?>();
        if (realm != "") overrides["realm"] = realm;
        if (reply != "") overrides["replyUrl"] = reply;
        return (RelyingParty.FromFile(path, overrides), raw);
    }

    public static int Run(string[] argv)
    {
        var port = 3000;
        var text = Environment.GetEnvironmentVariable("PORT");
        if (!string.IsNullOrEmpty(text) && int.TryParse(text, out var fromEnv)) port = fromEnv;
        for (var i = 0; i < argv.Length; i++)
        {
            if (argv[i] == "--port" && i + 1 < argv.Length && int.TryParse(argv[i + 1], out var fromArg))
                port = fromArg;
        }
        string publicUrl;
        bool given;
        try { (publicUrl, given) = PublicUrl(argv); }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
        var path = ConfigPath(argv);
        App? holder = null;
        try
        {
            return Serve(port, () =>
            {
                if (holder != null) return holder;
                var (party, raw) = LoadParty(path, port, publicUrl, given);
                var app = new App(party, null);
                var ssfBlock = raw.GetValueOrDefault("ssf") as Dictionary<string, object?>;
                var transmitterOf = ssfBlock?.GetValueOrDefault("transmitter") as string ?? "";
                if (raw.GetValueOrDefault("signals") is false) app.SetReceiverState("not configured (signals are off)");
                else if (transmitterOf == "") app.SetReceiverState("not configured (no ssf block in the configuration file)");
                else if (party.Config.PrivateKey == null) app.SetReceiverState("not running: the relying party has no private key");
                if (raw.GetValueOrDefault("signals") is not false)
                {
                    if (ssfBlock is Dictionary<string, object?> ssf && ssf.GetValueOrDefault("transmitter") is string transmitter && transmitter != "" && party.Config.PrivateKey != null)
                    {
                        var interval = 5000;
                        if (ssf.GetValueOrDefault("pollIntervalMs") is long n && n > 0) interval = (int)n;
                        else if (ssf.GetValueOrDefault("pollIntervalMs") is double d && d > 0) interval = (int)d;
                        try
                        {
                            var opts = new ReceiverOptions { PollIntervalMs = interval };
                            if (!string.IsNullOrEmpty(party.Config.IdPCa)) opts.Ca = party.Config.IdPCa;
                            if (party.Config.Certificate != null)
                                opts.Cert = Pem("CERTIFICATE", party.Config.Certificate.RawData);
                            opts.Key = Pem("PRIVATE KEY", party.Config.PrivateKey.ExportPkcs8PrivateKey());
                            var receiver = new SignalsReceiver(transmitter, (ids, _) =>
                            {
                                foreach (var id in ids) app.Drop(id);
                            }, opts);
                            receiver.On("*", app.Remember);
                            app.Receiver = receiver;
                            try { receiver.Start(); }
                            catch
                            {
                                app.Receiver = null;
                                throw;
                            }
                            var streamId = receiver.Stream?.GetValueOrDefault("stream_id") as string ?? "";
                            app.SetReceiverState("polling stream " + streamId + " at " + transmitter);
                        }
                        catch (Exception ex)
                        {
                            app.SetReceiverState("not running; the reason is in the demo's log");
                            Console.WriteLine("ssf: not started: " + ex.Message);
                        }
                    }
                }
                holder = app;
                return app;
            });
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    static string Pem(string label, byte[] der) => new string(PemEncoding.Write(label, der)) + "\n";

    static (string url, bool given) PublicUrl(string[] argv)
    {
        var given = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PUBLIC_URL"));
        var publicUrl = (Environment.GetEnvironmentVariable("PUBLIC_URL") ?? "").TrimEnd('/');
        for (var i = 0; i < argv.Length; i++)
        {
            if (argv[i] != "--public-url") continue;
            if (i + 1 >= argv.Length || argv[i + 1] == "") throw new InvalidOperationException("--public-url is empty");
            publicUrl = argv[i + 1].TrimEnd('/');
            given = true;
        }
        return (publicUrl, given);
    }

    static string ConfigPath(string[] argv)
    {
        var configured = Environment.GetEnvironmentVariable("WSFED_CONFIG") ?? "";
        for (var i = 0; i < argv.Length; i++)
        {
            if (argv[i] == "--config" && i + 1 < argv.Length) configured = argv[i + 1];
        }
        return configured == "" ? "demo/wsfed.json" : configured;
    }
}
