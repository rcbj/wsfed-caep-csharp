// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Text;

namespace IyaSec.WsFed;

public sealed class LoginRequest
{
    public string Id { get; set; } = "";
    public string Url { get; set; } = "";
    public string Wctx { get; set; } = "";
}

public sealed class ReplyRequest
{
    public string Method { get; set; } = "";
    public string Url { get; set; } = "";
    public object? Body { get; set; }
}

public sealed class LoginOptions
{
    public string? RelayState { get; set; }
    public bool ForceAuthn { get; set; }
    public int? Freshness { get; set; }
    public string AuthenticationMethod { get; set; } = "";
    public string HomeRealm { get; set; } = "";
    public Dictionary<string, string>? Params { get; set; }
}

public sealed class RelyingParty
{
    public const int MaxRelayState = 1024;
    static readonly HashSet<string> ProtocolParams = new(StringComparer.Ordinal)
    {
        "wa", "wtrealm", "wreply", "wctx", "wct", "wreq", "wreqptr", "wfresh", "wauth", "whr",
    };

    public Resolved Config { get; }
    public IdPMetadata? Idp { get; private set; }
    readonly MemoryReplayCache _replay = new();

    RelyingParty(Resolved config) { Config = config; }

    public static RelyingParty Create(IDictionary<string, object?> config, string? baseDir)
    {
        var party = new RelyingParty(WsfedConfig.Resolve(config, baseDir));
        party.RefreshMetadata();
        return party;
    }

    public static RelyingParty FromFile(string path, IDictionary<string, object?>? overrides)
    {
        var party = new RelyingParty(WsfedConfig.ReadFile(path, overrides));
        party.RefreshMetadata();
        return party;
    }

    public IdPMetadata RefreshMetadata()
    {
        var source = Config.IdPMetadata;
        string xml;
        if (source.StartsWith('<')) xml = source;
        else if (source.StartsWith("http://", StringComparison.Ordinal) || source.StartsWith("https://", StringComparison.Ordinal))
        {
            TlsMaterial? tls = string.IsNullOrEmpty(Config.IdPCa) ? null : new TlsMaterial { Ca = Config.IdPCa };
            var answer = HttpSend.Send(source, "GET", new Dictionary<string, string> { ["accept"] = "application/samlmetadata+xml, application/xml, text/xml" }, null, tls, "metadata");
            if (answer.Status != 200) throw new WsFedException("metadata", source + " answered HTTP " + answer.Status);
            xml = answer.Body;
        }
        else
        {
            try { xml = File.ReadAllText(source); }
            catch (Exception ex) { throw new WsFedException("metadata", "the identity provider metadata file " + source + " cannot be read", ex); }
        }
        var meta = Metadata.Read(xml, Config.IdPEntityId);
        Idp = meta;
        return meta;
    }

    IdPMetadata Loaded() => Idp ?? throw new WsFedException("metadata", "the identity provider's metadata has not been loaded");

    public string MetadataXml() => Metadata.Write(Config.Realm, Config.ReplyUrl, Config.Certificate);

    public LoginRequest Login(LoginOptions? opts)
    {
        opts ??= new LoginOptions();
        var idp = Loaded();
        if (opts.RelayState != null && Encoding.UTF8.GetByteCount(opts.RelayState) > MaxRelayState)
            throw new WsFedException("config", "relayState is longer than " + MaxRelayState + " bytes");
        var requestId = Convert.ToHexString(RandomNumberGenerator.GetBytes(20)).ToLowerInvariant();
        var wctx = "id=" + Uri.EscapeDataString(requestId);
        if (opts.RelayState != null) wctx += "&ru=" + Uri.EscapeDataString(opts.RelayState);
        var pairs = new Dictionary<string, string>(StringComparer.Ordinal);
        var order = new List<string> { "wa", "wtrealm", "wreply", "wctx", "wct" };
        pairs["wa"] = "wsignin1.0";
        pairs["wtrealm"] = Config.Realm;
        pairs["wreply"] = Config.ReplyUrl;
        pairs["wctx"] = wctx;
        pairs["wct"] = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");
        if (Config.RequestTokenType)
        {
            order.Add("wreq");
            pairs["wreq"] = "<wst:RequestSecurityToken xmlns:wst=\"" + Names.Trust13 + "\"><wst:TokenType>" + Names.Saml2Token + "</wst:TokenType></wst:RequestSecurityToken>";
        }
        if (opts.ForceAuthn)
        {
            order.Add("wfresh");
            pairs["wfresh"] = "0";
        }
        else if (opts.Freshness != null)
        {
            if (opts.Freshness < 0) throw new WsFedException("config", "freshness is a whole number of minutes");
            order.Add("wfresh");
            pairs["wfresh"] = opts.Freshness.Value.ToString();
        }
        if (opts.AuthenticationMethod != "")
        {
            order.Add("wauth");
            pairs["wauth"] = opts.AuthenticationMethod;
        }
        if (opts.HomeRealm != "")
        {
            order.Add("whr");
            pairs["whr"] = opts.HomeRealm;
        }
        if (opts.Params != null)
        {
            foreach (var pair in opts.Params)
            {
                if (ProtocolParams.Contains(pair.Key))
                    throw new WsFedException("config", "params cannot set " + pair.Key + "; it is the protocol's own");
                order.Add(pair.Key);
                pairs[pair.Key] = pair.Value;
            }
        }
        return new LoginRequest { Id = requestId, Url = JoinQuery(idp.PassiveRequestorEndpoint, Encode(pairs, order)), Wctx = wctx };
    }

    public Login HandleReply(ReplyRequest request, IReadOnlyList<string>? requestIds)
    {
        var idp = Loaded();
        var (form, query) = ParamsOf(request);
        var wa = form.TryGetValue("wa", out var posted) ? posted : query.GetValueOrDefault("wa") ?? "";
        if (wa is "wsignoutcleanup1.0" or "wsignout1.0")
            throw new WsFedException("message", "the request is " + wa + ", a sign-out, not a sign-in response; see isSignOutCleanup()");
        if (!string.Equals(request.Method, "POST", StringComparison.OrdinalIgnoreCase))
            throw new WsFedException("message", "a sign-in response is POSTed (WS-Federation 13.2.2); this request is a GET");
        if (wa != "wsignin1.0")
        {
            var shown = wa == "" ? "(none)" : wa;
            throw new WsFedException("message", "the request's wa is " + shown + ", not wsignin1.0");
        }
        if (form.ContainsKey("wresultptr"))
            throw new WsFedException("message", "the response is by reference (wresultptr), which is never dereferenced; only wresult is accepted");
        form.TryGetValue("wresult", out var wresult);
        if (string.IsNullOrEmpty(wresult)) throw new WsFedException("message", "the request carries no wresult");
        var wctx = FirstMap(form.GetValueOrDefault("wctx") ?? "");
        var hasId = wctx.TryGetValue("id", out var gotId);
        if (hasId)
        {
            var ok = requestIds != null && requestIds.Contains(gotId);
            if (!ok) throw new WsFedException("validation", "the response answers " + gotId + ", which is not a sign-in this browser has outstanding");
        }
        else if (!Config.AllowUnsolicited)
        {
            throw new WsFedException("validation", "the response is unsolicited (its wctx names no request), and unsolicited responses are not accepted");
        }
        var token = Token.Validate(wresult!, new TokenContext
        {
            Realm = Config.Realm,
            ReplyUrl = Config.ReplyUrl,
            IdPEntityId = idp.EntityId,
            IdPCertificates = idp.SigningCertificates,
            DecryptionKey = Config.PrivateKey,
            ClockSkewMs = Config.ClockSkewMs,
            WantAssertionsEncrypted = Config.WantAssertionsEncrypted,
            Replay = _replay,
        });
        if (hasId) token.RequestId = gotId;
        if (wctx.TryGetValue("ru", out var ru)) token.RelayState = ru;
        return token;
    }

    public bool IsSignOutCleanup(ReplyRequest request)
    {
        var (form, query) = ParamsOf(request);
        var wa = form.TryGetValue("wa", out var posted) ? posted : query.GetValueOrDefault("wa") ?? "";
        return wa is "wsignoutcleanup1.0" or "wsignout1.0";
    }

    public string Logout(string reply)
    {
        var idp = Loaded();
        var pairs = new Dictionary<string, string> { ["wa"] = "wsignout1.0", ["wtrealm"] = Config.Realm };
        var order = new List<string> { "wa", "wtrealm" };
        if (reply != "")
        {
            order.Add("wreply");
            pairs["wreply"] = reply;
        }
        return JoinQuery(idp.PassiveRequestorEndpoint, Encode(pairs, order));
    }

    static string JoinQuery(string endpoint, string query)
    {
        var joiner = endpoint.Contains('?') ? "&" : "?";
        return endpoint + joiner + query;
    }

    static string Encode(Dictionary<string, string> values, List<string> order)
    {
        var b = new StringBuilder();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var key in order)
        {
            if (!seen.Add(key) || !values.TryGetValue(key, out var value)) continue;
            if (b.Length > 0) b.Append('&');
            b.Append(Uri.EscapeDataString(key)).Append('=').Append(Uri.EscapeDataString(value));
        }
        return b.ToString();
    }

    public static Dictionary<string, string> FirstMap(string raw)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        if (raw == "") return map;
        foreach (var part in raw.Split('&'))
        {
            if (part == "") continue;
            var cut = part.IndexOf('=');
            var key = Uri.UnescapeDataString((cut < 0 ? part : part[..cut]).Replace("+", " ", StringComparison.Ordinal));
            var value = Uri.UnescapeDataString((cut < 0 ? "" : part[(cut + 1)..]).Replace("+", " ", StringComparison.Ordinal));
            if (!map.ContainsKey(key)) map[key] = value;
        }
        return map;
    }

    static Dictionary<string, string> FormOf(object? body)
    {
        switch (body)
        {
            case null: return new Dictionary<string, string>();
            case string text: return FirstMap(text);
            case IDictionary<string, string> map:
                return new Dictionary<string, string>(map, StringComparer.Ordinal);
            case IDictionary<string, object?> any:
                var outMap = new Dictionary<string, string>(StringComparer.Ordinal);
                foreach (var pair in any)
                    if (pair.Value is string text) outMap[pair.Key] = text;
                return outMap;
            default: return new Dictionary<string, string>();
        }
    }

    static (Dictionary<string, string> form, Dictionary<string, string> query) ParamsOf(ReplyRequest request)
    {
        var raw = request.Url ?? "";
        var query = "";
        var q = raw.IndexOf('?');
        if (q >= 0)
        {
            query = raw[(q + 1)..];
            var hash = query.IndexOf('#');
            if (hash >= 0) query = query[..hash];
        }
        var parsed = FirstMap(query);
        var form = string.Equals(request.Method, "POST", StringComparison.OrdinalIgnoreCase) ? FormOf(request.Body) : new Dictionary<string, string>();
        return (form, parsed);
    }
}
