// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace IyaSec.WsFed;

public static class Events
{
    const string Caep = "https://schemas.openid.net/secevent/caep/event-type/";
    const string Risc = "https://schemas.openid.net/secevent/risc/event-type/";
    const string Ssf = "https://schemas.openid.net/secevent/ssf/event-type/";

    public static readonly IReadOnlyDictionary<string, string> Catalog = new Dictionary<string, string>
    {
        ["session_revoked"] = Caep + "session-revoked",
        ["token_claims_change"] = Caep + "token-claims-change",
        ["credential_change"] = Caep + "credential-change",
        ["assurance_level_change"] = Caep + "assurance-level-change",
        ["device_compliance_change"] = Caep + "device-compliance-change",
        ["session_established"] = Caep + "session-established",
        ["session_presented"] = Caep + "session-presented",
        ["risk_level_change"] = Caep + "risk-level-change",
        ["account_credential_change_required"] = Risc + "account-credential-change-required",
        ["account_purged"] = Risc + "account-purged",
        ["account_disabled"] = Risc + "account-disabled",
        ["account_enabled"] = Risc + "account-enabled",
        ["identifier_changed"] = Risc + "identifier-changed",
        ["identifier_recycled"] = Risc + "identifier-recycled",
        ["credential_compromise"] = Risc + "credential-compromise",
        ["opt_in"] = Risc + "opt-in",
        ["opt_out_initiated"] = Risc + "opt-out-initiated",
        ["opt_out_cancelled"] = Risc + "opt-out-cancelled",
        ["opt_out_effective"] = Risc + "opt-out-effective",
        ["recovery_activated"] = Risc + "recovery-activated",
        ["recovery_information_changed"] = Risc + "recovery-information-changed",
        ["sessions_revoked"] = Risc + "sessions-revoked",
        ["verification"] = Ssf + "verification",
        ["stream_updated"] = Ssf + "stream-updated",
    };

    public static readonly IReadOnlyList<string> CaepEvents = Catalog.Values.Where(value => value.StartsWith(Caep, StringComparison.Ordinal)).ToList();
    public static readonly IReadOnlyList<string> RiscEvents = Catalog.Values.Where(value => value.StartsWith(Risc, StringComparison.Ordinal)).ToList();

    public static readonly string[] DefaultRequested =
    {
        Catalog["session_revoked"], Catalog["credential_change"], Catalog["assurance_level_change"],
        Catalog["token_claims_change"], Catalog["account_disabled"], Catalog["account_enabled"],
        Catalog["account_purged"], Catalog["credential_compromise"], Catalog["sessions_revoked"],
        Catalog["account_credential_change_required"],
    };

    public static readonly string[] DefaultEnding =
    {
        Catalog["session_revoked"], Catalog["account_disabled"], Catalog["account_purged"],
        Catalog["credential_compromise"], Catalog["sessions_revoked"],
    };

    public static Dictionary<string, string> SubjectOf(object? subId, string issuer)
    {
        if (subId is not Dictionary<string, object?> item) return new Dictionary<string, string>();
        var fmt = Str(item, "format");
        if (fmt == "") fmt = Str(item, "subject_type");
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (fmt == "complex" || (fmt == "" && (item.ContainsKey("user") || item.ContainsKey("session"))))
        {
            var user = Simple(item.GetValueOrDefault("user"), issuer);
            var session = Simple(item.GetValueOrDefault("session"), issuer);
            if (user.GetValueOrDefault("sub") is { Length: > 0 } person) result["person"] = person;
            if (user.GetValueOrDefault("email") is { Length: > 0 } email) result["email"] = email;
            var sessionId = session.GetValueOrDefault("opaque");
            if (string.IsNullOrEmpty(sessionId)) sessionId = session.GetValueOrDefault("sub");
            if (!string.IsNullOrEmpty(sessionId)) result["idp_session"] = sessionId!;
            return result;
        }
        var one = Simple(item, issuer);
        if (one.GetValueOrDefault("sub") is { Length: > 0 } sub) result["person"] = sub;
        if (one.GetValueOrDefault("email") is { Length: > 0 } mail) result["email"] = mail;
        return result;
    }

    static Dictionary<string, string> Simple(object? identifier, string issuer)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (identifier is not Dictionary<string, object?> item) return result;
        var fmt = Str(item, "format");
        if (fmt == "") fmt = Str(item, "subject_type");
        switch (fmt)
        {
            case "iss_sub":
                if (item.GetValueOrDefault("sub") is string sub && (item.GetValueOrDefault("iss") == null || Equals(item["iss"], issuer)))
                    result["sub"] = sub;
                break;
            case "email":
                if (item.GetValueOrDefault("email") is string email) result["email"] = email;
                break;
            case "opaque":
                if (item.GetValueOrDefault("id") is string id) result["opaque"] = id;
                break;
            case "aliases":
                if (item.GetValueOrDefault("identifiers") is List<object?> list)
                    foreach (var child in list)
                        foreach (var pair in Simple(child, issuer)) result[pair.Key] = pair.Value;
                break;
        }
        return result;
    }

    static string Str(Dictionary<string, object?> item, string key) => item.GetValueOrDefault(key) as string ?? "";
}

public sealed class Session
{
    public string LocalId { get; set; } = "";
    public string Person { get; set; } = "";
    public string Email { get; set; } = "";
    public string IdPSession { get; set; } = "";
    public DateTimeOffset? ExpiresAt { get; set; }
}

public sealed class MemorySessionIndex
{
    readonly object _gate = new();
    readonly Dictionary<string, Session> _sessions = new();
    readonly int _max;
    static readonly string[] MailAttributes =
    {
        "urn:oid:0.9.2342.19200300.100.1.3", "mail", "email",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    };

    public MemorySessionIndex(int maxEntries = 0) { _max = maxEntries <= 0 ? 100000 : maxEntries; }

    public void Add(Session session)
    {
        lock (_gate)
        {
            if (_sessions.Count >= _max && !_sessions.ContainsKey(session.LocalId))
            {
                var now = DateTimeOffset.UtcNow;
                foreach (var key in _sessions.Where(pair => pair.Value.ExpiresAt != null && pair.Value.ExpiresAt <= now).Select(pair => pair.Key).ToList())
                    _sessions.Remove(key);
                while (_sessions.Count >= _max)
                {
                    var first = _sessions.Keys.First();
                    _sessions.Remove(first);
                }
            }
            if (session.Email != "") session.Email = session.Email.ToLowerInvariant();
            _sessions[session.LocalId] = session;
        }
    }

    public void Remove(string localId) { lock (_gate) _sessions.Remove(localId); }

    public List<string> ByPerson(string person) => Find(session => session.Person == person);
    public List<string> ByEmail(string email)
    {
        var wanted = email.ToLowerInvariant();
        return Find(session => session.Email == wanted);
    }
    public List<string> ByIdPSession(string idpSession) => Find(session => session.IdPSession == idpSession);

    List<string> Find(Func<Session, bool> match)
    {
        lock (_gate)
        {
            var now = DateTimeOffset.UtcNow;
            var list = new List<string>();
            foreach (var pair in _sessions.ToList())
            {
                if (pair.Value.ExpiresAt != null && pair.Value.ExpiresAt <= now)
                {
                    _sessions.Remove(pair.Key);
                    continue;
                }
                if (match(pair.Value)) list.Add(pair.Key);
            }
            return list;
        }
    }

    public static Session TrackedFrom(string localId, Login? login, string? subjectAttribute, DateTimeOffset? expiresAt)
    {
        if (string.IsNullOrEmpty(subjectAttribute)) subjectAttribute = Names.DefaultSubjectAttribute;
        var person = "";
        if (login?.Attributes != null && login.Attributes.TryGetValue(subjectAttribute, out var people) && people.Count > 0)
            person = people[0];
        var email = "";
        if (login?.Attributes != null)
        {
            foreach (var name in MailAttributes)
            {
                if (login.Attributes.TryGetValue(name, out var values) && values.Count > 0 && values[0] != "")
                {
                    email = values[0];
                    break;
                }
            }
        }
        if (email == "" && login?.NameIdFormat == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress") email = login.NameId;
        return new Session
        {
            LocalId = localId,
            Person = person,
            Email = email,
            IdPSession = login?.SessionIndex ?? "",
            ExpiresAt = expiresAt ?? login?.SessionNotOnOrAfter,
        };
    }
}

public interface ISignalsLog
{
    void Info(string message);
    void Warn(string message);
    void Error(string message);
}

public sealed class SignalEvent
{
    public string Type { get; set; } = "";
    public object? Payload { get; set; }
    public Dictionary<string, string> Subject { get; set; } = new();
    public string Jti { get; set; } = "";
    public List<string> Sessions { get; set; } = new();
    public bool Ended { get; set; }
    public double? Iat { get; set; }
    public string? Txn { get; set; }
}

public delegate void EndSessions(IReadOnlyList<string> ids, SignalEvent evt);
public delegate void SignalHandler(SignalEvent evt);

public sealed class ReceiverOptions
{
    public string? Ca { get; set; }
    public string? Cert { get; set; }
    public string? Key { get; set; }
    public Func<Dictionary<string, string>>? Headers { get; set; }
    public IReadOnlyList<string>? EventsRequested { get; set; }
    public IReadOnlyList<string>? EndOn { get; set; }
    public MemorySessionIndex? Index { get; set; }
    public string SubjectAttribute { get; set; } = "";
    public string Description { get; set; } = "";
    public int PollIntervalMs { get; set; }
    public int MaxEvents { get; set; }
    public ISignalsLog? Log { get; set; }
}

public static class Jws
{
    static readonly Regex B64Url = new("^[A-Za-z0-9_-]*$", RegexOptions.Compiled);
    static readonly string[] Supported = { "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "Ed25519" };

    public static (Dictionary<string, object?> header, Dictionary<string, object?> payload) Verify(string token, IReadOnlyList<Dictionary<string, object?>> keys)
    {
        var parts = token.Split('.');
        if (parts.Length != 3) throw new WsFedException("signature", "the SET is not a compact JWS");
        var headerRaw = B64(parts[0], "header");
        var payloadRaw = B64(parts[1], "payload");
        Dictionary<string, object?> header;
        Dictionary<string, object?> payload;
        try
        {
            header = JsonMaps.ParseObject(headerRaw);
            payload = JsonMaps.ParseObject(payloadRaw);
        }
        catch (Exception ex) { throw new WsFedException("signature", "the SET's header or payload is not JSON", ex); }
        var alg = header.GetValueOrDefault("alg") as string ?? "";
        if (!Supported.Contains(alg))
        {
            var shown = alg == "" ? "(no alg)" : alg;
            throw new WsFedException("signature", "the SET is signed with " + shown + ", which this receiver does not verify (" + string.Join(", ", Supported) + ")");
        }
        if (header.ContainsKey("crit"))
            throw new WsFedException("signature", "the SET's header has a crit member this receiver does not understand");
        var kid = header.GetValueOrDefault("kid") as string ?? "";
        var kty = alg.StartsWith('E') && alg != "EdDSA" && alg != "Ed25519" ? "EC" : alg is "EdDSA" or "Ed25519" ? "OKP" : "RSA";
        var candidates = new List<Dictionary<string, object?>>();
        foreach (var key in keys)
        {
            if (kid != "" && (key.GetValueOrDefault("kid") as string ?? "") != kid) continue;
            if ((key.GetValueOrDefault("kty") as string ?? "") != kty) continue;
            var use = key.GetValueOrDefault("use") as string ?? "";
            if (use != "" && use != "sig") continue;
            var keyAlg = key.GetValueOrDefault("alg") as string ?? "";
            if (keyAlg != "" && keyAlg != alg) continue;
            candidates.Add(key);
        }
        if (candidates.Count == 0)
        {
            var suffix = kid == "" ? "" : " with kid " + kid;
            throw new WsFedException("signature", "the transmitter publishes no " + kty + " signing key" + suffix);
        }
        var data = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        var signature = B64(parts[2], "signature");
        foreach (var jwk in candidates)
        {
            if (VerifyOne(jwk, alg, data, signature)) return (header, payload);
        }
        throw new WsFedException("signature", "the SET's signature does not verify against the transmitter's keys");
    }

    static bool VerifyOne(Dictionary<string, object?> jwk, string alg, byte[] data, byte[] signature)
    {
        try
        {
            if (alg.StartsWith("RS") || alg.StartsWith("PS"))
            {
                using var rsa = RSA.Create();
                rsa.ImportParameters(new RSAParameters
                {
                    Modulus = B64(jwk.GetValueOrDefault("n") as string ?? "", "key"),
                    Exponent = B64(jwk.GetValueOrDefault("e") as string ?? "", "key"),
                });
                var hash = alg.EndsWith("384") ? HashAlgorithmName.SHA384 : alg.EndsWith("512") ? HashAlgorithmName.SHA512 : HashAlgorithmName.SHA256;
                var padding = alg.StartsWith("PS") ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
                return rsa.VerifyData(data, signature, hash, padding);
            }
            return false;
        }
        catch { return false; }
    }

    static byte[] B64(string value, string what)
    {
        if (!B64Url.IsMatch(value)) throw new WsFedException("signature", "the SET's " + what + " is not base64url");
        var pad = value.Length % 4 == 0 ? "" : new string('=', 4 - (value.Length % 4));
        try { return Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + pad); }
        catch (Exception ex) { throw new WsFedException("signature", "the SET's " + what + " is not base64url", ex); }
    }
}

public sealed class SignalsReceiver
{
    const string PollMethod = "urn:ietf:rfc:8936";
    public string Transmitter { get; }
    readonly EndSessions _onEnd;
    readonly TlsMaterial? _tls;
    readonly Func<Dictionary<string, string>>? _headers;
    readonly List<string> _eventsRequested;
    readonly List<string> _endOn;
    readonly MemorySessionIndex _index;
    readonly string _subjectAttribute;
    readonly string _description;
    readonly int _pollIntervalMs;
    readonly int _maxEvents;
    readonly ISignalsLog _log;
    readonly object _gate = new();
    readonly object _pollGate = new();
    Dictionary<string, object?>? _config;
    Dictionary<string, object?>? _stream;
    List<Dictionary<string, object?>> _keys = new();
    DateTimeOffset _keysAt;
    bool _running;
    List<string> _ack = new();
    Dictionary<string, Dictionary<string, string>> _errs = new();
    readonly Dictionary<string, List<SignalHandler>> _handlers = new();
    Flight? _inflight;
    CancellationTokenSource? _stop;
    Task? _loop;

    sealed class Flight
    {
        public ManualResetEventSlim Done { get; } = new(false);
        public bool Result;
        public Exception? Error;
    }

    public SignalsReceiver(string transmitter, EndSessions onEnd, ReceiverOptions? opts = null)
    {
        if (onEnd == null) throw new WsFedException("config", "onEndSessions is required");
        if (!(transmitter.StartsWith("http://", StringComparison.Ordinal) || transmitter.StartsWith("https://", StringComparison.Ordinal)))
            throw new WsFedException("config", "transmitter must be an http(s) URL");
        opts ??= new ReceiverOptions();
        Transmitter = transmitter.TrimEnd('/');
        _onEnd = onEnd;
        if (opts.Ca != null || opts.Cert != null || opts.Key != null)
            _tls = new TlsMaterial { Ca = opts.Ca, Cert = opts.Cert, Key = opts.Key };
        _headers = opts.Headers;
        _eventsRequested = (opts.EventsRequested ?? Events.DefaultRequested).ToList();
        _endOn = (opts.EndOn ?? Events.DefaultEnding).ToList();
        _index = opts.Index ?? new MemorySessionIndex();
        _subjectAttribute = opts.SubjectAttribute;
        _description = opts.Description;
        _pollIntervalMs = opts.PollIntervalMs == 0 ? 5000 : opts.PollIntervalMs;
        _maxEvents = opts.MaxEvents == 0 ? 50 : opts.MaxEvents;
        _log = opts.Log ?? new ConsoleLog();
    }

    public Dictionary<string, object?>? Stream { get { lock (_gate) return _stream; } }

    public void Track(string localId, Login? login, DateTimeOffset? expiresAt = null) =>
        _index.Add(MemorySessionIndex.TrackedFrom(localId, login, _subjectAttribute, expiresAt));

    public void Untrack(string localId) => _index.Remove(localId);

    public SignalsReceiver On(string eventType, SignalHandler handler)
    {
        lock (_gate)
        {
            if (!_handlers.TryGetValue(eventType, out var list))
            {
                list = new List<SignalHandler>();
                _handlers[eventType] = list;
            }
            list.Add(handler);
        }
        return this;
    }

    public void Start()
    {
        lock (_gate) { if (_running) return; }
        var config = Discover();
        lock (_gate) _config = config;
        Jwks(true);
        var stream = EnsureStream();
        var delivery = stream.GetValueOrDefault("delivery") as Dictionary<string, object?>;
        if (Str(delivery, "endpoint_url") == "") throw new WsFedException("ssf", "the stream has no poll endpoint_url");
        lock (_gate)
        {
            _stream = stream;
            if (_running) return;
            _running = true;
            _stop = new CancellationTokenSource();
            var token = _stop.Token;
            var delivered = stream.GetValueOrDefault("events_delivered") as List<object?>;
            _log.Info("ssf: polling stream " + Str(stream, "stream_id") + " at " + Str(delivery, "endpoint_url") + ", delivering " + (delivered?.Count ?? 0) + " event type(s)");
            _loop = Task.Run(() => Loop(token));
        }
    }

    public void Stop()
    {
        Task? loop;
        lock (_gate)
        {
            _running = false;
            _stop?.Cancel();
            loop = _loop;
        }
        try { loop?.Wait(TimeSpan.FromSeconds(20)); } catch (AggregateException) { }
    }

    void Loop(CancellationToken token)
    {
        try
        {
            while (true)
            {
                bool running;
                lock (_gate) running = _running;
                if (!running || token.IsCancellationRequested) return;
                var delay = _pollIntervalMs;
                try
                {
                    if (PollOnce()) delay = 0;
                }
                catch (Exception ex)
                {
                    _log.Warn("ssf: poll failed: " + ex.Message);
                    delay = Math.Min(_pollIntervalMs * 4, 60000);
                }
                if (token.WaitHandle.WaitOne(delay)) return;
                lock (_gate) running = _running;
                if (!running) return;
            }
        }
        finally { }
    }

    public bool PollOnce()
    {
        Flight current;
        var owner = false;
        lock (_pollGate)
        {
            if (_inflight != null) current = _inflight;
            else
            {
                current = new Flight();
                _inflight = current;
                owner = true;
            }
        }
        if (!owner)
        {
            current.Done.Wait();
            if (current.Error != null) throw current.Error;
            return current.Result;
        }
        try { current.Result = PollNow(); }
        catch (Exception ex) { current.Error = ex; }
        finally
        {
            lock (_pollGate) { if (_inflight == current) _inflight = null; }
            current.Done.Set();
        }
        if (current.Error != null) throw current.Error;
        return current.Result;
    }

    bool PollNow()
    {
        Dictionary<string, object?>? delivery;
        string rawUrl;
        List<string> ack;
        Dictionary<string, Dictionary<string, string>> setErrs;
        lock (_gate)
        {
            delivery = _stream?.GetValueOrDefault("delivery") as Dictionary<string, object?>;
            rawUrl = Str(delivery, "endpoint_url");
            ack = _ack.ToList();
            _ack = new List<string>();
            setErrs = _errs;
            _errs = new Dictionary<string, Dictionary<string, string>>();
        }
        var body = new Dictionary<string, object?> { ["maxEvents"] = _maxEvents, ["returnImmediately"] = true };
        if (ack.Count > 0) body["ack"] = ack;
        if (setErrs.Count > 0) body["setErrs"] = setErrs;
        int status;
        object? parsed;
        try { (status, parsed) = Call("POST", rawUrl, body); }
        catch
        {
            Restore(ack, setErrs);
            throw;
        }
        if (status != 200)
        {
            Restore(ack, setErrs);
            var text = JsonSerializer.Serialize(parsed);
            if (text.Length > 300) text = text[..300];
            throw new WsFedException("ssf", "the poll answered " + status + ": " + text);
        }
        var payload = parsed as Dictionary<string, object?> ?? new Dictionary<string, object?>();
        if (payload.GetValueOrDefault("sets") is Dictionary<string, object?> sets)
        {
            foreach (var pair in sets)
            {
                var text = pair.Value as string ?? "";
                try { Handle(pair.Key, text); }
                catch (Exception ex)
                {
                    _log.Warn("ssf: SET " + pair.Key + " refused: " + ex.Message);
                    var code = ex is WsFedException ws && ws.Code == "signature" ? "invalid_key" : "invalid_request";
                    lock (_gate) _errs[pair.Key] = new Dictionary<string, string> { ["err"] = code, ["description"] = ex.Message };
                    continue;
                }
                lock (_gate) _ack.Add(pair.Key);
            }
        }
        return payload.GetValueOrDefault("moreAvailable") is true;
    }

    void Restore(List<string> ack, Dictionary<string, Dictionary<string, string>> setErrs)
    {
        lock (_gate)
        {
            ack.AddRange(_ack);
            _ack = ack;
            foreach (var pair in _errs) setErrs[pair.Key] = pair.Value;
            _errs = setErrs;
        }
    }

    void Handle(string jti, string token)
    {
        var keys = Jwks(false);
        Dictionary<string, object?> header;
        Dictionary<string, object?> payload;
        try { (header, payload) = Jws.Verify(token, keys); }
        catch (Exception ex)
        {
            var message = ex.Message;
            if (message.Contains("publishes no") || message.Contains("does not verify"))
            {
                keys = Jwks(true);
                (header, payload) = Jws.Verify(token, keys);
            }
            else throw;
        }
        if (header.TryGetValue("typ", out var typ) && typ != null && !string.Equals(typ.ToString(), "secevent+jwt", StringComparison.OrdinalIgnoreCase))
            throw new WsFedException("validation", "the SET's typ is " + typ);
        string issuer;
        Dictionary<string, object?>? stream;
        lock (_gate)
        {
            issuer = Str(_config, "issuer");
            stream = _stream;
        }
        if ((payload.GetValueOrDefault("iss") as string ?? "") != issuer)
            throw new WsFedException("validation", "the SET was issued by " + payload.GetValueOrDefault("iss") + ", not " + issuer);
        var wantList = Strings(stream?.GetValueOrDefault("aud"));
        var audList = Strings(payload.GetValueOrDefault("aud"));
        if (wantList.Count > 0 && !audList.Any(item => wantList.Contains(item)))
            throw new WsFedException("validation", "the SET is for " + string.Join(", ", audList) + ", not this stream");
        if (payload.GetValueOrDefault("jti") != null && (payload["jti"] as string ?? "") != jti)
            throw new WsFedException("validation", "the SET's jti is not the one it was delivered under");
        if (payload.GetValueOrDefault("events") is not Dictionary<string, object?> events || events.Count == 0)
            throw new WsFedException("validation", "the SET carries no events");
        foreach (var pair in events)
        {
            object? sub = payload.GetValueOrDefault("sub_id");
            if (sub == null && pair.Value is Dictionary<string, object?> bodyMap) sub = bodyMap.GetValueOrDefault("subject");
            var subject = Events.SubjectOf(sub, issuer);
            var sessions = SessionsFor(pair.Key, subject);
            var ends = _endOn.Contains(pair.Key) && sessions.Count > 0;
            var evt = new SignalEvent { Type = pair.Key, Payload = pair.Value, Subject = subject, Jti = jti, Sessions = sessions, Ended = ends };
            if (payload.GetValueOrDefault("iat") is double d) evt.Iat = d;
            else if (payload.GetValueOrDefault("iat") is long n) evt.Iat = n;
            if (payload.GetValueOrDefault("txn") is string txn) evt.Txn = txn;
            if (ends)
            {
                try { _onEnd(sessions, evt); }
                catch (Exception ex)
                {
                    _log.Error("ssf: onEndSessions threw for " + pair.Key + " (SET " + jti + " is still acknowledged): " + ex.Message);
                    evt.Ended = false;
                }
                if (evt.Ended)
                    foreach (var localId in sessions) _index.Remove(localId);
            }
            List<SignalHandler> handlers;
            lock (_gate)
            {
                handlers = new List<SignalHandler>();
                if (_handlers.TryGetValue(pair.Key, out var typed)) handlers.AddRange(typed);
                if (_handlers.TryGetValue("*", out var star)) handlers.AddRange(star);
            }
            foreach (var handler in handlers)
            {
                try { handler(evt); }
                catch (Exception ex)
                {
                    _log.Error("ssf: a handler for " + pair.Key + " threw (SET " + jti + " is still acknowledged): " + ex.Message);
                }
            }
        }
    }

    List<string> SessionsFor(string eventType, Dictionary<string, string> subject)
    {
        if (eventType == Events.Catalog["verification"] || eventType == Events.Catalog["stream_updated"]) return new List<string>();
        if (subject.TryGetValue("idp_session", out var idp) && idp != "")
        {
            var found = _index.ByIdPSession(idp);
            if (found.Count > 0 || eventType == Events.Catalog["session_revoked"]) return found;
        }
        if (subject.TryGetValue("person", out var person) && person != "") return _index.ByPerson(person);
        if (subject.TryGetValue("email", out var email) && email != "") return _index.ByEmail(email);
        return new List<string>();
    }

    Dictionary<string, object?> Discover()
    {
        var rawUrl = Transmitter + "/.well-known/ssf-configuration";
        var (status, parsed) = Call("GET", rawUrl, null);
        var config = parsed as Dictionary<string, object?>;
        if (status != 200 || config == null || Str(config, "configuration_endpoint") == "" || Str(config, "jwks_uri") == "")
            throw new WsFedException("ssf", rawUrl + " answered " + status + " without a usable transmitter configuration");
        if (config.GetValueOrDefault("delivery_methods_supported") is List<object?> supported && !supported.Contains(PollMethod))
            throw new WsFedException("ssf", "the transmitter does not offer poll delivery (RFC 8936)");
        return config;
    }

    List<Dictionary<string, object?>> Jwks(bool force)
    {
        lock (_gate)
        {
            if (!force && _keys.Count > 0 && DateTimeOffset.UtcNow - _keysAt < TimeSpan.FromHours(1)) return _keys;
        }
        string uri;
        lock (_gate) uri = Str(_config, "jwks_uri");
        var (status, parsed) = Call("GET", uri, null);
        var body = parsed as Dictionary<string, object?>;
        var keys = new List<Dictionary<string, object?>>();
        if (body?.GetValueOrDefault("keys") is List<object?> list)
            foreach (var item in list)
                if (item is Dictionary<string, object?> key) keys.Add(key);
        if (status != 200 || (body == null || !body.ContainsKey("keys")) && keys.Count == 0 && body?.ContainsKey("keys") != true)
        {
            if (status != 200 || body == null || !body.ContainsKey("keys"))
                throw new WsFedException("ssf", "the transmitter's JWKS answered " + status);
        }
        lock (_gate)
        {
            _keys = keys;
            _keysAt = DateTimeOffset.UtcNow;
        }
        return keys;
    }

    Dictionary<string, object?> EnsureStream()
    {
        var endpoint = "";
        lock (_gate) endpoint = Str(_config, "configuration_endpoint");
        var (status, parsed) = Call("GET", endpoint, null);
        if (status == 200)
        {
            var all = parsed switch
            {
                List<object?> list => list,
                Dictionary<string, object?> one => new List<object?> { one },
                _ => new List<object?>(),
            };
            foreach (var item in all)
            {
                if (item is not Dictionary<string, object?> stream || Str(stream, "stream_id") == "") continue;
                var delivery = stream.GetValueOrDefault("delivery") as Dictionary<string, object?>;
                if (Str(delivery, "method") == PollMethod) return stream;
            }
        }
        else if (status != 404)
        {
            var text = JsonSerializer.Serialize(parsed);
            if (text.Length > 300) text = text[..300];
            throw new WsFedException("ssf", "listing the streams at " + endpoint + " answered " + status + ": " + text);
        }
        var body = new Dictionary<string, object?>
        {
            ["delivery"] = new Dictionary<string, object?> { ["method"] = PollMethod },
            ["events_requested"] = _eventsRequested,
        };
        if (_description != "") body["description"] = _description;
        (status, parsed) = Call("POST", endpoint, body);
        var created = parsed as Dictionary<string, object?>;
        if ((status != 200 && status != 201) || created == null || Str(created, "stream_id") == "")
        {
            var text = JsonSerializer.Serialize(parsed);
            if (text.Length > 300) text = text[..300];
            throw new WsFedException("ssf", "creating a stream at " + endpoint + " answered " + status + ": " + text);
        }
        return created;
    }

    (int status, object? parsed) Call(string method, string rawUrl, object? body)
    {
        var headers = new Dictionary<string, string> { ["accept"] = "application/json" };
        if (_headers != null)
            foreach (var pair in _headers()) headers[pair.Key] = pair.Value;
        string? payload = null;
        if (body != null)
        {
            payload = JsonSerializer.Serialize(body);
            headers["content-type"] = "application/json";
        }
        var answer = HttpSend.Send(rawUrl, method, headers, payload, _tls, "ssf");
        object? parsed = null;
        if (answer.Body != "")
        {
            try
            {
                using var doc = JsonDocument.Parse(answer.Body);
                parsed = JsonMaps.FromElement(doc.RootElement);
            }
            catch { parsed = answer.Body; }
        }
        return (answer.Status, parsed);
    }

    static string Str(Dictionary<string, object?>? map, string key) => map?.GetValueOrDefault(key) as string ?? "";

    static List<string> Strings(object? value) => value switch
    {
        null => new List<string>(),
        string text when text != "" => new List<string> { text },
        string => new List<string>(),
        List<object?> list => list.Select(item => item?.ToString() ?? "").ToList(),
        _ => new List<string> { value.ToString() ?? "" },
    };

    sealed class ConsoleLog : ISignalsLog
    {
        public void Info(string message) => Console.WriteLine(message);
        public void Warn(string message) => Console.Error.WriteLine(message);
        public void Error(string message) => Console.Error.WriteLine(message);
    }
}
