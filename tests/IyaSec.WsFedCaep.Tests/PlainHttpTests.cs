// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Net;
using System.Net.Sockets;
using System.Text;
using Xunit;

namespace IyaSec.WsFed.Tests;

// Plain http is refused for every fetch (federation metadata, the Shared
// Signals transmitter) unless the host is loopback, before any connection is
// opened, and the refusal names only the scheme and host.
public class PlainHttpTests
{
    const string Refused = "is refused: plain http is allowed only to a loopback host";

    sealed class Quiet : ISignalsLog
    {
        public void Info(string message) { }
        public void Warn(string message) { }
        public void Error(string message) { }
    }

    // A loopback stub: /md answers the stub IdP's metadata, /away a 302 to
    // http://example.com/md, anything else 404. It counts every request.
    sealed class Stub : IDisposable
    {
        readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        readonly string _metadata = StubIdp.IdPMetadata();
        int _hits;
        public int Port { get; }
        public int Hits => Volatile.Read(ref _hits);

        public Stub()
        {
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            new Thread(Loop) { IsBackground = true }.Start();
        }

        void Loop()
        {
            while (true)
            {
                TcpClient client;
                try { client = _listener.AcceptTcpClient(); }
                catch { return; }
                Interlocked.Increment(ref _hits);
                using (client)
                {
                    try { Answer(client.GetStream()); }
                    catch { }
                }
            }
        }

        void Answer(NetworkStream stream)
        {
            var head = new List<byte>();
            while (head.Count < 65536)
            {
                var b = stream.ReadByte();
                if (b < 0) break;
                head.Add((byte)b);
                var n = head.Count;
                if (n >= 4 && head[n - 4] == '\r' && head[n - 3] == '\n' && head[n - 2] == '\r' && head[n - 1] == '\n') break;
            }
            var line = Encoding.ASCII.GetString(head.ToArray()).Split("\r\n")[0];
            var parts = line.Split(' ');
            var path = parts.Length > 1 ? parts[1].Split('?')[0] : "";
            string reply = path switch
            {
                "/md" => "HTTP/1.1 200 OK\r\ncontent-type: application/samlmetadata+xml\r\ncontent-length: " + Encoding.UTF8.GetByteCount(_metadata) + "\r\nconnection: close\r\n\r\n" + _metadata,
                "/away" => "HTTP/1.1 302 Found\r\nlocation: http://example.com/md\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                _ => "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            };
            var bytes = Encoding.UTF8.GetBytes(reply);
            stream.Write(bytes, 0, bytes.Length);
        }

        public void Dispose() => _listener.Stop();
    }

    static RelyingParty Party(string metadataUrl) => RelyingParty.Create(new Dictionary<string, object?>
    {
        ["realm"] = StubIdp.Realm,
        ["replyUrl"] = StubIdp.Reply,
        ["privateKey"] = StubIdp.RpKey,
        ["certificate"] = StubIdp.RpCert,
        ["idpMetadata"] = metadataUrl,
    }, Path.GetTempPath());

    static void Receiver(string transmitter)
    {
        var receiver = new SignalsReceiver(transmitter, (_, _) => { }, new ReceiverOptions { Log = new Quiet() });
        try { receiver.Start(); }
        finally { receiver.Stop(); }
    }

    static WsFedException RefusedAs(Action fn, string code, string shown)
    {
        var err = Assert.Throws<WsFedException>(fn);
        Assert.Equal(code, err.Code);
        Assert.StartsWith(shown + " " + Refused, err.Message);
        foreach (var part in new[] { "s3cret", "/md", "/ssf", "federationmetadata", "token=" })
            Assert.DoesNotContain(part, err.Message);
        return err;
    }

    static int ClosedPort()
    {
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        return port;
    }

    [Fact]
    public void PlainHttpMetadataOffLoopbackIsRefused() =>
        RefusedAs(() => Party("http://example.com/federationmetadata.xml?token=s3cret"), "metadata", "http://example.com");

    [Fact]
    public void PlainHttpTransmitterOffLoopbackIsRefused() =>
        RefusedAs(() => Receiver("http://example.com/ssf"), "ssf", "http://example.com");

    [Fact]
    public void RefusedBeforeConnecting()
    {
        // On Linux http://0.0.0.0:<port> reaches a listener on 127.0.0.1, so
        // an empty backlog on this listener shows no connection was opened.
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var plain = "http://0.0.0.0:" + ((IPEndPoint)listener.LocalEndpoint).Port;
            RefusedAs(() => Party(plain + "/md"), "metadata", plain);
            RefusedAs(() => Receiver(plain), "ssf", plain);
            Thread.Sleep(300);
            Assert.False(listener.Pending(), "a refused fetch opened a connection");
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public void UserinfoIsNeverLoopbackAndNeverShown()
    {
        using var stub = new Stub();
        var origin = "127.0.0.1:" + stub.Port;
        var err = RefusedAs(() => Party("http://alice:s3cret@" + origin + "/md"), "metadata", "http://" + origin);
        Assert.DoesNotContain("alice", err.Message);
        RefusedAs(() => Party("http://localhost:80@example.com/md"), "metadata", "http://example.com");
        RefusedAs(() => Receiver("http://alice:s3cret@" + origin + "/ssf"), "ssf", "http://" + origin);
        Assert.Equal(0, stub.Hits);
    }

    [Fact]
    public void WhitespaceAndControlCharactersAreRefused()
    {
        using var stub = new Stub();
        var origin = "http://127.0.0.1:" + stub.Port;
        foreach (var url in new[] { origin + " @example.com/md", origin + "/m\td", origin + "\0@example.com/md", "https://example.com/m\nd" })
        {
            var err = Assert.Throws<WsFedException>(() => Party(url));
            Assert.Equal("metadata", err.Code);
            Assert.Contains("whitespace or a control character", err.Message);
        }
        var ssf = Assert.Throws<WsFedException>(() => Receiver(origin + "/s sf"));
        Assert.Equal("ssf", ssf.Code);
        Assert.Equal(0, stub.Hits);
    }

    [Fact]
    public void ARedirectIsNotFollowed()
    {
        // Redirects are never followed, so a 302 to plain http off loopback is
        // the answer and example.com is never dialled.
        using var stub = new Stub();
        var err = Assert.Throws<WsFedException>(() => Party("http://127.0.0.1:" + stub.Port + "/away"));
        Assert.Equal("metadata", err.Code);
        Assert.Contains("answered HTTP 302", err.Message);
    }

    [Fact]
    public void PlainHttpToLoopbackStillWorks()
    {
        using var stub = new Stub();
        foreach (var host in new[] { "127.0.0.1", "localhost" })
        {
            Assert.Equal(StubIdp.IdPEntity, Party("http://" + host + ":" + stub.Port + "/md").Idp!.EntityId);
            var before = stub.Hits;
            var err = Assert.Throws<WsFedException>(() => Receiver("http://" + host + ":" + stub.Port + "/ssf"));
            Assert.Equal("ssf", err.Code);
            Assert.DoesNotContain(Refused, err.Message);
            Assert.True(stub.Hits > before, "the transmitter on " + host + " was not reached");
        }
        // Other loopback forms are not refused: a closed port fails to connect.
        var closed = ClosedPort();
        foreach (var origin in new[] { "http://127.200.0.9:" + closed, "http://[::1]:" + closed, "http://LOCALHOST:" + closed })
        {
            var err = Assert.Throws<WsFedException>(() => Party(origin + "/md"));
            Assert.DoesNotContain(Refused, err.Message);
        }
        RefusedAs(() => Party("http://127.0.0.1.example.com/md"), "metadata", "http://127.0.0.1.example.com");
    }

    [Fact]
    public void HttpsToAnUnreachableHostIsAConnectionError()
    {
        var https = "https://127.0.0.1:" + ClosedPort();
        foreach (var fn in new Action[] { () => Party(https + "/md"), () => Receiver(https) })
        {
            var err = Assert.Throws<WsFedException>(fn);
            Assert.DoesNotContain(Refused, err.Message);
            Assert.StartsWith(https, err.Message);
        }
    }
}
