<!--
SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
SPDX-License-Identifier: MIT
-->

# wsfed-caep

Server-side WS-Federation relying party for C#. It accepts SAML 2.0 bearer assertions, reads identity-provider federation metadata, writes relying-party metadata, verifies XML signatures, decrypts encrypted assertions, and remembers assertion ids so a bearer token cannot be replayed. A Shared Signals poll receiver for CAEP and RISC is included. The relying party does not start that receiver.

Version 0.1.2. License: MIT. Package `IyaSec.WsFedCaep`, namespace `IyaSec.WsFed`, `net8.0`. A pull request merged into `main` publishes the package to nuget.org after the test workflow succeeds on that commit. A direct push does not. The key comes from nuget.org Trusted Publishing (`NuGet/login` trades the workflow's GitHub OIDC token for a one-hour API key); the `NUGET_USER` repository secret is the nuget.org profile name that owns the policy for this repository and `publish.yml`. A version already on nuget.org stays there; the next release is a new `Version` in the library's `.csproj`. `develop` and `main` are the same commit when this tree is published; nothing here creates a remote.

## Usage

```csharp
var party = RelyingParty.FromFile("wsfed.json", null);
var request = party.Login(new LoginOptions { RelayState = "/" });
var who = party.HandleReply(new ReplyRequest { Method = "POST", Url = "/wsfed", Body = body }, new[] { request.Id });
var metadata = party.MetadataXml();
```

JSON keys match the Node configuration: `realm`, `replyUrl`, `idpMetadata`, `privateKey`, `certificate`, `idpCa`, `idpEntityId`, `clockSkewSeconds`, `wantAssertionsEncrypted`, `allowUnsolicited`, `requestTokenType`, `signals`, `ssf`. `file:` and `env:` prefixes are accepted. The default subject attribute is `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier`.

`signals` omitted or `true` is on. The resolved configuration omits the key in that case (`SignalsSet` stays false). `false` is kept, does not start a receiver, and does not require transmitter metadata. Sign-in is unchanged either way: WS-Federation does not send OAuth scopes. Any other value raises a config error whose message is `signals must be true or false`.

```sh
docker compose build
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  wsfed-caep-csharp-demo \
  wsfed-caep generate-keys --config demo/wsfed.json
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  wsfed-caep-csharp-demo \
  wsfed-caep metadata --config demo/wsfed.json
```

The generated certificate's common name defaults to `wsfed-caep-nodejs relying party` plus the realm, cut at 64 characters.

## Tests

```bash
docker build --target test .
```

The suite runs in a container.

`dotnet test` covers the stub IdP (a signed SAML assertion the library accepts), replay, metadata, the self-signed certificate, the SSF poll receiver, the setup script's signals behavior, the setup script writing the whole trust chain where `idpCa` points, the library taking that file as its trust store (and refusing a chain from another root, or a certificate that chains to it but names another host), the demo handler, and `GET /live-status`. No live iya-sts.

## The iya-sts TLS trust chain (`idpCa`)

`idpCa` names the file that holds the iya-sts TLS listener CA trust chain; the demo's is `generated/idp-ca.pem` (relative to `demo/`). `scripts/configure_iya_sts.py`, the install script, writes it on every run: the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS issuing CA, intermediate, root), or the chain the TLS handshake presents when that path is missing. It prints the path, the trust anchor's subject and its SHA-256 fingerprint. `scripts/trust_chain.py --config demo/wsfed.json --idp https://host:port` refreshes the file by itself.

The install script never prints a generated test-user password: it writes it to `demo/generated/<user>.password` (created mode 0600) and prints only that path. No line it or the live script prints carries anything derived from a password or secret.

The library reads every certificate in that file. The self-signed ones are the trust anchors and the others are intermediates the server's chain may be built through; a file with no self-signed certificate trusts every certificate in it, as a one-certificate file always did. The metadata fetch and the Shared Signals receiver both use it. The server's certificate must also name the host in the URL: a DNS name must match a DNS SAN and an IP literal such as `127.0.0.1` an IP address SAN. A certificate that chains to the file but names another host is refused.

The demo image carries the file from build time: the Dockerfile copies `demo/` after the build, and `.dockerignore` admits only `demo/generated/idp-ca.pem` from `demo/generated` (no keys, no metadata). A build before the install script has run (a fresh clone, CI's `--target test`) copies nothing from `demo/generated` and still succeeds. Run the install script, then build the demo image; after running it against a different iya-sts, rebuild.

## Live sign-in

`python3 scripts/live_iya_sts.py` is the live half, on the host's Python. It starts a fresh iya-sts (main, memory mode, no persistence, no clustering) unless `IYA_STS_URL` is already set; `IYA_STS_IMAGE` starts one from an image you already have. It follows the install order: it copies the checkout to a scratch build context, points that copy's `demo/wsfed.json` at this iya-sts and demo port (leaving `idpCa` as written), builds the demo image, runs `wsfed-caep generate-keys` inside it, runs `scripts/configure_iya_sts.py` on the host (standard library only), which writes the trust chain where `idpCa` names it, builds the image again so it carries that chain, and runs it. It never fetches or mounts a CA for the demo; only the key pair and the IdP metadata are mounted. The .NET SDK never runs on the host. The script signs in through `/authn-api`, emits credential-change, then session-revoked, and requires `GET /live-status` to show both. That JSON is `signedIn`, `subject`, `receiver`, and `events` of `type` and `jti`. It has no tokens. session-revoked leaves `signedIn` false. The last thing it prints is JSON with `"ok": true`.

```sh
python3 scripts/live_iya_sts.py
IYA_STS_IMAGE=iya-sts-live:main LIVE_STS_PORT=18525 LIVE_DEMO_PORT=18625 python3 scripts/live_iya_sts.py
```

The defaults are 18525 for iya-sts and 18625 for the demo. Do not bind host ports 3000, 8081, or 18481 to 18495. The containers are `iya-sts-live-wsfed-caep-csharp` and `wsfed-caep-csharp-live-demo`, and the script removes both. Secrets reach `docker run` as `-e NAME`, never on the command line.

iya-sts main sets the WS-Federation assertion SessionIndex to the assertion id. The CAEP session-revoked subject names the sign-on session, so the index finds nobody. The demo ends its one session from the event handler (`App.Remember` in `demo/IyaSec.WsFed.Demo/App.cs`). That is demo code.

[`.github/workflows/nightly.yml`](.github/workflows/nightly.yml) runs `docker build --target test .` and then the live script at 07:38 UTC (`38 7 * * *`), and on `workflow_dispatch`. Push and pull-request CI stays in `tests.yml`.

## Layout

`src/IyaSec.WsFedCaep/` library. `demo/` HTTP handler. `src/IyaSec.WsFed.Cli/` command line. `scripts/configure_iya_sts.py` registers the demo with iya-sts and writes the `idpCa` trust chain; the container `PORT` wins over the shell `PORT`, and an explicit public URL wins over both. `scripts/trust_chain.py` fetches the chain. `scripts/live_iya_sts.py` is the live sign-in. `Dockerfile` and comment-free `docker-compose.yml` use `network_mode: host`, `ENV PORT=3000`, and a health check of `http://127.0.0.1:${PORT}/healthz`.

## Demo

`PORT` defaults to 3000. Loopback realm and reply URLs follow the running port. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `200` and `ok` before the identity provider is dialed. `GET /live-status` is described under Live sign-in. The page links to `/login`, which redirects with `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`. The reply URL handles the POST and sign-out cleanup. `POST /logout` signs out. Demo JSON uses `file:` placeholders and omits `signals`. Do not commit `demo/generated`.

```sh
docker compose up --build
```
