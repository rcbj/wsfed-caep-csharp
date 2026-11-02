<!--
SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
SPDX-License-Identifier: MIT
-->

# wsfed-caep

C# port of the server-side WS-Federation relying party. Package `IyaSec.WsFedCaep`, namespace `IyaSec.WsFed`, target `net8.0`. Version 0.1.2. License MIT (`LICENSE`). A pull request merged into `main` publishes the package to nuget.org after the test workflow succeeds on that commit. A direct push does not. The key comes from nuget.org Trusted Publishing (`NuGet/login` trades the workflow's GitHub OIDC token for a one-hour API key); the `NUGET_USER` repository secret is the nuget.org profile name that owns the policy for this repository and `publish.yml`. A version already on nuget.org stays there; the next release is a new `Version` in the library's `.csproj`. When this tree is published, `develop` and `main` are the same commit.

## Usage

`RelyingParty.FromFile("wsfed.json", null)`, then `Login` and `HandleReply`. JSON keys are the Node keys. Public metadata is `MetadataXml()`.

The party accepts SAML 2.0 assertions with bearer confirmation `urn:oasis:names:tc:SAML:2.0:cm:bearer`. It reads IdP metadata, writes RP metadata, verifies XML signatures (rsa-sha256 is `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`), decrypts encrypted elements, and caches assertion ids. Status success is `urn:oasis:names:tc:SAML:2.0:status:Success`. The default subject attribute is `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier`. `wsfed-caep generate-keys` writes a self-signed RSA key pair. The subject key identifier is the SHA-1 of the PKCS#1 public key.

## signals

Omitted or `true` means on. The resolved configuration leaves `SignalsSet` false in that case, which is the omitted key. `false` sets `SignalsSet` and `Signals` false. It does not start the receiver and does not require transmitter metadata. The relying party never starts the receiver itself; `SignalsReceiver` is separate. `Stop` waits until the background poll loop has finished. Sign-in does not change when signals are off, because WS-Federation does not send OAuth scopes. A non-boolean raises a config error: `signals must be true or false`. The shipped demo omits the key.

**Plain http (#18).** `HttpSend.Send` is the one place every fetch goes through (metadata URL, SSF configuration, JWKS, stream and poll). `RefusePlainHttpOffLoopback` parses with `System.Uri`, as `HttpClient` dials, and refuses plain `http://` to a host that is not loopback (`127.0.0.0/8`, `::1`, `localhost`) before connecting, without resolving a name, naming only the scheme and host[:port]; userinfo is never loopback, and `RefuseUnsafeCharacters` refuses whitespace and control characters first. Redirects are not followed (`AllowAutoRedirect = false`), so the checked URL is the only one dialled. No opt-out. `PlainHttpTests` covers it; `http://0.0.0.0:<port>` reaches a 127.0.0.1 listener on Linux, so an empty backlog proves no connection was opened.

## Tests

```bash
docker build --target test .
```

The `test` stage runs `dotnet test --nologo` in `mcr.microsoft.com/dotnet/sdk:8.0`. GitHub Actions uses that command. Do not run the .NET SDK on the host. The demo image does not run the suite.

The suite covers the stub IdP (a signed SAML assertion the library accepts), replay, metadata, the self-signed certificate, the SSF poll receiver, the setup script's signals behavior, the trust chain (`TrustChainTests`: the script writes all four certificates where `idpCa` points, and the library builds a leaf-only server chain through that file's intermediates, and refuses a certificate that chains to it but names another host), the demo handler, and `GET /live-status` (`LiveStatusTests`). No live iya-sts. XML signatures use `System.Security.Cryptography.Xml.SignedXml` with exclusive canonicalization and RSA-SHA256. This tree does not wrap another WS-Federation relying party.

### idpCa: the iya-sts TLS listener CA trust chain

`idpCa` (demo: `generated/idp-ca.pem`, relative to `demo/`) is the whole chain, not one certificate. `scripts/configure_iya_sts.py` writes it on every run through `save_trust_chain()` in `scripts/trust_chain.py` (`GET /tls/server-certificate`, else the handshake chain) and prints the path, the anchor's subject and SHA-256. `HttpSend.TrustStore` reads every PEM block; self-signed certificates go in the `CustomTrustStore`, the rest in the `ExtraStore`; no self-signed certificate means every one is an anchor. `HttpSend.Accept` also checks the name, because the custom callback replaces the platform's whole decision: a `RemoteCertificateNameMismatch`, or a host `MatchesHostname` rejects (no common-name fallback; an IP literal needs an IP SAN), is refused even when the chain builds. The demo Dockerfile copies `demo/` after the publish step and `.dockerignore` admits only `demo/generated/idp-ca.pem`, so the image carries the chain from build time and a build without it still succeeds. Rebuild after re-running the install script against a different iya-sts.

The install script never prints a generated test-user password: it writes it to `demo/generated/<user>.password` (created mode 0600) and prints only that path. No line it or the live script prints carries anything derived from a password or secret.

### Live sign-in and nightly

`python3 scripts/live_iya_sts.py` is the live half, on the host's Python. It starts a fresh iya-sts (main, memory mode, persistence and clustering off, no workers) unless `IYA_STS_URL` is set, or from `IYA_STS_IMAGE` when that is set. Order: copy the checkout to a scratch build context, rewrite that copy's `demo/wsfed.json` (ssf transmitter, `pollIntervalMs` 1000, loopback realm and reply; never `idpCa`), build the demo image, `wsfed-caep generate-keys` inside it, `python3 scripts/configure_iya_sts.py` on the host (standard library only, no `wsfed_caep` Python import, no .NET on the host), build again (the image now carries the chain), and run with only `rp.key`, `rp.crt` and `idp-metadata.xml` mounted. It checks that the image's chain is the one the script wrote. It signs in through `/authn-api`, emits credential-change and then session-revoked through `/admin-api/caep/emit`, and requires `GET /live-status` to show both, with `signedIn` false after the second. Secrets go to docker as `-e NAME`. Ports default to `LIVE_STS_PORT=18525` and `LIVE_DEMO_PORT=18625`; never 3000, 8081, or 18481 to 18495. Containers: `iya-sts-live-wsfed-caep-csharp`, `wsfed-caep-csharp-live-demo`. A second run against an already-registered relying party needs a fresh iya-sts.

`GET /live-status` is JSON: `signedIn`, `subject`, `receiver`, and `events` (`type` as the full CAEP URI, and `jti`). No tokens or assertions. iya-sts main sets the assertion SessionIndex to the assertion id, so a session-revoked event finds nobody in the index. `App.Remember` then ends the demo's one session and untracks it. That is demo code; the library is unchanged there.

`.github/workflows/nightly.yml` runs `docker build --target test .` and then `python3 scripts/live_iya_sts.py` at 07:38 UTC (`38 7 * * *`), and on `workflow_dispatch`. `tests.yml` has no schedule.

## Layout

`src/IyaSec.WsFedCaep/` library. `demo/` handler and `demo/IyaSec.WsFed.Demo`. `src/IyaSec.WsFed.Cli`. `scripts/configure_iya_sts.py` registers the demo with iya-sts and writes the `idpCa` chain; the container `PORT` wins over the shell `PORT`, and an explicit public URL wins over both. `scripts/live_iya_sts.py` is the live sign-in. `Dockerfile` builds in an SDK stage and runs on `dotnet/runtime:8.0`; and comment-free `docker-compose.yml` use `network_mode: host`, `ENV PORT=3000`, and a health check of `http://127.0.0.1:${PORT}/healthz`.

## Demo

`PORT` defaults to 3000. Loopback realm and reply URLs follow the running port. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `200` and `ok`. `GET /live-status` is described above. The page links to `/login`, which redirects with `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`. The reply URL handles the POST and sign-out cleanup. `POST /logout` signs out. Demo JSON uses `file:` placeholders. Do not commit `demo/generated`.
