# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
# `docker build --target test` runs the suite in this image.
# The demo image below does not run it.
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS test
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV DOTNET_NOLOGO=1
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN dotnet test --nologo

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV DOTNET_NOLOGO=1
WORKDIR /src
COPY src src
COPY demo/IyaSec.WsFed.Demo demo/IyaSec.WsFed.Demo
RUN dotnet publish demo/IyaSec.WsFed.Demo/IyaSec.WsFed.Demo.csproj -c Release -o /opt/demo --nologo \
 && dotnet publish src/IyaSec.WsFed.Cli/IyaSec.WsFed.Cli.csproj -c Release -o /opt/cli --nologo

FROM mcr.microsoft.com/dotnet/runtime:10.0
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /opt/demo /opt/demo
COPY --from=build /opt/cli /opt/cli
# demo/ comes after the build, so a new trust chain does not rebuild the binaries.
# .dockerignore admits one file of demo/generated: idp-ca.pem, the iya-sts TLS
# listener CA trust chain scripts/configure_iya_sts.py writes where idpCa names
# it. When the file exists this COPY puts it at /app/demo/generated/idp-ca.pem,
# so the image trusts that iya-sts with no mount and no fetch at start. When it
# does not (a fresh clone, CI) nothing from demo/generated is copied and the
# build still succeeds. Keys and metadata never enter the image.
COPY demo demo
COPY scripts scripts
COPY LICENSE README.md VERSION ./
ENV PATH="/opt/cli:${PATH}"
ENV DOTNET_ROOT=/usr/share/dotnet
ENV PORT=3000
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s \
  CMD curl -fsS "http://127.0.0.1:${PORT}/healthz" || exit 1
CMD ["/opt/demo/wsfed-demo"]
