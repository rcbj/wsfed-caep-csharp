# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
# `docker build --target test` runs the suite in this image.
# The demo image below does not run it.
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS test
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV DOTNET_NOLOGO=1
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN dotnet test --nologo

FROM mcr.microsoft.com/dotnet/sdk:8.0
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY . .
RUN dotnet publish demo/IyaSec.WsFed.Demo/IyaSec.WsFed.Demo.csproj -c Release -o /opt/demo --nologo \
 && dotnet publish src/IyaSec.WsFed.Cli/IyaSec.WsFed.Cli.csproj -c Release -o /opt/cli --nologo
ENV PATH="/opt/cli:${PATH}"
ENV PORT=3000
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s \
  CMD curl -fsS "http://127.0.0.1:${PORT}/healthz" || exit 1
CMD ["/opt/demo/wsfed-demo"]
