# DnSpySql - Copyright (C) 2026 Rakan Alduwaysan. GPL-3.0-only with additional terms: see LICENSE and NOTICE.
# dnspysql: SQL over .NET assemblies, as a sandbox-friendly image.
#   docker build -t dnspysql .
#   docker run --rm --network none -v "$PWD:/samples:ro" dnspysql /samples/app.dll -c "SELECT count(*) FROM types"
# Build context: the repository with its submodules checked out (git submodule update --init, and the two nested
# dnSpyEx submodules listed in README.md).
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
RUN apt-get update && apt-get install -y --no-install-recommends cmake ninja-build g++ && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN rm -rf build && sh build.sh \
 && mkdir -p /out && cp -r build/dnspysql build/engine /out/

FROM mcr.microsoft.com/dotnet/runtime:8.0
COPY --from=build /out /opt/dnspysql
RUN useradd --uid 1000 --create-home dnspysql \
 && mkdir -p /samples /projects && chown dnspysql /projects
USER 1000
WORKDIR /projects
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_gcServer=0
EXPOSE 8081
ENTRYPOINT ["/opt/dnspysql/dnspysql"]
CMD ["--help"]
