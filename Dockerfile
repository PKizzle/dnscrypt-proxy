FROM --platform=$BUILDPLATFORM cgr.dev/chainguard/go as build

WORKDIR /src

COPY --chown=nonroot:nonroot dnscrypt-proxy ./dnscrypt-proxy
COPY --chown=nonroot:nonroot vendor ./vendor
COPY --chown=nonroot:nonroot go.mod .
COPY --chown=nonroot:nonroot go.sum .

WORKDIR /src/dnscrypt-proxy

ARG TARGETOS TARGETARCH TARGETVARIANT

ARG CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH

RUN --mount=type=cache,target=/home/nonroot/.cache/go-build,uid=65532,gid=65532 \
    --mount=type=cache,target=/go/pkg \
    GOARM="${TARGETVARIANT//v}" go build -v -ldflags="-s -w" -mod vendor

WORKDIR /config

RUN cp -a /src/dnscrypt-proxy/example-* ./

COPY dnscrypt-proxy.toml ./

# ----------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM cgr.dev/chainguard/go as probe

WORKDIR /src/dnsprobe

ARG TARGETOS TARGETARCH TARGETVARIANT

ARG CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH

COPY dnsprobe/ ./

RUN GOARM="${TARGETVARIANT//v}" go build -o /usr/local/bin/dnsprobe .

# ----------------------------------------------------------------------------
# hadolint ignore=DL3007
FROM cgr.dev/chainguard/static

COPY --from=build /src/dnscrypt-proxy/dnscrypt-proxy /usr/local/bin/
COPY --from=probe /usr/local/bin/dnsprobe /usr/local/bin/
COPY --from=build --chown=nonroot:65532 /config /config

USER nonroot

ENTRYPOINT [ "dnscrypt-proxy" ]

CMD [ "-config", "/config/dnscrypt-proxy.toml" ]
