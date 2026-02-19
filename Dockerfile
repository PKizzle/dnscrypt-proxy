FROM --platform=$BUILDPLATFORM golang:1.26 AS build

WORKDIR /src

COPY --chown=65532:65532 dnscrypt-proxy ./dnscrypt-proxy
COPY --chown=65532:65532 vendor ./vendor
COPY --chown=65532:65532 go.mod .
COPY --chown=65532:65532 go.sum .

WORKDIR /src/dnscrypt-proxy

ARG TARGETOS TARGETARCH TARGETVARIANT

ARG CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH

RUN --mount=type=cache,target=/home/nonroot/.cache/go-build,uid=65532,gid=65532 \
    --mount=type=cache,target=/go/pkg \
    GOARM="${TARGETVARIANT#v}" go build -v -ldflags="-s -w" -mod vendor

WORKDIR /config

RUN cp -a /src/dnscrypt-proxy/example-* ./

COPY dnscrypt-proxy.toml ./

# ----------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM cgr.dev/chainguard/go AS probe

WORKDIR /src/dnsprobe

ARG TARGETOS TARGETARCH TARGETVARIANT

ARG CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH

COPY dnsprobe/ ./

RUN GOARM="${TARGETVARIANT#v}" go build -o /usr/local/bin/dnsprobe .

# ----------------------------------------------------------------------------
# hadolint ignore=DL3007
FROM gcr.io/distroless/static:nonroot

COPY --from=build /src/dnscrypt-proxy/dnscrypt-proxy /usr/local/bin/
COPY --from=probe /usr/local/bin/dnsprobe /usr/local/bin/
COPY --from=build --chown=nonroot:65532 /config /config

USER nonroot

ENTRYPOINT [ "dnscrypt-proxy" ]

CMD [ "-config", "/config/dnscrypt-proxy.toml" ]
