FROM docker.io/golang:1.20-alpine3.17 as builder

WORKDIR /build

COPY go.mod go.sum .
RUN --mount=type=cache,target=/root/.go/pkg go mod download -x
COPY . .
RUN --mount=type=cache,target=/root/.go/pkg --mount=type=cache,target=/root/.cache/go-build \
  go build -v .

FROM alpine:3.17

RUN apk add --no-cache shadow && useradd --home-dir /dev/null --shell /bin/false appuser && apk del shadow

USER appuser

WORKDIR /app

CMD ["/app/kube-request-access", "--addr=0.0.0.0:8443"]

COPY --from=builder /build/kube-request-access /app/
