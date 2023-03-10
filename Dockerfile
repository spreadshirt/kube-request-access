FROM docker.io/golang:1.20-alpine3.17 as builder

WORKDIR /build

COPY . .
RUN go build .

FROM alpine:3.17

RUN apk add --no-cache shadow && useradd --home-dir /dev/null --shell /bin/false appuser && apk del shadow

USER appuser

WORKDIR /app

CMD ["/app/kube-request-access", "--addr=0.0.0.0:8443"]

COPY --from=builder /build/kube-request-access /app/
