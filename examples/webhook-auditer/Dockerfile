FROM golang:1.19.3 AS gobuild

RUN adduser --gecos 'appuser' --system appuser --uid 1000

WORKDIR /app

FROM scratch

COPY --from=gobuild /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=gobuild /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=gobuild /etc/passwd /etc/passwd

COPY --from=gobuild /etc/resolv.conf /etc/resolv.conf

USER appuser

WORKDIR /app

CMD ["/app/webhook-auditer", "--addr=0.0.0.0:8443"]

ADD webhook-auditer /app/webhook-auditer