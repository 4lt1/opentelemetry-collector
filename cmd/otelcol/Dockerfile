FROM ubuntu:latest as hc
ADD https://github.com/chrisaxiom/docker-health-check/archive/v0.3.tar.gz /
RUN tar -xvzf /v0.3.tar.gz

FROM alpine:3.12 as certs
RUN apk --update add ca-certificates

FROM alpine:3.12 AS otelcol
COPY otelcol /
# Note that this shouldn't be necessary, but in some cases the file seems to be
# copied with the execute bit lost (see #1317)
RUN chmod 755 /otelcol

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=otelcol /otelcol /
COPY config.yaml /etc/otel/config.yaml
COPY --from=hc /docker-health-check-0.3/docker-health-check /docker-health-check
HEALTHCHECK --interval=8s --timeout=120s --retries=8 CMD ["/docker-health-check", "-url=http://localhost:13133/health"]
ENTRYPOINT ["/otelcol"]
CMD ["--config", "/etc/otel/config.yaml"]
EXPOSE 55678 55679
