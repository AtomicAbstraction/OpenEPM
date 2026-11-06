FROM traefik@sha256:1336e85aaed293bd63d005086e0dd013b04078b26aaeb1c18b26a2f928af7e65 AS upstream

FROM python:3.14-slim@sha256:35caba83af2fe6da9a5d922f9b0156f21d1246a48278c58a08bd253303ba42e8 AS rewrite
COPY --from=upstream /usr/local/bin/traefik /input/traefik
COPY scripts/retire_proxy_binary.py /retire_proxy_binary.py
RUN python /retire_proxy_binary.py /input/traefik /output/traefik

# Traefik is statically linked. Flattening into scratch ensures the retired
# upstream string does not survive in a lower layer and removes the shell and
# package manager from the public ingress runtime.
FROM scratch
COPY --from=upstream /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=rewrite /output/traefik /usr/local/bin/traefik
USER 65532:65532
EXPOSE 80 443 8080
ENTRYPOINT ["/usr/local/bin/traefik"]
