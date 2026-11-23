ARG CADDY_IMAGE=caddy@sha256:4851e54a46b206517c574821bb5cc67f170d2156041e9fbc4c9193b45e84a75b
FROM ${CADDY_IMAGE}
# Fresh named volumes inherit these directories and their ownership on first use.
USER root
RUN mkdir -p /data /config \
    && chown -R 10001:10001 /data /config \
    && chmod 0700 /data /config
COPY deploy/Caddyfile /etc/caddy/Caddyfile
COPY client/dist /srv/client
RUN chmod -R a=rX /srv/client \
    && caddy fmt --overwrite /etc/caddy/Caddyfile
USER 10001:10001
