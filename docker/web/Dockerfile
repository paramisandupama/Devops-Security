# =============================================================================
# Web tier - NGINX
#
# Serves the compiled Angular bundle and reverse-proxies every API call to the
# backend container. Putting an NGINX tier in front of the application is not
# decoration: it is the control that carries several of the threat-model
# mitigations (security headers, request rate limiting, request-size caps, and
# a single place to terminate TLS).
#
# The static bundle is copied out of the API image so the Angular build only
# runs once.
# =============================================================================
# syntax=docker/dockerfile:1
ARG API_IMAGE=ie3142-juice-shop-api:1.0

FROM ${API_IMAGE} AS api

FROM nginx:1.28-alpine
RUN apk add --no-cache ca-certificates && rm -rf /var/cache/apk/*

COPY docker/web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=api /juice-shop/frontend/dist/frontend /usr/share/nginx/html

# NGINX needs a writable cache/tmp tree because the image runs as an
# unprivileged, arbitrary UID on OpenShift-compatible runtimes.
RUN mkdir -p /var/cache/nginx /var/log/nginx /tmp && \
    chgrp -R 0 /var/cache/nginx /var/log/nginx /etc/nginx /usr/share/nginx/html /tmp && \
    chmod -R g=u /var/cache/nginx /var/log/nginx /etc/nginx /usr/share/nginx/html /tmp

# Run unprivileged. uid 101 is the image's nginx user; gid 0 keeps the
# group-writable cache/log tree usable on OpenShift-compatible runtimes
# that remap the UID.
USER 101:0

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

CMD ["nginx", "-g", "daemon off;"]
