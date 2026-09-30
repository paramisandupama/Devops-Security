# =============================================================================
# API tier - OWASP Juice Shop backend (Node.js / Express / Sequelize / SQLite)
#
# Three stages so that neither the TypeScript compiler nor the dev dependencies
# end up in the shipped image (smaller image = smaller attack surface, and Trivy
# has fewer packages to complain about).
# =============================================================================
# syntax=docker/dockerfile:1

# ---------- Stage 1: build the Angular single-page application ---------------
FROM node:24-alpine AS frontend-build
WORKDIR /juice-shop
COPY package.json package-lock.json ./
COPY frontend/package.json frontend/package-lock.json ./frontend/
RUN npm ci --ignore-scripts
COPY frontend ./frontend
RUN cd frontend && npm run build

# ---------- Stage 2: compile the TypeScript server ---------------------------
FROM node:24-alpine AS api-build
WORKDIR /juice-shop
COPY package.json package-lock.json tsconfig.json ./
COPY --from=frontend-build /juice-shop/frontend/node_modules ./frontend/node_modules
RUN npm ci --ignore-scripts
RUN npm install -g typescript@^6.0.3
COPY app.ts server.ts ./
COPY config ./config
COPY data ./data
COPY lib ./lib
COPY models ./models
COPY routes ./routes
COPY views ./views
COPY rsn ./rsn
RUN npx tsc -p .

# ---------- Stage 3: runtime ------------------------------------------------
FROM node:24-alpine AS runtime
WORKDIR /juice-shop

# Run as an unprivileged user; never run a Node web service as root.
RUN addgroup -g 65532 -S juiceshop && \
    adduser -u 65532 -S juiceshop -G juiceshop && \
    apk add --no-cache su-exec

ENV NODE_ENV=production
ENV PORT=3000

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

COPY --from=api-build  /juice-shop/build            ./build
COPY --from=api-build  /juice-shop/node_modules     ./node_modules
COPY --from=frontend-build /juice-shop/frontend/dist ./frontend/dist

COPY config ./config
COPY data ./data
COPY lib ./lib
COPY models ./models
COPY routes ./routes
COPY views ./views
COPY rsn ./rsn
COPY encryptionkeys ./encryptionkeys
COPY app.ts server.ts ./

RUN mkdir -p logs frontend/dist/frontend/assets/public/images/uploads && \
    chgrp -R 0 logs data frontend/dist && \
    chmod -R g=u logs data frontend/dist

# The private signing key is mounted at runtime (Docker secret or Vault).
# It is deliberately NOT present in the image.
COPY docker/api/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER 65532
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/rest/admin/application-version').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["node", "build/app.js"]
