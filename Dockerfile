# check=skip=SecretsUsedInArgOrEnv
# PORTFOLIO_AUTH_MODE is a public branch contract, not a credential.
FROM node:22.23.2-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS build
ARG PORTFOLIO_BRANCH
ARG PORTFOLIO_AUTH_MODE
ENV PORTFOLIO_BRANCH=${PORTFOLIO_BRANCH} \
    PORTFOLIO_AUTH_MODE=${PORTFOLIO_AUTH_MODE}

WORKDIR /app

RUN apk add --no-cache python3

COPY package.json package-lock.json ./
RUN npm ci

COPY index.html vite.config.ts tsconfig.json tsconfig.node.json tsconfig.server.json ./
COPY src ./src
COPY server ./server
COPY ops ./ops
COPY scripts ./scripts

# The workflow's native test gate keeps Vitest's strict default timeout. The
# amd64 stage can run through QEMU on the ARM release runner, so bound its
# parallelism and allow emulation overhead without weakening the native gate.
RUN ./scripts/portfolio-auth-mode.sh check \
    && npm run test:portfolio-auth \
    && npm run typecheck \
    && npm run test:raw -- --maxWorkers=2 --testTimeout=30000 \
    && npm run build

FROM node:22.23.2-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS production-dependencies

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

FROM node:22.23.2-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS runtime

ARG PORTFOLIO_BRANCH
ARG PORTFOLIO_AUTH_MODE
ENV NODE_ENV=production \
    PORT=8080 \
    MONITOR_DATA_DIR=/data \
    PORTFOLIO_BRANCH=${PORTFOLIO_BRANCH} \
    PORTFOLIO_AUTH_MODE=${PORTFOLIO_AUTH_MODE}
LABEL work.bonifacio.portfolio.branch=${PORTFOLIO_BRANCH} \
      work.bonifacio.portfolio.auth-mode=${PORTFOLIO_AUTH_MODE}

# The production process invokes node directly. Do not ship npm/npx or their
# transitive package-manager attack surface in the runtime image.
RUN rm -rf /usr/local/lib/node_modules/npm \
    /usr/local/bin/npm \
    /usr/local/bin/npx

RUN printf '%s\n%s\n' "$PORTFOLIO_BRANCH" "$PORTFOLIO_AUTH_MODE" \
      > /etc/portfolio-auth-build \
    && chmod 0444 /etc/portfolio-auth-build

WORKDIR /app

COPY --from=production-dependencies /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./package.json
COPY scripts/portfolio-auth-mode.sh ./scripts/portfolio-auth-mode.sh

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8080/readyz').then((response) => { if (!response.ok) process.exit(1) }).catch(() => process.exit(1))"

ENTRYPOINT ["./scripts/portfolio-auth-mode.sh", "exec", "--"]
CMD ["node", "--enable-source-maps", "dist/server/index.js"]
