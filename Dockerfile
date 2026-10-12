# syntax=docker/dockerfile:1

# --- Build: compile with the project's own Node + pnpm toolchain -----------
FROM node:24 AS build
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY tsconfig.json ./
COPY src ./src
COPY scripts ./scripts
RUN pnpm build

# --- Runtime: minimal image, production deps only, unprivileged user -------
FROM node:24-slim AS runtime
ENV NODE_ENV=production \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0
ARG CITRX_VERSION=0.7.2
LABEL org.opencontainers.image.title="citrx" \
      org.opencontainers.image.description="Local-first Apache/Nginx access log analysis CLI" \
      org.opencontainers.image.url="https://github.com/javipm/citrx" \
      org.opencontainers.image.version="${CITRX_VERSION}"
RUN corepack enable
WORKDIR /app
COPY --chown=node:node package.json pnpm-lock.yaml pnpm-workspace.yaml README.md README_ES.md LICENSE ./
# The pnpm store/cache is only needed at install time; node_modules is
# self-contained afterwards, so drop it to keep the image small.
RUN pnpm install --frozen-lockfile --prod && rm -rf /root/.local/share/pnpm /root/.cache
COPY --from=build --chown=node:node /app/dist ./dist
# Conventional mount point for access logs; mount it read-only (-v ...:/logs:ro).
RUN mkdir -p /logs && chown node:node /logs
USER node
ENTRYPOINT ["node", "dist/cli.js"]
