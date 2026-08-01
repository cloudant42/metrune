FROM node:24-bookworm AS deps
WORKDIR /app
COPY web/package*.json ./
# --omit=optional drops next's optional `sharp` dependency. The dashboard uses
# no next/image, so the image optimizer is never invoked; excluding it keeps the
# LGPL-3.0 libvips binaries (@img/sharp-libvips-*) out of the published image
# and out of NOTICE. next.config.mjs sets images.unoptimized to match.
RUN npm ci --omit=optional

FROM node:24-bookworm AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY web .
RUN npm run build

FROM node:24-bookworm-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
# The standalone server only needs the Node runtime. Package managers and
# Corepack are build tooling, expand the attack surface, and have no purpose in
# the published image.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /opt/yarn-* \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
        /usr/local/bin/yarn /usr/local/bin/yarnpkg
USER node
COPY --from=builder --chown=node:node /app/.next/standalone ./
COPY --from=builder --chown=node:node /app/.next/static ./.next/static
COPY --from=builder --chown=node:node /app/public ./public
EXPOSE 3000
CMD ["node", "server.js"]
