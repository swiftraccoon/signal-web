# Stage 1: Build server + client bundle
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN NODE_ENV=production npm run build

# Stage 2: Production runtime
FROM node:20-alpine
WORKDIR /app

# Install only production dependencies
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy compiled server
COPY --from=build /app/dist/ ./dist/

# Copy built client
COPY client/index.html ./client/index.html
COPY client/css/ ./client/css/
COPY --from=build /app/client/dist/ ./client/dist/

# Create non-root user and data directory
RUN addgroup -S app && adduser -S app -G app && \
    mkdir -p /data && chown app:app /data && chmod 700 /data

ENV NODE_ENV=production
ENV DB_PATH=/data/signal-web.db
ENV PORT=3000

EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1

USER app

CMD ["node", "dist/server/index.js"]
