# Stage 1: Build client bundle
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

# Copy server code
COPY server/ ./server/
COPY shared/ ./shared/

# Copy built client
COPY client/index.html ./client/index.html
COPY client/css/ ./client/css/
COPY --from=build /app/client/dist/ ./client/dist/

# Create data directory for SQLite
RUN mkdir -p /data

ENV NODE_ENV=production
ENV DB_PATH=/data/signal-web.db
ENV PORT=3000

EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1

CMD ["node", "server/index.js"]
