# ── Dev image (Vite dev server with hot-reload) ───────────────────────────────
FROM node:20-alpine AS dev

RUN apk add --no-cache wget

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --ignore-scripts && npm rebuild esbuild

COPY . .

EXPOSE 5173
CMD ["npm", "run", "dev"]

# ── Production build ──────────────────────────────────────────────────────────
FROM node:20-alpine AS builder-prod

WORKDIR /app

# Accept VITE_* env vars as build args (baked into static JS at build time).
# SECURITY: Never pass secrets here — everything becomes part of the JS bundle.
ARG VITE_ALLOW_MOCK_LOGIN=false
ARG VITE_BACKEND_URL=

COPY package.json package-lock.json* ./
RUN npm install --ignore-scripts && npm rebuild esbuild

COPY . .
RUN npm run build

# ── Production image (nginx serving compiled static files) ────────────────────
FROM nginx:alpine AS prod

RUN apk upgrade --no-cache

COPY --from=builder-prod /app/dist /usr/share/nginx/html
COPY nginx.prod.conf /etc/nginx/templates/default.conf.template

# Regenerate /config.js from VITE_* env on each container start (runtime config).
COPY docker-entrypoint.d/40-runtime-config.sh /docker-entrypoint.d/40-runtime-config.sh
RUN chmod +x /docker-entrypoint.d/40-runtime-config.sh

# BACKEND_URL is substituted into the nginx config at container startup.
# Default: http://proxy-backend:8080 (Docker service name from compose)
ENV BACKEND_URL=http://proxy-backend:8080

EXPOSE 80
# nginx:alpine uses docker-entrypoint.sh which runs envsubst on /etc/nginx/templates/*.template
CMD ["nginx", "-g", "daemon off;"]

# ── E2E image (prod build + API proxy to backend) ────────────────────────────
FROM nginx:alpine AS e2e

RUN apk upgrade --no-cache && apk add --no-cache wget

COPY --from=builder-prod /app/dist /usr/share/nginx/html
COPY nginx.e2e.conf /etc/nginx/conf.d/default.conf
COPY docker-entrypoint.d/40-runtime-config.sh /docker-entrypoint.d/40-runtime-config.sh
RUN chmod +x /docker-entrypoint.d/40-runtime-config.sh

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
