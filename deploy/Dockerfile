# Build context is the repository root: docker build -f deploy/Dockerfile .
FROM node:lts AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
# vite.config.ts writes the bundle to ../backend/internal/webui/dist
RUN mkdir -p /src/backend/internal/webui/dist && npm run build

FROM golang:latest AS backend
WORKDIR /src/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
COPY --from=web /src/backend/internal/webui/dist ./internal/webui/dist
RUN CGO_ENABLED=0 go build -p 4 -trimpath -ldflags="-s -w" -o /out/dashboard ./cmd/dashboard
RUN CGO_ENABLED=0 go build -p 4 -trimpath -ldflags="-s -w" -o /out/hashpassword ./cmd/hashpassword

FROM gcr.io/distroless/static:nonroot
COPY --from=backend /out/dashboard /dashboard
# One-shot helper, no shell needed: docker run --rm -i --entrypoint /hashpassword <image> <<< "$password"
COPY --from=backend /out/hashpassword /hashpassword
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/dashboard"]
