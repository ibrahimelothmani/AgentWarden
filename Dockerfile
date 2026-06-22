# ---- Build stage -----------------------------------------------------
FROM golang:1.22-alpine AS build

WORKDIR /src

# Cache dependency downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/agentwarden ./cmd/agentwarden

# ---- Runtime stage -----------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

WORKDIR /app
COPY --from=build /out/agentwarden /app/agentwarden
COPY warden.yaml /app/warden.yaml

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/app/agentwarden"]
