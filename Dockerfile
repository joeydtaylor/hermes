# ---- build stage ----
FROM golang:1.24.6-alpine AS build
RUN apk add --no-cache ca-certificates git
WORKDIR /src

# cache deps
COPY go.mod go.sum ./
RUN go mod download

# build
COPY . .
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags "-s -w" -o /out/hermes server.go

# ---- runtime stage ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates curl
WORKDIR /app

# binary
COPY --from=build /out/hermes /app/hermes
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# non-root
RUN adduser -D -H -u 10001 hermes && chown -R hermes:hermes /app
USER hermes

EXPOSE 4000
# keep the entrypoint simple: no sh wrappers, no cp
ENTRYPOINT ["/app/hermes"]
