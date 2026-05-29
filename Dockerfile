# Build a static kms-server binary and ship it on scratch.
FROM golang:1.26-alpine AS build
WORKDIR /src

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO disabled => fully static binary, safe to run on scratch.
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /kms-server ./cmd/kms-server

FROM scratch
COPY --from=build /kms-server /kms-server
LABEL org.opencontainers.image.source=https://github.com/gustinn/talos-kms
ENTRYPOINT ["/kms-server"]
