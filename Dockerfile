# Build stage
FROM golang:1.26-alpine AS builder

ARG VERSION=v0.1.0-dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w -X github.com/possum-security/possum-core/pkg/version.Version=${VERSION} -X github.com/possum-security/possum-core/pkg/version.GitCommit=${COMMIT} -X github.com/possum-security/possum-core/pkg/version.BuildDate=${BUILD_DATE}" \
    -o /bin/possum ./cmd/possum

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates git \
    && addgroup -S possum && adduser -S -G possum possum

COPY --from=builder /bin/possum /usr/local/bin/possum

USER possum

ENTRYPOINT ["possum"]
CMD ["--help"]
