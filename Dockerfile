# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /bin/possum ./cmd/possum

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates git

COPY --from=builder /bin/possum /usr/local/bin/possum

ENTRYPOINT ["possum"]
CMD ["--help"]
