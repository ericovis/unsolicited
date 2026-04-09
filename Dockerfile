FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /unsolicited ./cmd/server

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

RUN addgroup -S app && adduser -S app -G app

WORKDIR /app

COPY --from=builder /unsolicited /app/unsolicited
COPY templates/ /app/templates/
COPY static/ /app/static/

RUN mkdir -p /data && chown -R app:app /app /data

USER app

EXPOSE 8080 2222

CMD ["/app/unsolicited"]
