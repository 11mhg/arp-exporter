FROM golang:1.24.4-bookworm AS builder

WORKDIR /app

RUN apt-get update && \
  apt-get install -y dbus libpcap-dev

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o /usr/local/bin/arp-viz ./cmd/arp-viz/main.go

FROM debian:bookworm

RUN apt-get update && \
  apt-get install -y dbus libpcap-dev && \
  rm -rf /var/lib/apt/lists/*

WORKDIR /

COPY --from=builder /usr/local/bin/arp-viz /usr/local/bin/arp-viz

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/arp-viz"]

