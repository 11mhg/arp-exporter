build:
	go build -o ./bin/arp-exporter ./cmd/arp-exporter/main.go

run: build
	sudo ./bin/arp-exporter
