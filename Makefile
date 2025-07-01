build:
	go build -o ./bin/arp-viz ./cmd/arp-viz/main.go

run: build
	sudo ./bin/arp-viz
