package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"

	"github.com/11mhg/arp-exporter/internal/monitoring"
	"github.com/11mhg/arp-exporter/internal/server"
	"github.com/urfave/cli/v3"
)

const httpPort = "8080"

var (
	wg sync.WaitGroup
)

func run_solution(cliCtx context.Context, cmd *cli.Command) error {
	device := cmd.String("interface")

	ctx, cancel := signal.NotifyContext(cliCtx, os.Interrupt)
	defer cancel() // Make sure cancel() is called when run_solution exits

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := monitoring.RunForever(device, ctx)
		if err != nil {
			log.Fatalf("Arp monitoring failed: %v", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := server.RunForever(device, httpPort, ctx)
		if err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	//Wait for an interrupt signal
	<-ctx.Done()

	wg.Wait()
	return nil
}

func main() {
	cmd := &cli.Command{
		Name:   "arp-exporter",
		Usage:  "Run a server to export arp metrics and to run gARPs.",
		Action: run_solution,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "interface",
				Aliases: []string{"i"},
				Usage:   "Network `INTERFACE` to monitor and inject packets on for gARP (e.g. eth0, en0)",
				Value:   "eth0",
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
