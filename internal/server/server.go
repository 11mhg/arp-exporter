package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/11mhg/arp-viz/internal/monitoring"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func RunForever(device string, httpPort string, ctx context.Context) error {
	iface, err := net.InterfaceByName(device)
	if err != nil {
		log.Fatalf("Error getting interface %s: %v", device, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/garp", makeHandleSendGarp(device, iface))
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:    ":" + httpPort,
		Handler: mux,
	}

	go func() {
		fmt.Printf("HTTP server listening on :%s\n", httpPort)
		log.Fatalf("HTTP server died: %v", server.ListenAndServe())
	}()

	// Block until interrupt
	<-ctx.Done()
	log.Println("HTTP server: Context Cancelled. Shutting down gracefully....")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err = server.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP server graceful shutdown failed: %v", err)
		return fmt.Errorf("http server shutdown error: %w", err)
	}

	return nil
}

func makeHandleSendGarp(device string, iface *net.Interface) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(w, "Only GET requests are allowed", http.StatusMethodNotAllowed)
			return
		}

		query := req.URL.Query()
		targetIPStr := query.Get("target")
		newIPStr := query.Get("new")

		if targetIPStr == "" || newIPStr == "" {
			errorString := fmt.Sprintf("Missing 'target' or 'new' query parameters: '%s' - '%s'", targetIPStr, newIPStr)
			http.Error(w, errorString, http.StatusBadRequest)
			return
		}

		targetIP := net.ParseIP(targetIPStr)
		newIP := net.ParseIP(newIPStr)

		if targetIP == nil || newIP == nil {
			http.Error(w, "Invalid IP Address format", http.StatusBadRequest)
			return
		}

		fmt.Printf("\nReceived request to send gARP: target_ip=%s, new_ip=%s\n", targetIPStr, newIPStr)
		err := sendGratuitousARP(newIP, iface)

		if err != nil {
			errMsg := fmt.Sprintf("Error sending gARP for %s: %v", newIPStr, err)
			log.Println(errMsg)
			http.Error(w, errMsg, http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Successfully sent gARP for %s\n", newIPStr)
		log.Printf("Successfully sent gARP for %s\n", newIPStr)
	}
}

func sendGratuitousARP(ip net.IP, iface *net.Interface) error {

	if ip.To4() == nil {
		return fmt.Errorf("Only ipv4 addresses are supported for gARP")
	}

	// Create an Ethernet Layer for broadcasting ARP
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet, // Hardware type is Ethernet
		Protocol:          layers.EthernetTypeIPv4, // Protocol type is IPv4
		HwAddressSize:     uint8(len(iface.HardwareAddr)),
		ProtAddressSize:   uint8(len(ip.To4())),
		Operation:         layers.ARPReply,
		SourceHwAddress:   iface.HardwareAddr,
		SourceProtAddress: ip.To4(),
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    ip.To4(),
	}

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	},
		ethernetLayer,
		arpLayer,
	)

	if err != nil {
		return fmt.Errorf("Error serializing layers: %w", err)
	}

	pcapHandle := monitoring.GetHandle()

	if pcapHandle == nil {
		return fmt.Errorf("Could not get a handle to pcap...")
	}

	err = pcapHandle.WritePacketData(buffer.Bytes())
	if err != nil {
		return fmt.Errorf("error injecting packet: %w", err)
	}

	return nil
}
