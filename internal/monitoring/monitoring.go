package monitoring

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mitchellh/hashstructure/v2"
	"github.com/prometheus/client_golang/prometheus"
)

type LabelEntry struct {
	LastTime time.Time
	Labels   prometheus.Labels
}

var (
	pcapHandle   *pcap.Handle
	activeLabels map[uint64]LabelEntry
	mu           sync.RWMutex
)

func GetHandle() *pcap.Handle {
	return pcapHandle
}

func RunForever(device string, ctx context.Context) error {
	fmt.Printf("Starting arp monitoring on device %s\n", device)

	PromInit()
	activeLabels = make(map[uint64]LabelEntry)
	mu = sync.RWMutex{}

	var err error

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("Error getting hostname: %v\n", err)
	}

	pcapHandle, err = pcap.OpenLive(device, 65536, true, 30*time.Second)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", device, err)
	}
	defer pcapHandle.Close()

	err = pcapHandle.SetBPFFilter("arp")
	if err != nil {
		log.Fatalf("Error setting BPF Filter: %v", err)
	}

	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
	totalArpPackets := GetCounterVec()

	go cleanupInactiveLabels()

	for {
		select {
		case <-ctx.Done():
			log.Printf("Context cancelled, stopping ARP monitor on %s.", device)
			return ctx.Err()
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return fmt.Errorf("Packet source channel closed unexpectedly...")
			}

			mu.Lock()
			processPacket(packet, totalArpPackets, hostname, device)
			mu.Unlock()
		}
	}

	return nil
}

func cleanupInactiveLabels() {
	for range time.Tick(5 * time.Minute) {
		for _, entry := range activeLabels {
			if time.Since(entry.LastTime) > 10*time.Minute {
				mu.Lock()
				totalArpPackets.Delete(entry.Labels)
				mu.Unlock()
			}
		}
	}
}

func processPacket(packet gopacket.Packet, totalArpPackets *prometheus.CounterVec, hostname string, device string) {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return
	}
	ethernetPacket := ethernetLayer.(*layers.Ethernet)

	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		return
	}
	arpPacket := arpLayer.(*layers.ARP)

	var opType string
	switch arpPacket.Operation {
	case layers.ARPRequest:
		opType = "Request"
	case layers.ARPReply:
		opType = "Reply"
	default:
		opType = fmt.Sprintf("Unknown (%d)", arpPacket.Operation)
	}

	md := MonitoringData{
		Node:      hostname,
		Device:    device,
		SrcMac:    ethernetPacket.SrcMAC.String(),
		DstMac:    ethernetPacket.DstMAC.String(),
		SenderMac: net.HardwareAddr(arpPacket.SourceHwAddress).String(),
		SenderIP:  net.IP(arpPacket.SourceProtAddress).String(),
		TargetMac: net.HardwareAddr(arpPacket.DstHwAddress).String(),
		TargetIP:  net.IP(arpPacket.DstProtAddress).String(),
		OpType:    opType,
	}

	fmt.Printf("--- ARP Packet (%s) ---\n", opType)
	fmt.Printf("  Timestamp: %s\n", packet.Metadata().Timestamp.Format(time.RFC3339Nano))
	fmt.Printf("  Src MAC: %s\n", ethernetPacket.SrcMAC)
	fmt.Printf("  Dst MAC: %s\n", ethernetPacket.DstMAC)
	fmt.Printf("  Sender MAC: %s\n", net.HardwareAddr(arpPacket.SourceHwAddress))
	fmt.Printf("  Sender IP: %s\n", net.IP(arpPacket.SourceProtAddress))
	fmt.Printf("  Target MAC: %s\n", net.HardwareAddr(arpPacket.DstHwAddress))
	fmt.Printf("  Target IP: %s\n", net.IP(arpPacket.DstProtAddress))
	fmt.Println("-----------------------")

	hashValue, err := hashstructure.Hash(md, hashstructure.FormatV2, nil)
	if err != nil {
		fmt.Printf("Could not hash structure: %v\n", err)
		return
	}

	promLabels := prometheus.Labels{
		"node":       md.Node,
		"device":     md.Device,
		"src_mac":    md.SrcMac,
		"dst_mac":    md.DstMac,
		"sender_mac": md.SenderMac,
		"sender_ip":  md.SenderIP,
		"target_mac": md.TargetMac,
		"target_ip":  md.TargetIP,
		"op_type":    md.OpType,
	}

	totalArpPackets.With(promLabels).Inc()

	activeLabels[hashValue] = LabelEntry{
		LastTime: time.Now(),
		Labels:   promLabels,
	}

}
