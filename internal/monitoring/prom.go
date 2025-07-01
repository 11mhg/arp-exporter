package monitoring

import "github.com/prometheus/client_golang/prometheus"

type MonitoringData struct {
	Node      string // The node name
	Device    string // The device name (Interface)
	SrcMac    string // The source mac address of the ethernet packet
	DstMac    string // The destination mac address of the ethernet packet
	SenderMac string // Sender Mac Address
	SenderIP  string // Sender IP Address
	TargetMac string // Target MAC Address
	TargetIP  string // Target IP Address
	OpType    string // Operation type
}

var (
	totalArpPackets *prometheus.CounterVec // Total number of arp packets
)

func GetCounterVec() *prometheus.CounterVec {
	return totalArpPackets
}

func PromInit() {
	totalArpPackets = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "arp_packets_total",
			Help: "Total number of ARP Packets observed, labelled.",
		},
		[]string{"node", "device", "src_mac", "dst_mac", "sender_mac", "sender_ip", "target_mac", "target_ip", "op_type"},
	)
	prometheus.MustRegister(totalArpPackets)
	return
}
