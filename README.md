# Arp Exporter


I got tired of having to diagnose arp issues post-hoc. I figured if folks are exporting tons of metrics for cpu, network bandwidth, etc, folks might be interested in a tool that can export arp metrics and allow filtering by labels prometheus side.

Once running, this exporter will intercept all ARP queries and replies on a particular interface and export prometheus counters labelled with the information abuot this ARP query/reply.

# gARP

The server is also able to gratuitously ARP for a particular IP when the target ip matches the nodes ip.... This forces all nodes on L2 to update their arp cache entry for this IP.

