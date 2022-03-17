/* For compilers to find libpcap you may need to set:
 export LDFLAGS="-L/opt/homebrew/opt/libpcap/lib"
 export CPPFLAGS="-I/opt/homebrew/opt/libpcap/include"
sudo setcap cap_net_raw+ep ./sniff
*/

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/yomorun/yomo"
)

var (
	iface  = "lo0"
	buffer = int32(1600)
	filter = "udp and port 9000"
	// filter = "src host 172.31.28.84 and udp"
)

// StreamLogEntity represents the structure of data
type StreamLogEntity struct {
	From    string `json:"from"`    // source IP address
	Packets int    `json:"packets"` // udp packets
}

func main() {

	// connect to YoMo-Zipper.
	addr := "localhost:9999"
	if v := os.Getenv("YOMO_ADDR"); v != "" {
		addr = v
	}
	collector := yomo.NewSource(
		"yomo-source",
		yomo.WithZipperAddr(addr),
	)
	err := collector.Connect()
	if err != nil {
		return
	}

	defer collector.Close()

	collector.SetDataTag(0x33)

	fmt.Println("--= YoMo x TDEngine =>>> Realtime Sniffer =--")
	fmt.Println("A simple packet sniffer in golang")

	if !deviceExists(iface) {
		log.Fatal("Unable to open device ", iface)
	}

	handler, err := pcap.OpenLive(iface, buffer, false, pcap.BlockForever)

	if err != nil {
		log.Fatal(err)
	}
	defer handler.Close()

	if err := handler.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	source := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range source.Packets() {
		harvestNetworkDeviceCreds(packet, collector)
	}
}

func harvestNetworkDeviceCreds(packet gopacket.Packet, collector yomo.Source) {
	log.Printf("harvest: %v", packet)

	nl := packet.NetworkLayer()
	log.Printf("\tNetworkFlow: %s", nl.NetworkFlow().String()) //.Dst().String())

	tl := packet.TransportLayer()
	log.Printf("\tTransportFlow: %s", tl.TransportFlow().Dst().String())

	src := fmt.Sprintf("%s:%s", nl.NetworkFlow().Src().String(), tl.TransportFlow().Src().String())
	dst := fmt.Sprintf("%s:%s", nl.NetworkFlow().Dst().String(), tl.TransportFlow().Dst().String())

	log.Printf("\t%s -> %s", src, dst)

	app := packet.ApplicationLayer()
	if app != nil {
		payload := app.Payload()
		log.Printf("\t\t%# x", payload)
		buf, _ := json.Marshal(&StreamLogEntity{
			From:    src,
			Packets: len(payload),
		})
		collector.Write(buf)
		// dst := packet.NetworkLayer().NetworkFlow().Dst()
		// if bytes.Contains(payload, []byte("USER")) {
		// 	fmt.Print(dst, "  ->  ", string(payload))
		// } else if bytes.Contains(payload, []byte("PASS")) {
		// 	fmt.Print(dst, " -> ", string(payload))
		// }
	}
}

func deviceExists(name string) bool {
	devices, err := pcap.FindAllDevs()

	if err != nil {
		log.Panic(err)
	}

	for _, device := range devices {
		// log.Printf("[found device] %v", device.Addresses)
		if device.Name == name {
			log.Printf("[found device] %v", device.Addresses)
			return true
		}
	}
	return false
}
