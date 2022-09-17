package sorter

import (
	"fmt"
	"log"
	"os"
	"sort"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// ByAge implements sort.Interface based on the Age field.
type ByTimestamp []gopacket.Packet

func (a ByTimestamp) Len() int { return len(a) }
func (a ByTimestamp) Less(i, j int) bool {
	return a[i].Metadata().Timestamp.Before(a[j].Metadata().Timestamp)
}
func (a ByTimestamp) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

func LoadPacketsFromPcap(pcap string) (packets []gopacket.Packet, snaplen uint32, err error) {
	packets = make([]gopacket.Packet, 0)
	snaplen = 0

	inputFile, err := os.Open(pcap)
	if err != nil {
		return
	}

	reader, err := pcapgo.NewReader(inputFile)
	if err != nil {
		return
	}

	snaplen = reader.Snaplen()
	source := gopacket.NewPacketSource(reader, reader.LinkType())
	source.DecodeOptions = gopacket.DecodeOptions{NoCopy: true, Lazy: true}

	for packet := range source.Packets() {
		packets = append(packets, packet)
	}
	return
}

func Sort(pcaps []string, output string) (err error) {
	sortedPackets := make([]gopacket.Packet, 0)
	var frameSize uint32 = 0

	for _, inputPcapPath := range pcaps {
		var tmp []gopacket.Packet
		tmp, frameSize, err = LoadPacketsFromPcap(inputPcapPath)
		if err != nil {
			return
		}
		sortedPackets = append(sortedPackets, tmp...)
	}
	sort.Sort(ByTimestamp(sortedPackets))

	outputFile, err := os.Create(output)
	if err != nil {
		log.Println(output, err, "(error opening output file)")
		return
	}

	writer := pcapgo.NewWriter(outputFile)
	err = writer.WriteFileHeader(frameSize, layers.LinkTypeEthernet)
	if err != nil {
		err = fmt.Errorf("error writing file header")
		return
	}
	for _, packet := range sortedPackets {
		err = writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		if err != nil {
			err = fmt.Errorf("error writing packet")
			return
		}
	}

	return
}
