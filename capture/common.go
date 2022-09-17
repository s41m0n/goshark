package capture

import (
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"golang.org/x/net/bpf"
)

// IsDeviceExists checks if device with name exists
func IsDeviceExists(name string) (ok bool, err error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return
	}
	for _, device := range devices {
		if name == device.Name {
			ok = true
			return
		}
	}
	return
}

// ListDevices prints a list of found devices
func ListDevices() (err error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return
	}
	log.Println("Found Devices")
	for _, device := range devices {
		log.Println("--------------------------")
		log.Printf("Device Name: %s\n", device.Name)
		log.Printf("Device Description: %s\n", device.Description)
	}
	return
}

func NewAfpacketHandle(device string, snaplen int, block_size int, num_blocks int,
	useVLAN bool, timeout time.Duration, filter string, isFanout bool) (*afpacket.TPacket, gopacket.ZeroCopyPacketDataSource, error) {
	var source gopacket.ZeroCopyPacketDataSource
	var err error

	h, err := afpacket.NewTPacket(
		afpacket.OptInterface(device),
		afpacket.OptFrameSize(snaplen),
		afpacket.OptBlockSize(block_size),
		afpacket.OptNumBlocks(num_blocks),
		afpacket.OptAddVLANHeader(useVLAN),
		afpacket.OptPollTimeout(timeout),
		afpacket.SocketRaw,
		afpacket.TPacketVersion3)

	if err != nil {
		return h, source, err
	}

	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, snaplen, filter)
	if err != nil {
		return h, source, err
	}
	bpfIns := []bpf.RawInstruction{}
	for _, ins := range pcapBPF {
		bpfIns2 := bpf.RawInstruction{
			Op: ins.Code,
			Jt: ins.Jt,
			Jf: ins.Jf,
			K:  ins.K,
		}
		bpfIns = append(bpfIns, bpfIns2)
	}
	err = h.SetBPF(bpfIns)

	if err != nil {
		return h, source, err
	}

	if isFanout {
		err = h.SetFanout(afpacket.FanoutRollover, fanoutGroup)
	}

	if err == nil {
		source = gopacket.ZeroCopyPacketDataSource(h)
	}
	return h, source, err
}

func logStats(id int, handle *afpacket.TPacket) {
	_, afpacketStats, err := handle.SocketStats()
	if err != nil {
		log.Println(err)
	}
	log.Println("[Stats] WorkerID: ", id, "{received, dropped, queue-freeze}:", afpacketStats)
}

func RegisterStatsEvent(id int, handle *afpacket.TPacket, seconds time.Duration) {
	ticker := time.NewTicker(seconds * time.Second)
	go func() {
		for {
			<-ticker.C
			logStats(id, handle)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		logStats(id, handle)
		os.Exit(1)
	}()
}

func RegisterCpuProfile(path string) (err error) {
	log.Println("[Profiling]: Writing CPU profile to", path)
	f, err := os.Create(path)
	if err != nil {
		return
	}
	err = pprof.StartCPUProfile(f)
	return
}
