package capture

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// Opt opt
type Opt struct {
	Device     string
	BPFFilter  string
	CpuProfile string
	FrameSize  int
	BlockSize  int
	NumBlock   int
	StatsSec   uint64
	Promiscous bool
	UseVlan    bool
	UseFanout  bool
	Pcap       string
	Module     string
}

const (
	DefaultDevice      = ""
	DefaultBPFFilter   = ""
	DefaultCPUProfile  = ""
	DefaultFrameSize   = afpacket.DefaultFrameSize
	DefaultBlockSize   = afpacket.DefaultBlockSize
	DefaultNumBlock    = afpacket.DefaultNumBlocks
	DefaultStatsSec    = 5
	DefaultPromiscuous = false
	DefaultVlan        = false
	DefaultFanout      = false
	DefaultPcap        = ""
	DefaultModule      = ""
)
const fanoutGroup = 42

var module Module

func (opt *Opt) OK() (err error) {
	if opt.Device == "" {
		err = fmt.Errorf("must Provide device")
		return
	}
	ok, err := IsDeviceExists(opt.Device)
	if err != nil {
		return
	}
	if !ok {
		err = fmt.Errorf("device with name %s does not exist", opt.Device)
		return
	}
	if opt.Pcap == "" && opt.Module == "" {
		err = fmt.Errorf("specify at least pcap file or monitoring module")
		return
	}
	if opt.Pcap != "" && !strings.HasSuffix(opt.Pcap, ".pcap") {
		opt.Pcap += ".pcap"
	}
	if opt.Module != "" {
		mod, err := filepath.Abs(opt.Module)
		if err != nil {
			log.Fatal(err)
		}
		opt.Module = mod
	}

	if opt.CpuProfile != "" && !strings.HasSuffix(opt.CpuProfile, ".profile") {
		opt.CpuProfile += ".profile"
	}
	return
}

func Capture(opt *Opt) (err error) {

	if opt.CpuProfile != "" {
		err = RegisterCpuProfile(opt.CpuProfile)
		if err != nil {
			return
		}
		defer pprof.StopCPUProfile()
	}

	if opt.Module != "" {
		err = loadPlugin(opt.Module)
		if err != nil {
			log.Fatal(err)
		}

		// add watcher for module change
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			log.Fatal("NewWatcher failed: ", err)
		}
		defer watcher.Close()

		err = watcher.Add(filepath.Dir(opt.Module))
		if err != nil {
			log.Fatal("Add failed:", err)
		}

		go watchEvent(watcher, opt.Module)
	}

	workerCount := 0

	if opt.UseFanout {
		workerCount = runtime.NumCPU()

		for w := 0; w+1 < workerCount; w++ {
			log.Printf("Starting worker id %d on interface %s", w, opt.Device)
			go workerFanout(w, opt)
		}
		log.Printf("%d workers started. Collecting results ", workerCount)
	}
	workerFanout(workerCount, opt)
	return
}

func workerFanout(id int, opt *Opt) {
	handle, source, err := NewAfpacketHandle(opt.Device, opt.FrameSize, opt.BlockSize, opt.NumBlock, opt.UseVlan, pcap.BlockForever, opt.BPFFilter, true)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var w *pcapgo.Writer

	if opt.Pcap != "" {
		var filename string
		pos := strings.Index(opt.Pcap, ".pcap")
		if pos == -1 {
			if opt.UseFanout {
				filename = opt.Pcap + strconv.Itoa(id) + ".pcap"
			} else {
				filename = opt.Pcap + ".pcap"
			}
		} else {
			if opt.UseFanout {
				filename = opt.Pcap[:pos] + strconv.Itoa(id) + opt.Pcap[pos:]
			} else {
				filename = opt.Pcap
			}
		}

		fx, err := os.Create(filename)
		if err != nil {
			log.Fatal(err)
		}
		defer fx.Close()

		w = pcapgo.NewWriter(fx)
		err = w.WriteFileHeader(uint32(opt.FrameSize), layers.LinkTypeEthernet)
		if err != nil {
			log.Fatal("error writing file header")
		}
	}

	RegisterStatsEvent(id, handle, time.Duration(opt.StatsSec))

	for {
		data, ci, err := source.ZeroCopyReadPacketData()
		if err != nil {
			log.Fatal(err)
		}
		if w != nil {
			log.Println("[Capture] dumped packet of", len(data), "bytes")
			err = w.WritePacket(ci, data)
			if err != nil {
				log.Println("error writing packet")
			}
			// TODO: timer to aggregate pcap using sorter command
			// TODO: swap pcap file for performance
		}
		if module != nil {
			if opt.UseFanout {
				module.ParseConcurrent(data, ci, id)
			} else {
				module.Parse(data, ci)
			}
		}
	}
}
