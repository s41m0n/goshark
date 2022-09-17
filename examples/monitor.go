package main

// go build -buildmode=plugin -linkshared -o monitor.so examples/monitor.go

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type module bool

func parse(data []byte, cinfo gopacket.CaptureInfo) (str string) {
	p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{NoCopy: true, Lazy: true})
	ip, _ := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	return fmt.Sprintf("srcIp: %s, dstIp: %s", ip.SrcIP, ip.DstIP)
}

func (m module) Parse(data []byte, cinfo gopacket.CaptureInfo) {
	msg := parse(data, cinfo)
	log.Println("[Monitor]", msg)
}

func (m module) ParseConcurrent(data []byte, cinfo gopacket.CaptureInfo, id int) {
	msg := parse(data, cinfo)
	log.Println("[Monitor] workerId:", id, msg)
}

var Module module
