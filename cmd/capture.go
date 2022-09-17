package cmd

import (
	"github.com/s41m0n/goshark/go/capture"
	"github.com/spf13/cobra"
)

var captureCmd = &cobra.Command{
	Use:   "capture",
	Short: "Capture packets",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		pcap, err := cmd.Flags().GetString("pcap")
		if err != nil {
			return
		}
		module, err := cmd.Flags().GetString("module")
		if err != nil {
			return
		}
		device, err := cmd.Flags().GetString("device")
		if err != nil {
			return
		}
		filter, err := cmd.Flags().GetString("filter")
		if err != nil {
			return
		}
		cpuprofile, err := cmd.Flags().GetString("cpuprofile")
		if err != nil {
			return
		}
		framesize, err := cmd.Flags().GetInt("framesize")
		if err != nil {
			return
		}
		blocksize, err := cmd.Flags().GetInt("blocksize")
		if err != nil {
			return
		}
		numblock, err := cmd.Flags().GetInt("numblock")
		if err != nil {
			return
		}
		statsec, err := cmd.Flags().GetUint64("statsec")
		if err != nil {
			return
		}
		promiscuous, err := cmd.Flags().GetBool("promiscuous")
		if err != nil {
			return
		}
		vlan, err := cmd.Flags().GetBool("vlan")
		if err != nil {
			return
		}
		fanout, err := cmd.Flags().GetBool("multicore")
		if err != nil {
			return
		}
		captureOpt := capture.Opt{
			Device:     device,
			BPFFilter:  filter,
			CpuProfile: cpuprofile,
			FrameSize:  framesize,
			StatsSec:   statsec,
			BlockSize:  blocksize,
			NumBlock:   numblock,
			Promiscous: promiscuous,
			UseVlan:    vlan,
			UseFanout:  fanout,
			Pcap:       pcap,
			Module:     module,
		}
		err = captureOpt.OK()
		if err != nil {
			return
		}
		_ = capture.Capture(&captureOpt)
		return
	},
}

func init() {
	rootCmd.AddCommand(captureCmd)
	captureCmd.Flags().StringP("device", "d", capture.DefaultDevice, "Device to capture on")
	captureCmd.Flags().StringP("filter", "F", capture.DefaultBPFFilter, "BPF filter")
	captureCmd.Flags().BoolP("promiscuous", "P", capture.DefaultPromiscuous, "Promiscuous Mode")
	captureCmd.Flags().IntP("framesize", "f", capture.DefaultFrameSize, "Frame Size")
	captureCmd.Flags().IntP("blocksize", "b", capture.DefaultBlockSize, "Block Size (MB)")
	captureCmd.Flags().IntP("numblock", "n", capture.DefaultNumBlock, "Num Block")
	captureCmd.Flags().Uint64P("statsec", "s", capture.DefaultStatsSec, "Stats print interval")
	captureCmd.Flags().StringP("cpuprofile", "c", capture.DefaultCPUProfile, "File to store CPU profile")
	captureCmd.Flags().BoolP("vlan", "V", capture.DefaultVlan, "Use vlan")
	captureCmd.Flags().BoolP("multicore", "m", capture.DefaultFanout, "Use Fanout (multicore)")
	captureCmd.Flags().StringP("pcap", "p", capture.DefaultPcap, "Pcap file to store")
	captureCmd.Flags().StringP("module", "M", capture.DefaultModule, "Module to load")
}
