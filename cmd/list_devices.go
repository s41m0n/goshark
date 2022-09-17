package cmd

import (
	"log"

	"github.com/s41m0n/goshark/go/capture"

	"github.com/spf13/cobra"
)

var listDevicesCmd = &cobra.Command{
	Use:   "list_devices",
	Short: "Listen network devices",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		err = capture.ListDevices()
		if err != nil {
			log.Fatal(err)
		}
		return
	},
}

func init() {
	rootCmd.AddCommand(listDevicesCmd)
}
