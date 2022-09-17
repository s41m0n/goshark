package cmd

import (
	"github.com/s41m0n/goshark/go/sorter"
	"github.com/spf13/cobra"
)

var sorterCmd = &cobra.Command{
	Use:   "sorter",
	Short: "Sort Pcaps",
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		pcaps, err := cmd.Flags().GetStringArray("pcaps")
		if err != nil {
			return
		}
		output, err := cmd.Flags().GetString("output")
		if err != nil {
			return
		}
		err = sorter.Sort(pcaps, output)
		return
	},
}

func init() {
	rootCmd.AddCommand(sorterCmd)
	sorterCmd.Flags().StringArrayP("pcaps", "p", []string{}, "Pcaps to sort")
	sorterCmd.Flags().StringP("output", "o", "", "Output file")
}
