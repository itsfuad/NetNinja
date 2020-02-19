package cmd

import (
	"net-ninja/pkg/list"
	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "TODO",
	Long: `TODO`,

	Run: func(cmd *cobra.Command, args []string) {
		list.ListDevices()
	},
}

func init() {
	RootCmd.AddCommand(listCmd)
}
