package cmd

import (
	// "fmt"
	"log"

	"net-ninja/pkg/sniffer"
	"github.com/spf13/cobra"
)

// openCmd represents the open command
var openCmd = &cobra.Command{
	Use:   "open",
	Short: "TODO",
	Long: `TODO`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		path := args[0]

		filter, err := cmd.Flags().GetString("filter")
		if err != nil{
			log.Fatal(err)
			return
		}
	
		num, err := cmd.Flags().GetInt("num")
		if err != nil{
			log.Fatal(err)
			return
		}
		
		report, err := cmd.Flags().GetBool("report")
		if err != nil{
			log.Fatal(err)
			return
		}
		var tcp, udp, ipv4, ipv6, dns, icmp, layers, showPacket bool

		filterParams := &FilterParams{
			TCP: tcp,
			UDP: udp,
			IPv4: ipv4,
			IPv6: ipv6,
			DNS: dns,
			ICMP: icmp,
			Layers: layers,
			ShowPacket: showPacket,
		}

		parseFilters(filter, filterParams)
		
		props := sniffer.OpenOfflineParams{
			FilePath: path,
			MaxPacket: num,
			Report: report,
			Tcp: tcp,
			Udp: udp,
			Ipv4: ipv4,
			Ipv6: ipv6,
			Dns: dns,
			Icmp: icmp,
			Layers: layers,
			ShowPacket: showPacket,
		}

		sniffer.OpenOffline(props)
	},
}

func init() {
	RootCmd.AddCommand(openCmd)

	openCmd.Flags().StringP("filter", "f", "", "wanted layers, for exp: TCP, UDP, ...")
	openCmd.Flags().BoolP("report", "r", false, "want report")

	openCmd.Flags().IntP("num","n",-1,"Maximum number of packets to capture")
}
