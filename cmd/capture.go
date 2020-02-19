package cmd

import (
	// "fmt"
	"log"
	"strings"
	
	"net-ninja/pkg/sniffer"
	"github.com/spf13/cobra"
)

// captureCmd represents the capture command
var captureCmd = &cobra.Command{
	Use:   "capture",
	Short: "TODO",
	Long: `TODO`,
	Run: func(cmd *cobra.Command, args []string) {
		
		device, err := cmd.Flags().GetString("interface")
		if err != nil{
			log.Fatal(err)
			return
		}
		
		pcapOutPath, err := cmd.Flags().GetString("output")
		if err != nil{
			log.Fatal(err)
			return
		}

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

		props := FilterParams{
			TCP: tcp,
			UDP: udp,
			IPv4: ipv4,
			IPv6: ipv6,
			DNS: dns,
			ICMP: icmp,
			Layers: layers,
			ShowPacket: showPacket,
		}

		parseFilters(filter, &props)
		
		CapProps := sniffer.CaptureLiveParams{
			DeviceName: device,
			PcapPath: pcapOutPath,
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

		sniffer.CaptureLive(CapProps)
	},
}

type FilterParams struct {
	TCP        bool
	UDP        bool
	IPv4       bool
	IPv6       bool
	DNS        bool
	ICMP       bool
	Layers     bool
	ShowPacket bool
}

func parseFilters(filter string, params *FilterParams) {
	filter = strings.ToLower(filter)
	if strings.Contains(filter, "tcp") {
		params.TCP = true
	}
	if strings.Contains(filter, "udp") {
		params.UDP = true
	}
	if strings.Contains(filter, "ipv4") {
		params.IPv4 = true
	}
	if strings.Contains(filter, "ipv6") {
		params.IPv6 = true
	}
	if strings.Contains(filter, "dns") {
		params.DNS = true
	}
	if strings.Contains(filter, "icmp") {
		params.ICMP = true
	}
	if strings.Contains(filter, "layers") {
		params.Layers = true
	}
	if strings.Contains(filter, "packet") {
		params.ShowPacket = true
	}
	if strings.Contains(filter, "all") {
		params.TCP = true
		params.UDP = true
		params.IPv4 = true
		params.IPv6 = true
		params.DNS = true
		params.ICMP = true
		params.Layers = true
		params.ShowPacket = true
	}
}

func init() {
	RootCmd.AddCommand(captureCmd)

	captureCmd.Flags().StringP("interface", "i", "", "Network interface")
	captureCmd.Flags().StringP("output", "o", "", "save capture results in path/file.pcap")
	captureCmd.Flags().StringP("filter", "f", "", "wanted layers, for exp: TCP, UDP, ...")
	captureCmd.Flags().BoolP("report", "r", false, "want report")

	captureCmd.Flags().IntP("num","n",-1,"Maximum number of packets to capture")
}
