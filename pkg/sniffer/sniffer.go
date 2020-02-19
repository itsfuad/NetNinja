package sniffer

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"net-ninja/pkg/filehandler"
	"net-ninja/pkg/report"
)
const(
	snapshotLen int32 = 65535
	promiscuous bool = false
	timeout time.Duration = -1 * time.Second
)
var (

	tcpCount, udpCount, icmpCount int
	ipPacket map[string]int
	ipFragments map[uint16]int
	minPacketSize, maxPacketSize uint16
	totalPacketsCount int
	totalPacketsLength uint64

	writer *pcapgo.Writer
	pcapFile *os.File

	shouldContinue bool
)
func RunConsole(){
	fmt.Println("[$] Starting Console...")
	reader := bufio.NewReader(os.Stdin)
	for {
		input,_ := reader.ReadString('\n')

		cmdStr := strings.Split(input, " ")[0]
		cmdStr = strings.Trim(cmdStr, "\n\r ")

		if cmdStr == "exit"{
			shouldContinue = false
		}
	}
}
func clearCounters(){
	udpCount = 0
	tcpCount = 0
	icmpCount = 0
	totalPacketsLength = 0
	totalPacketsCount = 0
	minPacketSize = 65535
	maxPacketSize = 0
	ipPacket = make(map[string]int)

	ipFragments = make(map[uint16]int)
	shouldContinue = true
}
type OpenOfflineParams struct {
	FilePath    string
	MaxPacket   int
	Report      bool
	Tcp         bool
	Udp         bool
	Ipv4        bool
	Ipv6        bool
	Dns         bool
	Icmp        bool
	Layers      bool
	ShowPacket  bool
}

func OpenOffline(params OpenOfflineParams) error {
	filePath := params.FilePath
	maxPacket := params.MaxPacket
	report := params.Report
	tcp := params.Tcp
	udp := params.Udp
	ipv4 := params.Ipv4
	ipv6 := params.Ipv6
	dns := params.Dns
	icmp := params.Icmp
	layers := params.Layers
	showPacket := params.ShowPacket
	handle, err := pcap.OpenOffline(filePath)
	if err != nil{
		log.Fatal(err)
		return err
	}
	defer handle.Close()

	return ReadPackets(ReadPacketsParams{
		Handle: handle,
		MaxPacket: maxPacket,
		NeedReport: report,
		TCP: tcp,
		UDP: udp,
		IPv4: ipv4,
		IPv6: ipv6,
		DNS: dns,
		ICMP: icmp,
		Layers: layers,
		ShowPacket: showPacket,
	})
}
type CaptureLiveParams struct {
	DeviceName   string
	PcapPath     string
	MaxPacket    int
	Report       bool
	Tcp          bool
	Udp          bool
	Ipv4         bool
	Ipv6         bool
	Dns          bool
	Icmp         bool
	Layers       bool
	ShowPacket   bool
}

func CaptureLive(params CaptureLiveParams) error {
	deviceName := params.DeviceName
	pcapPath := params.PcapPath
	maxPacket := params.MaxPacket
	report := params.Report
	tcp := params.Tcp
	udp := params.Udp
	ipv4 := params.Ipv4
	ipv6 := params.Ipv6
	dns := params.Dns
	icmp := params.Icmp
	layers := params.Layers
	showPacket := params.ShowPacket

	handle, err := pcap.OpenLive(deviceName, snapshotLen, promiscuous, timeout)
	if err != nil{
		log.Fatal(err)
		return err
	}
	defer handle.Close()

	return ReadPackets(ReadPacketsParams{
		Handle: handle,
		MaxPacket: maxPacket,
		PcapOut: pcapPath,
		NeedReport: report,
		TCP: tcp,
		UDP: udp,
		IPv4: ipv4,
		IPv6: ipv6,
		DNS: dns,
		ICMP: icmp,
		Layers: layers,
		ShowPacket: showPacket,
	})
}
type ReadPacketsParams struct {
	Handle      *pcap.Handle
	MaxPacket   int
	PcapOut     string
	NeedReport  bool
	TCP         bool
	UDP         bool
	IPv4        bool
	IPv6        bool
	DNS         bool
	ICMP        bool
	Layers      bool
	ShowPacket  bool
}

func ReadPackets(params ReadPacketsParams) error {
	handle := params.Handle
	pcapOut := params.PcapOut
	needReport := params.NeedReport

	go RunConsole()
	clearCounters();
	if pcapOut != ""{
		writer, pcapFile, _ = filehandler.InitFile(pcapOut)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	LoopPack(packetSource, &params)

	defer pcapFile.Close()

	if needReport{
		report.Report(report.ReportParams{
			MaxPacketSize: maxPacketSize,
			MinPacketSize: minPacketSize,
			TotalPacketsLength: totalPacketsLength,
			TotalPacketsCount: totalPacketsCount,
			IPFragments: ipFragments,
			IPPacket: ipPacket,
			ICMPCount: icmpCount,
			TCPCount: tcpCount,
			UDPCount: udpCount,
		})
	}
	return nil
}

func processPacket(packet gopacket.Packet, params *ReadPacketsParams) {
	if params.Layers {
		printLayers(packet)
	}
	if params.TCP {
		checkTCP(packet)
	}
	if params.UDP {
		checkUDP(packet)
	}
	if params.IPv4 {
		checkIPv4(packet)
	}
	if params.IPv6 {
		checkIPv6(packet)
	}
	if params.ICMP {
		checkICMP(packet)
	}
	if params.ShowPacket {
		printPacket(packet)
	}
}

func LoopPack(packetSource *gopacket.PacketSource,params *ReadPacketsParams) {

	maxPacket := params.MaxPacket
	pcapOut := params.PcapOut

	for packet := range packetSource.Packets(){
		fmt.Println("=================================PACKET==================================")

		processPacket(packet, params)
		
		if pcapOut != "" {
			filehandler.SavePacket(writer, packet)
		}
		if maxPacket > 0 {
			maxPacket--;
			if maxPacket == 0{
				break
			}
		}
		if !shouldContinue{
			break
		}	
	}
}

func checkIPv4(packet gopacket.Packet){
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer != nil{
		ip, _ := ip4Layer.(*layers.IPv4)

		if value, ok := ipPacket[ip.SrcIP.String()]; !ok{
			ipPacket[ip.SrcIP.String()] = 1
		}else{
			ipPacket[ip.SrcIP.String()] = value + 1
		}

		if ip.Length > maxPacketSize{
			maxPacketSize = ip.Length
		}

		if ip.Length < minPacketSize {
			minPacketSize = ip.Length
		}
		totalPacketsLength += uint64(ip.Length)
		totalPacketsCount++;

		if (ip.FragOffset == 0 && ip.Flags == layers.IPv4MoreFragments) || ip.FragOffset > 0 {
			if _, ok := ipFragments[ip.Id]; !ok{
				ipFragments[ip.Id] = 1
			}
		}

		
		fmt.Println("Type:", ip.LayerType())
		fmt.Printf("From %s, To %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol:",ip.Protocol)
		fmt.Println("Flags:", ip.Flags)
		fmt.Println("FragOffset:", ip.FragOffset)
		fmt.Println("IHL:", ip.IHL)
		fmt.Println("Id:", ip.Id)
		printLength(ip.Length)
		fmt.Println("Options:", ip.Options)

		fmt.Println("Padding:", ip.Padding)
		printBaseLayer(ip.BaseLayer)
		printCheckSum(ip.Checksum)
		fmt.Println("TTL:", ip.TTL)
		fmt.Println("version:", ip.Version)
		fmt.Println("TOS:", ip.TOS)

		fmt.Println("##########################IPv4###############################")
	}
}

func printBaseLayer(baseLayer layers.BaseLayer){
	fmt.Println("BaseLayer:", baseLayer)
}

func printLength(length uint16){
	fmt.Printf("Length: %d\n", length)
}

func printCheckSum(sum uint16) {
	fmt.Printf("Checksum: %d\n", sum)
}

func checkIPv6(packet gopacket.Packet){
	ip6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ip6Layer != nil{
		ip6, _ := ip6Layer.(*layers.IPv6)
		
		fmt.Println("Type:", ip6.LayerType())
		fmt.Printf("From: %s, To: %s\n", ip6.SrcIP, ip6.DstIP)
		fmt.Println("HopByHop",ip6.HopByHop)
		fmt.Println("HopLimit",ip6.HopLimit)
		fmt.Println("FlowLabel",ip6.FlowLabel)
		fmt.Println("TrafficClass",ip6.TrafficClass)

		printLength(ip6.Length)
		fmt.Println("Content:", ip6.Contents)
		fmt.Println("Payload",ip6.Payload)

		fmt.Println("NextHeader",ip6.NextHeader)
		fmt.Println("##########################IPv6###############################")
	}
}
func checkTCP(packet gopacket.Packet){
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp,_ := tcpLayer.(*layers.TCP)
		tcpCount++;

		fmt.Println("Type:", tcp.LayerType())

		fmt.Printf("From port: %s, To port: %s\n", tcp.SrcPort, tcp.DstPort)
		fmt.Println("Options:", tcp.Options)
		fmt.Println("Padding:", tcp.Padding)
		fmt.Println("Urgent:", tcp.Urgent)
		fmt.Println("Window:", tcp.Window)
		fmt.Println("Seq:", tcp.Seq)
		fmt.Println("int Ack :", tcp.Ack)
		fmt.Println("Bool ACK:", tcp.ACK)
		fmt.Println("Bool CWR:", tcp.CWR)
		fmt.Println("Bool URG:", tcp.URG)
		fmt.Println("Bool ECE:", tcp.ECE)
		fmt.Println("Bool FIN:", tcp.FIN)
		fmt.Println("Bool NS:", tcp.NS)
		fmt.Println("Bool RST:", tcp.RST)
		fmt.Println("Bool PSH:", tcp.PSH)
		fmt.Println("Bool Syn:", tcp.SYN)
		fmt.Println("Offset:", tcp.DataOffset)

		fmt.Println("Content:", tcp.Contents)
		printCheckSum(tcp.Checksum)
		printBaseLayer(tcp.BaseLayer)
		
		fmt.Println("##########################TCP###############################")
	
	}
}
func checkUDP(packet gopacket.Packet){
	udpLayer := packet.Layer(gopacket.LayerType(layers.LayerTypeUDP))
	if udpLayer != nil {
		udpCount++;

		udp,_ := udpLayer.(*layers.UDP)
		fmt.Println("Type:", udp.LayerType())
		printLength(udp.Length)
		fmt.Println("SrcPort:", udp.SrcPort)
		fmt.Println("DstPort:", udp.DstPort)
		printCheckSum(udp.Checksum)
		printBaseLayer(udp.BaseLayer)
		fmt.Println("Payload:", udp.Payload)
		fmt.Println("Contents:", udp.Contents)

		fmt.Println("##########################UDP###############################")
	}
	
}
func checkICMP(packet gopacket.Packet){
	icmpLayer := packet.Layer(gopacket.LayerType(layers.LayerTypeICMPv4))
	if icmpLayer != nil {
		icmp,_ := icmpLayer.(*layers.ICMPv4)
		icmpCount++;
		fmt.Println("Type:", icmp.LayerType())
		fmt.Println("TypeCode:", icmp.TypeCode)
		fmt.Println("Id:", icmp.Id)
		fmt.Println("Seq:", icmp.Seq)
		printBaseLayer(icmp.BaseLayer)
		printCheckSum(icmp.Checksum)
		fmt.Println("Payload:", icmp.Payload)
		fmt.Println("##########################ICMP###############################")
	}
}

func printLayers(packet gopacket.Packet){

	fmt.Println("==================PACKET LAYERS===================")
	for _, layer := range packet.Layers(){
		fmt.Println(layer.LayerType())
	} 
}
func printPacket(packet gopacket.Packet){
	fmt.Println(packet)
}