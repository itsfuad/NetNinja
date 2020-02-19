package report

import( 
	"fmt"
	"sort"
	"time"
	"strconv"
	"net-ninja/pkg/filehandler"
)


type pair struct {
	Key   string
	Value int
}

type pairList []pair
func (p pairList) Len() int           { return len(p) }
func (p pairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p pairList) Less(i, j int) bool { return p[i].Value > p[j].Value }

type ReportParams struct {
	MaxPacketSize        uint16
	MinPacketSize        uint16
	TotalPacketsLength   uint64
	TotalPacketsCount    int
	IPFragments          map[uint16]int
	IPPacket             map[string]int
	ICMPCount            int
	TCPCount             int
	UDPCount             int
}

func Report(params ReportParams) {
	maxPacketSize := params.MaxPacketSize
	minPacketSize := params.MinPacketSize
	totalPacketsLength := params.TotalPacketsLength
	totalPacketsCount := params.TotalPacketsCount
	ipFragments := params.IPFragments
	ipPacket := params.IPPacket
	icmpCount := params.ICMPCount
	tcpCount := params.TCPCount
	udpCount := params.UDPCount
	fmt.Println("##############################################################")
	fmt.Println("max length:",maxPacketSize)
	fmt.Println("min length:",minPacketSize)
	fmt.Println("total length:",totalPacketsLength)
	fmt.Println("total count:", totalPacketsCount)
	fmt.Println("total icmp:",icmpCount)
	fmt.Println("total tcp:", tcpCount)
	fmt.Println("total udp:", udpCount)

	totalFragmentations := len(ipFragments)
	fmt.Println("total fragmentations:", totalFragmentations)

	t := time.Now().Unix()
	
	countParams := filehandler.CountRecordsParams{
		Path: "./reports/"+strconv.FormatInt(t, 10)+"-Counts.txt",
		MaxPacketSize: maxPacketSize,
		MinPacketSize: minPacketSize,
		TotalPacketsLength: totalPacketsLength,
		TotalPacketsCount: totalPacketsCount,
		ICMPCount: icmpCount,
		TCPCount: tcpCount,
		UDPCount: udpCount,
		TotalFragmentations: totalFragmentations,
	}

	filehandler.SaveCountRecords(countParams)
	filehandler.SaveIPPacketRecords("./reports/"+strconv.FormatInt(t, 10)+"-IpPacketsSorted.txt", ipPacket)
	p := make(pairList, len(ipPacket))

	i := 0
	for k, v := range ipPacket {
		p[i] = pair{k, v}
		i++
	}

	
	sort.Sort(p)
	//p is sorted
	
	for _, k := range p {
        fmt.Printf("%v\t%v\n", k.Key, k.Value)
    }

}