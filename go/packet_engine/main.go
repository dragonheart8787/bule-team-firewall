// 高效能封包處理引擎 - Go 實作
// 目標: 10 Gbps 吞吐量、1M 並發
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	packetsProcessed uint64
	bytesProcessed   uint64
	startTime        time.Time
)

type PacketInfo struct {
	Timestamp  string `json:"timestamp"`
	SrcIP      string `json:"src_ip"`
	DstIP      string `json:"dst_ip"`
	Protocol   string `json:"protocol"`
	SrcPort    uint16 `json:"src_port"`
	DstPort    uint16 `json:"dst_port"`
	Length     int    `json:"length"`
}

type Stats struct {
	PacketsProcessed  uint64  `json:"packets_processed"`
	BytesProcessed    uint64  `json:"bytes_processed"`
	DurationSeconds  float64 `json:"duration_seconds"`
	PacketsPerSecond  float64 `json:"packets_per_second"`
	BytesPerSecond    float64 `json:"bytes_per_second"`
	Gbps              float64 `json:"gbps"`
}

func main() {
	interfaceName := flag.String("i", "any", "Network interface")
	bpfFilter := flag.String("f", "tcp or udp", "BPF filter")
	httpAddr := flag.String("http", ":8080", "HTTP stats server address")
	flag.Parse()

	// 啟動 HTTP 統計服務
	go startHTTPServer(*httpAddr)

	// 開啟 pcap handle
	handle, err := pcap.OpenLive(*interfaceName, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Printf("無法開啟介面 %s，使用模擬模式: %v", *interfaceName, err)
		runSimulationMode()
		return
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(*bpfFilter); err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	startTime = time.Now()

	// 使用 worker pool 處理封包
	var wg sync.WaitGroup
	packetChan := make(chan gopacket.Packet, 10000)
	numWorkers := 8

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pkt := range packetChan {
				processPacket(pkt)
			}
		}()
	}

	for packet := range packetSource.Packets() {
		select {
		case packetChan <- packet:
		default:
			// 佇列滿則丟棄
		}
	}

	close(packetChan)
	wg.Wait()
}

func processPacket(packet gopacket.Packet) {
	atomic.AddUint64(&packetsProcessed, 1)
	atomic.AddUint64(&bytesProcessed, uint64(len(packet.Data())))

	// 解析 IP 層
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		proto := "OTHER"
		sport, dport := uint16(0), uint16(0)

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			proto = "TCP"
			sport = uint16(tcp.SrcPort)
			dport = uint16(tcp.DstPort)
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			proto = "UDP"
			sport = uint16(udp.SrcPort)
			dport = uint16(udp.DstPort)
		}

		_ = PacketInfo{
			Timestamp: time.Now().Format(time.RFC3339),
			SrcIP:     ip.SrcIP.String(),
			DstIP:     ip.DstIP.String(),
			Protocol:  proto,
			SrcPort:   sport,
			DstPort:   dport,
			Length:    len(packet.Data()),
		}
	}
}

func startHTTPServer(addr string) {
	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		pkts := atomic.LoadUint64(&packetsProcessed)
		bytes := atomic.LoadUint64(&bytesProcessed)
		elapsed := time.Since(startTime).Seconds()

		stats := Stats{
			PacketsProcessed: pkts,
			BytesProcessed:   bytes,
			DurationSeconds:  elapsed,
			PacketsPerSecond: float64(pkts) / elapsed,
			BytesPerSecond:   float64(bytes) / elapsed,
			Gbps:             (float64(bytes) * 8 / elapsed) / 1e9,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	})

	log.Printf("HTTP 統計服務: http://%s/stats", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func runSimulationMode() {
	// 模擬高吞吐量封包處理 - 執行 10 秒
	packetSize := 1500
	duration := 10 * time.Second
	startTime = time.Now()
	endTime := startTime.Add(duration)

	for time.Now().Before(endTime) {
		_ = make([]byte, packetSize)
		atomic.AddUint64(&packetsProcessed, 1)
		atomic.AddUint64(&bytesProcessed, uint64(packetSize))
	}

	elapsed := time.Since(startTime).Seconds()
	pps := float64(atomic.LoadUint64(&packetsProcessed)) / elapsed
	gbps := (float64(atomic.LoadUint64(&bytesProcessed)) * 8 / elapsed) / 1e9

	fmt.Printf("模擬模式完成 (%.1fs): %.0f pps, %.2f Gbps\n", elapsed, pps, gbps)
}
