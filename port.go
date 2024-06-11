package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type PortResult struct {
	port   int
	status string
}

func sendFin(target string, port int) {
	handle, err := pcap.OpenLive("eth0", 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	ipLayer := &layers.IPv4{
		SrcIP:    net.ParseIP("your_source_ip"),
		DstIP:    net.ParseIP(target),
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(port),
		Seq:     1105024978,
		Window:  14600,
		ACK:     false,
		SYN:     false,
		FIN:     true,
		PSH:     false,
		URG:     false,
		RST:     false,
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buffer, opts, ipLayer, tcpLayer)

	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Sent FIN packet to %s:%d\n", target, port)
}

func sendWindow(target string, port int) {
	handle, err := pcap.OpenLive("eth0", 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	ipLayer := &layers.IPv4{
		SrcIP:    net.ParseIP("your_source_ip"),
		DstIP:    net.ParseIP(target),
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(port),
		Seq:     1105024978,
		Window:  14600,
		ACK:     false,
		SYN:     false,
		FIN:     false,
		PSH:     false,
		URG:     false,
		RST:     false,
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buffer, opts, ipLayer, tcpLayer)

	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Sent Window packet to %s:%d\n", target, port)
}

func sendXmas(target string, port int) {
	handle, err := pcap.OpenLive("eth0", 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	ipLayer := &layers.IPv4{
		SrcIP:    net.ParseIP("your_source_ip"),
		DstIP:    net.ParseIP(target),
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(port),
		Seq:     1105024978,
		Window:  14600,
		ACK:     false,
		SYN:     false,
		FIN:     true,
		PSH:     true,
		URG:     true,
		RST:     false,
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buffer, opts, ipLayer, tcpLayer)

	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Sent Xmas packet to %s:%d\n", target, port)
}

func portTarama(protocol, ip string, port int, results chan<- PortResult, wg *sync.WaitGroup) {
	defer wg.Done()
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.Dial(protocol, address)
	if err != nil {
		results <- PortResult{port: port, status: "Kapalı"}
		return
	}
	conn.Close()
	results <- PortResult{port: port, status: "Açık"}
}

func checkHostActive(ip string) {
	targetIP := net.ParseIP(ip)
	conn, err := net.Dial("ip4:icmp", ip)
	if err != nil {
		fmt.Println("Bağlantı hatası:", err)
		return
	}
	defer conn.Close()

	echoRequest := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("Hello ICMP"),
		},
	}

	echoRequestBytes, err := echoRequest.Marshal(nil)
	if err != nil {
		fmt.Println("ICMP paketi oluşturma hatası:", err)
		return
	}

	start := time.Now()
	if _, err := conn.Write(echoRequestBytes); err != nil {
		fmt.Println("ICMP paketi gönderme hatası:", err)
		return
	}

	reply := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(reply)
	if err != nil {
		fmt.Println("Hedef aktif değil veya yanıt vermedi.")
		return
	}

	duration := time.Since(start)
	echoReply, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		fmt.Println("ICMP yanıtını ayrıştırma hatası:", err)
		return
	}

	switch echoReply.Type {
	case ipv4.ICMPTypeEchoReply:
		fmt.Printf("ICMP yanıtı %s: seq=%d zaman=%v\n", targetIP, echoReply.Body.(*icmp.Echo).Seq, duration)
	default:
		fmt.Println("Hedef yanıt vermedi.")
	}
}

func sendPacket(targetIP net.IP, targetPort layers.TCPPort, flags ,layers.TCPFlag) {
	handle, err := pcap.OpenLive("eth0", 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	ipLayer := &layers.IPv4{
		SrcIP:    net.ParseIP("your_source_ip"),
		DstIP:    targetIP,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: targetPort,
		Seq:     1105024978,
		Window:  14600,
		Flags:   flags,
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buffer, opts, ipLayer, tcpLayer)

	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Sent packet with flags %v to %s:%d\n", flags, targetIP, targetPort)
}

func bilgi(string protocol) {
	var ip string
	var port1, port2 int
	var protocol string
	var kapalıChoice int

	fmt.Print("İp adresini girin: ")
	fmt.Scan(&ip)

	fmt.Print("Başlangıç portunu giriniz: ")
	fmt.Scan(&port1)

	fmt.Print("Bitiş portunu giriniz: ")
	fmt.Scan(&port2)

	fmt.Print("Protokolü seçiniz: \n [1] Tcp \n [2] Udp \n \n Sayı girin: ")
	var protocolChoice int
	fmt.Scan(&protocolChoice)

	fmt.Print("Kapalı portları görmek istiyor musunuz? \n [1] Evet \n [2] Hayır \n Lütfen sayı girin: ")
	fmt.Scan(&kapalıChoice)

	if protocolChoice == 1 {
		protocol = "tcp"
	} else {
		protocol = "udp"
	}

	results := make(chan PortResult)
	var wg sync.WaitGroup

	for port := port1; port <= port2; port++ {
		wg.Add(1)
		go portTarama(protocol, ip, port, results, &wg)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	openPorts := []int{}
	closedPorts := []int{}

	for result := range results {
		if result.status == "Açık" {
			openPorts = append(openPorts, result.port)
		} else {
			closedPorts = append(closedPorts, result.port)
		}
	}

	fmt.Println("Açık portlar:")
	for _, port := range openPorts {
		fmt.Printf("%d\n", port)
	}

	if kapalıChoice == 1 {
		fmt.Println("Kapalı portlar:")
		for _, port := range closedPorts {
			fmt.Printf("%d\n", port)
		}
	}

	fmt.Println("Tarama tamamlandı.")

	// ICMP aktiflik kontrolü
	checkHostActive(ip)

	// Ekstra tarama yöntemleri
	fmt.Println("Ekstra tarama yöntemleri başlatılıyor...")
	targetIP := net.ParseIP(ip)
	for _, port := range openPorts {
		// FIN Scan
		sendPacket(targetIP, layers.TCPPort(port), layers.TCPFlagFin)
		// TCP Window Scan
		sendPacket(targetIP, layers.TCPPort(port), layers.TCPFlagAck)
		// Xmas Scan
		sendPacket(targetIP, layers.TCPPort(port), layers.TCPFlagFin|layers.TCPFlagPsh|layers.TCPFlagUrg)
	}
}

func main(string ip) {
	bilgi()
}
