package main

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// Packet 表示捕获的数据包
// 使用 CmdType + ParamType 二级路由
type Packet struct {
	Time      time.Time
	Direction string // "C2S" 或 "S2C"
	CmdType   int    // 一级命令类型
	ParamType int    // 二级命令类型
	MsgID     int    // 消息ID = CmdType * 1000 + ParamType
	Name      string
	Data      interface{}
	RawData   []byte
}

var (
	packets     []Packet
	packetMutex sync.Mutex
	handle      *pcap.Handle
	capturing   bool
)

// tcpStreamFactory 实现 tcpassembly.StreamFactory
type tcpStreamFactory struct{}

// tcpStream 实现 tcpassembly.Stream
type tcpStream struct {
	net, transport gopacket.Flow
	reader         tcpreader.ReaderStream
	buffer         *TCPStreamBuffer
	direction      string
}

func (f *tcpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	s := &tcpStream{
		net:       net,
		transport: transport,
		reader:    tcpreader.NewReaderStream(),
		buffer:    NewTCPStreamBuffer(),
	}

	// 判断方向 - 检查端口是否在范围内
	srcPort := transport.Src().String()
	dstPort := transport.Dst().String()

	srcPortNum, _ := strconv.Atoi(srcPort)
	dstPortNum, _ := strconv.Atoi(dstPort)

	if dstPortNum >= int(config.TargetPortMin) && dstPortNum <= int(config.TargetPortMax) {
		s.direction = "C2S"
	} else if srcPortNum >= int(config.TargetPortMin) && srcPortNum <= int(config.TargetPortMax) {
		s.direction = "S2C"
	} else {
		s.direction = "UNK"
	}

	go s.run()
	return &s.reader
}

func (s *tcpStream) run() {
	buf := make([]byte, 4096)
	for {
		n, err := s.reader.Read(buf)
		if err != nil {
			return
		}
		if n > 0 {
			s.buffer.Append(buf[:n])
			s.processPackets()
		}
	}
}

func (s *tcpStream) processPackets() {
	packets, err := s.buffer.TryDecode()
	if err != nil {
		color.Red("Decode error: %v", err)
		s.buffer.Clear()
		return
	}

	for _, pkt := range packets {
		handlePacket(pkt, s.direction)
	}
}

// handlePacket 处理解析后的数据包
func handlePacket(pkt *PacketData, direction string) {
	// 获取 Proto 名称（使用 MsgID 查找）
	protoName := GetProtoNameById(pkt.MsgID)
	if protoName == "" {
		protoName = fmt.Sprintf("Unknown_%d", pkt.MsgID)
	}

	// 检查过滤器
	if len(packetFilter) > 0 {
		if _, filtered := packetFilter[protoName]; filtered {
			return
		}
	}

	// 解析 Proto 数据
	var parsedData interface{}
	if len(pkt.ProtoData) > 0 {
		parsedData = parseProtoToInterface(pkt.MsgID, pkt.ProtoData)
	}

	// 创建 Packet 记录
	packet := Packet{
		Time:      time.Now(),
		Direction: direction,
		CmdType:   pkt.CmdType,
		ParamType: pkt.ParamType,
		MsgID:     pkt.MsgID,
		Name:      protoName,
		Data:      parsedData,
		RawData:   pkt.RawData,
	}

	// 添加到列表
	packetMutex.Lock()
	packets = append(packets, packet)
	packetMutex.Unlock()

	// 打印日志
	logPacket(&packet)

	// 发送到前端
	notifyFrontend(&packet)
}

// logPacket 打印数据包日志
func logPacket(pkt *Packet) {
	var dirColor *color.Color
	var arrow string

	if pkt.Direction == "C2S" {
		dirColor = color.New(color.FgCyan)
		arrow = ">>>"
	} else {
		dirColor = color.New(color.FgYellow)
		arrow = "<<<"
	}

	timestamp := pkt.Time.Format("15:04:05.000")
	// 显示格式: [时间] 方向 [CmdType=X, Param=Y, MsgID=Z] 消息名称
	dirColor.Printf("[%s] %s [Cmd=%d, Param=%d, MsgID=%d] %s\n",
		timestamp, arrow, pkt.CmdType, pkt.ParamType, pkt.MsgID, pkt.Name)

	// 如果有解析的数据，打印 JSON
	if pkt.Data != nil {
		jsonStr := parseProtoToJson(pkt.MsgID, pkt.RawData[TotalHeaderSize:])
		if jsonStr != "" {
			color.White("    %s\n", jsonStr)
		}
	}
}

// openCapture 打开实时捕获
func openCapture(deviceName string) {
	var err error

	// 先设置 capturing 状态
	capturing = true

	// 构建 BPF 过滤器 - 支持端口范围
	bpfFilter := fmt.Sprintf("tcp portrange %d-%d", config.TargetPortMin, config.TargetPortMax)

	color.Cyan("Opening device: %s", deviceName)
	color.Cyan("BPF Filter: %s", bpfFilter)

	handle, err = pcap.OpenLive(deviceName, 65535, true, pcap.BlockForever)
	if err != nil {
		color.Red("Error opening device: %v", err)
		capturing = false
		return
	}
	defer handle.Close()

	err = handle.SetBPFFilter(bpfFilter)
	if err != nil {
		color.Red("Error setting BPF filter: %v", err)
		capturing = false
		return
	}
	color.Green("Capture started. Press Ctrl+C to stop.")

	// 创建 TCP 组装器
	streamFactory := &tcpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// 自动保存 PCAP
	var pcapWriter *pcapgo.Writer
	var pcapFile *os.File
	if config.AutoSavePcapFiles {
		filename := fmt.Sprintf("capture_%s.pcap", time.Now().Format("20060102_150405"))
		pcapFile, err = os.Create(filename)
		if err != nil {
			color.Yellow("Warning: Could not create pcap file: %v", err)
		} else {
			defer pcapFile.Close()
			pcapWriter = pcapgo.NewWriter(pcapFile)
			pcapWriter.WriteFileHeader(65535, handle.LinkType())
			color.Green("Saving to: %s", filename)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		if !capturing {
			break
		}

		// 保存到 PCAP 文件
		if pcapWriter != nil {
			pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}

		// 处理 TCP 包
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			assembler.AssembleWithTimestamp(
				packet.NetworkLayer().NetworkFlow(),
				tcp,
				packet.Metadata().Timestamp,
			)
		}
	}
}

// openPcap 打开 PCAP 文件进行分析
func openPcap(filename string) {
	var err error

	color.Cyan("Opening pcap file: %s", filename)

	handle, err = pcap.OpenOffline(filename)
	if err != nil {
		color.Red("Error opening pcap file: %v", err)
		return
	}
	defer handle.Close()

	// 设置过滤器 - 支持端口范围
	bpfFilter := fmt.Sprintf("tcp portrange %d-%d", config.TargetPortMin, config.TargetPortMax)
	err = handle.SetBPFFilter(bpfFilter)
	if err != nil {
		color.Red("Error setting BPF filter: %v", err)
		return
	}

	// 清空之前的数据包
	packetMutex.Lock()
	packets = nil
	packetMutex.Unlock()

	// 创建 TCP 组装器
	streamFactory := &tcpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			assembler.AssembleWithTimestamp(
				packet.NetworkLayer().NetworkFlow(),
				tcp,
				packet.Metadata().Timestamp,
			)
		}
	}

	// 刷新所有流
	assembler.FlushAll()

	color.Green("Finished processing pcap file. Total packets: %d", len(packets))
}

// stopCapture 停止捕获
func stopCapture() {
	capturing = false
	if handle != nil {
		handle.Close()
	}
	color.Yellow("Capture stopped.")
}

// getPackets 获取所有数据包
func getPackets() []Packet {
	packetMutex.Lock()
	defer packetMutex.Unlock()
	return packets
}

// clearPackets 清空数据包
func clearPackets() {
	packetMutex.Lock()
	defer packetMutex.Unlock()
	packets = nil
}
