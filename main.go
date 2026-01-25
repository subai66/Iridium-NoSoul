package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/google/gopacket/pcap"
)

type Config struct {
	DeviceName        string   `json:"deviceName"`
	PacketFilter      []string `json:"packetFilter"`
	AutoSavePcapFiles bool     `json:"autoSavePcapFiles"`
	TargetPortMin     uint16   `json:"targetPortMin"`
	TargetPortMax     uint16   `json:"targetPortMax"`
}

var config Config
var packetFilter map[string]bool

func main() {
	listDevices := flag.Bool("l", false, "List all network devices")
	ipAddress := flag.String("ip", "", "Select device by IP address")
	flag.Parse()

	// 加载配置
	configData, err := os.ReadFile("./config.json")
	if err != nil {
		color.Red("Could not load ./config.json: %v", err)
		os.Exit(1)
	}

	err = json.Unmarshal(configData, &config)
	if err != nil {
		color.Red("Could not parse ./config.json: %v", err)
		os.Exit(1)
	}

	// 初始化包过滤器
	packetFilter = make(map[string]bool)
	for _, filter := range config.PacketFilter {
		if filter != "" {
			packetFilter[filter] = true
		}
	}

	// 列出设备
	if *listDevices {
		listAllDevices()
		return
	}

	// 初始化 Proto 解析器
	InitProto()

	// 选择设备
	deviceName := config.DeviceName
	if *ipAddress != "" {
		deviceName = findDeviceByIP(*ipAddress)
		if deviceName == "" {
			color.Red("Could not find device with IP: %s", *ipAddress)
			os.Exit(1)
		}
	}

	if deviceName == "" {
		color.Yellow("No device specified. Use -l to list devices or set deviceName in config.json")
		listAllDevices()
		return
	}

	color.Green("===========================================")
	color.Green("  NotesOfSoul TCP Packet Sniffer")
	color.Green("  Target Port: %d - %d", config.TargetPortMin, config.TargetPortMax)
	color.Green("  Device: %s", deviceName)
	color.Green("===========================================")
	color.Cyan("Web UI: http://localhost:1984/")
	color.Yellow("Click 'Start Capture' in the web UI to begin.")

	// 启动前端服务器（阻塞）
	startServer()
}

func listAllDevices() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		color.Red("Error finding devices: %v", err)
		return
	}

	color.Cyan("Available network devices:")
	fmt.Println()

	for i, device := range devices {
		color.Yellow("[%d] %s", i, device.Name)
		if device.Description != "" {
			color.White("    Description: %s", device.Description)
		}
		for _, addr := range device.Addresses {
			color.Green("    IP: %s", addr.IP)
		}
		fmt.Println()
	}
}

func findDeviceByIP(ip string) string {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return ""
	}

	for _, device := range devices {
		for _, addr := range device.Addresses {
			if addr.IP.String() == ip {
				return device.Name
			}
		}
	}
	return ""
}
