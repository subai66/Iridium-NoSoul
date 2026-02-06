package main

import (
	"embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
)

//go:embed frontend/public/*
var frontendFS embed.FS

var (
	eventStream   chan string
	eventClients  map[chan string]bool
	clientsMutex  sync.Mutex
)

func init() {
	eventStream = make(chan string, 100)
	eventClients = make(map[chan string]bool)

	// 广播事件到所有客户端
	go func() {
		for event := range eventStream {
			clientsMutex.Lock()
			for client := range eventClients {
				select {
				case client <- event:
				default:
					// 客户端缓冲区满，跳过
				}
			}
			clientsMutex.Unlock()
		}
	}()
}

// notifyFrontend 通知前端有新数据包
func notifyFrontend(pkt *Packet) {
	data := map[string]interface{}{
		"time":      pkt.Time.Format("15:04:05.000"),
		"direction": pkt.Direction,
		"cmdType":   pkt.CmdType,
		"paramType": pkt.ParamType,
		"msgId":     pkt.MsgID,
		"name":      pkt.Name,
		"data":      pkt.Data,
		"rawHex":    hex.EncodeToString(pkt.RawData),
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return
	}

	select {
	case eventStream <- string(jsonBytes):
	default:
		// 缓冲区满，丢弃
	}
}

// embedFileSystem 包装嵌入的文件系统
type embedFileSystem struct {
	http.FileSystem
}

func (e embedFileSystem) Exists(prefix string, path string) bool {
	_, err := e.Open(path)
	return err == nil
}

// EmbedFolder 创建嵌入文件系统
func EmbedFolder(fsEmbed embed.FS, targetPath string) http.FileSystem {
	subFS, err := fs.Sub(fsEmbed, targetPath)
	if err != nil {
		panic(err)
	}
	return http.FS(subFS)
}

// startServer 启动前端服务器
func startServer() {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	// API 路由
	api := router.Group("/api")
	{
		api.GET("/start", handleStart)
		api.GET("/stop", handleStop)
		api.GET("/clear", handleClear)
		api.GET("/packets", handleGetPackets)
		api.POST("/upload", handleUpload)
		api.GET("/stream", handleStream)
		api.GET("/config", handleGetConfig)
	}

	// 静态文件
	router.NoRoute(func(c *gin.Context) {
		// 尝试从嵌入的文件系统提供文件
		path := c.Request.URL.Path
		if path == "/" {
			path = "/index.html"
		}

		file, err := frontendFS.ReadFile("frontend/public" + path)
		if err != nil {
			c.String(http.StatusNotFound, "Not Found")
			return
		}

		// 设置内容类型
		contentType := "text/html"
		switch filepath.Ext(path) {
		case ".js":
			contentType = "application/javascript"
		case ".css":
			contentType = "text/css"
		case ".json":
			contentType = "application/json"
		case ".png":
			contentType = "image/png"
		case ".svg":
			contentType = "image/svg+xml"
		}

		c.Data(http.StatusOK, contentType, file)
	})

	color.Cyan("Frontend server running at http://localhost:1984/")
	router.Run(":1984")
}

// handleStart 开始捕获
func handleStart(c *gin.Context) {
	if capturing {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Already capturing"})
		return
	}

	deviceName := c.Query("device")
	if deviceName == "" {
		deviceName = config.DeviceName
	}

	if deviceName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No device specified"})
		return
	}

	go openCapture(deviceName)
	c.JSON(http.StatusOK, gin.H{"status": "started"})
}

// handleStop 停止捕获
func handleStop(c *gin.Context) {
	stopCapture()
	c.JSON(http.StatusOK, gin.H{"status": "stopped"})
}

// handleClear 清空数据包
func handleClear(c *gin.Context) {
	clearPackets()
	c.JSON(http.StatusOK, gin.H{"status": "cleared"})
}

// handleGetPackets 获取所有数据包
func handleGetPackets(c *gin.Context) {
	pkts := getPackets()

	result := make([]map[string]interface{}, len(pkts))
	for i, pkt := range pkts {
		result[i] = map[string]interface{}{
			"time":      pkt.Time.Format("15:04:05.000"),
			"direction": pkt.Direction,
			"cmdType":   pkt.CmdType,
			"paramType": pkt.ParamType,
			"msgId":     pkt.MsgID,
			"name":      pkt.Name,
			"data":      pkt.Data,
			"rawHex":    hex.EncodeToString(pkt.RawData),
		}
	}

	c.JSON(http.StatusOK, result)
}

// handleUpload 上传 PCAP 文件
func handleUpload(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
		return
	}

	// 保存到临时目录
	tempDir := os.TempDir()
	tempFile := filepath.Join(tempDir, file.Filename)

	err = c.SaveUploadedFile(file, tempFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
		return
	}

	// 处理 PCAP 文件
	go openPcap(tempFile)

	c.JSON(http.StatusOK, gin.H{"status": "processing", "file": tempFile})
}

// handleStream SSE 事件流
func handleStream(c *gin.Context) {
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("Access-Control-Allow-Origin", "*")

	// 创建客户端通道
	clientChan := make(chan string, 10)

	clientsMutex.Lock()
	eventClients[clientChan] = true
	clientsMutex.Unlock()

	defer func() {
		clientsMutex.Lock()
		delete(eventClients, clientChan)
		clientsMutex.Unlock()
		close(clientChan)
	}()

	c.Stream(func(w io.Writer) bool {
		select {
		case event, ok := <-clientChan:
			if !ok {
				return false
			}
			c.SSEvent("packet", event)
			return true
		case <-c.Request.Context().Done():
			return false
		}
	})
}

// handleGetConfig 获取配置
func handleGetConfig(c *gin.Context) {
	c.JSON(http.StatusOK, config)
}
