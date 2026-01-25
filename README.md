# NotesOfSoul TCP Packet Sniffer

灵境奇谈 TCP 数据包捕获器，基于 [Iridium-Ww](https://github.com/WutheringWavesGame/Iridium-Ww) 修改。

## 协议格式

```
┌─────────────────────────────────────────────────────────────┐
│ Main Header (8 bytes)                                       │
│   [0:4]  uint32 reserved      - 保留字段（始终为0）          │
│   [4:8]  uint32 payload_length - 有效载荷长度                │
├─────────────────────────────────────────────────────────────┤
│ Payload Header (6 bytes)                                    │
│   [0:1]  byte cmd             - 命令类型                    │
│   [1:2]  byte sub             - 子命令                      │
│   [2:6]  uint32 proto_length  - Protobuf数据长度            │
├─────────────────────────────────────────────────────────────┤
│ Protobuf Data (variable)                                    │
└─────────────────────────────────────────────────────────────┘

MsgID = cmd * 1000 + sub
例: cmd=103, sub=5 -> MsgID=103005
```

## 依赖

- Go 1.21+
- Npcap (Windows) 或 libpcap (Linux/macOS)

## 安装

```bash
cd Sniffer
go mod tidy
go build -o sniffer.exe
```

## 配置

编辑 `config.json`:

```json
{
    "deviceName": "",           // 网卡名称，留空则需要手动选择
    "packetFilter": [],         // 过滤的消息名称列表
    "autoSavePcapFiles": true,  // 自动保存 PCAP 文件
    "targetPort": 20000         // 目标端口
}
```

## 数据文件

在 `data/` 目录下放置:

- `packetIds.json` - 消息 ID 映射文件
- `NotesOfSoul.proto` - Protobuf 定义文件

### packetIds.json 格式

```json
{
    "LoginReq": 101001,
    "LoginRsp": 101002,
    ...
}
```

## 使用

### 列出网卡

```bash
./sniffer -l
```

### 通过 IP 选择网卡

```bash
./sniffer -ip 192.168.1.100
```

### 直接运行

```bash
./sniffer
```

### Web 界面

启动后访问: http://localhost:1984/

## 功能

- ✅ TCP 流重组
- ✅ 实时数据包捕获
- ✅ PCAP 文件分析
- ✅ Protobuf 解析
- ✅ Web 可视化界面
- ✅ 数据包过滤
- ✅ 自动保存 PCAP

## 与原版 Iridium-Ww 的区别

| 特性 | Iridium-Ww | NotesOfSoul Sniffer |
|------|------------|---------------------|
| 协议 | KCP (UDP) | TCP |
| 加密 | AES-ECB + RSA | 无加密 |
| 端口 | 13100-13120 | 可配置 (默认 20000) |
| 包头 | KCP 格式 | 自定义 14 字节头 |

## 许可证

MIT License
