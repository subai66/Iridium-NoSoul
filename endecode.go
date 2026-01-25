package main

import (
	"encoding/binary"
	"fmt"
)

const (
	MainHeaderSize    = 8  // [reserved:4][payload_length:4]
	PayloadHeaderSize = 6  // [cmd:1][sub:1][proto_length:4]
	TotalHeaderSize   = MainHeaderSize + PayloadHeaderSize
	MaxPacketSize     = 1024 * 1024 // 1MB
)

// PacketData 表示解析后的数据包
type PacketData struct {
	MsgID     int
	Cmd       byte
	Sub       byte
	ProtoData []byte
	RawData   []byte
}

// TCPStreamBuffer TCP 流缓冲区，用于处理粘包/拆包
type TCPStreamBuffer struct {
	buffer []byte
}

// NewTCPStreamBuffer 创建新的流缓冲区
func NewTCPStreamBuffer() *TCPStreamBuffer {
	return &TCPStreamBuffer{
		buffer: make([]byte, 0),
	}
}

// Append 追加数据到缓冲区
func (s *TCPStreamBuffer) Append(data []byte) {
	s.buffer = append(s.buffer, data...)
}

// TryDecode 尝试从缓冲区解码数据包
// 返回解码的数据包列表
func (s *TCPStreamBuffer) TryDecode() ([]*PacketData, error) {
	var packets []*PacketData

	for {
		packet, bytesConsumed, err := decodePacket(s.buffer)
		if err != nil {
			return packets, err
		}
		if packet == nil {
			// 数据不足，等待更多数据
			break
		}

		packets = append(packets, packet)
		s.buffer = s.buffer[bytesConsumed:]
	}

	return packets, nil
}

// Clear 清空缓冲区
func (s *TCPStreamBuffer) Clear() {
	s.buffer = s.buffer[:0]
}

// decodePacket 解码单个数据包
// 返回: 数据包, 消耗的字节数, 错误
func decodePacket(buffer []byte) (*PacketData, int, error) {
	if len(buffer) < MainHeaderSize {
		return nil, 0, nil // 数据不足
	}

	// 解析 Main Header
	// [0:4] reserved (uint32, little-endian)
	// [4:8] payload_length (uint32, little-endian)
	reserved := binary.LittleEndian.Uint32(buffer[0:4])
	payloadLen := binary.LittleEndian.Uint32(buffer[4:8])

	_ = reserved // 保留字段，暂不使用

	// 验证长度
	if payloadLen > MaxPacketSize || payloadLen < PayloadHeaderSize {
		return nil, 0, fmt.Errorf("invalid packet length: payload=%d", payloadLen)
	}

	fullPacketLen := MainHeaderSize + int(payloadLen)
	if len(buffer) < fullPacketLen {
		return nil, 0, nil // 数据不足，等待更多数据
	}

	// 解析 Payload Header
	// [8]   cmd (byte)
	// [9]   sub (byte)
	// [10:14] proto_length (uint32, little-endian)
	cmd := buffer[8]
	sub := buffer[9]
	protoLen := binary.LittleEndian.Uint32(buffer[10:14])

	// 计算 MsgID: cmd * 1000 + sub
	msgID := int(cmd)*1000 + int(sub)

	// 提取 Proto 数据
	var protoData []byte
	if protoLen > 0 {
		protoData = make([]byte, protoLen)
		copy(protoData, buffer[TotalHeaderSize:TotalHeaderSize+int(protoLen)])
	}

	// 保存原始数据
	rawData := make([]byte, fullPacketLen)
	copy(rawData, buffer[:fullPacketLen])

	packet := &PacketData{
		MsgID:     msgID,
		Cmd:       cmd,
		Sub:       sub,
		ProtoData: protoData,
		RawData:   rawData,
	}

	return packet, fullPacketLen, nil
}

// EncodePacket 编码数据包
func EncodePacket(msgID int, protoData []byte) []byte {
	cmd := byte(msgID / 1000)
	sub := byte(msgID % 1000)
	protoLen := uint32(len(protoData))
	payloadLen := uint32(PayloadHeaderSize) + protoLen

	packet := make([]byte, MainHeaderSize+payloadLen)

	// Main Header
	binary.LittleEndian.PutUint32(packet[0:4], 0)          // reserved
	binary.LittleEndian.PutUint32(packet[4:8], payloadLen) // payload_length

	// Payload Header
	packet[8] = cmd
	packet[9] = sub
	binary.LittleEndian.PutUint32(packet[10:14], protoLen) // proto_length

	// Proto Data
	if len(protoData) > 0 {
		copy(packet[TotalHeaderSize:], protoData)
	}

	return packet
}

// SplitMsgID 从 MsgID 获取 cmd 和 sub
func SplitMsgID(msgID int) (cmd byte, sub byte) {
	return byte(msgID / 1000), byte(msgID % 1000)
}

// CombineMsgID 从 cmd 和 sub 组合 MsgID
func CombineMsgID(cmd, sub byte) int {
	return int(cmd)*1000 + int(sub)
}

// GetPacketInfo 获取数据包的可读描述
func GetPacketInfo(packet *PacketData) string {
	return fmt.Sprintf("[MsgID=%d (cmd=%d, sub=%d), proto_len=%d]",
		packet.MsgID, packet.Cmd, packet.Sub, len(packet.ProtoData))
}
