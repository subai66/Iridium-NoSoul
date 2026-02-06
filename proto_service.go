package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/desc/protoparse"
	"github.com/jhump/protoreflect/dynamic"
)

var (
	protoMap    map[int]*desc.MessageDescriptor
	protoIdMap  map[int]string
	protoParser *protoparse.Parser
)

// InitProto 初始化 Proto 解析器
func InitProto() {
	protoMap = make(map[int]*desc.MessageDescriptor)
	protoIdMap = make(map[int]string)

	// 加载 packetIds.json
	loadPacketIds()

	// 加载 proto 文件
	loadProto()
}

// loadPacketIds 加载数据包 ID 映射
func loadPacketIds() {
	data, err := os.ReadFile("./data/packetIds.json")
	if err != nil {
		color.Yellow("Warning: Could not load ./data/packetIds.json: %v", err)
		color.Yellow("Proto names will not be available.")
		return
	}

	// packetIds.json 格式: {"102001": "MsgName", ...}
	var idMap map[string]string
	err = json.Unmarshal(data, &idMap)
	if err != nil {
		color.Yellow("Warning: Could not parse packetIds.json: %v", err)
		return
	}

	// 解析映射: ID (string) -> Name
	for idStr, name := range idMap {
		var id int
		_, err := fmt.Sscanf(idStr, "%d", &id)
		if err != nil {
			continue
		}
		protoIdMap[id] = name
	}

	color.Green("Loaded %d packet IDs", len(protoIdMap))
}

// loadProto 加载 proto 文件
func loadProto() {
	protoDir := "./data/proto"

	// 检查目录是否存在
	if _, err := os.Stat(protoDir); os.IsNotExist(err) {
		color.Yellow("Warning: Proto directory not found: %s", protoDir)
		color.Yellow("Proto parsing will not be available.")
		return
	}

	// 获取所有 .proto 文件
	protoFiles, err := filepath.Glob(filepath.Join(protoDir, "*.proto"))
	if err != nil || len(protoFiles) == 0 {
		color.Yellow("Warning: No proto files found in %s", protoDir)
		return
	}

	// 提取文件名列表
	var fileNames []string
	for _, f := range protoFiles {
		fileNames = append(fileNames, filepath.Base(f))
	}

	// 创建解析器
	protoParser = &protoparse.Parser{
		ImportPaths: []string{protoDir},
	}

	// 解析所有 proto 文件
	fds, err := protoParser.ParseFiles(fileNames...)
	if err != nil {
		color.Yellow("Warning: Could not parse proto files: %v", err)
		return
	}

	if len(fds) == 0 {
		color.Yellow("Warning: No proto definitions found")
		return
	}

	// 建立消息名称到描述符的映射
	msgMap := make(map[string]*desc.MessageDescriptor)
	for _, fd := range fds {
		for _, msg := range fd.GetMessageTypes() {
			msgMap[msg.GetName()] = msg
			// 也添加带包名的版本
			fullName := msg.GetFullyQualifiedName()
			msgMap[fullName] = msg
		}
	}

	// 将 ID 映射到消息描述符
	mappedCount := 0
	unmappedCount := 0
	for id, name := range protoIdMap {
		// 尝试不同的名称格式
		if msgDesc, ok := msgMap[name]; ok {
			protoMap[id] = msgDesc
			mappedCount++
		} else {
			// 尝试去掉可能的前缀
			simpleName := name
			if idx := strings.LastIndex(name, "."); idx >= 0 {
				simpleName = name[idx+1:]
			}
			if msgDesc, ok := msgMap[simpleName]; ok {
				protoMap[id] = msgDesc
				mappedCount++
			} else {
				unmappedCount++
				// 只打印前几个未映射的消息
				if unmappedCount <= 5 {
					color.Yellow("  Unmapped: %d -> %s", id, name)
				}
			}
		}
	}

	// 统计总消息数
	totalMsgTypes := 0
	for _, fd := range fds {
		totalMsgTypes += len(fd.GetMessageTypes())
	}
	color.Green("Loaded %d proto files with %d message types", len(fds), totalMsgTypes)
	color.Green("Mapped %d packet IDs to proto messages (%d unmapped)", mappedCount, unmappedCount)
}

// GetProtoById 根据 ID 获取消息描述符
func GetProtoById(id int) *desc.MessageDescriptor {
	return protoMap[id]
}

// GetProtoNameById 根据 ID 获取消息名称
func GetProtoNameById(id int) string {
	return protoIdMap[id]
}

// parseProto 解析 proto 数据
func parseProto(id int, data []byte) *dynamic.Message {
	msgDesc := GetProtoById(id)
	if msgDesc == nil {
		color.Yellow("Debug: No proto descriptor for ID %d (name: %s)", id, GetProtoNameById(id))
		return nil
	}

	msg := dynamic.NewMessage(msgDesc)
	err := msg.Unmarshal(data)
	if err != nil {
		color.Yellow("Debug: Failed to unmarshal proto ID %d (%s): %v", id, msgDesc.GetName(), err)
		color.Yellow("Debug: Data length: %d, Data (hex): %x", len(data), data[:min(len(data), 64)])
		return nil
	}

	return msg
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// parseProtoToJson 解析 proto 数据为 JSON 字符串
func parseProtoToJson(id int, data []byte) string {
	msg := parseProto(id, data)
	if msg == nil {
		return ""
	}

	jsonBytes, err := msg.MarshalJSON()
	if err != nil {
		return ""
	}

	return string(jsonBytes)
}

// parseProtoToInterface 解析 proto 数据为 interface{}
func parseProtoToInterface(id int, data []byte) interface{} {
	msg := parseProto(id, data)
	if msg == nil {
		// 正常解析失败，尝试原始解码
		return decodeRaw(data)
	}

	// 转换为 map
	jsonBytes, err := msg.MarshalJSON()
	if err != nil {
		return nil
	}

	var result interface{}
	err = json.Unmarshal(jsonBytes, &result)
	if err != nil {
		return nil
	}

	return result
}

// decodeRaw 原始解码 protobuf 数据（类似 protoc --decode_raw）
func decodeRaw(data []byte) interface{} {
	if len(data) == 0 {
		return nil
	}

	result := make(map[string]interface{})
	result["_raw_decode"] = true
	fields := decodeRawFields(data)
	if fields != nil {
		result["fields"] = fields
	}
	return result
}

// decodeRawFields 解码原始字段
func decodeRawFields(data []byte) []map[string]interface{} {
	var fields []map[string]interface{}
	pos := 0

	for pos < len(data) {
		// 读取 tag
		tag, newPos := readVarint(data, pos)
		if newPos == pos {
			break
		}
		pos = newPos

		fieldNum := tag >> 3
		wireType := tag & 0x07

		field := make(map[string]interface{})
		field["field"] = fieldNum

		switch wireType {
		case 0: // Varint
			value, newPos := readVarint(data, pos)
			if newPos == pos {
				break
			}
			pos = newPos
			field["type"] = "varint"
			field["value"] = value
			// 尝试解释为有符号数
			if value > 0x7FFFFFFFFFFFFFFF {
				field["signed"] = int64(value)
			}

		case 1: // 64-bit
			if pos+8 > len(data) {
				break
			}
			value := uint64(data[pos]) | uint64(data[pos+1])<<8 | uint64(data[pos+2])<<16 | uint64(data[pos+3])<<24 |
				uint64(data[pos+4])<<32 | uint64(data[pos+5])<<40 | uint64(data[pos+6])<<48 | uint64(data[pos+7])<<56
			pos += 8
			field["type"] = "fixed64"
			field["value"] = value

		case 2: // Length-delimited
			length, newPos := readVarint(data, pos)
			if newPos == pos || pos+int(length) > len(data) {
				break
			}
			pos = newPos
			fieldData := data[pos : pos+int(length)]
			pos += int(length)

			field["type"] = "bytes"
			field["length"] = length

			// 尝试解释为字符串
			if str := tryDecodeString(fieldData); str != "" {
				field["string"] = str
			} else {
				// 尝试解释为嵌套消息
				nested := decodeRawFields(fieldData)
				if nested != nil && len(nested) > 0 {
					field["nested"] = nested
				} else {
					// 显示为十六进制
					field["hex"] = bytesToHex(fieldData)
				}
			}

		case 5: // 32-bit
			if pos+4 > len(data) {
				break
			}
			value := uint32(data[pos]) | uint32(data[pos+1])<<8 | uint32(data[pos+2])<<16 | uint32(data[pos+3])<<24
			pos += 4
			field["type"] = "fixed32"
			field["value"] = value

		default:
			// 未知 wire type，跳过
			break
		}

		if len(field) > 1 {
			fields = append(fields, field)
		}
	}

	return fields
}

// readVarint 读取 varint
func readVarint(data []byte, pos int) (uint64, int) {
	var result uint64
	var shift uint
	for pos < len(data) {
		b := data[pos]
		result |= uint64(b&0x7f) << shift
		pos++
		if b&0x80 == 0 {
			return result, pos
		}
		shift += 7
		if shift > 63 {
			break
		}
	}
	return result, pos
}

// tryDecodeString 尝试解码为 UTF-8 字符串
func tryDecodeString(data []byte) string {
	// 检查是否是有效的 UTF-8 字符串
	for _, b := range data {
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			return ""
		}
	}
	s := string(data)
	// 检查是否全是可打印字符
	for _, r := range s {
		if r < 32 && r != '\n' && r != '\r' && r != '\t' {
			return ""
		}
	}
	return s
}

// bytesToHex 转换为十六进制字符串
func bytesToHex(data []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(data)*2)
	for i, b := range data {
		result[i*2] = hexChars[b>>4]
		result[i*2+1] = hexChars[b&0x0f]
	}
	return string(result)
}
