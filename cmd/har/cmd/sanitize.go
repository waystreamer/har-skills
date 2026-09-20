package cmd

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/waystreamer/har-skills/cmd/har/internal"
	"github.com/spf13/cobra"
)

// sanitizeCmd 清洗第三方工具导出的 HAR，使其通过严格校验
var sanitizeCmd = &cobra.Command{
	Use:   "sanitize <input.har>",
	Short: "清洗 HAR 使其通过校验（Reqable/Charles/Fiddler 导出预处理）",
	Long: `清洗第三方抓包工具导出的 HAR 文件，修正常见的不合规字段，输出可直接
被所有子命令（以及 har_skills 生态其它工具）加载的干净 HAR。

处理项（就地修正，原始文件只读）：
  timings.send/wait/receive 为 -1 或缺失  -> 归零（HAR 规范允许 -1，但旧校验器拒绝）
  timings.blocked/dns/connect/ssl 为负     -> 归 -1（规范表示"不适用"）
  entry.time 为负或缺失                    -> 归零
  response.content.mimeType 缺失           -> 补 application/octet-stream
  request.postData.mimeType 缺失           -> 补 application/octet-stream
  name 为空的 cookie/header/query 参数     -> 补 "unnamed-N"（保留数据，满足校验）
  响应残缺（status 非 100..599 或无 httpVersion）-> 丢弃该条并计数（中断/失败请求，编造状态码会污染分析）
  startedDateTime 缺失/非法                -> 补 Unix 纪元（仅加 --fix-time 时；默认丢弃）

不经过严格解析器：直接操作 JSON，损坏再严重也能洗。

示例:
  har sanitize raw.har -o clean.har
  har sanitize raw.har -o clean.har --fix-time
  type raw.har | har sanitize - -o clean.har`,
	Args: cobra.ExactArgs(1),
	RunE: runSanitize,
}

func init() {
	rootCmd.AddCommand(sanitizeCmd)
	sanitizeCmd.Flags().Bool("fix-time", false, "startedDateTime 缺失时补 Unix 纪元而不是丢弃该条")
}

// sanitizeStats 计数器，输出改了什么丢了几条
type sanitizeStats struct {
	counters map[string]int
}

func newSanitizeStats() *sanitizeStats { return &sanitizeStats{counters: map[string]int{}} }
func (s *sanitizeStats) add(k string) { s.counters[k]++ }

func runSanitize(cmd *cobra.Command, args []string) error {
	fixTime, _ := cmd.Flags().GetBool("fix-time")
	outPath := internal.GetOutputPath(cmd)
	if outPath == "" {
		return fmt.Errorf("必须指定 -o <输出路径>，sanitize 不覆盖原文件")
	}

	// 读原始字节（支持 - 从 stdin、支持 .gz）
	data, err := readInputBytes(args[0])
	if err != nil {
		return err
	}

	// 直接走 map 解析，绕过严格校验器
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("JSON 解析失败（文件可能不是 HAR）: %w", err)
	}

	logRaw, ok := doc["log"]
	if !ok {
		return fmt.Errorf("缺少 log 字段，不是 HAR 文件")
	}
	var logObj map[string]json.RawMessage
	if err := json.Unmarshal(logRaw, &logObj); err != nil {
		return fmt.Errorf("log 字段不是对象: %w", err)
	}

	entriesRaw, ok := logObj["entries"]
	if !ok {
		return fmt.Errorf("log.entries 缺失")
	}
	var entries []map[string]interface{}
	if err := json.Unmarshal(entriesRaw, &entries); err != nil {
		return fmt.Errorf("log.entries 解析失败: %w", err)
	}

	stats := newSanitizeStats()
	kept := make([]map[string]interface{}, 0, len(entries))
	droppedStatus := map[string]int{}

	for _, e := range entries {
		resp, _ := e["response"].(map[string]interface{})
		if resp == nil {
			stats.add("dropped_broken_response")
			droppedStatus["<missing>"]++
			continue
		}

		// 响应残缺：status 不在 100..599 或缺 httpVersion -> 丢弃
		statusF, ok := resp["status"].(float64)
		status := int(statusF)
		httpVersion, _ := resp["httpVersion"].(string)
		if !ok || status < 100 || status > 599 || httpVersion == "" {
			stats.add("dropped_broken_response")
			droppedStatus[fmt.Sprintf("%v", resp["status"])]++
			continue
		}

		// timings 修正
		if timings, ok := e["timings"].(map[string]interface{}); ok {
			for _, k := range []string{"send", "wait", "receive"} {
				if v, ok := timings[k].(float64); !ok || v < 0 {
					timings[k] = 0
					stats.add("fixed_timings_" + k)
				}
			}
			for _, k := range []string{"blocked", "dns", "connect", "ssl"} {
				if v, ok := timings[k].(float64); ok && v < 0 {
					timings[k] = -1
					stats.add("fixed_timings_" + k)
				}
			}
		}

		// entry.time 为负或缺失 -> 归零
		if v, ok := e["time"].(float64); !ok || v < 0 {
			e["time"] = 0
			stats.add("fixed_time")
		}

		// content.mimeType 缺失 -> 补
		if content, ok := resp["content"].(map[string]interface{}); ok {
			if mt, _ := content["mimeType"].(string); mt == "" {
				content["mimeType"] = "application/octet-stream"
				stats.add("fixed_content_mimetype")
			}
		}

		// postData.mimeType 缺失 -> 补
		if req, ok := e["request"].(map[string]interface{}); ok {
			if post, ok := req["postData"].(map[string]interface{}); ok {
				if mt, _ := post["mimeType"].(string); mt == "" {
					post["mimeType"] = "application/octet-stream"
					stats.add("fixed_postdata_mimetype")
				}
			}
			// 无名 cookie/header/query 补占位名（保留数据）
			fixNameList(req, "cookies", "unnamed-cookie", stats)
			fixNameList(req, "headers", "unnamed-header", stats)
			fixNameList(req, "queryString", "unnamed-param", stats)
		}
		fixNameList(resp, "cookies", "unnamed-cookie", stats)
		fixNameList(resp, "headers", "unnamed-header", stats)

		// startedDateTime 处理
		if sdt, _ := e["startedDateTime"].(string); sdt == "" {
			if fixTime {
				e["startedDateTime"] = time.Unix(0, 0).UTC().Format(time.RFC3339Nano)
				stats.add("fixed_startedDateTime")
			} else {
				stats.add("dropped_no_startedDateTime")
				continue
			}
		}

		kept = append(kept, e)
	}

	// 写回
	keptRaw, err := json.Marshal(kept)
	if err != nil {
		return fmt.Errorf("序列化清洗结果失败: %w", err)
	}
	logObj["entries"] = keptRaw
	logRaw2, err := json.Marshal(logObj)
	if err != nil {
		return fmt.Errorf("序列化 log 失败: %w", err)
	}
	doc["log"] = logRaw2
	out, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("序列化输出失败: %w", err)
	}

	if err := os.WriteFile(outPath, out, 0644); err != nil {
		return fmt.Errorf("无法写入 '%s': %w", outPath, err)
	}

	// 报告（走 stderr 之外的 WriteStringOutput 不合适——这里需要结构化汇总，直接打印）
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("sanitize 完成: %s -> %s\n", args[0], outPath))
	sb.WriteString(fmt.Sprintf("entries: %d -> %d\n", len(entries), len(kept)))
	keys := make([]string, 0, len(stats.counters))
	for k := range stats.counters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sb.WriteString(fmt.Sprintf("  %-30s %d\n", k, stats.counters[k]))
	}
	if len(droppedStatus) > 0 {
		sb.WriteString(fmt.Sprintf("  dropped response.status 分布: %v\n", droppedStatus))
	}
	sb.WriteString("现在可以对该文件运行任何子命令（已跳过加载期校验，但其它工具可能需要合规文件）。\n")
	fmt.Print(sb.String())
	return nil
}

// fixNameList 把 list 中 name 为空的项补占位名
func fixNameList(parent map[string]interface{}, field, prefix string, stats *sanitizeStats) {
	arr, ok := parent[field].([]interface{})
	if !ok {
		return
	}
	n := 0
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if name, _ := m["name"].(string); name == "" {
			n++
			m["name"] = fmt.Sprintf("%s-%d", prefix, n)
			stats.add("fixed_empty_name_" + field)
		}
	}
}

// readInputBytes 读取输入（支持 "-" 从 stdin；gzip 文件按魔数自动解压）
func readInputBytes(path string) ([]byte, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("无法读取 '%s': %w", path, err)
	}
	// gzip 魔数检测，自动解压
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("gzip 解压失败: %w", err)
		}
		defer zr.Close()
		return io.ReadAll(zr)
	}
	return data, nil
}
