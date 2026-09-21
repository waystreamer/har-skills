package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/waystreamer/har-skills/cmd/har/internal"
	har "github.com/waystreamer/har-skills/pkg/har"
)

// valueTraceCmd 值溯源：cookie-trace 的泛化，追踪任意值在整个 HAR 里的出现位置
var valueTraceCmd = &cobra.Command{
	Use:   "value-trace <value>",
	Short: "溯源任意值：它在哪些请求/响应的哪些字段出现过",
	Long: `在整个 HAR 中追踪一个值的所有出现位置。

搜索范围：URL、query 参数、请求/响应 header、cookie、POST 参数、请求体、响应体。
除精确匹配外，还可匹配 URL-encode / base64 / hex 编码后的变体。

这回答逆向分析的核心问题："这个 token / sign / session 值是谁发的、谁在用？"
比 cookie-trace 更通用：cookie-trace 只查 cookie，value-trace 查所有字段。

输出的 INDEX 是全局索引，可直接喂 extract --index 看完整请求/响应。

示例:
  har -f capture.har value-trace "abc123def"                    # 基础溯源
  har -f capture.har value-trace "token=xyz" --base64           # 含 base64 变体
  har -f capture.har value-trace "sess-999" --no-body           # 跳过 body（大文件快）
  har -f capture.har value-trace "sig" --format json            # JSON 输出`,
	Args: cobra.ExactArgs(1),
	RunE: runValueTrace,
}

func init() {
	rootCmd.AddCommand(valueTraceCmd)
	valueTraceCmd.Flags().Bool("no-body", false, "跳过请求体/响应体搜索（大 HAR 加速）")
	valueTraceCmd.Flags().Bool("url-encode", true, "额外匹配 URL-encode 后的值（默认开启）")
	valueTraceCmd.Flags().Bool("base64", false, "额外匹配 base64 编码后的值（可能误报）")
	valueTraceCmd.Flags().Bool("hex", false, "额外匹配 hex 编码后的值（可能误报）")
	valueTraceCmd.Flags().Bool("from-response", false, "只看响应侧（header/cookie/body），找值的来源")
	valueTraceCmd.Flags().Bool("first-only", false, "只报首次出现位置（大 HAR 快速定位）")
	valueTraceCmd.Flags().Int("url-max", 60, "URL 显示截断长度（0=不截断）")
	valueTraceCmd.Flags().Int("context", 40, "匹配位置上下文字符数（默认 40）")
}

func runValueTrace(cmd *cobra.Command, args []string) error {
	h := internal.LoadHar(cmd, args)
	noBody, _ := cmd.Flags().GetBool("no-body")
	urlEnc, _ := cmd.Flags().GetBool("url-encode")
	b64, _ := cmd.Flags().GetBool("base64")
	hexEnc, _ := cmd.Flags().GetBool("hex")
	fromResponse, _ := cmd.Flags().GetBool("from-response")
	firstOnly, _ := cmd.Flags().GetBool("first-only")
	urlMax, _ := cmd.Flags().GetInt("url-max")
	ctxLen, _ := cmd.Flags().GetInt("context")

	value := args[0]

	opts := har.ValueTraceOptions{
		IncludeBody:       !noBody,
		IncludeURLEncoded: urlEnc,
		IncludeBase64:     b64,
		IncludeHex:        hexEnc,
		ContextLen:        ctxLen,
	}

	report := h.TraceValue(value, opts)

	// --from-response: 只保留响应侧的命中
	if fromResponse {
		var filtered []har.ValueLocation
		for _, loc := range report.Locations {
			if loc.Direction == "response" {
				filtered = append(filtered, loc)
			}
		}
		report.Locations = filtered
		report.TotalHits = len(filtered)
		if len(filtered) > 0 {
			first := filtered[0]
			report.FirstSeen = &first
		} else {
			report.FirstSeen = nil
		}
	}

	// --first-only: 只保留首次出现
	if firstOnly && len(report.Locations) > 1 {
		report.Locations = report.Locations[:1]
		report.TotalHits = 1
	}

	return internal.WriteOutput(cmd, report, func() string {
		return formatValueTraceText(report, urlMax)
	}, nil)
}

func formatValueTraceText(r *har.ValueTraceReport, urlMax int) string {
	var sb strings.Builder

	displayValue := r.Value
	if len(displayValue) > 50 {
		displayValue = displayValue[:50] + "..."
	}
	sb.WriteString(fmt.Sprintf("值溯源: %q\n", displayValue))
	sb.WriteString(strings.Repeat("=", 78) + "\n")

	if r.TotalHits == 0 {
		sb.WriteString("未找到该值。\n")
		sb.WriteString("提示: 值区分大小写；若值可能被编码，试试 --base64 或 --hex。\n")
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("共 %d 处出现\n", r.TotalHits))
	if r.FirstSeen != nil {
		sb.WriteString(fmt.Sprintf("首次出现: [%d] %s %s (%s.%s)\n",
			r.FirstSeen.EntryIndex, r.FirstSeen.Method,
			truncateURL(r.FirstSeen.EntryURL, urlMax),
			r.FirstSeen.Direction, r.FirstSeen.FieldType))
	}

	// 按 direction + field_type 分组显示
	type groupKey struct {
		direction string
		fieldType string
	}
	groups := make(map[groupKey][]har.ValueLocation)
	var groupOrder []groupKey
	for _, loc := range r.Locations {
		k := groupKey{loc.Direction, loc.FieldType}
		if _, ok := groups[k]; !ok {
			groupOrder = append(groupOrder, k)
		}
		groups[k] = append(groups[k], loc)
	}

	for _, k := range groupOrder {
		locs := groups[k]
		sb.WriteString(fmt.Sprintf("\n%s / %s (%d 处):\n", k.direction, k.fieldType, len(locs)))
		for _, loc := range locs {
			name := ""
			if loc.FieldName != "" {
				name = fmt.Sprintf(" [%s]", loc.FieldName)
			}
			matchNote := ""
			if loc.MatchType != "exact" {
				matchNote = fmt.Sprintf(" (%s)", loc.MatchType)
			}
			sb.WriteString(fmt.Sprintf("  idx=%-5d %-4s%s%s %s\n",
				loc.EntryIndex, loc.Method, name, matchNote,
				truncateURL(loc.EntryURL, urlMax)))
			if loc.Context != "" {
				sb.WriteString(fmt.Sprintf("    %s\n", loc.Context))
			}
		}
	}

	sb.WriteString(fmt.Sprintf("\n提示: idx 为全局 entry 索引，可喂 `extract --index N` 查看完整条目。\n"))
	if urlMax > 0 {
		sb.WriteString("(URL 已截断到 --url-max)\n")
	}
	return sb.String()
}
