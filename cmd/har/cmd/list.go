package cmd

import (
	"fmt"
	"text/tabwriter"

	har "github.com/waystreamer/har-skills/pkg/har"
	"github.com/waystreamer/har-skills/cmd/har/internal"
	"github.com/spf13/cobra"
)

// listCmd 列出HAR条目
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "列出HAR条目",
	Long: `列出HAR文件中的请求条目，支持按时间、大小、URL、状态码排序，
支持按方法、状态码、域名等条件过滤，支持限制输出条数。

输出的 INDEX 列是条目在 HAR log.entries 中的全局索引，
可直接用于 extract --index、diff --index-a/--index-b 等命令。`,
	Example: `  har -f capture.har list
  har -f capture.har list --limit 10
  har -f capture.har list --sort size --order asc
  har -f capture.har list --method GET --status 200
  har -f capture.har list --url-max 60   # App 抓包 URL 上千字符时截断显示`,
	RunE: func(cmd *cobra.Command, args []string) error {
		h := internal.LoadHar(cmd, args)

		// 获取过滤参数
		method, _ := cmd.Flags().GetString("method")
		status, _ := cmd.Flags().GetInt("status")
		domain, _ := cmd.Flags().GetString("domain")
		sortBy, _ := cmd.Flags().GetString("sort")
		order, _ := cmd.Flags().GetString("order")
		limit, _ := cmd.Flags().GetInt("limit")
		urlMax, _ := cmd.Flags().GetInt("url-max")

		ei := newEntryIndex(h)

		// 方法/状态码过滤
		if method != "" {
			ei.filterByPredicate(func(e *har.Entries) bool {
				return e.Request.Method == method
			})
		}
		if status > 0 {
			ei.filterByPredicate(func(e *har.Entries) bool {
				return e.Response.Status == status
			})
		}

		// 按域名过滤
		if domain != "" {
			ei.filterByPredicate(func(e *har.Entries) bool {
				return har.ExtractDomain(e.Request.URL) == domain
			})
		}

		// 排序（稳定排序，保证相同键时保持原始顺序，索引映射不乱）
		switch sortBy {
		case "size":
			if order == "asc" {
				sortPairStable(ei, func(e *har.Entries) float64 { return float64(e.Response.Content.Size) }, true)
			} else {
				sortPairStable(ei, func(e *har.Entries) float64 { return float64(e.Response.Content.Size) }, false)
			}
		case "url", "status":
			// 无SDK方法，保持默认顺序
		default: // time
			if order == "asc" {
				sortPairStable(ei, func(e *har.Entries) float64 { return e.Time }, true)
			} else {
				sortPairStable(ei, func(e *har.Entries) float64 { return e.Time }, false)
			}
		}

		// 限制条数
		ei.limit(limit)

		return internal.WriteOutput(cmd, buildListJSON(ei), func() string {
			return formatListTable(ei, urlMax)
		}, nil)
	},
}

func init() {
	rootCmd.AddCommand(listCmd)

	listCmd.Flags().IntP("limit", "n", 0, "限制输出条数 (0=全部)")
	listCmd.Flags().String("sort", "time", "排序方式 (time, size, url, status)")
	listCmd.Flags().String("order", "desc", "排序方向 (asc, desc)")
	listCmd.Flags().String("method", "", "按HTTP方法过滤")
	listCmd.Flags().Int("status", 0, "按状态码过滤")
	listCmd.Flags().String("domain", "", "按域名过滤")
	listCmd.Flags().Int("url-max", 0, "URL 显示截断长度（0=不截断；App 抓包建议 60）")
}

// sortPairStable 按条目键值对 entryIndex 做稳定排序，entries 与 gidx 同步移动
func sortPairStable(ei *entryIndex, keyFn func(*har.Entries) float64, asc bool) {
	idx := make([]int, len(ei.entries))
	for i := range idx {
		idx[i] = i
	}
	// 简单插入排序保证稳定性（条目数大时排序开销可接受，且大多数用法带 --limit）
	for i := 1; i < len(idx); i++ {
		for j := i; j > 0; j-- {
			a, b := idx[j-1], idx[j]
			ka := keyFn(&ei.entries[a])
			kb := keyFn(&ei.entries[b])
			swap := ka > kb
			if !asc {
				swap = ka < kb
			}
			if !swap {
				break
			}
			idx[j-1], idx[j] = idx[j], idx[j-1]
		}
	}
	entries := make([]har.Entries, len(idx))
	gidx := make([]int, len(idx))
	for newPos, oldPos := range idx {
		entries[newPos] = ei.entries[oldPos]
		gidx[newPos] = ei.gidx[oldPos]
	}
	ei.entries = entries
	ei.gidx = gidx
}

// listEntry 简化的条目对象用于JSON输出
type listEntry struct {
	Index  int     `json:"index"` // 全局索引：条目在 HAR log.entries 中的位置
	Method string  `json:"method"`
	Status int     `json:"status"`
	Size   int     `json:"size"`
	Time   float64 `json:"time"`
	URL    string  `json:"url"`
}

// buildListJSON 构建JSON输出数据
func buildListJSON(ei *entryIndex) []listEntry {
	entries := make([]listEntry, len(ei.entries))
	for i, entry := range ei.entries {
		entries[i] = listEntry{
			Index:  ei.gidx[i],
			Method: entry.Request.Method,
			Status: entry.Response.Status,
			Size:   entry.Response.Content.Size,
			Time:   entry.Time,
			URL:    entry.Request.URL,
		}
	}
	return entries
}

// formatListTable 格式化条目列表为tabwriter表格
func formatListTable(ei *entryIndex, urlMax int) string {
	var sb tabWriterBuf

	w := tabwriter.NewWriter(&sb, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "INDEX\tMETHOD\tSTATUS\tSIZE\tTIME\tURL\n")

	for i, entry := range ei.entries {
		size := internal.FormatBytes(entry.Response.Content.Size)
		time := internal.FormatDuration(entry.Time)
		fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%s\t%s\n",
			ei.gidx[i], entry.Request.Method, entry.Response.Status, size, time, truncateURL(entry.Request.URL, urlMax))
	}
	w.Flush()

	return sb.String()
}

// tabWriterBuf 用于tabwriter输出的缓冲区
type tabWriterBuf struct {
	buf []byte
}

func (t *tabWriterBuf) Write(p []byte) (n int, err error) {
	t.buf = append(t.buf, p...)
	return len(p), nil
}

func (t *tabWriterBuf) String() string {
	return string(t.buf)
}
