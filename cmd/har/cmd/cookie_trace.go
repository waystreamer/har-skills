package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/waystreamer/har-skills/cmd/har/internal"
	"github.com/spf13/cobra"
)

// cookieTraceCmd Cookie 溯源：哪个响应下发了它，之后哪些请求带它
var cookieTraceCmd = &cobra.Command{
	Use:   "cookie-trace <cookie-name>",
	Short: "溯源 Cookie：谁下发、谁携带、值怎么变",
	Long: `按时间顺序追踪一个 Cookie 在 HAR 里的完整生命周期：

  1. SET    —— 哪些响应通过 Set-Cookie / response.cookies 下发了它（含值）
  2. SENT   —— 之后哪些请求带上了它（含值、目标 URL、全局索引）
  3. 值变化 —— 值发生变化的位置（新值下发 vs 客户端未更新）

这回答逆向分析的常见问题："这个 cookie 是哪个请求发的？后面哪些请求依赖它？"
比 cookie --evolution 更直接：evolution 输出全量时间线，cookie-trace 只给
"下发点 / 携带点 / 变化点"三段式答案。

输出的 INDEX 是全局索引，可直接喂给 extract --index 看完整请求/响应。

示例:
  har -f capture.har cookie-trace BDUSS
  har -f capture.har cookie-trace session_id --format json
  har -f capture.har cookie-trace token --show-value=false   # 脱敏只看位置`,
	Args: cobra.ExactArgs(1),
	RunE: runCookieTrace,
}

func init() {
	rootCmd.AddCommand(cookieTraceCmd)
	cookieTraceCmd.Flags().Bool("show-value", true, "显示 Cookie 值（false 时只显示长度，用于脱敏）")
	cookieTraceCmd.Flags().Int("url-max", 0, "URL 显示截断长度（0=不截断；终端阅读建议 60）")
}

// cookieTraceEvent 生命周期中的一个事件
type cookieTraceEvent struct {
	Kind     string `json:"kind"`      // "set"（响应下发）或 "sent"（请求携带）
	Index    int    `json:"index"`     // 全局索引
	Time     string `json:"time"`      // startedDateTime
	Method   string `json:"method"`
	URL      string `json:"url"`
	Value    string `json:"value"`     // show-value=false 时为 "<len:NN>"
	ValueLen int    `json:"value_len"`
	Changed  bool   `json:"changed"`   // 相对上一事件值是否变化
}

type cookieTraceReport struct {
	Name        string             `json:"name"`
	SetCount    int                `json:"set_count"`
	SentCount   int                `json:"sent_count"`
	ChangeCount int                `json:"change_count"`
	FirstSet    *cookieTraceEvent  `json:"first_set,omitempty"`
	Events      []cookieTraceEvent `json:"events"`
}

func runCookieTrace(cmd *cobra.Command, args []string) error {
	h := internal.LoadHar(cmd, args)
	showValue, _ := cmd.Flags().GetBool("show-value")
	urlMax, _ := cmd.Flags().GetInt("url-max")
	name := args[0]

	report := &cookieTraceReport{Name: name}
	var lastValue string
	haveLast := false

	// HAR entries 通常按时间序，但显式按 startedDateTime 排序保证正确性
	order := make([]int, len(h.Log.Entries))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		return h.Log.Entries[order[a]].StartedDateTime.Before(h.Log.Entries[order[b]].StartedDateTime)
	})

	mask := func(v string) string {
		if showValue {
			return v
		}
		return fmt.Sprintf("<len:%d>", len(v))
	}

	for _, gi := range order {
		e := &h.Log.Entries[gi]

		// 请求携带
		for _, c := range e.Request.Cookies {
			if c.Name != name {
				continue
			}
			changed := haveLast && c.Value != lastValue
			ev := cookieTraceEvent{
				Kind: "sent", Index: gi,
				Time: e.StartedDateTime.Format("15:04:05.000"),
				Method: e.Request.Method, URL: e.Request.URL,
				Value: mask(c.Value), ValueLen: len(c.Value), Changed: changed,
			}
			report.Events = append(report.Events, ev)
			report.SentCount++
			if changed {
				report.ChangeCount++
			}
			lastValue, haveLast = c.Value, true
		}

		// 响应下发（Set-Cookie）
		for _, c := range e.Response.Cookies {
			if c.Name != name {
				continue
			}
			changed := haveLast && c.Value != lastValue
			ev := cookieTraceEvent{
				Kind: "set", Index: gi,
				Time: e.StartedDateTime.Format("15:04:05.000"),
				Method: e.Request.Method, URL: e.Request.URL,
				Value: mask(c.Value), ValueLen: len(c.Value), Changed: changed,
			}
			report.Events = append(report.Events, ev)
			report.SetCount++
			if report.FirstSet == nil {
				first := ev
				report.FirstSet = &first
			}
			if changed {
				report.ChangeCount++
			}
			lastValue, haveLast = c.Value, true
		}
	}

	return internal.WriteOutput(cmd, report, func() string {
		return formatCookieTraceText(report, urlMax)
	}, nil)
}

// truncateURL 截断超长 URL 到指定长度 + 省略提示。
// 注意按 rune 截断：HAR 里常有中文 URL，按字节切会产生非法 UTF-8。
func truncateURL(u string, maxLen int) string {
	if maxLen <= 0 {
		return u
	}
	runes := []rune(u)
	if len(runes) <= maxLen {
		return u
	}
	if maxLen < 10 {
		maxLen = 10
	}
	return fmt.Sprintf("%s...[+%d chars]", string(runes[:maxLen]), len(runes)-maxLen)
}

func formatCookieTraceText(r *cookieTraceReport, urlMax int) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Cookie 溯源: %s\n", r.Name))
	sb.WriteString(strings.Repeat("=", 70) + "\n")

	if len(r.Events) == 0 {
		sb.WriteString("未找到该 Cookie（既无请求携带，也无响应下发）。\n")
		sb.WriteString("提示: 名称区分大小写，可先用 `cookie --evolution` 列出所有 Cookie 名。\n")
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("下发(SET): %d 次   携带(SENT): %d 次   值变化: %d 次\n",
		r.SetCount, r.SentCount, r.ChangeCount))
	if r.FirstSet != nil {
		sb.WriteString(fmt.Sprintf("首次下发: [%d] %s %s\n", r.FirstSet.Index, r.FirstSet.Method, truncateURL(r.FirstSet.URL, urlMax)))
	} else {
		sb.WriteString("首次下发: 不在本 HAR 内（请求携带时已有值，下发点在录制之前）\n")
	}

	sb.WriteString("\n时间线（INDEX 为全局索引，可 extract --index 查看完整条目）:\n")
	for _, ev := range r.Events {
		mark := " "
		if ev.Changed {
			mark = "*"
		}
		sb.WriteString(fmt.Sprintf("  %s [%s] idx=%-5d %-4s %-4s %s\n", mark, ev.Time, ev.Index, ev.Kind, ev.Method, truncateURL(ev.URL, urlMax)))
		sb.WriteString(fmt.Sprintf("      value: %s\n", ev.Value))
	}
	if r.ChangeCount > 0 {
		sb.WriteString("\n* = 值相对上一事件发生变化\n")
	}
	if urlMax > 0 {
		sb.WriteString("(URL 已截断到 --url-max，完整 URL 用 extract --index N 查看)\n")
	}

	return sb.String()
}
