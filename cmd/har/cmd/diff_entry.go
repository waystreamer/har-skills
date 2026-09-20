package cmd

import (
	"fmt"
	"sort"
	"strings"

	har "github.com/waystreamer/har-skills/pkg/har"
	"github.com/waystreamer/har-skills/cmd/har/internal"
	"github.com/spf13/cobra"
)

// diffEntryCmd 字段级对比两个请求条目（同接口的两次调用）
var diffEntryCmd = &cobra.Command{
	Use:   "diff-entry [file1] [file2]",
	Short: "字段级对比两个请求条目",
	Long: `对比两个请求条目的字段级差异：query 参数、请求头、Cookie、POST 参数、响应体逐项对比。

这解决的是逆向分析最常见的需求：同一个接口被调了两次（一次成功一次失败），
要逐项看清 query/cookie/header 哪里不一样。整体 diff 命令做不了这个（它按
URL/索引匹配两个文件，只比 header 名和响应体，给不出同一接口两实例的逐项 diff）。

条目选择（两选一，可混用）：
  --index-a/--index-b   全局索引（list/find 输出的 INDEX 列）
  --url-a/--url-b       URL 子串，取第一个匹配
省略 file2 时在同一个 HAR 内对比（--index-a 与 --index-b 必须都给）。

示例:
  # 同一 HAR 内对比第 42 条和第 87 条（同接口两次调用）
  har -f app.har diff-entry --index-a 42 --index-b 87

  # 跨文件：a.har 里的 /sign 与 b.har 里的 /sign
  har diff-entry a.har b.har --url-a "/sign" --url-b "/sign"

  # 只看请求侧差异（跳过响应体大段输出）
  har -f app.har diff-entry --index-a 42 --index-b 87 --skip-body`,
	Args: cobra.MaximumNArgs(2),
	RunE: runDiffEntry,
}

func init() {
	rootCmd.AddCommand(diffEntryCmd)

	diffEntryCmd.Flags().Int("index-a", -1, "第一个条目的全局索引（list/find 的 INDEX 列）")
	diffEntryCmd.Flags().Int("index-b", -1, "第二个条目的全局索引")
	diffEntryCmd.Flags().String("url-a", "", "第一个条目的 URL 子串（取第一个匹配）")
	diffEntryCmd.Flags().String("url-b", "", "第二个条目的 URL 子串（取第一个匹配）")
	diffEntryCmd.Flags().Bool("skip-body", false, "跳过响应体内容对比（大响应时建议开启）")
	diffEntryCmd.Flags().StringSlice("ignore-headers", nil, "对比时忽略的请求/响应头名（逗号分隔）")
	diffEntryCmd.Flags().StringSlice("ignore-cookies", nil, "对比时忽略的 Cookie 名（逗号分隔）")
	diffEntryCmd.Flags().StringSlice("ignore-query", nil, "对比时忽略的 query 参数名（逗号分隔）")
}

func runDiffEntry(cmd *cobra.Command, args []string) error {
	indexA, _ := cmd.Flags().GetInt("index-a")
	indexB, _ := cmd.Flags().GetInt("index-b")
	urlA, _ := cmd.Flags().GetString("url-a")
	urlB, _ := cmd.Flags().GetString("url-b")
	skipBody, _ := cmd.Flags().GetBool("skip-body")
	ignoreHeaders, _ := cmd.Flags().GetStringSlice("ignore-headers")
	ignoreCookies, _ := cmd.Flags().GetStringSlice("ignore-cookies")
	ignoreQuery, _ := cmd.Flags().GetStringSlice("ignore-query")

	// 加载第一个 HAR（必须有）
	var h1 *har.Har
	if len(args) >= 1 {
		h1 = internal.LoadHarFromArg(args[0])
	} else {
		// 允许走 -f / stdin
		h1 = internal.LoadHar(cmd, args)
	}

	// 第二个 HAR：缺省即同一文件
	var h2 *har.Har
	if len(args) >= 2 {
		h2 = internal.LoadHarFromArg(args[1])
	} else {
		h2 = h1
	}

	e1, g1, err := pickEntry(h1, indexA, urlA, "A")
	if err != nil {
		return err
	}
	e2, g2, err := pickEntry(h2, indexB, urlB, "B")
	if err != nil {
		return err
	}

	report := buildEntryDiffReport(e1, e2, g1, g2, entryDiffOptions{
		skipBody:      skipBody,
		ignoreHeaders: toLowerSet(ignoreHeaders),
		ignoreCookies: toLowerSet(ignoreCookies),
		ignoreQuery:   toLowerSet(ignoreQuery),
	})

	return internal.WriteOutput(cmd, report, func() string {
		return formatEntryDiffText(report)
	}, nil)
}

// pickEntry 按全局索引或 URL 子串选出一个条目，返回条目与全局索引
func pickEntry(h *har.Har, index int, urlPattern string, label string) (*har.Entries, int, error) {
	if index >= 0 {
		if index >= len(h.Log.Entries) {
			return nil, -1, fmt.Errorf("条目 %s 索引越界: %d（文件共 %d 条）", label, index, len(h.Log.Entries))
		}
		return &h.Log.Entries[index], index, nil
	}
	if urlPattern != "" {
		for i := range h.Log.Entries {
			if strings.Contains(h.Log.Entries[i].Request.URL, urlPattern) {
				return &h.Log.Entries[i], i, nil
			}
		}
		return nil, -1, fmt.Errorf("条目 %s 未找到 URL 包含 %q 的请求", label, urlPattern)
	}
	return nil, -1, fmt.Errorf("条目 %s 未指定选择器：请给 --index-%s 或 --url-%s", label, strings.ToLower(label), strings.ToLower(label))
}

type entryDiffOptions struct {
	skipBody      bool
	ignoreHeaders map[string]bool
	ignoreCookies map[string]bool
	ignoreQuery   map[string]bool
}

// entryFieldDiff 单项字段差异
type entryFieldDiff struct {
	Group string `json:"group"` // query / request-header / cookie / post-param / response-header / response-cookie / response-body / meta
	Name  string `json:"name"`
	A     string `json:"a"` // "<absent>" 表示该侧没有这一项
	B     string `json:"b"`
}

// entryDiffReport 完整对比报告
type entryDiffReport struct {
	IndexA      int              `json:"index_a"`
	IndexB      int              `json:"index_b"`
	MethodA     string           `json:"method_a"`
	MethodB     string           `json:"method_b"`
	URLA        string           `json:"url_a"`
	URLB        string           `json:"url_b"`
	StatusA     int              `json:"status_a"`
	StatusB     int              `json:"status_b"`
	Identical   int              `json:"identical_count"` // 两侧一致的分组字段数（不逐项列出，只报数）
	Differences []entryFieldDiff `json:"differences"`
}

const absentMarker = "<absent>"

func buildEntryDiffReport(e1, e2 *har.Entries, g1, g2 int, opts entryDiffOptions) *entryDiffReport {
	r := &entryDiffReport{
		IndexA: g1, IndexB: g2,
		MethodA: e1.Request.Method, MethodB: e2.Request.Method,
		URLA: e1.Request.URL, URLB: e2.Request.URL,
		StatusA: e1.Response.Status, StatusB: e2.Response.Status,
	}

	if e1.Request.Method != e2.Request.Method {
		r.Differences = append(r.Differences, entryFieldDiff{Group: "meta", Name: "method", A: e1.Request.Method, B: e2.Request.Method})
	}
	if e1.Response.Status != e2.Response.Status {
		r.Differences = append(r.Differences, entryFieldDiff{Group: "meta", Name: "status", A: fmt.Sprint(e1.Response.Status), B: fmt.Sprint(e2.Response.Status)})
	}

	// 1. Query 参数逐项对比（逆向最常看的一层）
	r.Identical += diffNameValues(&r.Differences, "query",
		queryStringToPairs(e1.Request.QueryString),
		queryStringToPairs(e2.Request.QueryString),
		opts.ignoreQuery)

	// 2. 请求头逐项对比
	r.Identical += diffNameValues(&r.Differences, "request-header",
		headersToPairs(e1.Request.Headers),
		headersToPairs(e2.Request.Headers),
		opts.ignoreHeaders)

	// 3. 请求 Cookie 逐项对比
	r.Identical += diffNameValues(&r.Differences, "cookie",
		cookiesToPairs(e1.Request.Cookies),
		cookiesToPairs(e2.Request.Cookies),
		opts.ignoreCookies)

	// 4. POST 参数逐项对比（表单型 postData.params）
	if e1.Request.PostData != nil || e2.Request.PostData != nil {
		var p1, p2 []har.Param
		var t1, t2 string
		if e1.Request.PostData != nil {
			p1 = e1.Request.PostData.Params
			t1 = e1.Request.PostData.Text
		}
		if e2.Request.PostData != nil {
			p2 = e2.Request.PostData.Params
			t2 = e2.Request.PostData.Text
		}
		r.Identical += diffNameValues(&r.Differences, "post-param", paramsToPairs(p1), paramsToPairs(p2), nil)
		if len(p1) == 0 && len(p2) == 0 && t1 != t2 {
			r.Differences = append(r.Differences, entryFieldDiff{
				Group: "post-body", Name: "text",
				A: truncateForDiff(t1), B: truncateForDiff(t2),
			})
		}
	}

	// 5. 响应头 / 响应 Set-Cookie
	r.Identical += diffNameValues(&r.Differences, "response-header",
		headersToPairs(e1.Response.Headers),
		headersToPairs(e2.Response.Headers),
		opts.ignoreHeaders)
	r.Identical += diffNameValues(&r.Differences, "response-cookie",
		cookiesToPairs(e1.Response.Cookies),
		cookiesToPairs(e2.Response.Cookies),
		opts.ignoreCookies)

	// 6. 响应体（截断展示，完整内容用 extract 拿）
	if !opts.skipBody {
		b1, _ := e1.DecodeContent()
		b2, _ := e2.DecodeContent()
		s1, s2 := string(b1), string(b2)
		if s1 != s2 {
			r.Differences = append(r.Differences, entryFieldDiff{
				Group: "response-body", Name: "text",
				A: truncateForDiff(s1), B: truncateForDiff(s2),
			})
		} else if s1 != "" {
			r.Identical++
		}
	}

	return r
}

// nameValuePair 把 har 的 name/value 列表统一成 (name, value) 对，保持出现顺序
type nameValuePair struct {
	Name  string
	Value string
}

func queryStringToPairs(qs []har.QueryString) []nameValuePair {
	out := make([]nameValuePair, len(qs))
	for i, q := range qs {
		out[i] = nameValuePair{q.Name, q.Value}
	}
	return out
}

func headersToPairs(hs []har.Headers) []nameValuePair {
	out := make([]nameValuePair, len(hs))
	for i, h := range hs {
		out[i] = nameValuePair{strings.ToLower(h.Name), h.Value}
	}
	return out
}

func cookiesToPairs(cs []har.Cookie) []nameValuePair {
	out := make([]nameValuePair, len(cs))
	for i, c := range cs {
		out[i] = nameValuePair{c.Name, c.Value}
	}
	return out
}

func paramsToPairs(ps []har.Param) []nameValuePair {
	out := make([]nameValuePair, len(ps))
	for i, p := range ps {
		out[i] = nameValuePair{p.Name, p.Value}
	}
	return out
}

// diffNameValues 逐项对比两组 name/value（同名取第一个值做对比，全部同值算一致）
// 返回一致项的数量
func diffNameValues(diffs *[]entryFieldDiff, group string, a, b []nameValuePair, ignore map[string]bool) int {
	identical := 0

	// 保持 A 侧顺序遍历，再补 B 侧多出来的项
	inB := make(map[string]string)
	for _, p := range b {
		if _, exists := inB[p.Name]; !exists {
			inB[p.Name] = p.Value
		}
	}
	seen := make(map[string]bool)

	for _, p := range a {
		if ignore[strings.ToLower(p.Name)] {
			continue
		}
		seen[p.Name] = true
		if bv, ok := inB[p.Name]; ok {
			if bv == p.Value {
				identical++
			} else {
				*diffs = append(*diffs, entryFieldDiff{Group: group, Name: p.Name, A: p.Value, B: bv})
			}
		} else {
			*diffs = append(*diffs, entryFieldDiff{Group: group, Name: p.Name, A: p.Value, B: absentMarker})
		}
	}
	for _, p := range b {
		if ignore[strings.ToLower(p.Name)] || seen[p.Name] {
			continue
		}
		*diffs = append(*diffs, entryFieldDiff{Group: group, Name: p.Name, A: absentMarker, B: p.Value})
	}
	return identical
}

func toLowerSet(items []string) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, it := range items {
		s[strings.ToLower(strings.TrimSpace(it))] = true
	}
	return s
}

// truncateForDiff 响应体等大字段截断到前 500 字符，完整内容交给 extract
func truncateForDiff(s string) string {
	const maxLen = 500
	if len(s) <= maxLen {
		return s
	}
	return fmt.Sprintf("%s... [共 %d 字符，截断；完整内容用 extract --index 查看]", s[:maxLen], len(s))
}

func formatEntryDiffText(r *entryDiffReport) string {
	var sb strings.Builder

	sb.WriteString("条目字段级对比\n")
	sb.WriteString(strings.Repeat("=", 70) + "\n")
	sb.WriteString(fmt.Sprintf("A: [%d] %s %s -> %d\n", r.IndexA, r.MethodA, r.URLA, r.StatusA))
	sb.WriteString(fmt.Sprintf("B: [%d] %s %s -> %d\n", r.IndexB, r.MethodB, r.URLB, r.StatusB))

	if len(r.Differences) == 0 {
		sb.WriteString(fmt.Sprintf("\n两侧完全一致（%d 个字段逐项相同）。\n", r.Identical))
		return sb.String()
	}

	// 按分组聚类输出，query/header/cookie 分开看才清楚
	groups := []string{"meta", "query", "request-header", "cookie", "post-param", "post-body", "response-header", "response-cookie", "response-body"}
	byGroup := make(map[string][]entryFieldDiff)
	for _, d := range r.Differences {
		byGroup[d.Group] = append(byGroup[d.Group], d)
	}
	// 收集未预料到的分组，不丢
	for g := range byGroup {
		found := false
		for _, known := range groups {
			if g == known {
				found = true
				break
			}
		}
		if !found {
			groups = append(groups, g)
		}
	}

	sb.WriteString(fmt.Sprintf("\n差异 %d 处（一致字段 %d 个，未逐项列出）:\n", len(r.Differences), r.Identical))
	for _, g := range groups {
		ds := byGroup[g]
		if len(ds) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("\n[%s] %d 处\n", g, len(ds)))
		// 名字排序，输出稳定
		sort.Slice(ds, func(i, j int) bool { return ds[i].Name < ds[j].Name })
		for _, d := range ds {
			sb.WriteString(fmt.Sprintf("  %s\n    A: %s\n    B: %s\n", d.Name, d.A, d.B))
		}
	}

	return sb.String()
}
