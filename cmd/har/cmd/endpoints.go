package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/waystreamer/har-skills/cmd/har/internal"
	har "github.com/waystreamer/har-skills/pkg/har"
)

// endpointsCmd 端点指纹：把归一化后的 API 端点列出来
var endpointsCmd = &cobra.Command{
	Use:   "endpoints",
	Short: "按 method+host+路径模板 聚类请求，列出归一化端点",
	Long: `对整个 HAR 做端点指纹归一化：

  - 路径中的动态段（纯数字 ID、UUID、hex、base64 形态）归一为 {param}
  - 单样本路径段不盲目归一（如 /order/20240920 只有一条时按字面量处理）
  - query 不参与指纹，但会记录该端点见过哪些 query key

输出每个端点的指纹、样本数、见过的状态码、query key、代表性 URL。
ENTRY_INDICES 是全局索引，可直接喂 extract --index / diff-entry --index-a。

这是后续所有上层分析的地基：schema 聚合、多样本 diff、依赖分析的样本组
都来自端点归一化。

示例:
  har -f capture.har endpoints                          # 全部端点
  har -f capture.har endpoints --sort count             # 按样本数排序（默认）
  har -f capture.har endpoints --sort host              # 按 host 排序
  har -f capture.har endpoints --host api.example.com   # 只看某个 host
  har -f capture.har endpoints --format json            # JSON 输出（含完整 entry 索引）`,
	Args: cobra.NoArgs,
	RunE: runEndpoints,
}

func init() {
	rootCmd.AddCommand(endpointsCmd)
	endpointsCmd.Flags().String("sort", "count", "排序方式: count（样本数，默认）/ host / path")
	endpointsCmd.Flags().String("host", "", "只看指定 host 的端点")
	endpointsCmd.Flags().Int("limit", 0, "最多显示多少个端点（0=全部）")
	endpointsCmd.Flags().Int("url-max", 60, "样本 URL 显示截断长度（0=不截断）")
	endpointsCmd.Flags().Bool("tree", false, "按 host + 路径前缀树状分组显示（大 HAR 概览用）")
}

type endpointsReport struct {
	TotalEntries int             `json:"total_entries"`
	TotalEndpoints int           `json:"total_endpoints"`
	Endpoints    []*har.Endpoint `json:"endpoints"`
}

func runEndpoints(cmd *cobra.Command, args []string) error {
	h := internal.LoadHar(cmd, args)
	sortBy, _ := cmd.Flags().GetString("sort")
	hostFilter, _ := cmd.Flags().GetString("host")
	limit, _ := cmd.Flags().GetInt("limit")
	urlMax, _ := cmd.Flags().GetInt("url-max")
	tree, _ := cmd.Flags().GetBool("tree")

	eps := h.BuildEndpoints()

	// host 过滤
	if hostFilter != "" {
		var filtered []*har.Endpoint
		for _, ep := range eps {
			if strings.Contains(ep.Host, hostFilter) {
				filtered = append(filtered, ep)
			}
		}
		eps = filtered
	}

	// 排序
	sort.SliceStable(eps, func(i, j int) bool {
		switch sortBy {
		case "host":
			if eps[i].Host != eps[j].Host {
				return eps[i].Host < eps[j].Host
			}
			return eps[i].PathTemplate < eps[j].PathTemplate
		case "path":
			return eps[i].PathTemplate < eps[j].PathTemplate
		default: // count
			if eps[i].Count != eps[j].Count {
				return eps[i].Count > eps[j].Count
			}
			return eps[i].ID < eps[j].ID
		}
	})

	total := len(eps)
	if limit > 0 && len(eps) > limit {
		eps = eps[:limit]
	}

	report := &endpointsReport{
		TotalEntries:   len(h.Log.Entries),
		TotalEndpoints: total,
		Endpoints:      eps,
	}

	return internal.WriteOutput(cmd, report, func() string {
		if tree {
			return formatEndpointsTree(report)
		}
		return formatEndpointsText(report, urlMax)
	}, nil)
}

// formatEndpointsTree 按 host + 路径前缀树状分组显示端点
func formatEndpointsTree(r *endpointsReport) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("端点指纹: %d 条请求 → %d 个端点\n", r.TotalEntries, r.TotalEndpoints))
	sb.WriteString(strings.Repeat("=", 78) + "\n")

	if len(r.Endpoints) == 0 {
		sb.WriteString("无匹配端点。\n")
		return sb.String()
	}

	// 按 host 分组，host 内按路径前缀分组
	type pathGroup struct {
		prefix string
		eps    []*har.Endpoint
	}
	type hostGroup struct {
		host   string
		total  int
		groups []pathGroup
	}

	hostMap := make(map[string]*hostGroup)
	var hostOrder []string

	for _, ep := range r.Endpoints {
		hg, ok := hostMap[ep.Host]
		if !ok {
			hg = &hostGroup{host: ep.Host}
			hostMap[ep.Host] = hg
			hostOrder = append(hostOrder, ep.Host)
		}
		hg.total += ep.Count

		// 取路径前两级作为前缀分组 key（如 /act/api/、/rest/2.0/membership/）
		prefix := pathPrefix(ep.PathTemplate, 2)
		found := false
		for i := range hg.groups {
			if hg.groups[i].prefix == prefix {
				hg.groups[i].eps = append(hg.groups[i].eps, ep)
				found = true
				break
			}
		}
		if !found {
			hg.groups = append(hg.groups, pathGroup{prefix: prefix, eps: []*har.Endpoint{ep}})
		}
	}

	// host 按总请求数降序
	sort.SliceStable(hostOrder, func(i, j int) bool {
		return hostMap[hostOrder[i]].total > hostMap[hostOrder[j]].total
	})

	for _, host := range hostOrder {
		hg := hostMap[host]
		sb.WriteString(fmt.Sprintf("\n%s (%d requests, %d endpoints)\n", hg.host, hg.total, len(hg.groups)))

		// 路径前缀组按总请求数降序
		sort.SliceStable(hg.groups, func(i, j int) bool {
			ti, tj := 0, 0
			for _, ep := range hg.groups[i].eps {
				ti += ep.Count
			}
			for _, ep := range hg.groups[j].eps {
				tj += ep.Count
			}
			return ti > tj
		})

		for _, g := range hg.groups {
			// 组内按 count 降序
			sort.SliceStable(g.eps, func(i, j int) bool {
				return g.eps[i].Count > g.eps[j].Count
			})
			sb.WriteString(fmt.Sprintf("  %s\n", g.prefix))
			for _, ep := range g.eps {
				// 只显示路径模板相对于前缀的部分
				leaf := strings.TrimPrefix(ep.PathTemplate, strings.TrimSuffix(g.prefix, "/"))
				if leaf == "" || leaf == ep.PathTemplate {
					leaf = ep.PathTemplate
				}
				sb.WriteString(fmt.Sprintf("    %-6s %-50s ×%d  status:%v\n",
					ep.Method, leaf, ep.Count, ep.StatusCodes))
			}
		}
	}

	sb.WriteString("\n提示: 用 `endpoints`（无 --tree）查看完整详情，含全局索引和样本 URL。\n")
	return sb.String()
}

// pathPrefix 取路径的前 n 段作为分组前缀
func pathPrefix(path string, n int) string {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	if len(segs) == 0 || segs[0] == "" {
		return "/"
	}
	if len(segs) <= n {
		return "/" + strings.Join(segs, "/") + "/"
	}
	return "/" + strings.Join(segs[:n], "/") + "/"
}

func formatEndpointsText(r *endpointsReport, urlMax int) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("端点指纹: %d 条请求 → %d 个端点\n", r.TotalEntries, r.TotalEndpoints))
	sb.WriteString(strings.Repeat("=", 78) + "\n")

	if len(r.Endpoints) == 0 {
		sb.WriteString("无匹配端点。\n")
		return sb.String()
	}

	for _, ep := range r.Endpoints {
		sb.WriteString(fmt.Sprintf("\n[%d] %s %s  (×%d)\n", ep.ID, ep.Method, ep.PathTemplate, ep.Count))
		sb.WriteString(fmt.Sprintf("    host: %s\n", ep.Host))
		if len(ep.StatusCodes) > 0 {
			sb.WriteString(fmt.Sprintf("    status: %v\n", ep.StatusCodes))
		}
		if len(ep.QueryKeys) > 0 {
			sb.WriteString(fmt.Sprintf("    query keys: %s\n", strings.Join(ep.QueryKeys, ", ")))
		}
		if len(ep.ParamSegments) > 0 {
			sb.WriteString(fmt.Sprintf("    参数段: %s\n", strings.Join(ep.ParamSegments, ", ")))
		}
		sb.WriteString(fmt.Sprintf("    样本: %s\n", truncateURL(ep.SampleURL, urlMax)))
		sb.WriteString(fmt.Sprintf("    索引: %v\n", ep.EntryIndices))
	}

	sb.WriteString(fmt.Sprintf("\n提示: 索引为全局 entry 号，可喂 `extract --index N` 或 `diff-entry --index-a N --index-b M`。\n"))
	if urlMax > 0 {
		sb.WriteString("(样本 URL 已截断到 --url-max)\n")
	}
	return sb.String()
}
