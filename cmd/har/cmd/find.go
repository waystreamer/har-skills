package cmd

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	har "github.com/waystreamer/har-skills/pkg/har"
	"github.com/waystreamer/har-skills/cmd/har/internal"
	"github.com/spf13/cobra"
)

// findCmd 搜索HAR条目
var findCmd = &cobra.Command{
	Use:   "find [pattern]",
	Short: "Search HAR entries",
	Long: `Search HAR entries by URL, status code, or conditions. Supports regex URL matching,
status code range, content type, domain, request/response headers, cookies, resource type,
time range, server IP, connection ID, cache hits, slow/fast/largest requests, etc.

The INDEX column is the global index of the entry in the HAR log.entries array
and can be passed directly to "extract --index" or "diff --index-a/--index-b".`,
	Example: `  har -f capture.har find "api/users"
  har -f capture.har find --regex "api/v[0-9]+"
  har -f capture.har find --errors
  har -f capture.har find --redirects
  har -f capture.har find --slow 1000
  har -f capture.har find --fastest 5
  har -f capture.har find --slowest 5
  har -f capture.har find --largest 5
  har -f capture.har find --status-code 404
  har -f capture.har find --method GET --domain example.com
  har -f capture.har find --response-header "Content-Type:application/json"
  har -f capture.har find --cookie "session_id"
  har -f capture.har find --start-time "2024-01-01T00:00:00Z" --end-time "2024-12-31T23:59:59Z"
  har -f capture.har find --server-ip "10.0.0.1"
  har -f capture.har find --cache-hits
  har -f capture.har find --connection "ABC123"`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		h := internal.LoadHar(cmd, args)

		// 获取所有过滤参数
		pattern := ""
		if len(args) > 0 {
			pattern = args[0]
		}
		useRegex, _ := cmd.Flags().GetBool("regex")
		method, _ := cmd.Flags().GetString("method")
		statusCode, _ := cmd.Flags().GetInt("status-code")
		statusMin, _ := cmd.Flags().GetInt("status-min")
		statusMax, _ := cmd.Flags().GetInt("status-max")
		contentType, _ := cmd.Flags().GetString("content-type")
		domain, _ := cmd.Flags().GetString("domain")
		headers, _ := cmd.Flags().GetStringSlice("header")
		responseHeaders, _ := cmd.Flags().GetStringSlice("response-header")
		cookieName, _ := cmd.Flags().GetString("cookie")
		resourceType, _ := cmd.Flags().GetString("resource-type")
		errors, _ := cmd.Flags().GetBool("errors")
		redirects, _ := cmd.Flags().GetBool("redirects")
		slow, _ := cmd.Flags().GetFloat64("slow")
		cacheHits, _ := cmd.Flags().GetBool("cache-hits")
		serverIP, _ := cmd.Flags().GetString("server-ip")
		connection, _ := cmd.Flags().GetString("connection")
		startTimeStr, _ := cmd.Flags().GetString("start-time")
		endTimeStr, _ := cmd.Flags().GetString("end-time")
		slowest, _ := cmd.Flags().GetInt("slowest")
		fastest, _ := cmd.Flags().GetInt("fastest")
		largest, _ := cmd.Flags().GetInt("largest")
		limit, _ := cmd.Flags().GetInt("limit")
		urlMax, _ := cmd.Flags().GetInt("url-max")

		// 构建过滤选项
		opts := []har.FilterOption{}

		// URL模式匹配
		if pattern != "" {
			opts = append(opts, har.WithFilterURL(pattern))
			if useRegex {
				opts = append(opts, har.WithFilterRegex())
			}
		}

		// 方法过滤
		if method != "" {
			opts = append(opts, har.WithFilterMethod(method))
		}

		// 状态码过滤
		if statusCode > 0 {
			opts = append(opts, har.WithFilterStatusCode(statusCode))
		}

		// 状态码范围过滤
		if statusMin > 0 || statusMax > 0 {
			opts = append(opts, har.WithFilterStatusCodeRange(statusMin, statusMax))
		}

		// 内容类型过滤
		if contentType != "" {
			opts = append(opts, har.WithFilterContentType(contentType))
		}

		// 错误过滤
		if errors {
			opts = append(opts, har.WithFilterHasError())
		}

		// 资源类型过滤
		if resourceType != "" {
			opts = append(opts, har.WithFilterResourceType(resourceType))
		}

		// 慢请求过滤
		if slow > 0 {
			opts = append(opts, har.WithFilterDuration(slow, 0))
		}

		// 请求头过滤
		for _, hdr := range headers {
			parts := strings.SplitN(hdr, ":", 2)
			name := parts[0]
			value := ""
			if len(parts) > 1 {
				value = strings.TrimSpace(parts[1])
			}
			opts = append(opts, har.WithFilterHeader(name, value))
		}

		// 执行过滤，转换为带全局索引的结果
		var ei *entryIndex
		if len(opts) > 0 {
			ei = fromFilterResult(h, h.FilterWith(opts...))
		} else {
			ei = newEntryIndex(h)
		}

		// intersectWith 将另一个过滤结果（按全局索引）与当前结果求交集
		intersectWith := func(other *entryIndex) {
			ei.filterByGlobalIndexSet(other.globalIndexSet())
		}

		// 按域名过滤（需单独处理）
		if domain != "" {
			ei.filterByPredicate(func(e *har.Entries) bool {
				return har.ExtractDomain(e.Request.URL) == domain
			})
		}

		// 响应头过滤
		for _, rh := range responseHeaders {
			parts := strings.SplitN(rh, ":", 2)
			name := parts[0]
			value := ""
			if len(parts) > 1 {
				value = strings.TrimSpace(parts[1])
			}
			intersectWith(fromFilterResult(h, h.FindByResponseHeader(name, value)))
		}

		// Cookie过滤
		if cookieName != "" {
			intersectWith(fromFilterResult(h, h.FindByCookie(cookieName)))
		}

		// 时间范围过滤
		if startTimeStr != "" || endTimeStr != "" {
			startTime := time.Time{}
			endTime := time.Now()
			if startTimeStr != "" {
				t, err := time.Parse(time.RFC3339, startTimeStr)
				if err != nil {
					return fmt.Errorf("invalid start-time format (use RFC3339): %w", err)
				}
				startTime = t
			}
			if endTimeStr != "" {
				t, err := time.Parse(time.RFC3339, endTimeStr)
				if err != nil {
					return fmt.Errorf("invalid end-time format (use RFC3339): %w", err)
				}
				endTime = t
			}
			intersectWith(fromFilterResult(h, h.FindByTimeRange(startTime, endTime)))
		}

		// Server IP过滤
		if serverIP != "" {
			intersectWith(fromFilterResult(h, h.FindByServerIP(serverIP)))
		}

		// Connection过滤
		if connection != "" {
			intersectWith(fromFilterResult(h, h.FindByConnection(connection)))
		}

		// 缓存命中过滤
		if cacheHits {
			intersectWith(fromFilterResult(h, h.FindCacheHits()))
		}

		// 重定向过滤
		if redirects {
			intersectWith(fromFilterResult(h, h.FindRedirects()))
		}

		// Slowest N requests
		if slowest > 0 {
			intersectWith(fromFilterResult(h, &har.FilterResult{Entries: h.SlowestRequests(slowest)}))
		}

		// Fastest N requests
		if fastest > 0 {
			intersectWith(fromFilterResult(h, &har.FilterResult{Entries: h.FastestRequests(fastest)}))
		}

		// Largest N responses
		if largest > 0 {
			intersectWith(fromFilterResult(h, &har.FilterResult{Entries: h.LargestResponses(largest)}))
		}

		// 限制条数
		ei.limit(limit)

		return internal.WriteOutput(cmd, buildListJSON(ei), func() string {
			return formatFindTable(ei, urlMax)
		}, nil)
	},
}

func init() {
	rootCmd.AddCommand(findCmd)

	// URL and pattern
	findCmd.Flags().Bool("regex", false, "Use regex for URL pattern matching")
	// Method and status
	findCmd.Flags().String("method", "", "Filter by HTTP method")
	findCmd.Flags().Int("status-code", 0, "Filter by exact status code")
	findCmd.Flags().Int("status-min", 0, "Minimum status code (range filter)")
	findCmd.Flags().Int("status-max", 0, "Maximum status code (range filter)")
	// Content and type
	findCmd.Flags().String("content-type", "", "Filter by content type")
	findCmd.Flags().String("resource-type", "", "Filter by resource type (document, script, stylesheet, image, font, xhr, etc.)")
	// Domain and network
	findCmd.Flags().String("domain", "", "Filter by domain name")
	findCmd.Flags().String("server-ip", "", "Filter by server IP address")
	findCmd.Flags().String("connection", "", "Filter by connection ID")
	// Headers
	findCmd.Flags().StringSlice("header", nil, "Filter by request header (format: name or name:value)")
	findCmd.Flags().StringSlice("response-header", nil, "Filter by response header (format: name or name:value)")
	// Cookies
	findCmd.Flags().String("cookie", "", "Filter entries containing a cookie by name")
	// Time
	findCmd.Flags().String("start-time", "", "Filter entries after this time (RFC3339 format, e.g. 2024-01-01T00:00:00Z)")
	findCmd.Flags().String("end-time", "", "Filter entries before this time (RFC3339 format)")
	findCmd.Flags().Float64("slow", 0, "Find slow requests (minimum duration in ms)")
	findCmd.Flags().Int("slowest", 0, "Find the N slowest requests")
	findCmd.Flags().Int("fastest", 0, "Find the N fastest requests")
	findCmd.Flags().Int("largest", 0, "Find the N largest responses by size")
	// Special filters
	findCmd.Flags().Bool("errors", false, "Find all error requests (4xx/5xx)")
	findCmd.Flags().Bool("redirects", false, "Find all redirect requests (3xx)")
	findCmd.Flags().Bool("cache-hits", false, "Find requests with cache hits")
	// Output
	findCmd.Flags().IntP("limit", "n", 0, "Limit output to N entries (0=all)")
	findCmd.Flags().Int("url-max", 80, "Truncate URL display to N chars (0=no truncation); default 80 cuts to path for long App URLs")
}

// formatFindTable 格式化搜索结果为tabwriter表格
// INDEX 列是全局索引，可直接用于 extract --index
func formatFindTable(ei *entryIndex, urlMax int) string {
	var sb tabWriterBuf

	w := tabwriter.NewWriter(&sb, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "INDEX\tMETHOD\tSTATUS\tSIZE\tTIME\tURL\n")

	for i, entry := range ei.entries {
		size := internal.FormatBytes(entry.Response.Content.Size)
		dur := internal.FormatDuration(entry.Time)
		fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%s\t%s\n",
			ei.gidx[i], entry.Request.Method, entry.Response.Status, size, dur, truncateURL(entry.Request.URL, urlMax))
	}
	w.Flush()

	return sb.String()
}
