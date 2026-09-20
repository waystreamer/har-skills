package har

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
)

// ValueLocation 值出现的位置描述
type ValueLocation struct {
	EntryIndex int    `json:"entry_index"` // 全局 entry 索引
	Direction  string `json:"direction"`   // "request" 或 "response"
	FieldType  string `json:"field_type"`  // url/query/header/cookie/post-param/body
	FieldName  string `json:"field_name"`  // 参数名/header名/cookie名（body 时为 ""）
	MatchType  string `json:"match_type"`  // exact / contains / url-encoded / base64 / hex
	Context    string `json:"context"`     // 匹配位置的上下文片段（前后各 40 字符）
	Method     string `json:"method"`      // 该 entry 的 HTTP 方法
	EntryURL   string `json:"entry_url"`   // 该 entry 的 URL
}

// ValueTraceReport 值溯源报告
type ValueTraceReport struct {
	Value       string          `json:"value"`
	TotalHits   int             `json:"total_hits"`
	FirstSeen   *ValueLocation  `json:"first_seen,omitempty"`
	Locations   []ValueLocation `json:"locations"`
}

// ValueTraceOptions 值溯源选项
type ValueTraceOptions struct {
	// IncludeBody 是否搜索请求体/响应体（默认 true）
	IncludeBody bool
	// IncludeURLEncoded 是否额外匹配 URL-encode 后的值（默认 true）
	IncludeURLEncoded bool
	// IncludeBase64 是否额外匹配 base64 编码后的值（默认 false，容易误报）
	IncludeBase64 bool
	// IncludeHex 是否额外匹配 hex 编码后的值（默认 false，容易误报）
	IncludeHex bool
	// ContextLen 上下文片段长度（默认 40）
	ContextLen int
}

// DefaultValueTraceOptions 返回默认的值溯源选项
func DefaultValueTraceOptions() ValueTraceOptions {
	return ValueTraceOptions{
		IncludeBody:       true,
		IncludeURLEncoded: true,
		IncludeBase64:     false,
		IncludeHex:        false,
		ContextLen:        40,
	}
}

// TraceValue 在整个 HAR 中追踪一个值的所有出现位置
//
// 搜索范围：URL、query 参数、请求/响应 header、cookie、POST 参数、请求体、响应体。
// 除精确匹配外，还会尝试 URL-encode、base64、hex 编码后的变体（可选）。
// 返回的 EntryIndex 是全局索引，可直接喂 extract --index。
func (h *Har) TraceValue(value string, opts ValueTraceOptions) *ValueTraceReport {
	if h == nil || value == "" {
		return &ValueTraceReport{Value: value}
	}
	if opts.ContextLen <= 0 {
		opts.ContextLen = 40
	}

	report := &ValueTraceReport{Value: value}

	// 构建匹配变体列表：(匹配串, matchType)
	type variant struct {
		pattern   string
		matchType string
	}
	variants := []variant{{value, "exact"}}

	if opts.IncludeURLEncoded {
		if enc := url.QueryEscape(value); enc != value {
			variants = append(variants, variant{enc, "url-encoded"})
		}
		// PathEscape 处理 / 等特殊字符
		if enc := url.PathEscape(value); enc != value && enc != url.QueryEscape(value) {
			variants = append(variants, variant{enc, "url-encoded"})
		}
	}
	if opts.IncludeBase64 && len(value) >= 4 {
		enc := base64.StdEncoding.EncodeToString([]byte(value))
		variants = append(variants, variant{enc, "base64"})
		// base64url 变体
		encURL := base64.URLEncoding.EncodeToString([]byte(value))
		if encURL != enc {
			variants = append(variants, variant{encURL, "base64"})
		}
	}
	if opts.IncludeHex && len(value) >= 4 {
		variants = append(variants, variant{hex.EncodeToString([]byte(value)), "hex"})
	}

	// 在目标串中查找所有变体，返回第一个命中的 (matchType, context)
	find := func(target string) (string, string) {
		for _, v := range variants {
			if idx := strings.Index(target, v.pattern); idx >= 0 {
				ctx := extractContext(target, idx, len(v.pattern), opts.ContextLen)
				return v.matchType, ctx
			}
		}
		return "", ""
	}

	for i := range h.Log.Entries {
		e := &h.Log.Entries[i]

		// --- 请求侧 ---
		if mt, ctx := find(e.Request.URL); mt != "" {
			report.Locations = append(report.Locations, ValueLocation{
				EntryIndex: i, Direction: "request", FieldType: "url",
				MatchType: mt, Context: ctx, Method: e.Request.Method, EntryURL: e.Request.URL,
			})
		}
		for _, qs := range e.Request.QueryString {
			if mt, ctx := find(qs.Value); mt != "" {
				report.Locations = append(report.Locations, ValueLocation{
					EntryIndex: i, Direction: "request", FieldType: "query", FieldName: qs.Name,
					MatchType: mt, Context: ctx, Method: e.Request.Method, EntryURL: e.Request.URL,
				})
			}
		}
		for _, hd := range e.Request.Headers {
			if mt, ctx := find(hd.Value); mt != "" {
				report.Locations = append(report.Locations, ValueLocation{
					EntryIndex: i, Direction: "request", FieldType: "header", FieldName: hd.Name,
					MatchType: mt, Context: ctx, Method: e.Request.Method, EntryURL: e.Request.URL,
				})
			}
		}
		for _, c := range e.Request.Cookies {
			if mt, ctx := find(c.Value); mt != "" {
				report.Locations = append(report.Locations, ValueLocation{
					EntryIndex: i, Direction: "request", FieldType: "cookie", FieldName: c.Name,
					MatchType: mt, Context: ctx, Method: e.Request.Method, EntryURL: e.Request.URL,
				})
			}
		}
		if e.Request.PostData != nil {
			for _, p := range e.Request.PostData.Params {
				if mt, ctx := find(p.Value); mt != "" {
					report.Locations = append(report.Locations, ValueLocation{
						EntryIndex: i, Direction: "request", FieldType: "post-param", FieldName: p.Name,
						MatchType: mt, Context: ctx, Method: e.Request.Method, EntryURL: e.Request.URL,
					})
				}
			}
			if opts.IncludeBody && e.Request.PostData.Text != "" {
				if mt, ctx := find(e.Request.PostData.Text); mt != "" {
					report.Locations = append(report.Locations, ValueLocation{
						EntryIndex: i, Direction: "request", FieldType: "body",
						MatchType: mt, Context: ctx, Method: e.Request.Method, EntryURL: e.Request.URL,
					})
				}
			}
		}

		// --- 响应侧 ---
		for _, hd := range e.Response.Headers {
			if mt, ctx := find(hd.Value); mt != "" {
				report.Locations = append(report.Locations, ValueLocation{
					EntryIndex: i, Direction: "response", FieldType: "header", FieldName: hd.Name,
					MatchType: mt, Context: ctx, Method: e.Request.Method, EntryURL: e.Request.URL,
				})
			}
		}
		for _, c := range e.Response.Cookies {
			if mt, ctx := find(c.Value); mt != "" {
				report.Locations = append(report.Locations, ValueLocation{
					EntryIndex: i, Direction: "response", FieldType: "cookie", FieldName: c.Name,
					MatchType: mt, Context: ctx, Method: e.Request.Method, EntryURL: e.Request.URL,
				})
			}
		}
		if opts.IncludeBody && e.Response.Content.Text != "" {
			body := e.Response.Content.Text
			// base64 编码的响应体先解码
			if e.Response.Content.IsBase64Encoded() {
				if decoded, err := e.DecodeEntryText(); err == nil && decoded != "" {
					body = decoded
				}
			}
			if mt, ctx := find(body); mt != "" {
				report.Locations = append(report.Locations, ValueLocation{
					EntryIndex: i, Direction: "response", FieldType: "body",
					MatchType: mt, Context: ctx, Method: e.Request.Method, EntryURL: e.Request.URL,
				})
			}
		}
	}

	report.TotalHits = len(report.Locations)
	if len(report.Locations) > 0 {
		first := report.Locations[0]
		report.FirstSeen = &first
	}
	return report
}

// extractContext 提取匹配位置前后各 contextLen 字符的上下文
func extractContext(target string, idx, patLen, contextLen int) string {
	start := idx - contextLen
	if start < 0 {
		start = 0
	}
	end := idx + patLen + contextLen
	if end > len(target) {
		end = len(target)
	}
	// 按 rune 截断避免破坏 UTF-8
	runes := []rune(target[start:end])
	ctx := string(runes)
	if start > 0 {
		ctx = "..." + ctx
	}
	if end < len(target) {
		ctx = ctx + "..."
	}
	return ctx
}
