package har

import (
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Endpoint 表示归一化后的 API 端点（fingerprint）
//
// 指纹由 method + host + 路径模板组成，路径中的动态段（数字 ID、UUID、hex、
// base64 等）被替换为 {param}。query 不参与指纹，但记录该端点见过的 query key。
// 同一指纹的多个请求视为同一端点的多个样本。
type Endpoint struct {
	ID            int      `json:"id"`             // 端点序号（按首次出现排序）
	Method        string   `json:"method"`         // HTTP 方法（大写）
	Host          string   `json:"host"`           // 规范化后的 host（小写，含非默认端口）
	PathTemplate  string   `json:"path_template"`  // 归一化路径，如 /user/{param}/orders
	Fingerprint   string   `json:"fingerprint"`    // 规范化指纹串，如 "GET example.com /user/{param}/orders"
	Count         int      `json:"count"`          // 样本总数
	EntryIndices  []int    `json:"entry_indices"`  // 全局 entry 索引（可直接喂 extract --index）
	QueryKeys     []string `json:"query_keys"`     // 见过的 query 参数名（排序去重）
	StatusCodes   []int    `json:"status_codes"`   // 见过的状态码（排序去重）
	FirstSeen     string   `json:"first_seen"`     // 首个样本的 startedDateTime（RFC3339）
	LastSeen      string   `json:"last_seen"`      // 最后一个样本的 startedDateTime（RFC3339）
	StaticURL     bool     `json:"static_url"`     // 所有样本的 URL 完全相同（路径无动态段）
	SampleURL     string   `json:"sample_url"`     // 一个代表性样本的完整 URL
	ParamSegments []string `json:"param_segments"` // 被归一化的路径段位置描述，如 "segment[2]"
}

// segmentFingerprint 路径段的形态分类
type segmentFingerprint int

const (
	segLiteral  segmentFingerprint = iota // 字面量段（含字母等非纯值字符）
	segNumeric                            // 纯数字段（ID、时间戳等）
	segHex                                // 纯十六进制段（≥8 位）
	segBase64                             // base64/base64url 形态段（≥12 位）
	segUUID                               // UUID 形态段
)

var (
	uuidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexRe    = regexp.MustCompile(`^[0-9a-fA-F]{8,}$`)
	b64Re    = regexp.MustCompile(`^[A-Za-z0-9_\-+/=]{12,}$`)
	numRe    = regexp.MustCompile(`^[0-9]+$`)
	digitRe  = regexp.MustCompile(`[0-9]`)
	letterRe = regexp.MustCompile(`[a-zA-Z]`)
)

// classifySegment 判定单个路径段的形态
func classifySegment(seg string) segmentFingerprint {
	if seg == "" {
		return segLiteral
	}
	if uuidRe.MatchString(seg) {
		return segUUID
	}
	if numRe.MatchString(seg) {
		return segNumeric
	}
	// 纯 hex 段：要求长度 ≥8 且不含 g-z 字母（短段如 "abc123" 容易误伤）
	if hexRe.MatchString(seg) {
		return segHex
	}
	// base64 形态：仅 base64 字符集、长度 ≥12、且同时含字母和数字
	if b64Re.MatchString(seg) && digitRe.MatchString(seg) && letterRe.MatchString(seg) {
		return segBase64
	}
	return segLiteral
}

// isParamLikeSegment 判定段是否应被视为路径参数（动态值）
func isParamLikeSegment(seg string) bool {
	switch classifySegment(seg) {
	case segUUID, segNumeric, segHex, segBase64:
		return true
	default:
		return false
	}
}

// normalizeHost 规范化 host：小写，剥离默认端口
func normalizeHost(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		return host
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		return host
	}
	return host + ":" + port
}

// splitPathSegments 按 "/" 拆分路径，丢弃空段
func splitPathSegments(path string) []string {
	raw := strings.Split(path, "/")
	var segs []string
	for _, s := range raw {
		if s != "" {
			segs = append(segs, s)
		}
	}
	return segs
}

// normalizePath 单 URL 局部归一化：参数形态的段替换为 {param}
// 返回归一化后的路径与被替换段的位置列表（0 基段索引）
func normalizePath(path string) (string, []int) {
	segs := splitPathSegments(path)
	if len(segs) == 0 {
		return "/", nil
	}
	var paramPositions []int
	out := make([]string, len(segs))
	for i, seg := range segs {
		if isParamLikeSegment(seg) {
			out[i] = "{param}"
			paramPositions = append(paramPositions, i)
		} else {
			out[i] = seg
		}
	}
	return "/" + strings.Join(out, "/"), paramPositions
}

// pathTemplateKey 生成用于分组的路径模板 key
func pathTemplateKey(method, host, normPath string) string {
	return strings.ToUpper(method) + " " + host + " " + normPath
}

// BuildEndpoints 对整个 HAR 做端点指纹归一化
//
// 实现策略：第一遍单 URL 局部归一化；第二遍收敛——若某模板只有一个样本
// （即该"参数段"从未变化），则回退为字面量段。这避免把 /order/20240920
// 这类单样本静态路径段误判为参数。
func (h *Har) BuildEndpoints() []*Endpoint {
	if h == nil || len(h.Log.Entries) == 0 {
		return nil
	}

	type accumulator struct {
		ep           *Endpoint
		normSegs     []string         // 归一化后的段
		rawSegValues map[int][]string // 参数段位置 → 各样本原始值
		singleURL    string           // 首个样本 URL（StaticURL 判定用）
		allSameURL   bool
	}

	acc := make(map[string]*accumulator)
	var order []string

	for i := range h.Log.Entries {
		e := &h.Log.Entries[i]
		u, err := url.Parse(e.Request.URL)
		if err != nil {
			// 无法解析的 URL 按原始字符串整段作为 path（host 为空）
			u = &url.URL{Path: e.Request.URL}
		}
		host := normalizeHost(u)
		normPath, paramPos := normalizePath(u.Path)
		key := pathTemplateKey(e.Request.Method, host, normPath)

		a, ok := acc[key]
		if !ok {
			ep := &Endpoint{
				ID:           len(order),
				Method:       strings.ToUpper(e.Request.Method),
				Host:         host,
				PathTemplate: normPath,
				Fingerprint:  key,
				SampleURL:    e.Request.URL,
				FirstSeen:    e.StartedDateTime.Format("2006-01-02T15:04:05.000Z07:00"),
				EntryIndices: []int{},
			}
			a = &accumulator{
				ep:           ep,
				normSegs:     splitPathSegments(normPath),
				rawSegValues: make(map[int][]string),
				singleURL:    e.Request.URL,
				allSameURL:   true,
			}
			acc[key] = a
			order = append(order, key)
		}

		ep := a.ep
		ep.EntryIndices = append(ep.EntryIndices, i)
		ep.Count++
		ep.LastSeen = e.StartedDateTime.Format("2006-01-02T15:04:05.000Z07:00")
		if e.Request.URL != a.singleURL {
			a.allSameURL = false
		}

		// 记录参数段的原始值（用于第二遍收敛）
		rawSegs := splitPathSegments(u.Path)
		for _, idx := range paramPos {
			if idx < len(rawSegs) {
				a.rawSegValues[idx] = append(a.rawSegValues[idx], rawSegs[idx])
			}
		}

		// query keys 与状态码
		for _, qs := range e.Request.QueryString {
			if !containsString(ep.QueryKeys, qs.Name) {
				ep.QueryKeys = append(ep.QueryKeys, qs.Name)
			}
		}
		if !containsInt(ep.StatusCodes, e.Response.Status) {
			ep.StatusCodes = append(ep.StatusCodes, e.Response.Status)
		}
	}

	// 第二遍收敛：单样本模板的参数段回退为字面量
	for _, key := range order {
		a := acc[key]
		if a.ep.Count > 1 || len(a.rawSegValues) == 0 {
			continue
		}
		// 恢复 {param} 为原始段值
		rawSegs := splitPathSegments(parsePathOnly(a.singleURL))
		segs := make([]string, len(a.normSegs))
		copy(segs, a.normSegs)
		changed := false
		for idx := range segs {
			if segs[idx] == "{param}" && idx < len(rawSegs) {
				segs[idx] = rawSegs[idx]
				changed = true
			}
		}
		if changed {
			newPath := "/" + strings.Join(segs, "/")
			a.ep.PathTemplate = newPath
			a.ep.Fingerprint = pathTemplateKey(a.ep.Method, a.ep.Host, newPath)
		}
	}

	// 收尾：排序字段、填充 ParamSegments、StaticURL
	result := make([]*Endpoint, 0, len(order))
	for _, key := range order {
		a := acc[key]
		ep := a.ep
		sort.Strings(ep.QueryKeys)
		sort.Ints(ep.StatusCodes)
		ep.StaticURL = a.allSameURL
		var ps []string
		for i, seg := range splitPathSegments(ep.PathTemplate) {
			if seg == "{param}" {
				ps = append(ps, "segment["+strconv.Itoa(i)+"]")
			}
		}
		ep.ParamSegments = ps
		result = append(result, ep)
	}
	return result
}

// parsePathOnly 提取 URL 的 path 部分（url.Parse 失败时返回原串）
func parsePathOnly(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Path
}

// 并发安全的端点缓存（按 Har 指针）
var endpointCache sync.Map // map[*Har][]*Endpoint

// BuildEndpointsCached 带缓存的 BuildEndpoints
func (h *Har) BuildEndpointsCached() []*Endpoint {
	if v, ok := endpointCache.Load(h); ok {
		return v.([]*Endpoint)
	}
	eps := h.BuildEndpoints()
	endpointCache.Store(h, eps)
	return eps
}

// FindEndpointByFingerprint 按指纹精确查找端点
func (h *Har) FindEndpointByFingerprint(fingerprint string) *Endpoint {
	for _, ep := range h.BuildEndpoints() {
		if ep.Fingerprint == fingerprint {
			return ep
		}
	}
	return nil
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func containsInt(slice []int, n int) bool {
	for _, v := range slice {
		if v == n {
			return true
		}
	}
	return false
}
