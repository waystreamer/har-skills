package har

import (
	"strings"
	"testing"
	"time"
)

// addEntry 快速添加测试 entry
func addEntryWithTime(h *Har, method, url string, status int, t time.Time) *Entries {
	e := h.AddEntry(method, url, "HTTP/1.1", "")
	e.SetResponseStatus(status, "OK")
	e.StartedDateTime = t
	return e
}

func TestClassifySegment(t *testing.T) {
	cases := []struct {
		seg      string
		expected segmentFingerprint
	}{
		{"users", segLiteral},
		{"api", segLiteral},
		{"v1", segLiteral},      // 含字母+数字但太短，字面量
		{"123", segNumeric},     // 纯数字
		{"0", segNumeric},
		{"550e8400-e29b-41d4-a716-446655440000", segUUID},
		{"a1b2c3d4e5f6", segHex}, // ≥8 位 hex
		{"deadbeef", segHex},
		{"abc123", segLiteral},  // 6 位太短，不按 hex 处理
		{"dGVzdA==", segLiteral}, // 8 位 base64 但 <12
		{"dGVzdCBsb25nIHN0cmluZw==", segBase64}, // ≥12 且含字母+数字
		{"", segLiteral},
	}
	for _, c := range cases {
		got := classifySegment(c.seg)
		if got != c.expected {
			t.Errorf("classifySegment(%q) = %d, want %d", c.seg, got, c.expected)
		}
	}
}

func TestNormalizePath(t *testing.T) {
	cases := []struct {
		path     string
		expected string
	}{
		{"/api/users", "/api/users"},
		{"/user/123/orders", "/user/{param}/orders"},
		{"/user/550e8400-e29b-41d4-a716-446655440000/profile", "/user/{param}/profile"},
		{"/", "/"},
		{"", "/"},
		{"/api/v1/items", "/api/v1/items"}, // v1 是字面量
	}
	for _, c := range cases {
		got, _ := normalizePath(c.path)
		if got != c.expected {
			t.Errorf("normalizePath(%q) = %q, want %q", c.path, got, c.expected)
		}
	}
}

func TestBuildEndpointsBasic(t *testing.T) {
	h := NewHar()
	now := time.Now()

	addEntryWithTime(h, "GET", "https://api.example.com/user/123/orders", 200, now)
	addEntryWithTime(h, "GET", "https://api.example.com/user/456/orders", 200, now.Add(time.Second))
	addEntryWithTime(h, "POST", "https://api.example.com/user/123/orders", 201, now.Add(2*time.Second))
	addEntryWithTime(h, "GET", "https://api.example.com/api/health", 200, now.Add(3*time.Second))

	eps := h.BuildEndpoints()
	if len(eps) != 3 {
		t.Fatalf("Expected 3 endpoints, got %d", len(eps))
	}

	// 找到 /user/{param}/orders 端点
	var target *Endpoint
	for _, ep := range eps {
		if ep.PathTemplate == "/user/{param}/orders" && ep.Method == "GET" {
			target = ep
		}
	}
	if target == nil {
		t.Fatal("Expected endpoint GET /user/{param}/orders not found")
	}
	if target.Count != 2 {
		t.Errorf("Expected count=2, got %d", target.Count)
	}
	if len(target.EntryIndices) != 2 || target.EntryIndices[0] != 0 || target.EntryIndices[1] != 1 {
		t.Errorf("Expected entry indices [0 1], got %v", target.EntryIndices)
	}
	if target.StaticURL {
		t.Error("Expected StaticURL=false (two different URLs)")
	}
	if len(target.ParamSegments) == 0 {
		t.Error("Expected ParamSegments to be non-empty")
	}
}

func TestBuildEndpointsMethodAndHostDistinct(t *testing.T) {
	h := NewHar()
	now := time.Now()

	addEntryWithTime(h, "GET", "https://a.com/api", 200, now)
	addEntryWithTime(h, "POST", "https://a.com/api", 200, now) // 不同 method → 不同 endpoint
	addEntryWithTime(h, "GET", "https://b.com/api", 200, now)  // 不同 host → 不同 endpoint

	eps := h.BuildEndpoints()
	if len(eps) != 3 {
		t.Errorf("Expected 3 endpoints, got %d", len(eps))
	}
}

func TestBuildEndpointsQueryNotInFingerprint(t *testing.T) {
	h := NewHar()
	now := time.Now()

	e1 := addEntryWithTime(h, "GET", "https://api.example.com/search?q=a&page=1", 200, now)
	e1.Request.QueryString = []QueryString{{Name: "q", Value: "a"}, {Name: "page", Value: "1"}}

	e2 := addEntryWithTime(h, "GET", "https://api.example.com/search?q=b&page=2", 200, now.Add(time.Second))
	e2.Request.QueryString = []QueryString{{Name: "q", Value: "b"}, {Name: "page", Value: "2"}}

	eps := h.BuildEndpoints()
	if len(eps) != 1 {
		t.Fatalf("Expected 1 endpoint (query ignored), got %d", len(eps))
	}
	ep := eps[0]
	if len(ep.QueryKeys) != 2 {
		t.Errorf("Expected 2 query keys (q, page), got %v", ep.QueryKeys)
	}
}

func TestBuildEndpointsSingleSampleStaticSegmentReverted(t *testing.T) {
	h := NewHar()
	now := time.Now()

	// 单样本：/order/20240920 的日期段看起来像数字，但只有一条样本，应回退为字面量
	addEntryWithTime(h, "GET", "https://api.example.com/order/20240920", 200, now)

	eps := h.BuildEndpoints()
	if len(eps) != 1 {
		t.Fatalf("Expected 1 endpoint, got %d", len(eps))
	}
	ep := eps[0]
	if ep.PathTemplate != "/order/20240920" {
		t.Errorf("Expected single-sample numeric segment reverted to literal, got %q", ep.PathTemplate)
	}
	if len(ep.ParamSegments) != 0 {
		t.Errorf("Expected no ParamSegments after revert, got %v", ep.ParamSegments)
	}
	if !ep.StaticURL {
		t.Error("Expected StaticURL=true for single entry")
	}
}

func TestBuildEndpointsMultiSampleNumericSegmentKept(t *testing.T) {
	h := NewHar()
	now := time.Now()

	// 多样本：/order/20240920 和 /order/20240921 → 数字段确实是参数
	addEntryWithTime(h, "GET", "https://api.example.com/order/20240920", 200, now)
	addEntryWithTime(h, "GET", "https://api.example.com/order/20240921", 200, now.Add(time.Second))

	eps := h.BuildEndpoints()
	if len(eps) != 1 {
		t.Fatalf("Expected 1 endpoint, got %d", len(eps))
	}
	ep := eps[0]
	if ep.PathTemplate != "/order/{param}" {
		t.Errorf("Expected multi-sample numeric segment kept as {param}, got %q", ep.PathTemplate)
	}
	if ep.Count != 2 {
		t.Errorf("Expected count=2, got %d", ep.Count)
	}
}

func TestBuildEndpointsUUID(t *testing.T) {
	h := NewHar()
	now := time.Now()

	addEntryWithTime(h, "GET", "https://api.example.com/session/550e8400-e29b-41d4-a716-446655440000", 200, now)
	addEntryWithTime(h, "GET", "https://api.example.com/session/6ba7b810-9dad-11d1-80b4-00c04fd430c8", 200, now.Add(time.Second))

	eps := h.BuildEndpoints()
	if len(eps) != 1 {
		t.Fatalf("Expected 1 endpoint, got %d", len(eps))
	}
	if eps[0].PathTemplate != "/session/{param}" {
		t.Errorf("Expected UUID normalized to {param}, got %q", eps[0].PathTemplate)
	}
}

func TestBuildEndpointsNilAndEmpty(t *testing.T) {
	var nilHar *Har
	if eps := nilHar.BuildEndpoints(); eps != nil {
		t.Error("Expected nil for nil Har")
	}

	h := NewHar()
	if eps := h.BuildEndpoints(); eps != nil {
		t.Error("Expected nil for empty Har")
	}
}

func TestBuildEndpointsDefaultPortStripped(t *testing.T) {
	h := NewHar()
	now := time.Now()

	addEntryWithTime(h, "GET", "https://api.example.com:443/api", 200, now)
	addEntryWithTime(h, "GET", "https://api.example.com/api", 200, now.Add(time.Second))

	eps := h.BuildEndpoints()
	if len(eps) != 1 {
		t.Errorf("Expected default port :443 stripped, got %d endpoints", len(eps))
	}
}

func TestBuildEndpointsNonDefaultPortKept(t *testing.T) {
	h := NewHar()
	now := time.Now()

	addEntryWithTime(h, "GET", "https://api.example.com:8443/api", 200, now)
	addEntryWithTime(h, "GET", "https://api.example.com/api", 200, now.Add(time.Second))

	eps := h.BuildEndpoints()
	if len(eps) != 2 {
		t.Errorf("Expected non-default port kept, got %d endpoints", len(eps))
	}
}

func TestBuildEndpointsStatusCodes(t *testing.T) {
	h := NewHar()
	now := time.Now()

	addEntryWithTime(h, "GET", "https://api.example.com/data", 200, now)
	addEntryWithTime(h, "GET", "https://api.example.com/data", 500, now.Add(time.Second))

	eps := h.BuildEndpoints()
	if len(eps) != 1 {
		t.Fatalf("Expected 1 endpoint, got %d", len(eps))
	}
	if len(eps[0].StatusCodes) != 2 {
		t.Errorf("Expected status codes [200 500], got %v", eps[0].StatusCodes)
	}
}

func TestBuildEndpointsInvalidURL(t *testing.T) {
	h := NewHar()
	now := time.Now()

	// 无法解析的 URL 不应 panic，按原字符串作为 path
	e := h.AddEntry("GET", "://invalid-url", "HTTP/1.1", "")
	e.SetResponseStatus(0, "")
	e.StartedDateTime = now

	eps := h.BuildEndpoints()
	if len(eps) != 1 {
		t.Fatalf("Expected 1 endpoint for invalid URL, got %d", len(eps))
	}
}

func TestFindEndpointByFingerprint(t *testing.T) {
	h := NewHar()
	now := time.Now()

	addEntryWithTime(h, "GET", "https://api.example.com/user/1/profile", 200, now)
	addEntryWithTime(h, "GET", "https://api.example.com/user/2/profile", 200, now.Add(time.Second))

	fp := "GET api.example.com /user/{param}/profile"
	ep := h.FindEndpointByFingerprint(fp)
	if ep == nil {
		t.Fatalf("Expected to find endpoint by fingerprint %q", fp)
	}
	if ep.Count != 2 {
		t.Errorf("Expected count=2, got %d", ep.Count)
	}

	if h.FindEndpointByFingerprint("GET api.example.com /nonexistent") != nil {
		t.Error("Expected nil for unknown fingerprint")
	}
}

func TestBuildEndpointsFingerprintFormat(t *testing.T) {
	h := NewHar()
	now := time.Now()

	addEntryWithTime(h, "POST", "https://api.example.com/user/99/orders", 201, now)
	addEntryWithTime(h, "POST", "https://api.example.com/user/100/orders", 201, now.Add(time.Second))

	eps := h.BuildEndpoints()
	if len(eps) != 1 {
		t.Fatalf("Expected 1 endpoint, got %d", len(eps))
	}
	ep := eps[0]
	if !strings.HasPrefix(ep.Fingerprint, "POST api.example.com ") {
		t.Errorf("Fingerprint format unexpected: %q", ep.Fingerprint)
	}
}
