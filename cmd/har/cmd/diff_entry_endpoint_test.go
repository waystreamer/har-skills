package cmd

import (
	"strings"
	"testing"
	"time"

	har "github.com/waystreamer/har-skills/pkg/har"
)

// makeEndpointHar 构造一个含已知端点的测试 HAR
func makeEndpointHar() *har.Har {
	h := har.NewHar()
	now := time.Now()

	// GET /user/{param}/orders ×2（status 200）
	e1 := h.AddEntry("GET", "https://api.example.com/user/1/orders", "HTTP/1.1", "")
	e1.SetResponseStatus(200, "OK")
	e1.StartedDateTime = now

	e2 := h.AddEntry("GET", "https://api.example.com/user/2/orders", "HTTP/1.1", "")
	e2.SetResponseStatus(200, "OK")
	e2.StartedDateTime = now.Add(time.Second)

	// POST /feed ×2（status 200 和 400）
	e3 := h.AddEntry("POST", "https://api.example.com/feed", "HTTP/1.1", "")
	e3.SetResponseStatus(200, "OK")
	e3.StartedDateTime = now.Add(2*time.Second)

	e4 := h.AddEntry("POST", "https://api.example.com/feed", "HTTP/1.1", "")
	e4.SetResponseStatus(400, "Bad Request")
	e4.StartedDateTime = now.Add(3*time.Second)

	return h
}

func TestPickByEndpointBasic(t *testing.T) {
	h := makeEndpointHar()

	a, b, err := pickByEndpoint(h, "POST api.example.com /feed", 200, 400)
	if err != nil {
		t.Fatalf("pickByEndpoint failed: %v", err)
	}
	if h.Log.Entries[a].Response.Status != 200 {
		t.Errorf("Expected A status 200, got %d", h.Log.Entries[a].Response.Status)
	}
	if h.Log.Entries[b].Response.Status != 400 {
		t.Errorf("Expected B status 400, got %d", h.Log.Entries[b].Response.Status)
	}
}

func TestPickByEndpointDefaultStatus(t *testing.T) {
	h := makeEndpointHar()

	// status -1 = 取第一个样本
	a, b, err := pickByEndpoint(h, "GET api.example.com /user/{param}/orders", -1, -1)
	if err == nil {
		// 同一个样本（a==b）应该报错
		if a == b {
			t.Error("Expected error when both statuses default to same sample")
		}
	}
	_ = err
}

func TestPickByEndpointNotFound(t *testing.T) {
	h := makeEndpointHar()

	_, _, err := pickByEndpoint(h, "GET nonexistent.com /api", -1, -1)
	if err == nil {
		t.Error("Expected error for unknown endpoint")
	}
	if !strings.Contains(err.Error(), "未找到端点") {
		t.Errorf("Expected '未找到端点' error, got: %v", err)
	}
}

func TestPickByEndpointStatusNotFound(t *testing.T) {
	h := makeEndpointHar()

	_, _, err := pickByEndpoint(h, "POST api.example.com /feed", 200, 404)
	if err == nil {
		t.Error("Expected error for missing status 404")
	}
	if !strings.Contains(err.Error(), "没有状态码 404") {
		t.Errorf("Expected status not found error, got: %v", err)
	}
}

func TestPathPrefix(t *testing.T) {
	cases := []struct {
		path     string
		n        int
		expected string
	}{
		{"/act/api/activityentry", 2, "/act/api/"},
		{"/rest/2.0/membership/user", 2, "/rest/2.0/"},
		{"/feed/cardinfos", 2, "/feed/cardinfos/"},
		{"/", 2, "/"},
		{"/api", 2, "/api/"},
	}
	for _, c := range cases {
		got := pathPrefix(c.path, c.n)
		if got != c.expected {
			t.Errorf("pathPrefix(%q, %d) = %q, want %q", c.path, c.n, got, c.expected)
		}
	}
}

func TestFormatEndpointsTree(t *testing.T) {
	report := &endpointsReport{
		TotalEntries:   10,
		TotalEndpoints: 2,
		Endpoints: []*har.Endpoint{
			{
				ID: 0, Method: "GET", Host: "pan.baidu.com",
				PathTemplate: "/rest/2.0/membership/user",
				Count: 6, EntryIndices: []int{0, 1, 2, 3, 4, 5},
				StatusCodes: []int{200},
				SampleURL: "https://pan.baidu.com/rest/2.0/membership/user",
			},
			{
				ID: 1, Method: "POST", Host: "pan.baidu.com",
				PathTemplate: "/feed/cardinfos",
				Count: 4, EntryIndices: []int{6, 7, 8, 9},
				StatusCodes: []int{200, 400},
				SampleURL: "https://pan.baidu.com/feed/cardinfos",
			},
		},
	}

	out := formatEndpointsTree(report)
	if !strings.Contains(out, "pan.baidu.com") {
		t.Error("Expected host in tree output")
	}
	if !strings.Contains(out, "/rest/2.0/") {
		t.Error("Expected path prefix in tree output")
	}
	if !strings.Contains(out, "×6") {
		t.Error("Expected count in tree output")
	}
}

func TestValueTraceFromResponse(t *testing.T) {
	h := har.NewHar()
	now := time.Now()

	// 响应下发
	e1 := h.AddEntry("POST", "https://api.example.com/login", "HTTP/1.1", "")
	e1.SetResponseStatus(200, "OK")
	e1.StartedDateTime = now
	e1.Response.Cookies = []har.Cookie{{Name: "session", Value: "srv-token-123"}}
	e1.Response.Content = har.Content{
		Size: 100, MimeType: "application/json",
		Text: `{"token": "srv-token-123"}`,
	}

	// 请求携带
	e2 := h.AddEntry("GET", "https://api.example.com/api", "HTTP/1.1", "")
	e2.SetResponseStatus(200, "OK")
	e2.StartedDateTime = now.Add(time.Second)
	e2.Request.Cookies = []har.Cookie{{Name: "session", Value: "srv-token-123"}}

	report := h.TraceValue("srv-token-123", har.DefaultValueTraceOptions())

	// 模拟 --from-response 过滤
	var filtered []har.ValueLocation
	for _, loc := range report.Locations {
		if loc.Direction == "response" {
			filtered = append(filtered, loc)
		}
	}
	if len(filtered) == 0 {
		t.Error("Expected response-side hits")
	}
	for _, loc := range filtered {
		if loc.Direction != "response" {
			t.Errorf("Expected only response locations, got %s", loc.Direction)
		}
	}
}
