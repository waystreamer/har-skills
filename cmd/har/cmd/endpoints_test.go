package cmd

import (
	"strings"
	"testing"
	"time"

	har "github.com/waystreamer/har-skills/pkg/har"
)

func TestFormatEndpointsText(t *testing.T) {
	report := &endpointsReport{
		TotalEntries:   10,
		TotalEndpoints: 2,
		Endpoints: []*har.Endpoint{
			{
				ID:           0,
				Method:       "GET",
				Host:         "api.example.com",
				PathTemplate: "/user/{param}/orders",
				Fingerprint:  "GET api.example.com /user/{param}/orders",
				Count:        3,
				EntryIndices: []int{0, 3, 7},
				QueryKeys:    []string{"page", "size"},
				StatusCodes:  []int{200},
				SampleURL:    "https://api.example.com/user/123/orders?page=1",
				FirstSeen:    time.Now().Format("2006-01-02T15:04:05.000Z07:00"),
				LastSeen:     time.Now().Format("2006-01-02T15:04:05.000Z07:00"),
			},
			{
				ID:           1,
				Method:       "POST",
				Host:         "api.example.com",
				PathTemplate: "/auth/login",
				Fingerprint:  "POST api.example.com /auth/login",
				Count:        1,
				EntryIndices: []int{5},
				StatusCodes:  []int{200, 401},
				SampleURL:    "https://api.example.com/auth/login",
				StaticURL:    true,
			},
		},
	}

	out := formatEndpointsText(report, 60)

	if !strings.Contains(out, "10 条请求") {
		t.Error("Expected total entries in output")
	}
	if !strings.Contains(out, "2 个端点") {
		t.Error("Expected total endpoints in output")
	}
	if !strings.Contains(out, "/user/{param}/orders") {
		t.Error("Expected path template in output")
	}
	if !strings.Contains(out, "×3") {
		t.Error("Expected sample count in output")
	}
	if !strings.Contains(out, "page, size") {
		t.Error("Expected query keys in output")
	}
	if !strings.Contains(out, "[0 3 7]") {
		t.Error("Expected entry indices in output")
	}
}

func TestFormatEndpointsTextEmpty(t *testing.T) {
	report := &endpointsReport{TotalEntries: 0, TotalEndpoints: 0}
	out := formatEndpointsText(report, 60)
	if !strings.Contains(out, "无匹配端点") {
		t.Error("Expected empty message")
	}
}
