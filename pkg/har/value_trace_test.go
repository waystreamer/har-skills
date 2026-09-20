package har

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestTraceValueInQueryParam(t *testing.T) {
	h := NewHar()
	now := time.Now()

	e := h.AddEntry("GET", "https://api.example.com/sign?token=abc123xyz", "HTTP/1.1", "")
	e.SetResponseStatus(200, "OK")
	e.StartedDateTime = now
	e.Request.QueryString = []QueryString{{Name: "token", Value: "abc123xyz"}}

	report := h.TraceValue("abc123xyz", DefaultValueTraceOptions())
	if report.TotalHits == 0 {
		t.Fatal("Expected hits for query param value")
	}

	found := false
	for _, loc := range report.Locations {
		if loc.FieldType == "query" && loc.FieldName == "token" {
			found = true
		}
	}
	if !found {
		t.Error("Expected query param location")
	}
}

func TestTraceValueInRequestHeader(t *testing.T) {
	h := NewHar()
	now := time.Now()

	e := h.AddEntry("GET", "https://api.example.com/api", "HTTP/1.1", "")
	e.SetResponseStatus(200, "OK")
	e.StartedDateTime = now
	e.Request.Headers = []Headers{{Name: "Authorization", Value: "Bearer my-secret-token"}}

	report := h.TraceValue("my-secret-token", DefaultValueTraceOptions())
	found := false
	for _, loc := range report.Locations {
		if loc.FieldType == "header" && loc.FieldName == "Authorization" && loc.Direction == "request" {
			found = true
		}
	}
	if !found {
		t.Error("Expected request header location")
	}
}

func TestTraceValueInCookie(t *testing.T) {
	h := NewHar()
	now := time.Now()

	// 响应下发 cookie
	e1 := h.AddEntry("POST", "https://api.example.com/login", "HTTP/1.1", "")
	e1.SetResponseStatus(200, "OK")
	e1.StartedDateTime = now
	e1.Response.Cookies = []Cookie{{Name: "session", Value: "sess-abc-999"}}

	// 后续请求携带
	e2 := h.AddEntry("GET", "https://api.example.com/profile", "HTTP/1.1", "")
	e2.SetResponseStatus(200, "OK")
	e2.StartedDateTime = now.Add(time.Second)
	e2.Request.Cookies = []Cookie{{Name: "session", Value: "sess-abc-999"}}

	report := h.TraceValue("sess-abc-999", DefaultValueTraceOptions())
	if report.TotalHits < 2 {
		t.Fatalf("Expected ≥2 hits (set + sent), got %d", report.TotalHits)
	}

	var setLoc, sentLoc bool
	for _, loc := range report.Locations {
		if loc.Direction == "response" && loc.FieldType == "cookie" {
			setLoc = true
		}
		if loc.Direction == "request" && loc.FieldType == "cookie" {
			sentLoc = true
		}
	}
	if !setLoc {
		t.Error("Expected response cookie (set) location")
	}
	if !sentLoc {
		t.Error("Expected request cookie (sent) location")
	}
}

func TestTraceValueInPostParam(t *testing.T) {
	h := NewHar()
	now := time.Now()

	e := h.AddEntry("POST", "https://api.example.com/submit", "HTTP/1.1", "")
	e.SetResponseStatus(200, "OK")
	e.StartedDateTime = now
	e.Request.PostData = &PostData{
		MimeType: "application/x-www-form-urlencoded",
		Params:   []Param{{Name: "csrf_token", Value: "csrf-xyz-123"}},
	}

	report := h.TraceValue("csrf-xyz-123", DefaultValueTraceOptions())
	found := false
	for _, loc := range report.Locations {
		if loc.FieldType == "post-param" && loc.FieldName == "csrf_token" {
			found = true
		}
	}
	if !found {
		t.Error("Expected post-param location")
	}
}

func TestTraceValueInResponseBody(t *testing.T) {
	h := NewHar()
	now := time.Now()

	e := h.AddEntry("GET", "https://api.example.com/api/data", "HTTP/1.1", "")
	e.SetResponseStatus(200, "OK")
	e.StartedDateTime = now
	e.Response.Content = Content{
		Size:     100,
		MimeType: "application/json",
		Text:     `{"sign": "sig-abc-777", "status": "ok"}`,
	}

	report := h.TraceValue("sig-abc-777", DefaultValueTraceOptions())
	found := false
	for _, loc := range report.Locations {
		if loc.FieldType == "body" && loc.Direction == "response" {
			found = true
			if !strings.Contains(loc.Context, "sig-abc-777") {
				t.Errorf("Expected context to contain the value, got %q", loc.Context)
			}
		}
	}
	if !found {
		t.Error("Expected response body location")
	}
}

func TestTraceValueURLEncoded(t *testing.T) {
	h := NewHar()
	now := time.Now()

	// 值含特殊字符，在 URL 里被 encode
	rawValue := "token/with+special=chars"
	e := h.AddEntry("GET", "https://api.example.com/callback?state=token%2Fwith%2Bspecial%3Dchars", "HTTP/1.1", "")
	e.SetResponseStatus(200, "OK")
	e.StartedDateTime = now
	e.Request.QueryString = []QueryString{{Name: "state", Value: "token%2Fwith%2Bspecial%3Dchars"}}

	opts := DefaultValueTraceOptions()
	opts.IncludeURLEncoded = true
	report := h.TraceValue(rawValue, opts)

	foundEncoded := false
	for _, loc := range report.Locations {
		if loc.MatchType == "url-encoded" {
			foundEncoded = true
		}
	}
	if !foundEncoded {
		t.Error("Expected url-encoded match type")
	}
}

func TestTraceValueBase64Encoded(t *testing.T) {
	h := NewHar()
	now := time.Now()

	secret := "my-secret-value"
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))

	e := h.AddEntry("POST", "https://api.example.com/api", "HTTP/1.1", "")
	e.SetResponseStatus(200, "OK")
	e.StartedDateTime = now
	e.Request.Headers = []Headers{{Name: "X-Token", Value: encoded}}

	opts := DefaultValueTraceOptions()
	opts.IncludeBase64 = true
	report := h.TraceValue(secret, opts)

	foundB64 := false
	for _, loc := range report.Locations {
		if loc.MatchType == "base64" {
			foundB64 = true
		}
	}
	if !foundB64 {
		t.Error("Expected base64 match type")
	}
}

func TestTraceValueEmptyAndNil(t *testing.T) {
	h := NewHar()
	e := h.AddEntry("GET", "https://example.com", "HTTP/1.1", "")
	e.SetResponseStatus(200, "OK")

	// 空值
	report := h.TraceValue("", DefaultValueTraceOptions())
	if report.TotalHits != 0 {
		t.Error("Expected 0 hits for empty value")
	}

	// nil HAR
	var nilHar *Har
	report = nilHar.TraceValue("anything", DefaultValueTraceOptions())
	if report.TotalHits != 0 {
		t.Error("Expected 0 hits for nil HAR")
	}
}

func TestTraceValueFirstSeen(t *testing.T) {
	h := NewHar()
	now := time.Now()

	e1 := h.AddEntry("GET", "https://api.example.com/first?val=find-me", "HTTP/1.1", "")
	e1.SetResponseStatus(200, "OK")
	e1.StartedDateTime = now
	e1.Request.QueryString = []QueryString{{Name: "val", Value: "find-me"}}

	e2 := h.AddEntry("GET", "https://api.example.com/second?val=find-me", "HTTP/1.1", "")
	e2.SetResponseStatus(200, "OK")
	e2.StartedDateTime = now.Add(time.Second)
	e2.Request.QueryString = []QueryString{{Name: "val", Value: "find-me"}}

	report := h.TraceValue("find-me", DefaultValueTraceOptions())
	if report.FirstSeen == nil {
		t.Fatal("Expected FirstSeen to be set")
	}
	if report.FirstSeen.EntryIndex != 0 {
		t.Errorf("Expected FirstSeen at index 0, got %d", report.FirstSeen.EntryIndex)
	}
}

func TestTraceValueBodySkippedWhenDisabled(t *testing.T) {
	h := NewHar()
	now := time.Now()

	e := h.AddEntry("POST", "https://api.example.com/api", "HTTP/1.1", "")
	e.SetResponseStatus(200, "OK")
	e.StartedDateTime = now
	e.Request.PostData = &PostData{
		MimeType: "application/json",
		Text:     `{"key": "body-only-value"}`,
	}

	opts := DefaultValueTraceOptions()
	opts.IncludeBody = false
	report := h.TraceValue("body-only-value", opts)

	for _, loc := range report.Locations {
		if loc.FieldType == "body" {
			t.Error("Expected no body matches when IncludeBody=false")
		}
	}
}

func TestTraceValueBase64ResponseBody(t *testing.T) {
	h := NewHar()
	now := time.Now()

	plainText := `{"token": "b64-body-secret"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(plainText))

	e := h.AddEntry("GET", "https://api.example.com/api", "HTTP/1.1", "")
	e.SetResponseStatus(200, "OK")
	e.StartedDateTime = now
	e.Response.Content = Content{
		Size:     len(plainText),
		MimeType: "application/json",
		Text:     encoded,
		Encoding: "base64",
	}

	report := h.TraceValue("b64-body-secret", DefaultValueTraceOptions())
	found := false
	for _, loc := range report.Locations {
		if loc.FieldType == "body" && loc.Direction == "response" {
			found = true
		}
	}
	if !found {
		t.Error("Expected base64-encoded response body to be decoded and matched")
	}
}

func TestExtractContext(t *testing.T) {
	target := "prefix_value-of-interest_suffix"
	idx := strings.Index(target, "value-of-interest")
	ctx := extractContext(target, idx, len("value-of-interest"), 5)
	if !strings.Contains(ctx, "value-of-interest") {
		t.Errorf("Expected context to contain match, got %q", ctx)
	}

	// 边界：值在开头
	ctx2 := extractContext("start-match-here", 0, 5, 5)
	if !strings.HasPrefix(ctx2, "start") {
		t.Errorf("Expected context at start, got %q", ctx2)
	}
}
