package cmd

import (
	"testing"
	"time"

	har "github.com/waystreamer/har-skills/pkg/har"
)

// 构造一个最小可用 HAR：两个条目，同一接口两次调用，query/cookie 有差异
func buildTwoEntryHar() *har.Har {
	ts := time.Date(2026, 6, 11, 8, 51, 23, 0, time.UTC)
	mkEntry := func(url string, qs []har.QueryString, cookies []har.Cookie, status int, body string) har.Entries {
		return har.Entries{
			StartedDateTime: ts,
			Request: har.Request{
				Method:      "GET",
				URL:         url,
				HTTPVersion: "HTTP/2",
				QueryString: qs,
				Cookies:     cookies,
			},
			Response: har.Response{
				Status:      status,
				HTTPVersion: "HTTP/2",
				Content: har.Content{
					Size:     len(body),
					MimeType: "application/json",
					Text:     body,
				},
			},
		}
	}

	e1 := mkEntry(
		"https://api.example.com/sign?t=1&rand=aaa",
		[]har.QueryString{{Name: "t", Value: "1"}, {Name: "rand", Value: "aaa"}, {Name: "sign", Value: "s1"}},
		[]har.Cookie{{Name: "PANPSC", Value: "v1"}, {Name: "BDUSS", Value: "same"}},
		200, `{"errno":0}`,
	)
	e2 := mkEntry(
		"https://api.example.com/sign?t=2&rand=bbb",
		[]har.QueryString{{Name: "t", Value: "2"}, {Name: "rand", Value: "bbb"}, {Name: "extra", Value: "only-b"}},
		[]har.Cookie{{Name: "PANPSC", Value: "v2"}, {Name: "BDUSS", Value: "same"}},
		200, `{"errno":9230}`,
	)

	return &har.Har{Log: har.Log{
		Version: "1.2",
		Creator: har.Creator{Name: "test", Version: "1.0"},
		Entries: []har.Entries{e1, e2},
	}}
}

func TestPickEntryByIndex(t *testing.T) {
	h := buildTwoEntryHar()

	e, g, err := pickEntry(h, 1, "", "A")
	if err != nil {
		t.Fatalf("pickEntry by index failed: %v", err)
	}
	if g != 1 {
		t.Errorf("expected global index 1, got %d", g)
	}
	if e.Request.URL != "https://api.example.com/sign?t=2&rand=bbb" {
		t.Errorf("wrong entry picked: %s", e.Request.URL)
	}

	// 越界
	_, _, err = pickEntry(h, 99, "", "A")
	if err == nil {
		t.Error("expected out-of-range error")
	}
}

func TestPickEntryByURL(t *testing.T) {
	h := buildTwoEntryHar()

	e, g, err := pickEntry(h, -1, "rand=aaa", "A")
	if err != nil {
		t.Fatalf("pickEntry by url failed: %v", err)
	}
	if g != 0 {
		t.Errorf("expected global index 0, got %d", g)
	}
	if e == nil {
		t.Error("nil entry")
	}

	_, _, err = pickEntry(h, -1, "no-such-thing", "A")
	if err == nil {
		t.Error("expected not-found error")
	}
}

func TestPickEntryNoSelector(t *testing.T) {
	h := buildTwoEntryHar()
	_, _, err := pickEntry(h, -1, "", "A")
	if err == nil {
		t.Error("expected error when neither index nor url given")
	}
}

func TestDiffNameValues(t *testing.T) {
	a := []nameValuePair{{"t", "1"}, {"rand", "aaa"}, {"sign", "s1"}}
	b := []nameValuePair{{"t", "2"}, {"rand", "bbb"}, {"extra", "only-b"}}

	var diffs []entryFieldDiff
	identical := diffNameValues(&diffs, "query", a, b, nil)

	if identical != 0 {
		t.Errorf("expected 0 identical, got %d", identical)
	}
	// t、rand 值不同 = 2；sign 只在 A = 1；extra 只在 B = 1 → 共 4 处
	if len(diffs) != 4 {
		t.Fatalf("expected 4 diffs, got %d: %+v", len(diffs), diffs)
	}

	// 验证 absent 标记
	var signDiff *entryFieldDiff
	for i := range diffs {
		if diffs[i].Name == "sign" {
			signDiff = &diffs[i]
		}
	}
	if signDiff == nil || signDiff.B != absentMarker {
		t.Errorf("sign diff missing or wrong: %+v", signDiff)
	}
}

func TestDiffNameValuesIgnore(t *testing.T) {
	a := []nameValuePair{{"t", "1"}, {"secret", "x"}}
	b := []nameValuePair{{"t", "2"}, {"secret", "y"}}

	var diffs []entryFieldDiff
	diffNameValues(&diffs, "query", a, b, map[string]bool{"secret": true})

	if len(diffs) != 1 || diffs[0].Name != "t" {
		t.Errorf("ignore not applied: %+v", diffs)
	}
}

func TestBuildEntryDiffReport(t *testing.T) {
	h := buildTwoEntryHar()
	r := buildEntryDiffReport(&h.Log.Entries[0], &h.Log.Entries[1], 0, 1, entryDiffOptions{})

	if r.IndexA != 0 || r.IndexB != 1 {
		t.Errorf("wrong indexes: %d vs %d", r.IndexA, r.IndexB)
	}

	// query 组应包含 t/rand 变化 + sign(A only) + extra(B only) = 4
	// cookie 组应包含 PANPSC 变化 = 1（BDUSS 相同不计）
	// response-body 不同 = 1
	var groups map[string]int = map[string]int{}
	for _, d := range r.Differences {
		groups[d.Group]++
	}
	if groups["query"] != 4 {
		t.Errorf("expected 4 query diffs, got %d", groups["query"])
	}
	if groups["cookie"] != 1 {
		t.Errorf("expected 1 cookie diff (PANPSC), got %d", groups["cookie"])
	}
	if groups["response-body"] != 1 {
		t.Errorf("expected 1 response-body diff, got %d", groups["response-body"])
	}

	// 一致字段计数 > 0（BDUSS 等）
	if r.Identical == 0 {
		t.Error("expected some identical fields")
	}
}

func TestBuildEntryDiffReportSkipBody(t *testing.T) {
	h := buildTwoEntryHar()
	r := buildEntryDiffReport(&h.Log.Entries[0], &h.Log.Entries[1], 0, 1, entryDiffOptions{skipBody: true})

	for _, d := range r.Differences {
		if d.Group == "response-body" {
			t.Error("skip-body should suppress response-body diff")
		}
	}
}

func TestTruncateForDiff(t *testing.T) {
	short := "abc"
	if truncateForDiff(short) != short {
		t.Error("short string should pass through")
	}
	long := make([]byte, 1000)
	for i := range long {
		long[i] = 'x'
	}
	out := truncateForDiff(string(long))
	if len(out) >= 1000 {
		t.Errorf("long string not truncated, len=%d", len(out))
	}
}

func TestFormatEntryDiffText(t *testing.T) {
	h := buildTwoEntryHar()
	r := buildEntryDiffReport(&h.Log.Entries[0], &h.Log.Entries[1], 0, 1, entryDiffOptions{})
	out := formatEntryDiffText(r)

	// 关键结构：标题、A/B 行、分组标题、一致计数
	for _, want := range []string{"条目字段级对比", "A: [0]", "B: [1]", "[query]", "一致字段"} {
		if !contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
