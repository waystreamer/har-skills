package cmd

import (
	"testing"

	har "github.com/waystreamer/har-skills/pkg/har"
)

// TestNewEntryIndex 全局索引就是初始顺序
func TestNewEntryIndex(t *testing.T) {
	h := buildTwoEntryHar()
	ei := newEntryIndex(h)

	if len(ei.entries) != 2 || len(ei.gidx) != 2 {
		t.Fatalf("expected 2 entries, got %d/%d", len(ei.entries), len(ei.gidx))
	}
	if ei.gidx[0] != 0 || ei.gidx[1] != 1 {
		t.Errorf("gidx not identity: %v", ei.gidx)
	}
}

// TestFromFilterResult 过滤后的条目必须映射回原始全局索引，而不是重编号
func TestFromFilterResult(t *testing.T) {
	h := buildTwoEntryHar()
	// 只取第二个条目（URL 含 rand=bbb）
	result := &har.FilterResult{Entries: []har.Entries{h.Log.Entries[1]}}
	ei := fromFilterResult(h, result)

	if len(ei.entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(ei.entries))
	}
	if ei.gidx[0] != 1 {
		t.Errorf("expected global index 1 (not result-relative 0), got %d", ei.gidx[0])
	}
}

// TestEntryIndexLimit limit 后 gidx 同步截断
func TestEntryIndexLimit(t *testing.T) {
	h := buildTwoEntryHar()
	ei := newEntryIndex(h)
	ei.limit(1)

	if len(ei.entries) != 1 || len(ei.gidx) != 1 {
		t.Fatalf("limit failed: %d/%d", len(ei.entries), len(ei.gidx))
	}
	if ei.gidx[0] != 0 {
		t.Errorf("expected gidx 0, got %d", ei.gidx[0])
	}
}

// TestEntryIndexFilterByPredicate 过滤保持 gidx 对应
func TestEntryIndexFilterByPredicate(t *testing.T) {
	h := buildTwoEntryHar()
	ei := newEntryIndex(h)
	ei.filterByPredicate(func(e *har.Entries) bool {
		return e.Request.URL == "https://api.example.com/sign?t=2&rand=bbb"
	})

	if len(ei.entries) != 1 {
		t.Fatalf("expected 1 entry after filter, got %d", len(ei.entries))
	}
	if ei.gidx[0] != 1 {
		t.Errorf("expected gidx 1, got %d", ei.gidx[0])
	}
}

// TestEntryIndexGlobalIndexSet 集合语义
func TestEntryIndexGlobalIndexSet(t *testing.T) {
	h := buildTwoEntryHar()
	ei := newEntryIndex(h)
	s := ei.globalIndexSet()

	if !s[0] || !s[1] || len(s) != 2 {
		t.Errorf("bad set: %v", s)
	}
}

// TestSortPairStable 排序必须 entries 和 gidx 同步移动，且稳定
func TestSortPairStable(t *testing.T) {
	h := buildTwoEntryHar()
	// 两个条目 time 都是 0，但给第二个条目一个更小的 size 来区分
	h.Log.Entries[0].Response.Content.Size = 100
	h.Log.Entries[1].Response.Content.Size = 50

	ei := newEntryIndex(h)
	// 按 size 升序：原来 index=1 的（size 50）应该排到前面，且 gidx 仍是 1
	sortPairStable(ei, func(e *har.Entries) float64 { return float64(e.Response.Content.Size) }, true)

	if ei.gidx[0] != 1 {
		t.Errorf("expected first gidx=1 (size 50), got %d", ei.gidx[0])
	}
	if ei.gidx[1] != 0 {
		t.Errorf("expected second gidx=0 (size 100), got %d", ei.gidx[1])
	}
}

// TestTruncateURL 截断按 rune 计，中文不出乱码
func TestTruncateURL(t *testing.T) {
	// 短于 maxLen 不动
	if truncateURL("http://a/b", 100) != "http://a/b" {
		t.Error("short url should pass through")
	}
	// maxLen=0 不截断
	long := "https://example.com/" + string(make([]byte, 200))
	if truncateURL(long, 0) != long {
		t.Error("maxLen=0 should disable truncation")
	}
	// 中文 URL 按 rune 截断，不产生非法 UTF-8
	cn := "https://example.com/中文路径测试abc"
	out := truncateURL(cn, 15)
	if !contains(out, "...[+") {
		t.Errorf("expected truncation marker, got %q", out)
	}
}
