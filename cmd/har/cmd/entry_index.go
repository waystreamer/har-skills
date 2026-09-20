package cmd

import (
	har "github.com/waystreamer/har-skills/pkg/har"
)

// entryIndex 包装条目切片，同时携带每个条目在 HAR log.entries 中的
// 全局索引。list/find 输出的 INDEX 必须能直接喂给 extract --index，
// 因此所有排序、过滤、limit 操作都必须在这个包装上进行，
// 不能只看过滤结果（那样索引会变成结果集相对序号）。
type entryIndex struct {
	entries []har.Entries
	gidx    []int
}

// newEntryIndex 从完整 HAR 构建初始映射（全局索引即初始顺序）
func newEntryIndex(h *har.Har) *entryIndex {
	ei := &entryIndex{
		entries: h.Log.Entries,
		gidx:    make([]int, len(h.Log.Entries)),
	}
	for i := range ei.gidx {
		ei.gidx[i] = i
	}
	return ei
}

// fromFilterResult 用 result 中的条目反查全局索引。
// 以 (Method, URL, StartedDateTime, Status) 为键做多重映射，
// 保证重复 URL 的条目按出现顺序各自对上。
func fromFilterResult(h *har.Har, result *har.FilterResult) *entryIndex {
	type key struct {
		method string
		url    string
		start  int64
		status int
	}
	makeKey := func(e *har.Entries) key {
		return key{e.Request.Method, e.Request.URL, e.StartedDateTime.UnixNano(), e.Response.Status}
	}

	// 全局索引多重映射：同一 key 可能有多个条目
	lookup := make(map[key][]int)
	for i := range h.Log.Entries {
		k := makeKey(&h.Log.Entries[i])
		lookup[k] = append(lookup[k], i)
	}

	ei := &entryIndex{}
	used := make(map[key]int)
	for i := range result.Entries {
		e := &result.Entries[i]
		k := makeKey(e)
		n := used[k]
		used[k] = n + 1
		if idxs, ok := lookup[k]; ok && n < len(idxs) {
			ei.entries = append(ei.entries, *e)
			ei.gidx = append(ei.gidx, idxs[n])
		} else {
			// 理论上不会发生；防御性保留条目，索引记为 -1
			ei.entries = append(ei.entries, *e)
			ei.gidx = append(ei.gidx, -1)
		}
	}
	return ei
}

// filterByGlobalIndexSet 保留全局索引在给定集合中的条目（求交集用）
func (ei *entryIndex) filterByGlobalIndexSet(keep map[int]bool) {
	var entries []har.Entries
	var gidx []int
	for i, g := range ei.gidx {
		if keep[g] {
			entries = append(entries, ei.entries[i])
			gidx = append(gidx, g)
		}
	}
	ei.entries = entries
	ei.gidx = gidx
}

// globalIndexSet 返回当前条目的全局索引集合
func (ei *entryIndex) globalIndexSet() map[int]bool {
	s := make(map[int]bool, len(ei.gidx))
	for _, g := range ei.gidx {
		s[g] = true
	}
	return s
}

// limit 保留前 n 条
func (ei *entryIndex) limit(n int) {
	if n > 0 && len(ei.entries) > n {
		ei.entries = ei.entries[:n]
		ei.gidx = ei.gidx[:n]
	}
}

// filterByPredicate 按条目内容过滤（保留谓词为真的条目）
func (ei *entryIndex) filterByPredicate(pred func(*har.Entries) bool) {
	var entries []har.Entries
	var gidx []int
	for i := range ei.entries {
		if pred(&ei.entries[i]) {
			entries = append(entries, ei.entries[i])
			gidx = append(gidx, ei.gidx[i])
		}
	}
	ei.entries = entries
	ei.gidx = gidx
}
