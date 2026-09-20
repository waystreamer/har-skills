package har

import (
	"encoding/json"
	"time"
)

// ---------------------------------------------------------------------------
// 纯结构体镜像：字段标签与 Har/Log/Entries 等完全一致，
// 但类型名不同，因此没有 UnmarshalJSON 方法，json.Unmarshal 直接走标准路径。
// 用于 ParseHarSkipValidation 的快速解析，避免嵌套 UnmarshalJSON 的
// O(depth × size) 重复解析开销。
// ---------------------------------------------------------------------------

type rawHar struct {
	Log rawLog `json:"log"`
}

type rawLog struct {
	Version string       `json:"version"`
	Creator Creator      `json:"creator"`
	Browser Browser      `json:"browser,omitempty"`
	Pages   []rawPages   `json:"pages,omitempty"`
	Entries []rawEntries `json:"entries"`
	Comment string       `json:"comment,omitempty"`
}

type rawPages struct {
	StartedDateTime time.Time   `json:"startedDateTime"`
	ID              string      `json:"id"`
	Title           string      `json:"title"`
	PageTimings     PageTimings `json:"pageTimings"`
	Comment         string      `json:"comment,omitempty"`
}

type rawEntries struct {
	StartedDateTime time.Time   `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         rawRequest  `json:"request"`
	Response        rawResponse `json:"response"`
	Cache           rawCache    `json:"cache"`
	Timings         rawTimings  `json:"timings"`
	Pageref         string      `json:"pageref,omitempty"`
	ServerIPAddress string      `json:"serverIPAddress,omitempty"`
	Connection      string      `json:"connection,omitempty"`
	Initiator       Initiator   `json:"_initiator,omitempty"`
	Priority        string      `json:"_priority,omitempty"`
	ResourceType    string      `json:"_resourceType,omitempty"`
	Comment         string      `json:"comment,omitempty"`
}

type rawRequest struct {
	Method       string        `json:"method"`
	URL          string        `json:"url"`
	HTTPVersion  string        `json:"httpVersion"`
	Cookies      []Cookie      `json:"cookies"`
	Headers      []Headers     `json:"headers"`
	QueryString  []QueryString `json:"queryString"`
	PostData     *rawPostData  `json:"postData,omitempty"`
	HeadersSize  int           `json:"headersSize"`
	BodySize     int           `json:"bodySize"`
	Comment      string        `json:"comment,omitempty"`
}

type rawPostData struct {
	MimeType string  `json:"mimeType"`
	Params   []Param `json:"params,omitempty"`
	Text     string  `json:"text,omitempty"`
	Comment  string  `json:"comment,omitempty"`
}

type rawResponse struct {
	Status       int        `json:"status"`
	StatusText   string     `json:"statusText"`
	HTTPVersion  string     `json:"httpVersion"`
	Cookies      []Cookie   `json:"cookies"`
	Headers      []Headers  `json:"headers"`
	Content      rawContent `json:"content"`
	RedirectURL  string     `json:"redirectURL"`
	HeadersSize  int        `json:"headersSize"`
	BodySize     int        `json:"bodySize"`
	TransferSize int        `json:"_transferSize,omitempty"`
	Error        any        `json:"_error,omitempty"`
	Comment      string     `json:"comment,omitempty"`
}

type rawContent struct {
	Size        int    `json:"size"`
	MimeType    string `json:"mimeType"`
	Compression int    `json:"compression,omitempty"`
	Text        string `json:"text,omitempty"`
	Encoding    string `json:"encoding,omitempty"`
	Comment     string `json:"comment,omitempty"`
}

type rawTimings struct {
	Blocked         float64 `json:"blocked"`
	DNS             float64 `json:"dns"`
	Connect         float64 `json:"connect"`
	Ssl             float64 `json:"ssl"`
	Send            float64 `json:"send"`
	Wait            float64 `json:"wait"`
	Receive         float64 `json:"receive"`
	BlockedQueueing float64 `json:"_blocked_queueing,omitempty"`
	BlockedProxy    float64 `json:"_blocked_proxy,omitempty"`
	Comment         string  `json:"comment,omitempty"`
}

type rawBeforeRequest struct {
	Expires     time.Time `json:"expires,omitempty"`
	LastAccess  time.Time `json:"lastAccess,omitempty"`
	ETag        string    `json:"eTag,omitempty"`
	HitCount    int       `json:"hitCount,omitempty"`
	Comment     string    `json:"comment,omitempty"`
}

type rawAfterRequest struct {
	Expires     time.Time `json:"expires,omitempty"`
	LastAccess  time.Time `json:"lastAccess,omitempty"`
	ETag        string    `json:"eTag,omitempty"`
	HitCount    int       `json:"hitCount,omitempty"`
	Comment     string    `json:"comment,omitempty"`
}

type rawCache struct {
	BeforeRequest *rawBeforeRequest `json:"beforeRequest,omitempty"`
	AfterRequest  *rawAfterRequest  `json:"afterRequest,omitempty"`
	Comment       string            `json:"comment,omitempty"`
}

// convertRawHar 将纯结构体镜像转换为 Har
func convertRawHar(raw *rawHar) *Har {
	h := &Har{}
	h.Log.Version = raw.Log.Version
	h.Log.Creator = raw.Log.Creator
	h.Log.Browser = raw.Log.Browser
	h.Log.Comment = raw.Log.Comment

	// Pages
	if len(raw.Log.Pages) > 0 {
		h.Log.Pages = make([]Pages, len(raw.Log.Pages))
		for i, p := range raw.Log.Pages {
			h.Log.Pages[i] = Pages{
				StartedDateTime: p.StartedDateTime,
				ID:              p.ID,
				Title:           p.Title,
				PageTimings:     p.PageTimings,
				Comment:         p.Comment,
			}
		}
	}

	// Entries
	if len(raw.Log.Entries) > 0 {
		h.Log.Entries = make([]Entries, len(raw.Log.Entries))
		for i, re := range raw.Log.Entries {
			e := Entries{
				StartedDateTime: re.StartedDateTime,
				Time:            re.Time,
				Pageref:         re.Pageref,
				ServerIPAddress: re.ServerIPAddress,
				Connection:      re.Connection,
				Initiator:       re.Initiator,
				Priority:        re.Priority,
				ResourceType:    re.ResourceType,
				Comment:         re.Comment,
			}

			// Request
			e.Request = Request{
				Method:      re.Request.Method,
				URL:         re.Request.URL,
				HTTPVersion: re.Request.HTTPVersion,
				Cookies:     re.Request.Cookies,
				Headers:     re.Request.Headers,
				QueryString: re.Request.QueryString,
				HeadersSize: re.Request.HeadersSize,
				BodySize:    re.Request.BodySize,
				Comment:     re.Request.Comment,
			}
			if re.Request.PostData != nil {
				e.Request.PostData = &PostData{
					MimeType: re.Request.PostData.MimeType,
					Params:   re.Request.PostData.Params,
					Text:     re.Request.PostData.Text,
					Comment:  re.Request.PostData.Comment,
				}
			}

			// Response
			e.Response = Response{
				Status:       re.Response.Status,
				StatusText:   re.Response.StatusText,
				HTTPVersion:  re.Response.HTTPVersion,
				Cookies:      re.Response.Cookies,
				Headers:      re.Response.Headers,
				RedirectURL:  re.Response.RedirectURL,
				HeadersSize:  re.Response.HeadersSize,
				BodySize:     re.Response.BodySize,
				TransferSize: re.Response.TransferSize,
				Error:        re.Response.Error,
				Comment:      re.Response.Comment,
			}
			e.Response.Content = Content{
				Size:        re.Response.Content.Size,
				MimeType:    re.Response.Content.MimeType,
				Compression: re.Response.Content.Compression,
				Text:        re.Response.Content.Text,
				Encoding:    re.Response.Content.Encoding,
				Comment:     re.Response.Content.Comment,
			}

			// Cache
			if re.Cache.BeforeRequest != nil {
				e.Cache.BeforeRequest = &BeforeRequest{
					Expires:    re.Cache.BeforeRequest.Expires,
					LastAccess: re.Cache.BeforeRequest.LastAccess,
					ETag:       re.Cache.BeforeRequest.ETag,
					HitCount:   re.Cache.BeforeRequest.HitCount,
					Comment:    re.Cache.BeforeRequest.Comment,
				}
			}
			if re.Cache.AfterRequest != nil {
				e.Cache.AfterRequest = &AfterRequest{
					Expires:    re.Cache.AfterRequest.Expires,
					LastAccess: re.Cache.AfterRequest.LastAccess,
					ETag:       re.Cache.AfterRequest.ETag,
					HitCount:   re.Cache.AfterRequest.HitCount,
					Comment:    re.Cache.AfterRequest.Comment,
				}
			}
			e.Cache.Comment = re.Cache.Comment

			// Timings
			e.Timings = Timings{
				Blocked:         re.Timings.Blocked,
				DNS:             re.Timings.DNS,
				Connect:         re.Timings.Connect,
				Ssl:             re.Timings.Ssl,
				Send:            re.Timings.Send,
				Wait:            re.Timings.Wait,
				Receive:         re.Timings.Receive,
				BlockedQueueing: re.Timings.BlockedQueueing,
				BlockedProxy:    re.Timings.BlockedProxy,
				Comment:         re.Timings.Comment,
			}

			h.Log.Entries[i] = e
		}
	}

	return h
}

// parseHarFast 用纯结构体快速解析 HAR，绕过嵌套 UnmarshalJSON 的重复解析。
//
// 注意：快速路径不提取 _ 前缀自定义字段（CustomFields 为空）。
// 需要自定义字段的场景请使用 ParseHar（完整解析）。
// ParseHarSkipValidation 的设计目标是快速加载第三方抓包文件用于分析，
// 自定义字段不是分析的核心需求。
func parseHarFast(data []byte) (*Har, error) {
	var raw rawHar
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, WrapJSONUnmarshalError(err)
	}
	return convertRawHar(&raw), nil
}
